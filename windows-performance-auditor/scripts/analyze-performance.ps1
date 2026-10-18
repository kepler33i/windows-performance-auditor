#Requires -Version 5.1
<#
.SYNOPSIS
  Analiza baseline.json (y opcionalmente hardware-health.json) y clasifica
  hallazgos. NO consulta ni modifica el sistema: solo lee los JSON indicados.

.DESCRIPTION
  Categorias: software-corregible, configuracion-optimizable,
  capacidad-insuficiente, posible-hardware, limitacion-estructural,
  evidencia-insuficiente. Las reglas estan documentadas en
  references/diagnostic-rules.md (mismos RuleId).

  Salidas en -OutputDir: findings.json, report.html (local, contiene rutas) y
  report-shareable.html (sanitizado: usuario, equipo, dominio, seriales, IP
  publicas, correos).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BaselinePath,
    [string]$HardwarePath,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [switch]$NoHtml
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$scriptName = 'analyze-performance'

try {
    $OutputDir = Assert-WpaOutputDir $OutputDir
    $baseline = [IO.File]::ReadAllText($BaselinePath) | ConvertFrom-Json
    $hardware = $null
    if ($HardwarePath) { $hardware = [IO.File]::ReadAllText($HardwarePath) | ConvertFrom-Json }
} catch {
    Write-WpaError ("Entrada invalida: " + $_.Exception.Message)
    exit 2
}

$findings = New-Object System.Collections.ArrayList

function Add-Finding {
    param(
        [string]$RuleId, [string]$Category, [string]$Severity, [string]$Title,
        [string[]]$Evidence, [string]$Interpretation, [string]$Recommendation,
        [string]$Confidence = 'media',
        [bool]$CanAgentFix = $false, [string]$AgentLimits = '', [string]$ManualTest = '',
        [bool]$BackupRecommended = $false, [string[]]$ProposedActionTypes = @(), $ActionTargets = $null
    )
    if ($script:WpaCategories -notcontains $Category) { throw "Categoria invalida: $Category" }
    [void]$findings.Add([pscustomobject]@{
        Id                  = ('F-{0:d3}' -f ($findings.Count + 1))
        RuleId              = $RuleId
        Category            = $Category
        Severity            = $Severity
        Confidence          = $Confidence
        Title               = $Title
        Evidence            = @($Evidence)
        Interpretation      = $Interpretation
        Recommendation      = $Recommendation
        CanAgentFix         = $CanAgentFix
        AgentLimits         = $AgentLimits
        ManualTest          = $ManualTest
        BackupRecommended   = $BackupRecommended
        ProposedActionTypes = @($ProposedActionTypes)
        ActionTargets       = $ActionTargets
    })
}

function V { param([string]$Path, $Default = $null) return (Get-WpaValue $baseline $Path $Default) }
function Hw { param([string]$Path, $Default = $null) return (Get-WpaValue $hardware $Path $Default) }
# Colecciones: descartan $null y objetos vacios ({}) de baselines antiguas o consultas sin resultados.
function VL { param([string]$Path) return @(Get-WpaList (Get-WpaValue $baseline $Path @())) }
function HwL { param([string]$Path) return @(Get-WpaList (Get-WpaValue $hardware $Path @())) }

$hwLimits = 'El agente no puede reparar ni reemplazar componentes fisicos. Una optimizacion de software no corrige una falla de hardware.'

# --- Contexto ----------------------------------------------------------------
$isManaged = [bool](V 'Device.IsManaged' $false)
if ($isManaged) {
    Add-Finding -RuleId 'CTX-MANAGED' -Category 'evidencia-insuficiente' -Severity 'info' -Confidence 'alta' `
        -Title 'Equipo posiblemente administrado (corporativo/escolar)' `
        -Evidence @((VL 'Device.ManagedReasons') | ForEach-Object { [string]$_ }) `
        -Interpretation 'Las politicas de la organizacion pueden controlar este equipo.' `
        -Recommendation 'No se propondran modificaciones sin autorizacion verificable del area de TI. Solo se ofrecen verificaciones de solo lectura.'
}

$totalRam = [double](V 'OS.TotalRamGB' 0)
$logical = [int](V 'CPU.LogicalProcessors' 0)
# Perfil de componentes calculado al inicio: varias reglas dependen de el.
$hwProfile = Get-WpaHardwareProfile -Baseline $baseline -Hardware $hardware

# --- Memoria -----------------------------------------------------------------
$commitPct = V 'Memory.CommitPercent'
$availGB = V 'Memory.AvailableGB'
$topMem = @(VL 'Sampling.TopByMemory')
if ($null -ne $commitPct -and [double]$commitPct -ge 80) {
    $sev = if ([double]$commitPct -ge 90) { 'high' } else { 'medium' }
    $cat = if ($totalRam -gt 0 -and $totalRam -le 8.5) { 'capacidad-insuficiente' } else { 'software-corregible' }
    $ev = @(('Memoria comprometida: {0}% del limite ({1} GB de {2} GB)' -f $commitPct, (V 'Memory.CommittedGB'), (V 'Memory.CommitLimitGB')),
            ('RAM instalada visible: {0} GB' -f $totalRam))
    if ($topMem.Count -gt 0) { $ev += ('Mayor consumidor: {0} ({1} MB privados, {2} procesos)' -f $topMem[0].Name, $topMem[0].PrivateMB, $topMem[0].Count) }
    Add-Finding -RuleId 'MEM-01' -Category $cat -Severity $sev -Title 'Presion alta de memoria comprometida' -Evidence $ev `
        -Interpretation $(if ($cat -eq 'capacidad-insuficiente') { 'Con 8 GB o menos, la carga actual excede la memoria fisica; Windows recurre al archivo de paginacion.' } else { 'La RAM instalada es razonable; el consumo proviene de aplicaciones concretas.' }) `
        -Recommendation $(if ($cat -eq 'capacidad-insuficiente') { 'Cerrar aplicaciones/pestanas pesadas. Si el uso es habitual, evaluar ampliacion de RAM (verificar si es ampliable).' } else { 'Revisar los procesos con mayor consumo y cerrarlos o reconfigurarlos desde la propia aplicacion.' })
}
if ($totalRam -gt 0 -and $null -ne $availGB -and ([double]$availGB / $totalRam) -lt 0.10) {
    Add-Finding -RuleId 'MEM-02' -Category 'capacidad-insuficiente' -Severity 'medium' -Title 'Memoria fisica disponible menor al 10%' `
        -Evidence @(('Disponible: {0} GB de {1} GB' -f $availGB, $totalRam)) `
        -Interpretation 'Poca memoria libre durante la muestra; puede ser puntual.' `
        -Recommendation 'Repetir la medicion con la carga de trabajo habitual antes de concluir.' -Confidence 'baja'
}
if ($topMem.Count -gt 0 -and $totalRam -gt 0) {
    $hog = $topMem[0]
    if (([double]$hog.PrivateMB / 1024) -ge (0.30 * $totalRam) -and $hog.Name -notin @('Memory Compression', 'System', 'Registry', 'vmmem', 'vmmemWSL')) {
        Add-Finding -RuleId 'MEM-03' -Category 'software-corregible' -Severity 'medium' -Title ('El grupo de procesos "{0}" usa mas del 30% de la RAM' -f $hog.Name) `
            -Evidence @(('{0}: {1} MB privados en {2} procesos' -f $hog.Name, $hog.PrivateMB, $hog.Count)) `
            -Interpretation 'Un programa concentra el consumo de memoria.' `
            -Recommendation 'Cerrar/reiniciar ese programa, reducir pestanas o extensiones, o actualizarlo. El agente no termina procesos automaticamente.'
    }
}
$pps = V 'Memory.PagesPerSec'
if ($null -ne $pps -and [int]$pps -ge 1000) {
    Add-Finding -RuleId 'MEM-04' -Category 'capacidad-insuficiente' -Severity 'low' -Confidence 'baja' -Title 'Paginacion elevada en la muestra' `
        -Evidence @(('Paginas/s: {0}' -f $pps)) -Interpretation 'Lecturas/escrituras de paginacion altas; una sola muestra no es concluyente.' `
        -Recommendation 'Correlacionar con MEM-01. Repetir la medicion.'
}
$exhaust = [int](V 'Events.ByProviderId.Microsoft-Windows-Resource-Exhaustion-Detector/2004' 0)
if ($exhaust -gt 0) {
    Add-Finding -RuleId 'MEM-05' -Category 'capacidad-insuficiente' -Severity 'high' -Title 'Windows registro agotamiento de memoria virtual' `
        -Evidence @(('Eventos Resource-Exhaustion-Detector 2004: {0} en {1} dias' -f $exhaust, (V 'Events.WindowDays'))) `
        -Interpretation 'El sistema se quedo sin memoria comprometible en algun momento.' `
        -Recommendation 'Identificar la aplicacion responsable en el evento; mantener el archivo de paginacion administrado por el sistema; evaluar mas RAM.'
}
if ($totalRam -gt 0 -and $totalRam -lt 7.5) {
    Add-Finding -RuleId 'RAM-SPEC' -Category 'limitacion-estructural' -Severity $(if ($totalRam -lt 5) { 'high' } else { 'medium' }) -Confidence 'alta' `
        -Title ('RAM instalada baja para Windows moderno ({0} GB)' -f $totalRam) -Evidence @(('RAM visible: {0} GB' -f $totalRam)) `
        -Interpretation 'Windows 10/11 con navegador moderno requiere en la practica 8 GB o mas.' `
        -Recommendation 'Ninguna optimizacion de software compensa la falta de RAM. Verificar si el equipo admite ampliacion (manual del fabricante).' `
        -AgentLimits 'El agente no puede ampliar memoria.'
}

# --- Archivo de paginacion -----------------------------------------------------
$pfPresent = V 'PageFile.Present'
$pfAuto = V 'PageFile.AutomaticManaged'
if ($null -ne $pfPresent -and -not [bool]$pfPresent -and -not [bool]$pfAuto) {
    Add-Finding -RuleId 'PAGE-01' -Category 'configuracion-optimizable' -Severity 'medium' -Confidence 'alta' -Title 'No hay archivo de paginacion activo' `
        -Evidence @('Win32_PageFileUsage sin entradas y AutomaticManagedPagefile = False') `
        -Interpretation 'Sin archivo de paginacion el limite de memoria comprometida es igual a la RAM y las aplicaciones pueden fallar.' `
        -Recommendation 'Reactivar manualmente: Configuracion avanzada del sistema > Rendimiento > Memoria virtual > "Administrar automaticamente". La skill nunca reduce ni desactiva la paginacion.'
}

# --- CPU ---------------------------------------------------------------------
$cpuAvg = V 'Sampling.CpuAvgPercent'
$topCpu = @(VL 'Sampling.TopByCpu')
if ($null -ne $cpuAvg -and [double]$cpuAvg -ge 80) {
    $top = if ($topCpu.Count -gt 0) { $topCpu[0] } else { $null }
    if ($top -and [double]$top.CpuPercent -ge 25 -and $top.Name -ne 'Idle') {
        Add-Finding -RuleId 'CPU-01' -Category 'software-corregible' -Severity 'high' -Title ('CPU saturada por "{0}"' -f $top.Name) `
            -Evidence @(('CPU promedio: {0}% (max {1}%) en {2} s' -f $cpuAvg, (V 'Sampling.CpuMaxPercent'), (V 'Sampling.SampleSeconds')), ('{0}: {1}% de CPU total' -f $top.Name, $top.CpuPercent)) `
            -Interpretation 'Un proceso concreto domina el uso de CPU.' `
            -Recommendation 'Verificar si es una tarea esperada (actualizacion, indexacion, antivirus). Si no, cerrarla o actualizar/reinstalar la aplicacion con su instalador oficial.'
    } elseif ($logical -gt 0 -and $logical -le 4) {
        Add-Finding -RuleId 'CPU-01' -Category 'capacidad-insuficiente' -Severity 'high' -Title 'CPU saturada sin un proceso dominante' `
            -Evidence @(('CPU promedio: {0}% con {1} procesadores logicos' -f $cpuAvg, $logical)) `
            -Interpretation 'La carga repartida supera la capacidad del procesador.' `
            -Recommendation 'Reducir aplicaciones simultaneas. Si es la carga habitual, el procesador es insuficiente para el uso.'
    } else {
        Add-Finding -RuleId 'CPU-01' -Category 'evidencia-insuficiente' -Severity 'medium' -Confidence 'baja' -Title 'CPU alta durante la muestra sin causa clara' `
            -Evidence @(('CPU promedio: {0}%' -f $cpuAvg)) `
            -Interpretation 'Puede ser una carga puntual.' -Recommendation 'Repetir la muestra en reposo y bajo carga habitual.'
    }
}
if ($logical -gt 0 -and $logical -le 2) {
    Add-Finding -RuleId 'CPU-SPEC' -Category 'limitacion-estructural' -Severity 'medium' -Confidence 'alta' -Title ('Procesador con {0} procesadores logicos' -f $logical) `
        -Evidence @(('CPU: {0}' -f (V 'CPU.Name'))) -Interpretation 'Capacidad de procesamiento muy limitada para Windows 10/11.' `
        -Recommendation 'Limitar multitarea. No hay correccion por software.' -AgentLimits 'El agente no puede mejorar el hardware.'
}

$activeScheme = [string](V 'Power.ActiveSchemeGuid' '')
$schemes = @(VL 'Power.Schemes')
if ($activeScheme -eq 'a1841308-3541-4fab-bc81-f71556f20b4a') {
    $balanced = @($schemes | Where-Object { $_.Guid -eq '381b4222-f694-41f0-9685-ff5bb260df2e' })
    Add-Finding -RuleId 'PWR-01' -Category 'configuracion-optimizable' -Severity 'medium' -Confidence 'alta' -Title 'Plan de energia Economizador activo' `
        -Evidence @(('Plan activo: {0} ({1})' -f (V 'Power.ActiveSchemeName'), $activeScheme)) `
        -Interpretation 'El plan Economizador limita la frecuencia del procesador.' `
        -Recommendation 'Cambiar a Equilibrado (reversible).' -CanAgentFix ($balanced.Count -gt 0) `
        -ProposedActionTypes $(if ($balanced.Count -gt 0) { @('POWER-SET-SCHEME') } else { @() }) `
        -ActionTargets $(if ($balanced.Count -gt 0) { @('381b4222-f694-41f0-9685-ff5bb260df2e') } else { $null })
}

$fwLimit = [int](V 'Events.ByProviderId.Microsoft-Windows-Kernel-Processor-Power/37' 0)
$fwLimitHw = [int](Hw 'Throttling.FirmwareLimitEvents' 0)
$fwEvents = [Math]::Max($fwLimit, $fwLimitHw)
$freqAvg = V 'Sampling.PercentOfMaxFrequencyAvg'
# Throttling: solo es "posible hardware" si la frecuencia cae BAJO CARGA durante la muestra.
# El evento 37 por si solo es habitual en portatiles (limites de energia en bateria o plan
# Equilibrado) y no prueba un problema termico.
$underLoad = ($null -ne $freqAvg -and [double]$freqAvg -lt 50 -and $null -ne $cpuAvg -and [double]$cpuAvg -ge 50)
if ($underLoad -or $fwEvents -gt 0) {
    $ev = @()
    if ($fwEvents -gt 0) { $ev += ('Eventos Kernel-Processor-Power 37 (limitacion por firmware): {0}' -f $fwEvents) }
    if ($null -ne $freqAvg) { $ev += ('Frecuencia promedio: {0}% del maximo con CPU {1}%' -f $freqAvg, $cpuAvg) }
    if ($underLoad) {
        Add-Finding -RuleId 'HW-THROTTLE' -Category 'posible-hardware' -Severity 'high' -Title 'Limitacion de velocidad del procesador bajo carga (throttling)' -Evidence $ev `
            -Interpretation 'Con CPU ocupada la frecuencia cae a menos de la mitad: suele deberse a temperatura alta (polvo, ventilador, pasta termica) o a limites de energia/cargador.' `
            -Recommendation 'Verificar ventilacion y limpieza, usar cargador original, revisar temperatura con la herramienta del fabricante. Servicio tecnico si persiste.' `
            -AgentLimits ($hwLimits + ' No se modifican BIOS, voltajes ni limites de energia.') `
            -ManualTest 'Diagnostico del fabricante (UEFI/BIOS) y revision fisica de ventiladores y disipador.'
    } else {
        Add-Finding -RuleId 'HW-THROTTLE' -Category 'evidencia-insuficiente' -Severity 'low' -Confidence 'baja' -Title 'El firmware limito la velocidad del procesador en algunos momentos' -Evidence $ev `
            -Interpretation 'El evento 37 es frecuente en portatiles por gestion de energia (bateria, plan Equilibrado) y no prueba un problema termico. No se observo caida de frecuencia bajo carga en la muestra.' `
            -Recommendation 'Si el usuario percibe lentitud bajo carga: repetir la medicion con el equipo conectado al cargador original mientras trabaja.' `
            -AgentLimits 'El agente no lee temperaturas reales sin herramientas del fabricante.' `
            -ManualTest 'Prueba de carga con cargador conectado y herramienta de diagnostico del fabricante.'
    }
}

# --- Almacenamiento ------------------------------------------------------------
$sysVol = @(VL 'Volumes') | Where-Object { $_.IsSystem } | Select-Object -First 1
$sysDiskNum = [string](V 'SystemDiskNumber' '')
$sysDisk = @(VL 'Disks') | Where-Object { [string]$_.DeviceId -eq $sysDiskNum } | Select-Object -First 1
if ($sysVol -and $null -ne $sysVol.FreePercent -and ([double]$sysVol.FreePercent -lt 10 -or [double]$sysVol.FreeGB -lt 15)) {
    $sev = if ([double]$sysVol.FreePercent -lt 5) { 'high' } else { 'medium' }
    $small = ([double]$sysVol.SizeGB -le 130)
    Add-Finding -RuleId 'DSK-01' -Category $(if ($small) { 'capacidad-insuficiente' } else { 'software-corregible' }) -Severity $sev -Confidence 'alta' `
        -Title ('Poco espacio libre en la unidad del sistema ({0})' -f $sysVol.DriveLetter) `
        -Evidence @(('Libre: {0} GB de {1} GB ({2}%)' -f $sysVol.FreeGB, $sysVol.SizeGB, $sysVol.FreePercent)) `
        -Interpretation 'Con poco espacio Windows no puede actualizar ni gestionar bien la paginacion.' `
        -Recommendation 'Usar Configuracion > Sistema > Almacenamiento (Sensor de almacenamiento) y desinstalar aplicaciones no usadas con su desinstalador. Revisar Descargas manualmente. La skill no borra documentos personales.'
}
if ($sysDisk -and $hwProfile.IsMechanical) {
    $optane = ($hwProfile.StorageClass -eq 'HDD-Optane')
    Add-Finding -RuleId 'DSK-02' -Category 'limitacion-estructural' -Severity 'high' -Confidence 'alta' `
        -Title $(if ($optane) { 'Windows instalado en HDD acelerado con Intel Optane' } else { 'Windows instalado en disco mecanico (HDD)' }) `
        -Evidence @(('Disco del sistema: {0} (reportado como {1}, {2})' -f $sysDisk.FriendlyName, $sysDisk.MediaType, $sysDisk.BusType)) `
        -Interpretation $(if ($optane) { 'La cache Optane acelera lo usado con frecuencia, pero el disco sigue siendo mecanico: arranque, actualizaciones y programas poco usados siguen lentos. Windows lo reporta como SSD.' } else { 'Un HDD es la causa mas comun de lentitud general en Windows 10/11 (arranque, actualizaciones, apertura de programas).' }) `
        -Recommendation 'Migrar a SSD (servicio tecnico o clonacion supervisada). Ninguna optimizacion de software iguala esta mejora.' `
        -AgentLimits 'El agente no puede reemplazar el disco ni clonar el sistema.'
}
$qAvg = V 'Sampling.DiskQueueAvg'; $dtAvg = V 'Sampling.DiskTimeAvgPercent'
if (($null -ne $dtAvg -and [double]$dtAvg -ge 90) -or ($null -ne $qAvg -and [double]$qAvg -ge 2)) {
    $isHdd = [bool]$hwProfile.IsMechanical
    Add-Finding -RuleId 'DSK-03' -Category $(if ($isHdd) { 'limitacion-estructural' } else { 'evidencia-insuficiente' }) -Severity 'medium' -Confidence 'baja' `
        -Title 'Presion de disco durante la muestra' -Evidence @(('Tiempo de disco: {0}%; cola promedio: {1}' -f $dtAvg, $qAvg)) `
        -Interpretation 'El disco estuvo ocupado; sin datos de E/S por proceso no se identifica la causa.' `
        -Recommendation 'Observar en Monitor de recursos > Disco que proceso genera la actividad.'
}

# --- Salud fisica del almacenamiento (hardware-health.json) --------------------
foreach ($d in @(HwL 'Storage')) {
    $ev = @(); $sev = $null
    $hs = [string](Get-WpaValue $d 'HealthStatus' '')
    if ($hs -and $hs -ne 'Healthy' -and $hs -ne 'Correcto') { $ev += ('HealthStatus: ' + $hs); $sev = 'critical' }
    $wear = Get-WpaValue $d 'Reliability.WearPercentUsed'
    if ($null -ne $wear -and [double]$wear -ge 70) { $ev += ('Desgaste reportado: {0}%' -f $wear); if (-not $sev -or [double]$wear -ge 90) { $sev = if ([double]$wear -ge 90) { 'critical' } else { 'high' } } }
    $rue = Get-WpaValue $d 'Reliability.ReadErrorsUncorrected'
    if ($null -ne $rue -and [double]$rue -gt 0) { $ev += ('Errores de lectura no corregidos: {0}' -f $rue); if (-not $sev) { $sev = 'high' } }
    if ([bool](Get-WpaValue $d 'FailurePredictAny' $false)) { $ev += 'SMART predice falla (PredictFailure = True)'; $sev = 'critical' }
    if ($ev.Count -gt 0) {
        Add-Finding -RuleId 'HW-DISK' -Category 'posible-hardware' -Severity $sev -Confidence 'alta' -Title ('Senales de degradacion en el disco "{0}"' -f $d.FriendlyName) -Evidence $ev `
            -Interpretation 'El dispositivo de almacenamiento reporta degradacion. Riesgo de perdida de datos.' `
            -Recommendation 'RESPALDAR DATOS IMPORTANTES DE INMEDIATO en otro dispositivo. Evaluar reemplazo del disco con servicio tecnico.' `
            -AgentLimits ($hwLimits + ' No se ejecuta chkdsk /r ni herramientas de escritura sobre un disco degradado.') `
            -ManualTest 'Herramienta de diagnostico del fabricante del disco; servicio tecnico.' -BackupRecommended $true
    }
}
$de = Hw 'DiskEvents'
$diskEvTotal = 0
if ($de) { $diskEvTotal = [int](Get-WpaValue $de 'BadBlock' 0) + [int](Get-WpaValue $de 'PagingError' 0) + [int](Get-WpaValue $de 'NtfsCorruption' 0) + [int](Get-WpaValue $de 'ControllerError' 0) }
else {
    foreach ($k in @('disk/7', 'disk/11', 'disk/51', 'Ntfs/55', 'Ntfs/98', 'Microsoft-Windows-Ntfs/55', 'Microsoft-Windows-Ntfs/98')) {
        $diskEvTotal += [int](V ('Events.ByProviderId.' + $k) 0)
    }
}
if ($diskEvTotal -gt 0) {
    Add-Finding -RuleId 'HW-DISK-EVENTS' -Category 'posible-hardware' -Severity 'high' -Confidence 'media' -Title 'Eventos de error de disco o sistema de archivos' `
        -Evidence @(('Eventos disk 7/11/51 y Ntfs 55/98: {0}' -f $diskEvTotal)) `
        -Interpretation 'Bloques defectuosos, errores de paginacion o corrupcion NTFS pueden indicar disco o cable/controlador con fallas.' `
        -Recommendation 'Respaldar datos. Verificar salud del disco con la herramienta del fabricante. No ejecutar reparaciones de escritura sin respaldo.' `
        -AgentLimits $hwLimits -ManualTest 'Diagnostico del fabricante del disco; revisar conexiones en equipos de escritorio.' -BackupRecommended $true
}

# --- Memoria fisica / WHEA -----------------------------------------------------
$wsum = Hw 'Memory.Whea'
if ($wsum -and [int](Get-WpaValue $wsum 'Total' 0) -gt 0) {
    # Clasificacion por componente y gravedad (version 2 de hardware-health)
    $range = '{0} eventos entre {1} y {2} ({3} por dia){4}' -f $wsum.Total,
        ([DateTime]'1970-01-01').AddSeconds([double]$wsum.FirstUnix).ToLocalTime().ToString('yyyy-MM-dd'),
        ([DateTime]'1970-01-01').AddSeconds([double]$wsum.LastUnix).ToLocalTime().ToString('yyyy-MM-dd'), $wsum.PerDay,
        $(if ($wsum.Capped) { ' - limite de lectura alcanzado, puede haber mas' } else { '' })
    $groupsEv = @((Get-WpaList $wsum.Groups) | Select-Object -First 6 | ForEach-Object {
        'Id {0}, {1}, {2}: {3}{4}{5}' -f $_.Id, $_.Component, $(if ($_.Fatal) { 'FATAL' } else { 'corregido' }), $_.Count,
            $(if ($_.Device) { ' - puerto: ' + $_.Device + ' (' + $_.VenDev + ')' } elseif ($_.VenDev) { ' - ' + $_.VenDev } else { '' }),
            $(if (@($_.ChildDevices).Count) { ' - dispositivo conectado: ' + (@($_.ChildDevices) -join ', ') } else { '' }) })
    $fatalOrCpu = [int]$wsum.Fatal + [int]$wsum.CpuCorrected
    if ($fatalOrCpu -gt 0 -or [int]$wsum.MemoryCorrected -gt 0) {
        Add-Finding -RuleId 'HW-WHEA' -Category 'posible-hardware' -Severity $(if ($fatalOrCpu -gt 0) { 'high' } else { 'medium' }) -Confidence 'media' `
            -Title $(if ([int]$wsum.Fatal -gt 0) { 'Errores de hardware FATALES reportados por WHEA' } else { 'Errores corregidos de memoria o CPU reportados por WHEA' }) `
            -Evidence (@($range) + $groupsEv) `
            -Interpretation 'Errores de CPU o memoria: si se repiten, indican un modulo de RAM o un procesador con problemas, o un overclock/XMP inestable.' `
            -Recommendation 'Ejecutar manualmente el Diagnostico de memoria de Windows (mdsched.exe, requiere reinicio) o la prueba del fabricante. No usar overclock/XMP inestable.' `
            -AgentLimits ($hwLimits + ' El agente no programa pruebas que reinicien el equipo.') `
            -ManualTest 'mdsched.exe o MemTest del fabricante; servicio tecnico si hay errores.' -BackupRecommended $true
    }
    if ([int]$wsum.PcieCorrected -gt 0) {
        $kids = @((Get-WpaList $wsum.Groups) | Where-Object { $_.Component -eq 'PCIe' } | ForEach-Object { @($_.ChildDevices) } | Where-Object { $_ } | Select-Object -Unique)
        Add-Finding -RuleId 'WHEA-PCIE-01' -Category 'configuracion-optimizable' -Severity 'medium' -Confidence 'media' `
            -Title ('Errores PCIe corregidos repetidos ({0}){1}' -f $wsum.PcieCorrected, $(if ($kids.Count) { ' en ' + ($kids -join ', ') } else { '' })) `
            -Evidence (@($range) + $groupsEv) `
            -Interpretation 'Errores CORREGIDOS del enlace PCI Express (AER), no fallas de RAM ni de CPU. Suelen deberse al ahorro de energia del enlace (ASPM) o a un controlador/firmware antiguo del dispositivo conectado (frecuente en tarjetas Wi-Fi). Llenan el registro y pueden causar microcortes.' `
            -Recommendation 'Manual: 1) actualizar el controlador del dispositivo conectado desde el fabricante del equipo; 2) actualizar la BIOS/UEFI; 3) si persiste, probar en Opciones de energia > PCI Express > Administracion de energia del estado de vinculo = Desactivado. No requiere prueba de memoria.' `
            -AgentLimits 'El agente no cambia controladores, BIOS ni ASPM automaticamente.'
    }
} else {
$whea = [int](Hw 'Memory.WheaEvents' 0)
if ($whea -eq 0) { $whea = [int](V 'Events.Counts.Hardware' 0) }
if ($whea -gt 0) {
    Add-Finding -RuleId 'HW-WHEA' -Category 'posible-hardware' -Severity 'high' -Confidence 'media' -Title 'Errores de hardware reportados por WHEA' `
        -Evidence @(('Eventos WHEA-Logger: {0}' -f $whea)) `
        -Interpretation 'WHEA registra errores corregidos o fatales de CPU, memoria o PCIe.' `
        -Recommendation 'Ejecutar manualmente el Diagnostico de memoria de Windows (mdsched.exe, requiere reinicio) o la prueba del fabricante. No usar overclock/XMP inestable.' `
        -AgentLimits ($hwLimits + ' El agente no programa pruebas que reinicien el equipo.') `
        -ManualTest 'mdsched.exe o MemTest del fabricante; servicio tecnico si hay errores.' -BackupRecommended $true
}
}

# --- Bateria -------------------------------------------------------------------
$batHealth = Hw 'Battery.HealthPercent'
if ($null -ne $batHealth -and [double]$batHealth -lt 70) {
    Add-Finding -RuleId 'HW-BATTERY' -Category 'posible-hardware' -Severity $(if ([double]$batHealth -lt 50) { 'high' } else { 'medium' }) -Confidence 'media' `
        -Title ('Bateria deteriorada ({0}% de la capacidad de diseno)' -f $batHealth) `
        -Evidence @(('Capacidad completa {0} mWh / diseno {1} mWh; ciclos: {2}' -f (Hw 'Battery.FullChargeCapacitymWh'), (Hw 'Battery.DesignCapacitymWh'), (Hw 'Battery.CycleCount'))) `
        -Interpretation 'Menor autonomia; algunos equipos reducen rendimiento con bateria degradada.' `
        -Recommendation 'Evaluar reemplazo de bateria con servicio tecnico autorizado. Si esta hinchada, dejar de usarla.' `
        -AgentLimits $hwLimits -ManualTest 'Diagnostico de bateria del fabricante.'
}

# --- Energia / apagados ----------------------------------------------------------
$kp41 = [int](Hw 'PowerEvents.KernelPower41' (V 'Events.ByProviderId.Microsoft-Windows-Kernel-Power/41' 0))
if ($kp41 -ge 3) {
    Add-Finding -RuleId 'HW-POWER' -Category 'posible-hardware' -Severity 'medium' -Confidence 'media' -Title 'Apagados inesperados repetidos' `
        -Evidence @(('Kernel-Power 41: {0}' -f $kp41)) `
        -Interpretation 'Puede deberse a sobrecalentamiento, fuente/cargador, bateria o controladores; tambien a cortes de energia o apagados forzados por el usuario.' `
        -Recommendation 'Confirmar con el usuario si fueron apagados forzados. Revisar temperatura, cargador y BugCheck en el Visor de eventos.' `
        -AgentLimits $hwLimits -ManualTest 'Revision de fuente/cargador y temperatura por servicio tecnico.'
} elseif ($kp41 -gt 0) {
    Add-Finding -RuleId 'HW-POWER' -Category 'evidencia-insuficiente' -Severity 'low' -Confidence 'baja' -Title 'Apagado inesperado aislado' `
        -Evidence @(('Kernel-Power 41: {0}' -f $kp41)) -Interpretation 'Un evento aislado no permite concluir una falla.' -Recommendation 'Monitorear si se repite.'
}

# --- Seguridad / actualizaciones ----------------------------------------------
$rtp = V 'Security.Defender.RealTimeProtectionEnabled'
$otherAv = @((VL 'Security.AntivirusProducts') | Where-Object { $_.Name -and $_.Name -notmatch 'Defender' })
if ($null -ne $rtp -and -not [bool]$rtp -and $otherAv.Count -eq 0) {
    Add-Finding -RuleId 'SEC-01' -Category 'configuracion-optimizable' -Severity 'high' -Confidence 'alta' -Title 'Proteccion en tiempo real desactivada sin otro antivirus' `
        -Evidence @('Defender RealTimeProtectionEnabled = False') -Interpretation 'Riesgo de seguridad; malware es causa frecuente de lentitud.' `
        -Recommendation 'Reactivar en Seguridad de Windows > Proteccion contra virus y amenazas. La skill nunca desactiva Defender.'
}
$fwOff = @((VL 'Security.Firewall') | Where-Object { -not $_.Enabled })
if ($fwOff.Count -gt 0) {
    Add-Finding -RuleId 'SEC-02' -Category 'configuracion-optimizable' -Severity 'high' -Confidence 'alta' -Title 'Firewall desactivado en algun perfil' `
        -Evidence @($fwOff | ForEach-Object { 'Perfil ' + $_.Profile + ' deshabilitado' }) -Interpretation 'Riesgo de seguridad.' `
        -Recommendation 'Reactivar desde Seguridad de Windows > Firewall. La skill no modifica el firewall.'
}
$wuDays = V 'Security.WindowsUpdate.DaysSinceLastHotfix'
if ($null -ne $wuDays -and [int]$wuDays -gt 60) {
    Add-Finding -RuleId 'SEC-03' -Category 'configuracion-optimizable' -Severity 'medium' -Confidence 'media' -Title ('Sin actualizaciones instaladas hace {0} dias' -f $wuDays) `
        -Evidence @(('Ultima actualizacion local (Get-HotFix): hace {0} dias' -f $wuDays)) -Interpretation 'Correcciones de rendimiento y seguridad pendientes.' `
        -Recommendation 'Revisar Configuracion > Windows Update manualmente. La skill no desactiva ni fuerza Windows Update.'
}
if ([bool](V 'Security.WindowsUpdate.PendingReboot' $false) -or ($null -ne (V 'OS.UptimeHours') -and [double](V 'OS.UptimeHours') -gt 168)) {
    Add-Finding -RuleId 'SYS-REBOOT' -Category 'configuracion-optimizable' -Severity 'low' -Confidence 'alta' -Title 'Reinicio pendiente o equipo encendido por mucho tiempo' `
        -Evidence @(('Reinicio pendiente: {0}; tiempo encendido: {1} h' -f (V 'Security.WindowsUpdate.PendingReboot'), (V 'OS.UptimeHours'))) `
        -Interpretation 'Actualizaciones a medio aplicar y fugas de memoria se acumulan.' `
        -Recommendation 'Reiniciar (no apagar con inicio rapido) cuando el usuario lo decida. El agente no reinicia el equipo.'
}

# --- Controladores, GPU, aplicaciones -------------------------------------------
# Codigo 22 = dispositivo deshabilitado por el usuario: no es una falla.
$drv = @((VL 'DriverProblems') | Where-Object { [int]$_.ErrorCode -ne 22 })
if ($drv.Count -gt 0) {
    Add-Finding -RuleId 'DRV-01' -Category 'software-corregible' -Severity 'medium' -Confidence 'alta' -Title ('{0} dispositivo(s) con problemas de controlador' -f $drv.Count) `
        -Evidence @($drv | Select-Object -First 10 | ForEach-Object { '{0} [{1}] codigo {2}' -f $_.Name, $_.Class, $_.ErrorCode }) `
        -Interpretation 'Dispositivos con error en el Administrador de dispositivos.' `
        -Recommendation 'Instalar manualmente el controlador desde el sitio del fabricante del equipo o Windows Update. La skill no instala ni cambia controladores.'
}
$tdr = [int](V 'Events.ByProviderId.Display/4101' 0)
if ($tdr -gt 0) {
    Add-Finding -RuleId 'GPU-01' -Category 'software-corregible' -Severity 'medium' -Confidence 'media' -Title 'El controlador de video se reinicio (TDR)' `
        -Evidence @(('Eventos Display 4101: {0}' -f $tdr)) `
        -Interpretation 'Normalmente controlador grafico desactualizado; si persiste con controlador correcto, posible problema termico o de GPU.' `
        -Recommendation 'Actualizar manualmente el controlador grafico desde el fabricante. Si persiste, revisar temperatura de la GPU.'
}
$crashes = @(VL 'Events.AppCrashes')
$frequent = @($crashes | Where-Object { [int]$_.Count -ge 5 })
if ($frequent.Count -gt 0) {
    Add-Finding -RuleId 'APP-01' -Category 'software-corregible' -Severity 'medium' -Confidence 'alta' -Title 'Aplicaciones que fallan repetidamente' `
        -Evidence @($frequent | ForEach-Object { '{0}: {1} fallos' -f $_.App, $_.Count }) `
        -Interpretation 'Fallos frecuentes de una aplicacion concreta.' `
        -Recommendation 'Actualizar o reparar la aplicacion desde Configuracion > Aplicaciones o su instalador oficial. Nunca borrar su carpeta manualmente.'
}
$crashTotal = 0; foreach ($c in $crashes) { $crashTotal += [int]$c.Count }
# Fallos concentrados en una sola aplicacion apuntan a esa aplicacion (APP-01), no a Windows.
$crashApps = @($crashes | Where-Object { [int]$_.Count -ge 2 }).Count
if (($crashTotal -ge 10 -and $crashApps -ge 3) -or $tdr -gt 0 -or $kp41 -ge 3) {
    Add-Finding -RuleId 'SYS-INTEGRITY' -Category 'evidencia-insuficiente' -Severity 'low' -Confidence 'baja' -Title 'Verificacion de integridad del sistema recomendada' `
        -Evidence @(('Fallos de aplicaciones: {0} en {1} aplicaciones; TDR: {2}; Kernel-Power 41: {3}' -f $crashTotal, $crashApps, $tdr, $kp41)) `
        -Interpretation 'La inestabilidad podria tener relacion con archivos del sistema danados; primero se verifica sin reparar.' `
        -Recommendation 'Ejecutar verificaciones de solo lectura (requieren administrador).' -CanAgentFix $true `
        -ProposedActionTypes @('VERIFY-DISM-CHECKHEALTH', 'VERIFY-SFC') -ActionTargets @('SYSTEM')
}

# --- Inicio y tareas -----------------------------------------------------------
$startup = @(VL 'Startup')
$enabled = @($startup | Where-Object { $_.State -ne 'Deshabilitado' })
# Umbral segun componentes: en equipos de gama baja cada programa residente pesa mas.
$startupThreshold = if ($hwProfile.RamTier -eq 'bajo' -or $hwProfile.LowEnd) { 4 } else { 8 }
if ($enabled.Count -ge $startupThreshold) {
    $exclude = 'SecurityHealth|Defender|MsMpEng|OneDrive|Dropbox|Google ?Drive|iCloud|Backup|Acronis|Veeam|Realtek|RtkAud|Synaptics|ETD|ELAN|igfx|Intel|NVIDIA|AMD|Radeon|Dolby|Waves|ctfmon|Bitwarden|1Password|KeePass'
    # Solo se protegen los antivirus REALMENTE registrados en Seguridad de Windows (no la marca completa:
    # p. ej. "McAfee Security Scan Plus" es publicidad, no un antivirus residente).
    $avWords = @((VL 'Security.AntivirusProducts') | ForEach-Object { ([string](Get-WpaValue $_ 'Name' '')).Split(' ')[0] } | Where-Object { $_ -and $_ -notmatch '(?i)^(windows|microsoft)$' } | Select-Object -Unique)
    $avPattern = if ($avWords.Count -gt 0) { '(?i)' + (($avWords | ForEach-Object { [regex]::Escape($_) }) -join '|') } else { $null }
    $cands = @($enabled | Where-Object {
        ($_.Location -match '^(HKCU|HKLM):\\Software\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run$' -or [string](Get-WpaValue $_ 'Sub' '') -eq 'StartupFolder') -and
        $_.Name -notmatch $exclude -and [string]$_.Executable -notmatch $exclude -and
        (-not $avPattern -or ($_.Name -notmatch $avPattern -and [string]$_.Executable -notmatch $avPattern)) })
    Add-Finding -RuleId 'STARTUP-01' -Category 'software-corregible' -Severity 'medium' -Confidence 'media' -Title ('{0} programas habilitados al inicio' -f $enabled.Count) `
        -Evidence @($enabled | Select-Object -First 15 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Scope }) `
        -Interpretation 'Muchos programas de inicio aumentan el tiempo de arranque y el consumo en segundo plano.' `
        -Recommendation 'Deshabilitar solo los que el usuario reconozca como innecesarios (reversible, como el Administrador de tareas). Se excluyen seguridad, sincronizacion, respaldo y controladores. Las entradas de equipo (HKLM) requieren administrador.' `
        -CanAgentFix ($cands.Count -gt 0) -ProposedActionTypes $(if ($cands.Count -gt 0) { @('STARTUP-DISABLE') } else { @() }) `
        -ActionTargets @($cands | ForEach-Object {
            $isFolder = ([string](Get-WpaValue $_ 'Sub' '') -eq 'StartupFolder')
            $hive = if ($isFolder) { [string](Get-WpaValue $_ 'Hive' 'HKCU') } elseif ($_.Location -like 'HKLM:*') { 'HKLM' } else { 'HKCU' }
            $sub = if ($isFolder) { 'StartupFolder' } elseif ($_.Location -match 'WOW6432Node') { 'Run32' } else { 'Run' }
            [pscustomobject]@{ Name = $_.Name; CommandHash = $_.CommandHash; Executable = $_.Executable; Hive = $hive; Sub = $sub } })
}
$nonMsTasks = [int](V 'ScheduledTasks.NonMicrosoftEnabled' 0)
if ($nonMsTasks -ge 25) {
    Add-Finding -RuleId 'TASK-01' -Category 'evidencia-insuficiente' -Severity 'info' -Confidence 'baja' -Title ('{0} tareas programadas de terceros habilitadas' -f $nonMsTasks) `
        -Evidence @(('Tareas no Microsoft habilitadas: {0}' -f $nonMsTasks)) -Interpretation 'Informativo. Un numero alto no implica problema por si mismo.' `
        -Recommendation 'Revisar manualmente las de programas ya desinstalados. La skill no deshabilita tareas masivamente.'
}

# --- Optimizacion segun componentes (perfil de hardware) ---------------------
# (perfil ya calculado al inicio)
Add-Finding -RuleId 'PROFILE' -Category 'evidencia-insuficiente' -Severity 'info' -Confidence 'alta' `
    -Title ('Perfil del equipo: disco {0}, RAM {1} ({2} GB), CPU {3} ({4} hilos), {5}, GPU {6}' -f $hwProfile.StorageClass, $hwProfile.RamTier, $hwProfile.RamGB, $hwProfile.CpuTier, $hwProfile.LogicalProcessors, $hwProfile.FormFactor, $hwProfile.GpuClass) `
    -Evidence @($hwProfile.Strategy) `
    -Interpretation 'Las acciones propuestas se eligen segun estos componentes.' `
    -Recommendation 'Seguir la estrategia indicada; las limitaciones fisicas se informan por separado.'

# --- Arranque y confiabilidad ------------------------------------------------------
$bootMed = V 'Boot.MedianBootSec'
if ($null -ne $bootMed) {
    $bootLimit = if ($hwProfile.IsMechanical) { 120 } else { 60 }
    if ([double]$bootMed -gt $bootLimit) {
        $enabledCount = @((VL 'Startup') | Where-Object { $_.State -ne 'Deshabilitado' }).Count
        $pkgEnabled = @((VL 'PackagedStartup') | Where-Object { $_.Enabled }).Count
        $totalStartup = $enabledCount + $pkgEnabled
        $bootEv = @(('Mediana de arranque: {0} s; ultimo: {1} s; post-arranque: {2} s' -f $bootMed, (V 'Boot.LastBootSec'), (V 'Boot.LastPostBootSec')),
                    ('Inicio habilitado: {0} programas + {1} apps de la Tienda' -f $enabledCount, $pkgEnabled))
        # Culpables identificados por Windows (Diagnostics-Performance 101-110)
        $bootEv += @((VL 'BootDegradation') | Select-Object -First 6 | ForEach-Object { 'Retrasa el arranque: {0} (promedio {1} s, {2} veces)' -f $_.Item, $_.AvgDegradationSec, $_.Count })
        Add-Finding -RuleId 'BOOT-01' -Category $(if ($totalStartup -ge 6) { 'software-corregible' } elseif ($hwProfile.IsMechanical) { 'limitacion-estructural' } else { 'evidencia-insuficiente' }) `
            -Severity 'medium' -Confidence 'alta' -Title ('Arranque lento: {0} s (mediana)' -f $bootMed) `
            -Evidence $bootEv `
            -Interpretation ('Referencia para este tipo de disco: menos de {0} s. Si la fase principal es corta y el post-arranque largo, la causa son las apps que se inician con la sesion (y el analisis de Defender sobre ellas).' -f $bootLimit) `
            -Recommendation 'Reducir programas y apps de la Tienda que se inician solos (los culpables listados primero). Defender no se desactiva: analiza menos si arrancan menos programas. En HDD, la mejora definitiva es migrar a SSD.'
    }
}
$stab = V 'Reliability.StabilityIndex'
if ($null -ne $stab -and [double]$stab -lt 5) {
    Add-Finding -RuleId 'REL-01' -Category 'evidencia-insuficiente' -Severity 'medium' -Confidence 'media' -Title ('Indice de confiabilidad bajo ({0}/10)' -f $stab) `
        -Evidence @(('Win32_ReliabilityStabilityMetrics: {0}' -f $stab)) `
        -Interpretation 'Fallos frecuentes de aplicaciones, Windows o hardware en las ultimas semanas.' `
        -Recommendation 'Revisar el Monitor de confiabilidad (perfmon /rel) y correlacionar con APP-01, GPU-01 y HW-*.'
}

# --- Ajustes segun componentes -------------------------------------------------------
if ($hwProfile.LowEnd) {
    Add-Finding -RuleId 'VISUAL-01' -Category 'configuracion-optimizable' -Severity 'low' -Confidence 'media' -Title 'Equipo de gama baja: reducir efectos visuales' `
        -Evidence @(('Disco {0}, RAM {1}, CPU {2}' -f $hwProfile.StorageClass, $hwProfile.RamTier, $hwProfile.CpuTier)) `
        -Interpretation 'Animaciones y transparencias consumen recursos que en este equipo son escasos.' `
        -Recommendation 'Reducir efectos visuales del usuario (reversible).' -CanAgentFix $true -ProposedActionTypes @('VISUAL-EFFECTS-PERFORMANCE') -ActionTargets @('USUARIO-ACTUAL')
}
$daysOpt = V 'DiskMaintenance.DaysSinceOptimize'
$sysLetter = if ($sysVol) { [string]$sysVol.DriveLetter } else { [string]$env:SystemDrive }
if ($hwProfile.StorageClass -notin @('desconocido', 'HDD-Optane') -and ($null -eq $daysOpt -or [int]$daysOpt -gt 30) -and $null -ne (V 'DiskMaintenance')) {
    $optMode = if ($hwProfile.StorageClass -eq 'HDD') { 'Defrag' } else { 'ReTrim' }
    Add-Finding -RuleId 'DISKOPT-01' -Category 'configuracion-optimizable' -Severity 'low' -Confidence 'alta' -Title ('Optimizacion de unidad atrasada ({0})' -f $optMode) `
        -Evidence @(('Dias desde la ultima optimizacion programada: {0}' -f $(if ($null -eq $daysOpt) { 'nunca/no disponible' } else { $daysOpt }))) `
        -Interpretation 'Windows optimiza semanalmente; si no ocurre, el rendimiento del disco se degrada.' `
        -Recommendation ('Ejecutar {0} en {1}. Nunca desfragmentar un SSD.' -f $optMode, $sysLetter) -CanAgentFix $true `
        -ProposedActionTypes @('DISK-OPTIMIZE') -ActionTargets @([pscustomobject]@{ Drive = $sysLetter; Mode = $optMode })
}
$hibOn = V 'Hibernation.HibernateEnabled'
if ($hwProfile.FormFactor -eq 'escritorio' -and $hibOn -eq $true) {
    Add-Finding -RuleId 'HIBER-01' -Category 'configuracion-optimizable' -Severity 'low' -Confidence 'alta' -Title 'Hibernacion activa en un equipo de escritorio' `
        -Evidence @(('hiberfil.sys: {0} GB; inicio rapido: {1}' -f (V 'Hibernation.HiberfilGB'), (V 'Hibernation.FastStartupEnabled'))) `
        -Interpretation 'En escritorios la hibernacion rara vez se usa; ocupa espacio y el inicio rapido puede arrastrar problemas entre reinicios.' `
        -Recommendation 'Desactivar hibernacion (reversible: se puede reactivar con la accion de reversion).' -CanAgentFix $true -ProposedActionTypes @('HIBERNATION-OFF') -ActionTargets @('SYSTEM')
}
$defOn = V 'Security.Defender.RealTimeProtectionEnabled'
$qsAge = V 'Security.Defender.QuickScanAgeDays'; $sigAge = V 'Security.Defender.SignatureAgeDays'
if ($defOn -eq $true -and (($null -ne $qsAge -and [int]$qsAge -gt 14) -or ($null -ne $sigAge -and [int]$sigAge -gt 7))) {
    Add-Finding -RuleId 'DEF-01' -Category 'configuracion-optimizable' -Severity 'low' -Confidence 'alta' -Title 'Analisis o firmas de Defender desactualizados' `
        -Evidence @(('Ultimo analisis rapido: hace {0} dias; firmas: {1} dias' -f $qsAge, $sigAge)) `
        -Interpretation 'Conviene descartar malware como causa de lentitud.' `
        -Recommendation 'Actualizar firmas y ejecutar analisis rapido (usa red).' -CanAgentFix $true -ProposedActionTypes @('DEFENDER-SCAN') -ActionTargets @('SYSTEM')
}

# --- Limpieza por categoria ------------------------------------------------------------
$cleanThresholds = [ordered]@{ 'CLEANUP-USER-TEMP' = 500; 'CLEANUP-WINDOWS-TEMP' = 500; 'CLEANUP-WER' = 200 }
foreach ($ct in $cleanThresholds.Keys) {
    $mb = V ('Cleanup.' + $ct + '.MB')
    if ($null -ne $mb -and [double]$mb -ge $cleanThresholds[$ct]) {
        Add-Finding -RuleId 'CLEANUP-01' -Category 'software-corregible' -Severity 'low' -Confidence 'alta' -Title ('Espacio recuperable: {0}' -f $ct) `
            -Evidence @(('{0} MB en {1} archivos con mas de 7 dias' -f $mb, (V ('Cleanup.' + $ct + '.Files')))) `
            -Interpretation 'Archivos temporales o informes antiguos regenerables.' `
            -Recommendation 'Limpiar la categoria (irreversible, riesgo medio; lista exacta en la bitacora).' -CanAgentFix $true `
            -ProposedActionTypes @($ct) -ActionTargets @(@(Get-WpaCleanupRoots $ct) -join ';')
    }
}
if (@($findings | ForEach-Object { $_.RuleId }) -contains 'DSK-01') {
    Add-Finding -RuleId 'CLEANUP-02' -Category 'software-corregible' -Severity 'low' -Confidence 'media' -Title 'Liberar espacio de componentes y cache de actualizaciones' `
        -Evidence @('Poco espacio en la unidad del sistema (DSK-01)') `
        -Interpretation 'WinSxS y la cache de Optimizacion de distribucion pueden ocupar varios GB.' `
        -Recommendation 'Limpieza soportada por Microsoft (irreversible, riesgo medio).' -CanAgentFix $true `
        -ProposedActionTypes @('COMPONENT-CLEANUP', 'CLEANUP-DELIVERY-OPTIMIZATION') -ActionTargets @('SYSTEM')
}

# --- Huerfanos ------------------------------------------------------------------------------
$oTasks = @(VL 'Orphans.Tasks')
if ($oTasks.Count -gt 0) {
    Add-Finding -RuleId 'ORPHAN-01' -Category 'software-corregible' -Severity 'low' -Confidence 'alta' -Title ('{0} tarea(s) programada(s) de programas ya desinstalados' -f $oTasks.Count) `
        -Evidence @($oTasks | Select-Object -First 10 | ForEach-Object { '{0} -> {1} (no existe)' -f $_.FullPath, $_.Execute }) `
        -Interpretation 'Se ejecutan y fallan repetidamente.' `
        -Recommendation 'Deshabilitar una por una (reversible). No se eliminan.' -CanAgentFix $true `
        -ProposedActionTypes @('TASK-DISABLE-ORPHAN') -ActionTargets @($oTasks | ForEach-Object { [string]$_.FullPath })
}
$oSvcs = @(VL 'Orphans.Services')
if ($oSvcs.Count -gt 0) {
    Add-Finding -RuleId 'ORPHAN-02' -Category 'software-corregible' -Severity 'low' -Confidence 'alta' -Title ('{0} servicio(s) de programas ya desinstalados' -f $oSvcs.Count) `
        -Evidence @($oSvcs | Select-Object -First 10 | ForEach-Object { '{0} ({1}) -> {2} (no existe)' -f $_.Name, $_.StartMode, $_.Exe }) `
        -Interpretation 'Servicios de terceros cuyo ejecutable ya no existe generan errores de inicio.' `
        -Recommendation 'Deshabilitar uno por uno (reversible, riesgo medio). No se eliminan ni se tocan servicios de Windows.' -CanAgentFix $true `
        -ProposedActionTypes @('SERVICE-DISABLE-ORPHAN') -ActionTargets @($oSvcs | ForEach-Object { [string]$_.Name })
}

# --- Programas sin uso (> 6 meses, sin romper nada) -----------------------------------------
$appsInv = V 'Apps'
if ($appsInv) {
    $ctx = [pscustomobject]@{ NowUnix = (Get-WpaUnixNow); OemManufacturer = [string](V 'Computer.Manufacturer' '') }
    $eligible = @(); $unknown = 0; $protected = 0; $recent = 0
    foreach ($a in @(Get-WpaList (Get-WpaValue $appsInv 'Items' @()))) {
        $chk = Test-WpaUninstallCandidate -App $a -Context $ctx
        if ($chk.Eligible) { $eligible += $a; continue }
        $joined = $chk.Reasons -join ' '
        if ($joined -match 'uso desconocido|cobertura') { $unknown++ }
        elseif ($joined -match 'protegida|Microsoft|fabricante') { $protected++ }
        elseif ($joined -match 'usado hace|menos de 6 meses') { $recent++ }
    }
    $evNote = ('Evidencia: Prefetch {0} (cobertura {1} dias), UserAssist {2}' -f $(if ($appsInv.PrefetchAvailable) { 'disponible' } else { 'no disponible (requiere administrador)' }), $appsInv.PrefetchCoverageDays, $(if ($appsInv.UserAssistAvailable) { 'disponible' } else { 'no disponible' }))
    if ($eligible.Count -gt 0) {
        Add-Finding -RuleId 'APP-UNUSED-01' -Category 'software-corregible' -Severity 'medium' -Confidence 'alta' -Title ('{0} programa(s) sin uso hace mas de 6 meses que se pueden desinstalar sin riesgo detectado' -f $eligible.Count) `
            -Evidence (@($evNote) + @($eligible | Select-Object -First 15 | ForEach-Object {
                $lu = if ($_.Usage.LastUseUnix) { 'ultimo uso hace {0} dias ({1})' -f [int](((Get-WpaUnixNow) - [int64]$_.Usage.LastUseUnix) / 86400), $_.Usage.Source } else { 'sin ejecuciones registradas por Prefetch en {0} dias (desde {1})' -f $_.Usage.NoRunsInCoverageDays, (Get-Date).AddDays(-[int]$_.Usage.NoRunsInCoverageDays).ToString('yyyy-MM-dd') }
                $lu += '; instalado ' + ([DateTime]'1970-01-01').AddSeconds([double]$_.InstallDateUnix).ToString('yyyy-MM-dd')
                '{0} {1} ({2}) - {3}; {4} MB' -f $_.DisplayName, $_.DisplayVersion, $_.Publisher, $lu, $_.EstimatedSizeMB })) `
            -Interpretation 'Cumplen todas las reglas: instalados y sin uso hace mas de 6 meses, sin servicios/drivers, sin procesos activos, sin carpeta compartida, no protegidos y con desinstalador oficial.' `
            -Recommendation 'CONFIRMAR CON EL USUARIO que no usa cada programa (la evidencia tecnica no reemplaza su criterio). Luego desinstalar uno por uno con su desinstalador oficial, previo punto de restauracion verificado.' -CanAgentFix $true `
            -ProposedActionTypes @('APP-UNINSTALL') -ActionTargets @($eligible | ForEach-Object {
                [pscustomobject]@{ KeyPath = $_.KeyPath; DisplayName = $_.DisplayName; Version = $_.DisplayVersion; Publisher = $_.Publisher; InstallLocation = $_.InstallLocation
                                   Fingerprint = $_.Fingerprint; Exe = $_.Uninstall.Exe; Args = $_.Uninstall.Args; Kind = $_.Uninstall.Kind
                                   LastUseUnix = $_.Usage.LastUseUnix; Evidence = $_.Usage.Evidence; Source = $_.Usage.Source; SizeMB = $_.EstimatedSizeMB } })
    }
    Add-Finding -RuleId 'APP-REVIEW' -Category 'evidencia-insuficiente' -Severity 'info' -Confidence 'alta' -Title 'Resumen del inventario de programas' `
        -Evidence @($evNote, ('Programas: {0}; candidatos: {1}; protegidos: {2}; usados recientemente: {3}; uso desconocido: {4}' -f $appsInv.Count, $eligible.Count, $protected, $recent, $unknown)) `
        -Interpretation 'Los programas con uso desconocido NO se proponen: la regla exige evidencia de mas de 6 meses sin uso.' `
        -Recommendation $(if (-not $appsInv.PrefetchAvailable) { 'Para mejorar la evidencia, repetir la recoleccion con -IncludeAppUsage en una consola elevada (con permiso del usuario).' } else { 'Revisar manualmente los programas de uso desconocido si el usuario lo desea.' })
}

# --- Inicio automatico de apps de la Tienda ---------------------------------------
$pkgStart = @((VL 'PackagedStartup') | Where-Object { $_.Enabled -and -not $_.Protected })
if ($pkgStart.Count -gt 0) {
    $deg = @(VL 'BootDegradation')
    Add-Finding -RuleId 'STARTUP-02' -Category 'software-corregible' -Severity 'medium' -Confidence 'alta' -Title ('{0} app(s) de la Tienda se inician solas con Windows' -f $pkgStart.Count) `
        -Evidence @($pkgStart | ForEach-Object {
            $name = $_.Pfn.Split('_')[0]
            $hit = @($deg | Where-Object { $name -like ('*' + ($_.Item -replace '\.exe$', '') + '*') -or $_.Item -like ('*' + $name.Split('.')[-1] + '*') }) | Select-Object -First 1
            '{0} (tarea {1}){2}' -f $_.Pfn, $_.TaskId, $(if ($hit) { (' - retrasa el arranque ~{0} s' -f $hit.AvgDegradationSec) } else { '' }) }) `
        -Interpretation 'Estas apps no aparecen en las claves Run: usan tareas de inicio de la Tienda (pestana Inicio del Administrador de tareas).' `
        -Recommendation 'Deshabilitar el inicio automatico de las que el usuario no necesite al encender (reversible; siguen disponibles al abrirlas).' -CanAgentFix $true `
        -ProposedActionTypes @('STARTUP-DISABLE-PACKAGED') -ActionTargets @($pkgStart | ForEach-Object { [string]$_.Target })
}

# --- Apps de la Tienda en segundo plano y fugas de memoria ------------------------
$bg = @((VL 'BackgroundApps') | Where-Object { -not $_.HasWindow -and $_.KeyExists -and $_.Disabled -ne $true -and -not $_.Protected })
if ($bg.Count -gt 0) {
    Add-Finding -RuleId 'BGAPP-01' -Category 'software-corregible' -Severity 'low' -Confidence 'media' -Title ('{0} app(s) de la Tienda ejecutandose en segundo plano' -f $bg.Count) `
        -Evidence @($bg | ForEach-Object { '{0}: {1} ({2} MB)' -f $_.Pfn, (@($_.Processes) -join ', '), $_.PrivateMB }) `
        -Interpretation 'Procesos sin ventana de apps empaquetadas. El permiso de Windows controla sus tareas de segundo plano; algunos servicios de escritorio empaquetados no dependen de el.' `
        -Recommendation 'Denegar el permiso de segundo plano solo a las apps que el usuario no necesite activas con la app cerrada (reversible).' -CanAgentFix $true `
        -ProposedActionTypes @('BACKGROUND-APP-DISABLE') -ActionTargets @($bg | ForEach-Object { [string]$_.Pfn })
}
$leaks = @(VL 'LeakWatch.Suspects')
if ($leaks.Count -gt 0) {
    Add-Finding -RuleId 'MEM-LEAK-01' -Category 'software-corregible' -Severity 'medium' -Confidence 'media' -Title ('Posible fuga de memoria en {0} proceso(s)' -f $leaks.Count) `
        -Evidence @($leaks | ForEach-Object { '{0} (PID {1}): {2} -> {3} MB en {4} min ({5} MB/min, crecio en {6}% de las muestras)' -f $_.Name, $_.Id, $_.StartMB, $_.EndMB, (V 'LeakWatch.Minutes'), $_.RateMBPerMin, $_.GrowingIntervalsPct }) `
        -Interpretation 'La memoria del proceso crece de forma sostenida sin liberarse; con el tiempo provoca paginacion y lentitud.' `
        -Recommendation 'Guardar el trabajo y reiniciar esa aplicacion; actualizarla a la ultima version. Si persiste, reportarlo al fabricante. El agente no cierra procesos.'
} elseif ($null -ne (V 'LeakWatch')) {
    Add-Finding -RuleId 'MEM-LEAK-00' -Category 'evidencia-insuficiente' -Severity 'info' -Confidence 'media' -Title 'Sin crecimiento sostenido de memoria en la observacion' `
        -Evidence @(('Procesos observados: {0} durante {1} min' -f (V 'LeakWatch.Tracked'), (V 'LeakWatch.Minutes'))) `
        -Interpretation 'Las fugas lentas pueden requerir una observacion mas larga.' -Recommendation 'Repetir con -LeakWatchMinutes mayor si el equipo se pone lento tras horas de uso.'
}

# --- Actualizaciones de aplicaciones ------------------------------------------------------------
if ([bool](V 'Winget.Available' $false)) {
    Add-Finding -RuleId 'APPUPD-01' -Category 'configuracion-optimizable' -Severity 'info' -Confidence 'alta' -Title 'Revision de actualizaciones de aplicaciones disponible (winget)' `
        -Evidence @('winget presente en el equipo') `
        -Interpretation 'Las versiones antiguas pueden tener problemas de rendimiento ya corregidos.' `
        -Recommendation 'Consultar actualizaciones (usa red) y luego aprobar cada actualizacion por separado. Los controladores se actualizan manualmente desde el fabricante.' `
        -CanAgentFix $true -ProposedActionTypes @('APP-UPDATE-CHECK') -ActionTargets @('ALL')
}

# --- Evidencia insuficiente ------------------------------------------------------
$missing = @()
foreach ($u in @(VL 'Unavailable') + @(HwL 'Unavailable')) { if ($u) { $missing += ('{0}: {1}' -f $u.Metric, $u.Reason) } }
if (-not $hardware) { $missing += 'hardware-health: no se ejecuto hardware-health.ps1' }
if ($missing.Count -gt 0) {
    Add-Finding -RuleId 'EVID-01' -Category 'evidencia-insuficiente' -Severity 'info' -Confidence 'alta' -Title 'Metricas no disponibles' -Evidence $missing `
        -Interpretation 'No se infieren valores faltantes. Algunas metricas requieren administrador o no estan expuestas por el hardware.' `
        -Recommendation 'Si el usuario lo autoriza, repetir solo las sondas faltantes en una consola elevada. No se instalan herramientas.'
}

# --- Resultado -----------------------------------------------------------------
$sevOrder = @{ critical = 0; high = 1; medium = 2; low = 3; info = 4 }
$sorted = @($findings | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Id)
$summary = [ordered]@{}
foreach ($c in $script:WpaCategories) { $summary[$c] = @($sorted | Where-Object { $_.Category -eq $c }).Count }

# Inventario de componentes identificados (base del diagnostico)
$components = New-Object System.Collections.ArrayList
if (V 'Bios.Version') { [void]$components.Add(('BIOS: {0} {1} ({2}, hace {3} anios)' -f (V 'Bios.Manufacturer'), (V 'Bios.Version'), (V 'Bios.ReleaseDate'), (V 'Bios.AgeYears'))) }
[void]$components.Add(('CPU: {0} - {1} nucleos / {2} hilos, {3} MHz' -f (V 'CPU.Name'), (V 'CPU.Cores'), (V 'CPU.LogicalProcessors'), (V 'CPU.MaxClockMHz')))
$memMods = @((HwL 'Memory.Modules') | ForEach-Object { '{0} GB {1} MHz' -f (Get-WpaValue $_ 'CapacityGB' '?'), (Get-WpaValue $_ 'SpeedMHz' '?') })
[void]$components.Add(('RAM: {0} GB visibles{1}' -f $totalRam, $(if ($memMods.Count) { ' - modulos: ' + ($memMods -join ' + ') } else { '' })))
if ($null -ne (Hw 'Memory.SlotsUsed')) { [void]$components.Add('RAM: ' + (Get-WpaRamUpgradeHint -SlotsTotal (Hw 'Memory.SlotsTotal') -SlotsUsed (Hw 'Memory.SlotsUsed'))) }
foreach ($g in (VL 'GPU')) { [void]$components.Add(('GPU: {0} (driver {1}, {2})' -f (Get-WpaValue $g 'Name' '?'), (Get-WpaValue $g 'DriverVersion' 'n/d'), (Get-WpaValue $g 'DriverDate' 'n/d'))) }
foreach ($d in (VL 'Disks')) {
    $dn = [string](Get-WpaValue $d 'FriendlyName' ''); $db = [string](Get-WpaValue $d 'BusType' '')
    $cls = if (Test-WpaOptaneHybrid -FriendlyName $dn -BusType $db) { 'HDD + Optane' } else { '{0}/{1}' -f (Get-WpaValue $d 'MediaType' '?'), $db }
    [void]$components.Add(('Disco: {0} ({1}, {2} GB, salud {3}){4}' -f $dn, $cls, (Get-WpaValue $d 'SizeGB' '?'), (Get-WpaValue $d 'HealthStatus' '?'), $(if ([string](Get-WpaValue $d 'DeviceId' '') -eq $sysDiskNum) { ' [sistema]' } else { '' })))
}
if ([bool](Hw 'Battery.Present' $false)) { [void]$components.Add(('Bateria: salud {0}' -f $(if ($null -ne (Hw 'Battery.HealthPercent')) { [string](Hw 'Battery.HealthPercent') + '%' } else { 'no disponible' }))) }

# BIOS antigua: solo recomendacion manual (la skill nunca modifica BIOS/firmware)
$biosAge = V 'Bios.AgeYears'
if ($null -ne $biosAge -and [double]$biosAge -ge 3) {
    Add-Finding -RuleId 'BIOS-01' -Category 'configuracion-optimizable' -Severity 'low' -Confidence 'media' -Title ('BIOS/UEFI de hace {0} anios' -f $biosAge) `
        -Evidence @(('BIOS {0} {1}, fecha {2}' -f (V 'Bios.Manufacturer'), (V 'Bios.Version'), (V 'Bios.ReleaseDate'))) `
        -Interpretation 'Las actualizaciones de BIOS corrigen estabilidad, gestion de energia, compatibilidad PCIe/Wi-Fi y seguridad.' `
        -Recommendation 'Revisar en el sitio de soporte del fabricante si hay una version mas reciente para este modelo e instalarla manualmente (con cargador conectado). La skill no actualiza BIOS ni firmware.' `
        -AgentLimits 'El agente no modifica BIOS, firmware ni controladores.'
    $sorted = @($findings | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Id)
    foreach ($c in $script:WpaCategories) { $summary[$c] = @($sorted | Where-Object { $_.Category -eq $c }).Count }
}

$result = [ordered]@{
    SchemaVersion   = 1
    Mode            = 'audit-only'
    AnalyzedUnix    = (Get-WpaUnixNow)
    BaselineCollectedUnix = (V 'CollectedUnix')
    IsManaged       = $isManaged
    System          = [ordered]@{
        OS = ('{0} ({1})' -f (V 'OS.Caption'), (V 'OS.Build')); CPU = (V 'CPU.Name'); RamGB = $totalRam
        Model = ('{0} {1}' -f (V 'Computer.Manufacturer'), (V 'Computer.Model'))
        FormFactor = $hwProfile.FormFactor
        Components = $components.ToArray()
    }
    HardwareProfile = $hwProfile
    Summary         = $summary
    Findings        = $sorted
}

function ConvertTo-Html5Report {
    param($Data, [string]$Title)
    $tplPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'assets\report-template.html'
    $tpl = [IO.File]::ReadAllText($tplPath)
    $e = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $sumRows = foreach ($k in $Data.Summary.PSObject.Properties) {
        '<tr><td>{0}</td><td>{1}</td></tr>' -f (& $e $k.Name), (& $e $k.Value)
    }
    $cards = foreach ($f in @($Data.Findings)) {
        $evi = (@($f.Evidence) | ForEach-Object { '<li>' + (& $e $_) + '</li>' }) -join ''
        $acts = if (@($f.ProposedActionTypes).Count -gt 0) { '<p><b>Acciones disponibles (requieren aprobacion):</b> ' + (& $e (@($f.ProposedActionTypes) -join ', ')) + '</p>' } else { '' }
        $lim = if ($f.AgentLimits) { '<p><b>Limites del agente:</b> ' + (& $e $f.AgentLimits) + '</p>' } else { '' }
        $man = if ($f.ManualTest) { '<p><b>Prueba manual / servicio tecnico:</b> ' + (& $e $f.ManualTest) + '</p>' } else { '' }
        $bak = if ($f.BackupRecommended) { '<p class="warn"><b>Respaldar datos importantes antes de cualquier otra accion.</b></p>' } else { '' }
        ('<article class="finding sev-{0}"><header><span class="badge">{0}</span> <span class="cat">{1}</span> <b>{2} - {3}</b> <small>[{4}, confianza {5}]</small></header><ul>{6}</ul><p>{7}</p><p><b>Recomendacion:</b> {8}</p>{9}{10}{11}{12}</article>' -f
            (& $e $f.Severity), (& $e $f.Category), (& $e $f.Id), (& $e $f.Title), (& $e $f.RuleId), (& $e $f.Confidence), $evi,
            (& $e $f.Interpretation), (& $e $f.Recommendation), $acts, $lim, $man, $bak)
    }
    $sys = $Data.System
    $sysHtml = '<p><b>{0}</b> ({1})<br>{2}</p>' -f (& $e $sys.Model), (& $e (Get-WpaValue $sys 'FormFactor' '')), (& $e $sys.OS)
    $compList = @(Get-WpaList (Get-WpaValue $sys 'Components' @()))
    if ($compList.Count) { $sysHtml += '<ul>' + (($compList | ForEach-Object { '<li>' + (& $e $_) + '</li>' }) -join '') + '</ul>' }
    $out = $tpl.Replace('{{TITLE}}', (& $e $Title)).Replace('{{GENERATED}}', (& $e (Get-Date).ToString('yyyy-MM-dd HH:mm'))).Replace('{{MODE}}', 'audit-only')
    $prof = $Data.HardwareProfile
    $profHtml = ''
    if ($prof) {
        $profHtml = ('<p>Disco: <b>{0}</b> &middot; RAM: <b>{1}</b> &middot; CPU: <b>{2}</b> &middot; Tipo: <b>{3}</b> &middot; GPU: <b>{4}</b></p><ul>{5}</ul>' -f
            (& $e $prof.StorageClass), (& $e $prof.RamTier), (& $e $prof.CpuTier), (& $e $prof.FormFactor), (& $e $prof.GpuClass),
            ((@($prof.Strategy) | ForEach-Object { '<li>' + (& $e $_) + '</li>' }) -join ''))
    }
    $out = $out.Replace('{{PROFILE}}', $profHtml)
    $out = $out.Replace('{{SYSTEM}}', $sysHtml).Replace('{{SUMMARY_ROWS}}', ($sumRows -join '')).Replace('{{FINDINGS}}', ($cards -join [Environment]::NewLine))
    return $out
}

try {
    $json = $result | ConvertTo-Json -Depth 8
    $fp = Write-WpaFile -OutputDir $OutputDir -Name 'findings.json' -Content $json
    if (-not $NoHtml) {
        $local = ConvertFrom-Json $json
        [void](Write-WpaFile -OutputDir $OutputDir -Name 'report.html' -Content (ConvertTo-Html5Report $local 'Auditoria de rendimiento (local)'))
        $shared = ConvertFrom-Json (ConvertTo-WpaSanitizedJson $json)
        $html = ConvertTo-WpaSanitizedText (ConvertTo-Html5Report $shared 'Auditoria de rendimiento (compartible, sanitizado)')
        [void](Write-WpaFile -OutputDir $OutputDir -Name 'report-shareable.html' -Content $html)
    }
    Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation 'end' -Result 'ok' -ExitCode 0 -Details ("hallazgos: {0}" -f $sorted.Count)
    Write-Output ("Hallazgos: {0}  ->  {1}" -f $sorted.Count, $fp)
    foreach ($k in $summary.Keys) { Write-Output ("  {0,-28} {1}" -f $k, $summary[$k]) }
    exit 0
} catch {
    Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation 'end' -Result 'error' -ExitCode 1 -Details $_.Exception.Message
    Write-WpaError $_.Exception.Message
    exit 1
}

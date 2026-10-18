#Requires -Version 5.1
<#
  lib/catalog.ps1 - ALLOWLIST de acciones, generacion del comando exacto,
  lectores de estado (solo lectura) y verificacion de resultados.
  Este archivo no ejecuta cambios: solo apply-approved-action.ps1 lo hace.
#>

$script:WpaRunKeys = @{
    'HKCU|Run'   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    'HKLM|Run'   = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    'HKLM|Run32' = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
}
$script:WpaApprovedKeys = @{
    'HKCU|Run'   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    'HKLM|Run'   = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    'HKLM|Run32' = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
    'HKCU|StartupFolder' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    'HKLM|StartupFolder' = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
}

function Get-WpaStartupFolderFile {
    # Ruta exacta de un acceso directo en la carpeta Inicio del usuario (HKCU) o comun (HKLM); $null si no existe.
    param([string]$Hive, [string]$Name)
    if ($Name -notmatch '^[^\\/:*?"<>|]{1,200}$' -or $Name -match '^\.') { return $null }
    $folder = if ($Hive -eq 'HKLM') { [Environment]::GetFolderPath('CommonStartup') } else { [Environment]::GetFolderPath('Startup') }
    if (-not $folder) { return $null }
    $p = Join-Path $folder $Name
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $null }
    return $p
}
# Compatibilidad con la version anterior
$script:WpaRunKey = $script:WpaRunKeys['HKCU|Run']
$script:WpaApprovedKey = $script:WpaApprovedKeys['HKCU|Run']

# Ajustes de efectos visuales (usuario actual). Equivalen a "Ajustar para obtener el mejor rendimiento"
# en sus partes de mayor costo; efecto completo al cerrar e iniciar sesion.
$script:WpaVisualSettings = @(
    [pscustomobject]@{ Path = 'HKCU:\Control Panel\Desktop\WindowMetrics'; Name = 'MinAnimate'; Value = '0'; Type = 'String' },
    [pscustomobject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'TaskbarAnimations'; Value = 0; Type = 'DWord' },
    [pscustomobject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'; Name = 'EnableTransparency'; Value = 0; Type = 'DWord' },
    [pscustomobject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'; Name = 'VisualFXSetting'; Value = 3; Type = 'DWord' }
)

$script:WpaBlockedUninstallers = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe',
    'regsvr32.exe', 'bitsadmin.exe', 'certutil.exe', 'curl.exe', 'wmic.exe', 'reg.exe', 'schtasks.exe', 'sc.exe', 'explorer.exe')

function New-WpaCatalogEntry {
    param([hashtable]$H)
    $defaults = @{ Modifies = $true; RequiresAdmin = $false; RequiresReboot = $false; Network = $false; RequiresRestorePoint = $false; Exe = ''; Args = @() }
    foreach ($k in $defaults.Keys) { if (-not $H.ContainsKey($k)) { $H[$k] = $defaults[$k] } }
    return [pscustomobject]$H
}

function Get-WpaSystemExe { param([string]$Name) return (Join-Path (Join-Path $env:SystemRoot 'System32') $Name) }

function Get-WpaWingetPath {
    try {
        $c = Get-Command -Name 'winget.exe' -CommandType Application -ErrorAction Stop | Select-Object -First 1
        return [string]$c.Source
    } catch { return $null }
}

function Get-WpaActionCatalog {
    $c = [ordered]@{}
    # --- Verificaciones (no modifican) -------------------------------------
    $c['VERIFY-SFC'] = New-WpaCatalogEntry @{ Type = 'VERIFY-SFC'; Risk = 'Low'; Modifies = $false; RequiresAdmin = $true
        Title = 'Verificar integridad de archivos del sistema (sin reparar)'
        Benefit = 'Determina si hay archivos de sistema danados antes de considerar reparaciones.'
        Affects = 'Ninguno (solo lectura). Escribe en el registro CBS de Windows.'
        Backup = 'No requiere.'; Rollback = 'No aplica: no realiza cambios.'; RollbackReliable = $true
        Validation = 'Codigo de salida y %SystemRoot%\Logs\CBS\CBS.log.'
        Exe = (Get-WpaSystemExe 'sfc.exe'); Args = @('/verifyonly') }
    $c['VERIFY-DISM-CHECKHEALTH'] = New-WpaCatalogEntry @{ Type = 'VERIFY-DISM-CHECKHEALTH'; Risk = 'Low'; Modifies = $false; RequiresAdmin = $true
        Title = 'Consultar estado de la imagen de Windows (DISM CheckHealth)'
        Benefit = 'Indica si la imagen de Windows esta marcada como danada.'
        Affects = 'Ninguno (solo lectura).'; Backup = 'No requiere.'; Rollback = 'No aplica.'; RollbackReliable = $true
        Validation = 'Codigo de salida 0 = sin dano detectado.'
        Exe = (Get-WpaSystemExe 'dism.exe'); Args = @('/Online', '/Cleanup-Image', '/CheckHealth') }
    $c['DISK-SCAN'] = New-WpaCatalogEntry @{ Type = 'DISK-SCAN'; Risk = 'Low'; Modifies = $false; RequiresAdmin = $true
        Title = 'Escanear el sistema de archivos en linea (chkdsk /scan)'
        Benefit = 'Detecta errores del sistema de archivos sin desmontar el volumen.'
        Affects = 'Volumen objetivo (lectura; NTFS puede registrar problemas para reparacion posterior).'
        Backup = 'No requiere.'; Rollback = 'No aplica.'; RollbackReliable = $true
        Validation = 'Codigo 0 = sin errores; 3 = requiere reparacion fuera de linea (manual, previo respaldo).'
        Exe = (Get-WpaSystemExe 'chkdsk.exe'); Args = @('/scan') }
    $c['APP-UPDATE-CHECK'] = New-WpaCatalogEntry @{ Type = 'APP-UPDATE-CHECK'; Risk = 'Low'; Modifies = $false; Network = $true
        Title = 'Consultar actualizaciones de aplicaciones instaladas (winget, usa red)'
        Benefit = 'Lista aplicaciones con versiones nuevas para proponer actualizaciones individuales.'
        Affects = 'Ninguno. Acepta los acuerdos de origen de winget (--accept-source-agreements). Conexion a los repositorios de winget.'
        Backup = 'No requiere.'; Rollback = 'No aplica.'; RollbackReliable = $true
        Validation = 'Se guarda winget-upgrades.json en la carpeta del plan.'
        Exe = 'winget'; Args = @('upgrade', '--include-unknown', '--accept-source-agreements', '--disable-interactivity') }
    # --- Cambios de bajo riesgo y reversibles ----------------------------
    $c['POWER-SET-SCHEME'] = New-WpaCatalogEntry @{ Type = 'POWER-SET-SCHEME'; Risk = 'Low'
        Title = 'Cambiar plan de energia activo'
        Benefit = 'Evita limitacion de rendimiento por plan Economizador.'
        Affects = 'Plan de energia activo (powercfg).'
        Backup = 'GUID del plan activo antes del cambio.'
        Rollback = 'powercfg.exe /setactive <GUID-anterior>.'; RollbackReliable = $true
        Validation = 'powercfg /getactivescheme muestra el GUID objetivo.'
        Exe = (Get-WpaSystemExe 'powercfg.exe'); Args = @('/setactive') }
    $c['STARTUP-DISABLE-USER-RUN'] = New-WpaCatalogEntry @{ Type = 'STARTUP-DISABLE-USER-RUN'; Risk = 'Low'
        Title = 'Deshabilitar un programa de inicio del usuario (como el Administrador de tareas)'
        Benefit = 'Reduce tiempo de inicio de sesion y consumo en segundo plano.'
        Affects = 'Un valor en HKCU\...\Explorer\StartupApproved\Run. La entrada Run original NO se elimina.'
        Backup = 'Valor previo de StartupApproved (o su ausencia).'
        Rollback = 'Restaurar el valor previo o quitarlo si no existia.'; RollbackReliable = $true
        Validation = 'Primer byte impar (deshabilitado) y entrada Run intacta.' }
    $c['STARTUP-DISABLE-MACHINE-RUN'] = New-WpaCatalogEntry @{ Type = 'STARTUP-DISABLE-MACHINE-RUN'; Risk = 'Low'; RequiresAdmin = $true
        Title = 'Deshabilitar un programa de inicio de todo el equipo (como el Administrador de tareas)'
        Benefit = 'Reduce tiempo de inicio y consumo en segundo plano para todos los usuarios.'
        Affects = 'Un valor en HKLM\...\Explorer\StartupApproved\Run o Run32. La entrada Run original NO se elimina.'
        Backup = 'Valor previo de StartupApproved (o su ausencia).'
        Rollback = 'Restaurar el valor previo o quitarlo si no existia.'; RollbackReliable = $true
        Validation = 'Primer byte impar (deshabilitado) y entrada Run intacta.' }
    $c['VISUAL-EFFECTS-PERFORMANCE'] = New-WpaCatalogEntry @{ Type = 'VISUAL-EFFECTS-PERFORMANCE'; Risk = 'Low'
        Title = 'Reducir efectos visuales (animaciones y transparencia) del usuario actual'
        Benefit = 'Menor carga de CPU/GPU/RAM en equipos de gama baja. Efecto completo al cerrar sesion.'
        Affects = 'HKCU: WindowMetrics\MinAnimate, Explorer\Advanced\TaskbarAnimations, Themes\Personalize\EnableTransparency, Explorer\VisualEffects\VisualFXSetting.'
        Backup = 'Valores previos (o su ausencia) de cada ajuste.'
        Rollback = 'Restaurar cada valor previo o quitarlo si no existia.'; RollbackReliable = $true
        Validation = 'Cada valor coincide con el objetivo.' }
    $c['HIBERNATION-OFF'] = New-WpaCatalogEntry @{ Type = 'HIBERNATION-OFF'; Risk = 'Low'; RequiresAdmin = $true
        Title = 'Desactivar hibernacion en equipo de escritorio'
        Benefit = 'Libera hiberfil.sys (aprox. 40% de la RAM) y desactiva el inicio rapido, que suele causar problemas.'
        Affects = 'Hibernacion e inicio rapido (powercfg). Solo se propone en escritorios.'
        Backup = 'Estado previo de HibernateEnabled.'
        Rollback = 'powercfg.exe /hibernate on'; RollbackReliable = $true
        Validation = 'HKLM\SYSTEM\CurrentControlSet\Control\Power\HibernateEnabled = 0.'
        Exe = (Get-WpaSystemExe 'powercfg.exe'); Args = @('/hibernate', 'off') }
    $c['TASK-DISABLE-ORPHAN'] = New-WpaCatalogEntry @{ Type = 'TASK-DISABLE-ORPHAN'; Risk = 'Low'; RequiresAdmin = $true
        Title = 'Deshabilitar una tarea programada huerfana (su programa ya no existe)'
        Benefit = 'Evita ejecuciones fallidas recurrentes de programas ya desinstalados.'
        Affects = 'Una tarea programada de terceros. No se elimina.'
        Backup = 'Estado previo de la tarea.'
        Rollback = 'Enable-ScheduledTask -TaskPath <ruta> -TaskName <nombre>.'; RollbackReliable = $true
        Validation = 'Estado de la tarea = Disabled y su ejecutable sigue sin existir.' }
    $c['STARTUP-DISABLE-USER-FOLDER'] = New-WpaCatalogEntry @{ Type = 'STARTUP-DISABLE-USER-FOLDER'; Risk = 'Low'
        Title = 'Deshabilitar un acceso directo de la carpeta Inicio del usuario (como el Administrador de tareas)'
        Benefit = 'Reduce tiempo de inicio de sesion y consumo en segundo plano.'
        Affects = 'Un valor en HKCU\...\Explorer\StartupApproved\StartupFolder. El acceso directo NO se borra.'
        Backup = 'Valor previo de StartupApproved (o su ausencia).'
        Rollback = 'Restaurar el valor previo o quitarlo si no existia.'; RollbackReliable = $true
        Validation = 'Primer byte impar (deshabilitado) y acceso directo intacto.' }
    $c['STARTUP-DISABLE-COMMON-FOLDER'] = New-WpaCatalogEntry @{ Type = 'STARTUP-DISABLE-COMMON-FOLDER'; Risk = 'Low'; RequiresAdmin = $true
        Title = 'Deshabilitar un acceso directo de la carpeta Inicio comun (todos los usuarios)'
        Benefit = 'Reduce tiempo de inicio y consumo en segundo plano para todos los usuarios.'
        Affects = 'Un valor en HKLM\...\Explorer\StartupApproved\StartupFolder. El acceso directo NO se borra.'
        Backup = 'Valor previo de StartupApproved (o su ausencia).'
        Rollback = 'Restaurar el valor previo o quitarlo si no existia.'; RollbackReliable = $true
        Validation = 'Primer byte impar (deshabilitado) y acceso directo intacto.' }
    $c['STARTUP-DISABLE-PACKAGED'] = New-WpaCatalogEntry @{ Type = 'STARTUP-DISABLE-PACKAGED'; Risk = 'Low'
        Title = 'Deshabilitar el inicio automatico de una app de la Tienda (como el Administrador de tareas)'
        Benefit = 'La app deja de abrirse sola al iniciar sesion: arranque mas rapido y menos consumo. Se puede seguir abriendo manualmente.'
        Affects = 'Valor State de la tarea de inicio de la app en HKCU (2 = habilitada -> 1 = deshabilitada por el usuario).'
        Backup = 'Valor State previo.'
        Rollback = 'Restaurar el valor State previo (o reactivarla en Administrador de tareas > Inicio).'; RollbackReliable = $true
        Validation = 'State = 1.' }
    $c['BACKGROUND-APP-DISABLE'] = New-WpaCatalogEntry @{ Type = 'BACKGROUND-APP-DISABLE'; Risk = 'Low'
        Title = 'Denegar permiso de segundo plano a una app de la Tienda (usuario actual)'
        Benefit = 'Evita que la app consuma CPU, RAM y bateria cuando esta cerrada (equivale a Configuracion > Apps > Ejecutar en segundo plano: Nunca).'
        Affects = 'HKCU\...\BackgroundAccessApplications\<app>: valores Disabled y DisabledByUser. Solo controla tareas en segundo plano gestionadas por Windows; servicios de escritorio empaquetados pueden seguir ejecutandose. Notificaciones de la app pueden dejar de llegar con la app cerrada.'
        Backup = 'Valores previos (o su ausencia).'
        Rollback = 'Restaurar los valores previos o quitarlos si no existian.'; RollbackReliable = $true
        Validation = 'Disabled = 1 y DisabledByUser = 1 en la clave de la app.' }
    $c['CREATE-RESTORE-POINT'] = New-WpaCatalogEntry @{ Type = 'CREATE-RESTORE-POINT'; Risk = 'Low'; RequiresAdmin = $true
        Title = 'Crear punto de restauracion del sistema'
        Benefit = 'Estado previo restaurable antes de desinstalar o reparar.'
        Affects = 'Proteccion del sistema (instantaneas). Puede eliminar el punto mas antiguo por cuota.'
        Backup = 'No aplica (es el respaldo).'
        Rollback = 'No requiere. Si la proteccion del sistema esta deshabilitada falla y NO se habilita automaticamente.'; RollbackReliable = $true
        Validation = 'Get-ComputerRestorePoint lista el punto nuevo. Si Windows lo impide por su limite de 24 h, se acepta un punto existente de menos de 24 h SOLO si es anterior a todo cambio de esta sesion, y se informa cual. Si no hay ninguno, se informa que NO existe respaldo.'
        Exe = 'Checkpoint-Computer' }
    $c['DISK-OPTIMIZE'] = New-WpaCatalogEntry @{ Type = 'DISK-OPTIMIZE'; Risk = 'Low'; RequiresAdmin = $true
        Title = 'Optimizar unidad segun su tipo (TRIM en SSD, desfragmentar en HDD)'
        Benefit = 'SSD: informa bloques libres al controlador. HDD: reduce fragmentacion. Nunca desfragmenta un SSD.'
        Affects = 'Volumen objetivo (sin cambios en datos). Uso intensivo de disco durante la operacion.'
        Backup = 'No requiere.'; Rollback = 'No requiere: no cambia datos ni configuracion.'; RollbackReliable = $true
        Validation = 'La operacion termina sin error.'
        Exe = 'Optimize-Volume' }
    $c['DEFENDER-SCAN'] = New-WpaCatalogEntry @{ Type = 'DEFENDER-SCAN'; Risk = 'Low'; RequiresAdmin = $true; Network = $true
        Title = 'Actualizar firmas y ejecutar analisis rapido de Microsoft Defender'
        Benefit = 'Descarta malware como causa de lentitud.'
        Affects = 'Firmas de Defender (descarga). Defender puede poner en cuarentena amenazas (restaurable desde Seguridad de Windows).'
        Backup = 'No requiere.'; Rollback = 'Elementos en cuarentena se restauran manualmente desde Seguridad de Windows.'; RollbackReliable = $true
        Validation = 'QuickScanAge = 0; se informan amenazas detectadas.'
        Exe = 'Start-MpScan' }
    # --- Riesgo medio ------------------------------------------------------
    $c['SERVICE-DISABLE-ORPHAN'] = New-WpaCatalogEntry @{ Type = 'SERVICE-DISABLE-ORPHAN'; Risk = 'Medium'; RequiresAdmin = $true
        Title = 'Deshabilitar un servicio huerfano de terceros (su ejecutable ya no existe)'
        Benefit = 'Elimina errores de inicio de servicios de programas desinstalados.'
        Affects = 'Tipo de inicio de un servicio detenido, de terceros, cuyo binario no existe. No se detiene ni elimina.'
        Backup = 'Tipo de inicio previo.'
        Rollback = 'Set-Service -Name <nombre> -StartupType <tipo-previo>.'; RollbackReliable = $true
        Validation = 'StartMode = Disabled; binario sigue sin existir; sin nuevos errores de servicios.' }
    $c['CLEANUP-USER-TEMP'] = New-WpaCatalogEntry @{ Type = 'CLEANUP-USER-TEMP'; Risk = 'Medium'
        Title = 'Limpiar temporales del usuario (> 7 dias)'
        Benefit = 'Libera espacio en disco.'
        Affects = 'Archivos de %LOCALAPPDATA%\Temp con mas de 7 dias. Sin seguir enlaces ni carpetas sincronizadas. Carpetas no se eliminan.'
        Backup = 'Lista exacta de archivos eliminados en cleanup-<ActionId>.json.'
        Rollback = 'NO EXISTE REVERSION: eliminacion permanente de archivos temporales regenerables.'; RollbackReliable = $false
        Validation = 'Espacio libre aumenta; archivos eliminados ya no existen.' }
    $c['CLEANUP-WINDOWS-TEMP'] = New-WpaCatalogEntry @{ Type = 'CLEANUP-WINDOWS-TEMP'; Risk = 'Medium'; RequiresAdmin = $true
        Title = 'Limpiar temporales de Windows (> 7 dias)'
        Benefit = 'Libera espacio en disco.'
        Affects = 'Archivos de %SystemRoot%\Temp con mas de 7 dias. Archivos en uso se omiten.'
        Backup = 'Lista exacta de archivos eliminados en cleanup-<ActionId>.json.'
        Rollback = 'NO EXISTE REVERSION: eliminacion permanente de temporales.'; RollbackReliable = $false
        Validation = 'Espacio libre aumenta.' }
    $c['CLEANUP-WER'] = New-WpaCatalogEntry @{ Type = 'CLEANUP-WER'; Risk = 'Medium'; RequiresAdmin = $true
        Title = 'Limpiar informes de errores de Windows (> 7 dias)'
        Benefit = 'Libera espacio ocupado por informes de fallos antiguos.'
        Affects = 'Archivos de %ProgramData%\Microsoft\Windows\WER\ReportArchive y ReportQueue con mas de 7 dias.'
        Backup = 'Lista exacta de archivos eliminados en cleanup-<ActionId>.json.'
        Rollback = 'NO EXISTE REVERSION: se pierden informes de fallos antiguos.'; RollbackReliable = $false
        Validation = 'Espacio libre aumenta.' }
    $c['CLEANUP-DELIVERY-OPTIMIZATION'] = New-WpaCatalogEntry @{ Type = 'CLEANUP-DELIVERY-OPTIMIZATION'; Risk = 'Medium'; RequiresAdmin = $true
        Title = 'Vaciar cache de Optimizacion de distribucion'
        Benefit = 'Libera espacio de actualizaciones ya descargadas y compartidas.'
        Affects = 'Cache de Delivery Optimization (Windows la regenera si la necesita).'
        Backup = 'No aplica.'; Rollback = 'NO EXISTE REVERSION: Windows vuelve a descargar si lo necesita.'; RollbackReliable = $false
        Validation = 'La operacion termina sin error.'
        Exe = 'Delete-DeliveryOptimizationCache' }
    $c['COMPONENT-CLEANUP'] = New-WpaCatalogEntry @{ Type = 'COMPONENT-CLEANUP'; Risk = 'Medium'; RequiresAdmin = $true
        Title = 'Limpiar componentes reemplazados de Windows (DISM StartComponentCleanup)'
        Benefit = 'Libera espacio en WinSxS de forma soportada por Microsoft.'
        Affects = 'Almacen de componentes. Despues no se pueden desinstalar actualizaciones ya reemplazadas.'
        Backup = 'No aplica.'; Rollback = 'NO EXISTE REVERSION: las versiones reemplazadas se eliminan.'; RollbackReliable = $false
        Validation = 'Codigo de salida 0.'
        Exe = (Get-WpaSystemExe 'dism.exe'); Args = @('/Online', '/Cleanup-Image', '/StartComponentCleanup') }
    $c['REPAIR-SFC-SCANNOW'] = New-WpaCatalogEntry @{ Type = 'REPAIR-SFC-SCANNOW'; Risk = 'Medium'; RequiresAdmin = $true; RequiresRestorePoint = $true
        Title = 'Reparar archivos del sistema (SFC /scannow)'
        Benefit = 'Reemplaza archivos de sistema danados detectados por VERIFY-SFC.'
        Affects = 'Archivos protegidos de %SystemRoot% detectados como danados.'
        Backup = 'Punto de restauracion verificado en esta sesion (obligatorio).'
        Rollback = 'NO EXISTE REVERSION CONFIABLE. Solo Restaurar sistema (rstrui.exe) al punto verificado.'; RollbackReliable = $false
        Validation = 'VERIFY-SFC posterior y CBS.log.'
        Exe = (Get-WpaSystemExe 'sfc.exe'); Args = @('/scannow') }
    $c['REPAIR-DISM-RESTOREHEALTH'] = New-WpaCatalogEntry @{ Type = 'REPAIR-DISM-RESTOREHEALTH'; Risk = 'Medium'; RequiresAdmin = $true; Network = $true; RequiresRestorePoint = $true
        Title = 'Reparar la imagen de Windows (DISM RestoreHealth, usa Windows Update)'
        Benefit = 'Repara el almacen de componentes danado; prerequisito de SFC /scannow.'
        Affects = 'Almacen de componentes. Descarga archivos desde Windows Update.'
        Backup = 'Punto de restauracion verificado en esta sesion (obligatorio).'
        Rollback = 'NO EXISTE REVERSION CONFIABLE.'; RollbackReliable = $false
        Validation = 'Codigo de salida 0 y VERIFY-DISM-CHECKHEALTH posterior.'
        Exe = (Get-WpaSystemExe 'dism.exe'); Args = @('/Online', '/Cleanup-Image', '/RestoreHealth') }
    $c['APP-UNINSTALL'] = New-WpaCatalogEntry @{ Type = 'APP-UNINSTALL'; Risk = 'Medium'; RequiresAdmin = $true; RequiresRestorePoint = $true
        Title = 'Desinstalar un programa sin uso (> 6 meses) con su desinstalador oficial'
        Benefit = 'Libera espacio y elimina procesos, servicios y actualizadores en segundo plano.'
        Affects = 'El programa indicado, mediante su desinstalador registrado en Windows. Nunca se borran carpetas manualmente.'
        Backup = 'Punto de restauracion verificado en esta sesion (obligatorio) e inventario de programas antes del cambio.'
        Rollback = 'Reinstalar desde el instalador oficial. Restaurar sistema (rstrui.exe) recupera registro/sistema pero no datos de la aplicacion.'; RollbackReliable = $false
        Validation = 'El programa ya no figura; ningun otro programa desaparecio; sin nuevos dispositivos o servicios con error.' }
    $c['APP-UPDATE'] = New-WpaCatalogEntry @{ Type = 'APP-UPDATE'; Risk = 'Medium'; Network = $true
        Title = 'Actualizar una aplicacion instalada (winget, usa red)'
        Benefit = 'Correcciones de rendimiento, estabilidad y seguridad del fabricante.'
        Affects = 'La aplicacion indicada; el instalador del fabricante puede pedir UAC o reiniciar la aplicacion.'
        Backup = 'Version instalada registrada en el plan.'
        Rollback = 'NO EXISTE REVERSION CONFIABLE: reinstalar la version anterior manualmente si estuviera disponible.'; RollbackReliable = $false
        Validation = 'Codigo de salida 0 y version nueva en el inventario.'
        Exe = 'winget' }
    return $c
}

# ---------------------------------------------------------------------------
# Limpieza por categoria
# ---------------------------------------------------------------------------

function Get-WpaCleanupRoots {
    param([string]$Type)
    switch ($Type) {
        'CLEANUP-USER-TEMP'    { return @((Get-WpaTempRoot)) }
        'CLEANUP-WINDOWS-TEMP' { return @((Join-Path $env:SystemRoot 'Temp')) }
        'CLEANUP-WER'          { $b = Join-Path $env:ProgramData 'Microsoft\Windows\WER'; return @((Join-Path $b 'ReportArchive'), (Join-Path $b 'ReportQueue')) }
        default                { return @() }
    }
}

function Get-WpaCleanupFiles {
    <#
      Enumera (solo lectura) archivos de las raices fijas de una categoria con
      antiguedad >= MinAgeDays. No sigue reparse points, omite rutas sincronizadas
      y rutas que no superen la validacion textual. Devuelve { Path; Bytes }.
    #>
    param([string[]]$Roots, [int]$MinAgeDays = 7, [int]$Max = 20000)
    $cutoff = [DateTime]::Now.AddDays(-$MinAgeDays)
    $out = New-Object System.Collections.ArrayList
    foreach ($root in $Roots) {
        if (-not $root -or -not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        if (-not (Test-WpaNoReparseChain $root).Ok) { continue }
        $stack = New-Object System.Collections.Stack
        $stack.Push((New-Object IO.DirectoryInfo($root)))
        while ($stack.Count -gt 0 -and $out.Count -lt $Max) {
            $dir = $stack.Pop()
            try { $entries = $dir.GetFileSystemInfos() } catch { continue }
            foreach ($e in $entries) {
                if (($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                if ($e -is [IO.DirectoryInfo]) { $stack.Push($e); continue }
                if ($e.LastWriteTime -ge $cutoff) { continue }
                if (-not (Test-WpaPathSyntax $e.FullName).Ok) { continue }
                if (Test-WpaInSyncRoot $e.FullName) { continue }
                [void]$out.Add([pscustomobject]@{ Path = $e.FullName; Bytes = [int64]$e.Length })
                if ($out.Count -ge $Max) { break }
            }
        }
    }
    return $out.ToArray()
}

# ---------------------------------------------------------------------------
# Desinstaladores
# ---------------------------------------------------------------------------

function ConvertTo-WpaArgList {
    # Tokeniza argumentos respetando comillas dobles. No interpreta metacaracteres.
    param([string]$ArgString)
    $list = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($ArgString)) { return @() }
    foreach ($m in [regex]::Matches($ArgString, '"([^"]*)"|(\S+)')) {
        if ($m.Groups[1].Success) { [void]$list.Add($m.Groups[1].Value) } else { [void]$list.Add($m.Groups[2].Value) }
    }
    return $list.ToArray()
}

function Resolve-WpaUninstallCommand {
    <#
      Convierte el desinstalador registrado de un programa en un ejecutable +
      argumentos verificables. Devuelve { Ok; Reason; Kind; Exe; Args }.
      MSI -> msiexec.exe /x {GUID} /passive /norestart (interfaz minima, sin preguntas).
      EXE -> el desinstalador registrado, solo si existe y esta en una ubicacion confiable.
    #>
    param($App)
    $fail = { param($r) [pscustomobject]@{ Ok = $false; Reason = $r; Kind = $null; Exe = $null; Args = '' } }
    $us = [string](Get-WpaValue $App 'UninstallString' '')
    $keyName = [string](Get-WpaValue $App 'KeyName' '')
    if ([bool](Get-WpaValue $App 'NoRemove' $false)) { return (& $fail 'el programa declara NoRemove') }
    $guidRx = '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
    $isMsi = [bool](Get-WpaValue $App 'WindowsInstaller' $false) -or ($us -match '(?i)msiexec')
    if ($isMsi) {
        $guid = $null
        if ($keyName -match ('^' + $guidRx + '$')) { $guid = $keyName } else { $m = [regex]::Match($us, $guidRx); if ($m.Success) { $guid = $m.Value } }
        if (-not $guid) { return (& $fail 'MSI sin codigo de producto') }
        return [pscustomobject]@{ Ok = $true; Reason = ''; Kind = 'MSI'; Exe = (Get-WpaSystemExe 'msiexec.exe'); Args = ('/x {0} /passive /norestart' -f $guid.ToUpperInvariant()) }
    }
    if ([string]::IsNullOrWhiteSpace($us)) { return (& $fail 'sin desinstalador registrado') }
    if ($us -match '[&|<>`\r\n]|\$\(') { return (& $fail 'desinstalador con metacaracteres de consola') }
    $exe = $null; $rest = ''
    $t = $us.Trim()
    if ($t.StartsWith('"')) {
        $end = $t.IndexOf('"', 1)
        if ($end -lt 2) { return (& $fail 'comillas desbalanceadas') }
        $exe = $t.Substring(1, $end - 1); $rest = $t.Substring($end + 1).Trim()
    } else {
        $i = $t.ToLowerInvariant().IndexOf('.exe')
        if ($i -lt 0) { return (& $fail 'no se identifica el ejecutable') }
        $exe = $t.Substring(0, $i + 4); $rest = $t.Substring($i + 4).Trim()
    }
    $exe = [Environment]::ExpandEnvironmentVariables($exe)
    $syn = Test-WpaPathSyntax $exe
    if (-not $syn.Ok) { return (& $fail ('ruta del desinstalador invalida: ' + $syn.Reason)) }
    $leaf = [IO.Path]::GetFileName($exe).ToLowerInvariant()
    if ($script:WpaBlockedUninstallers -contains $leaf) { return (& $fail ('desinstalador mediante interprete no permitido: ' + $leaf)) }
    if ($leaf -notmatch '\.exe$') { return (& $fail 'el desinstalador no es un .exe') }
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { return (& $fail 'el desinstalador no existe en disco') }
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:ProgramData 'Package Cache'), (Join-Path $env:LOCALAPPDATA 'Programs'))
    $loc = [string](Get-WpaValue $App 'InstallLocation' '')
    if ($loc) { $roots += $loc.TrimEnd('\') }
    $trusted = $false
    foreach ($r in $roots) { if ($r -and (Test-WpaIsUnder $exe $r)) { $trusted = $true } }
    if (-not $trusted) { return (& $fail 'desinstalador fuera de ubicaciones confiables') }
    return [pscustomobject]@{ Ok = $true; Reason = ''; Kind = 'EXE'; Exe = $exe; Args = $rest }
}

# ---------------------------------------------------------------------------
# Comando exacto
# ---------------------------------------------------------------------------

function Get-WpaActionCommand {
    <#
      Comando EXACTO que ejecutara apply para un tipo, objetivos y detalle.
      propose lo muestra; apply lo regenera y compara: el plan no aporta codigo.
    #>
    param([string]$Type, [string[]]$Targets, $Detail = $null)
    $cat = Get-WpaActionCatalog
    if (-not $cat.Contains($Type)) { throw "Tipo de accion fuera de la allowlist: $Type" }
    $a = $cat[$Type]
    $q = { param($s) ([string]$s).Replace("'", "''") }
    $t0 = if (@($Targets).Count -gt 0) { [string]$Targets[0] } else { '' }
    switch ($Type) {
        'POWER-SET-SCHEME' { return ('"{0}" /setactive {1}' -f $a.Exe, $t0) }
        'STARTUP-DISABLE-USER-RUN' {
            return ("Set-ItemProperty -LiteralPath '{0}' -Name '{1}' -Value ([byte[]](3,0,0,0,0,0,0,0,0,0,0,0)) -Type Binary" -f $script:WpaApprovedKeys['HKCU|Run'], (& $q $t0))
        }
        'STARTUP-DISABLE-MACHINE-RUN' {
            $sub = [string](Get-WpaValue $Detail 'Sub' '')
            if (-not $script:WpaApprovedKeys.ContainsKey('HKLM|' + $sub)) { throw 'Sub invalido para inicio de equipo' }
            return ("Set-ItemProperty -LiteralPath '{0}' -Name '{1}' -Value ([byte[]](3,0,0,0,0,0,0,0,0,0,0,0)) -Type Binary" -f $script:WpaApprovedKeys['HKLM|' + $sub], (& $q $t0))
        }
        'VISUAL-EFFECTS-PERFORMANCE' {
            $lines = foreach ($s in $script:WpaVisualSettings) { "Set-ItemProperty -LiteralPath '{0}' -Name '{1}' -Value {2} -Type {3}" -f $s.Path, $s.Name, $(if ($s.Type -eq 'String') { "'" + $s.Value + "'" } else { $s.Value }), $s.Type }
            return ($lines -join [Environment]::NewLine)
        }
        'TASK-DISABLE-ORPHAN' {
            $i = $t0.LastIndexOf('\')
            return ("Disable-ScheduledTask -TaskPath '{0}' -TaskName '{1}'" -f (& $q $t0.Substring(0, $i + 1)), (& $q $t0.Substring($i + 1)))
        }
        'SERVICE-DISABLE-ORPHAN' { return ("Set-Service -Name '{0}' -StartupType Disabled" -f (& $q $t0)) }
        { $_ -in @('STARTUP-DISABLE-USER-FOLDER', 'STARTUP-DISABLE-COMMON-FOLDER') } {
            if ($t0 -notmatch '^[^\\/:*?"<>|]{1,200}$') { throw 'Nombre de acceso directo invalido' }
            $hiveF = if ($Type -eq 'STARTUP-DISABLE-COMMON-FOLDER') { 'HKLM' } else { 'HKCU' }
            return ("Set-ItemProperty -LiteralPath '{0}' -Name '{1}' -Value ([byte[]](3,0,0,0,0,0,0,0,0,0,0,0)) -Type Binary" -f $script:WpaApprovedKeys[$hiveF + '|StartupFolder'], (& $q $t0))
        }
        'STARTUP-DISABLE-PACKAGED' {
            if (-not (Test-WpaPackagedStartupTarget $t0)) { throw 'Objetivo de inicio empaquetado invalido' }
            return ("Set-ItemProperty -LiteralPath '{0}' -Name 'State' -Value 1 -Type DWord" -f (Join-Path $script:WpaPackagedStartupBase $t0))
        }
        'BACKGROUND-APP-DISABLE' {
            if (-not (Test-WpaPackageFamilyName $t0)) { throw 'Nombre de paquete invalido' }
            $k = Join-Path $script:WpaBackgroundKey $t0
            return (("Set-ItemProperty -LiteralPath '{0}' -Name 'Disabled' -Value 1 -Type DWord" -f $k) + [Environment]::NewLine + ("Set-ItemProperty -LiteralPath '{0}' -Name 'DisabledByUser' -Value 1 -Type DWord" -f $k))
        }
        'CREATE-RESTORE-POINT' { return ("Checkpoint-Computer -Description '{0}' -RestorePointType MODIFY_SETTINGS" -f (& $q $t0)) }
        'DISK-SCAN' { return ('"{0}" {1} /scan' -f $a.Exe, $t0) }
        'DISK-OPTIMIZE' {
            $mode = [string](Get-WpaValue $Detail 'Mode' '')
            if ($mode -notin @('ReTrim', 'Defrag')) { throw 'Modo de optimizacion invalido' }
            return ('Optimize-Volume -DriveLetter {0} -{1}' -f $t0.TrimEnd(':'), $mode)
        }
        'DEFENDER-SCAN' { return ('Update-MpSignature' + [Environment]::NewLine + 'Start-MpScan -ScanType QuickScan') }
        { $_ -in @('CLEANUP-USER-TEMP', 'CLEANUP-WINDOWS-TEMP', 'CLEANUP-WER') } {
            $roots = (Get-WpaCleanupRoots $Type) -join "', '"
            return ("Remove-Item -LiteralPath '<archivo>' -Force   # por cada archivo con mas de 7 dias bajo '{0}', sin seguir enlaces; lista en cleanup-<ActionId>.json" -f $roots)
        }
        'CLEANUP-DELIVERY-OPTIMIZATION' { return 'Delete-DeliveryOptimizationCache -Force' }
        'APP-UNINSTALL' {
            $exe = [string](Get-WpaValue $Detail 'Exe' ''); $args2 = [string](Get-WpaValue $Detail 'Args' '')
            if (-not $exe) { throw 'APP-UNINSTALL sin ejecutable' }
            return ('"{0}" {1}' -f $exe, $args2).Trim()
        }
        'APP-UPDATE-CHECK' {
            $w = Get-WpaWingetPath; if (-not $w) { $w = 'winget.exe (no encontrado)' }
            return ('"{0}" {1}' -f $w, ($a.Args -join ' '))
        }
        'APP-UPDATE' {
            if ($t0 -notmatch '^[A-Za-z0-9][A-Za-z0-9.\-_+]{1,120}$') { throw 'Id de paquete winget invalido' }
            $w = Get-WpaWingetPath; if (-not $w) { $w = 'winget.exe (no encontrado)' }
            return ('"{0}" upgrade --id {1} --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity' -f $w, $t0)
        }
        default { return ('"{0}" {1}' -f $a.Exe, ($a.Args -join ' ')) }
    }
}

# ---------------------------------------------------------------------------
# Lectores de estado (solo lectura)
# ---------------------------------------------------------------------------

function Get-WpaActivePowerScheme {
    $exe = Get-WpaSystemExe 'powercfg.exe'
    $out = & $exe /getactivescheme 2>$null
    $m = [regex]::Match(($out -join ' '), '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
    if ($m.Success) { return $m.Value.ToLowerInvariant() }
    return $null
}

function Get-WpaPowerSchemes {
    $exe = Get-WpaSystemExe 'powercfg.exe'
    $out = & $exe /list 2>$null
    $list = @()
    foreach ($line in @($out)) {
        $m = [regex]::Match($line, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s*\(([^)]*)\)\s*(\*)?')
        if ($m.Success) { $list += [pscustomobject]@{ Guid = $m.Groups[1].Value.ToLowerInvariant(); Name = $m.Groups[2].Value; Active = $m.Groups[3].Success } }
    }
    return $list
}

function Get-WpaStartupApprovedValue {
    param([string]$Name, [string]$Hive = 'HKCU', [string]$Sub = 'Run')
    $key = $script:WpaApprovedKeys[$Hive + '|' + $Sub]
    if (-not $key) { return $null }
    try { return ,([byte[]]((Get-ItemProperty -LiteralPath $key -Name $Name -ErrorAction Stop).$Name)) } catch { return $null }
}

function Get-WpaRunEntry {
    param([string]$Name, [string]$Hive = 'HKCU', [string]$Sub = 'Run')
    $key = $script:WpaRunKeys[$Hive + '|' + $Sub]
    if (-not $key) { return $null }
    try { return [string]((Get-ItemProperty -LiteralPath $key -Name $Name -ErrorAction Stop).$Name) } catch { return $null }
}

function Get-WpaRegValue {
    # Devuelve @{ Exists; Value } de un valor de registro.
    param([string]$Path, [string]$Name)
    try {
        $v = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
        return [pscustomobject]@{ Exists = $true; Value = $v }
    } catch { return [pscustomobject]@{ Exists = $false; Value = $null } }
}

function Get-WpaHibernateEnabled {
    $r = Get-WpaRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled'
    if (-not $r.Exists) { $r = Get-WpaRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabledDefault' }
    if (-not $r.Exists) { return $null }
    return ([int]$r.Value -ne 0)
}

function Get-WpaServiceInfo {
    param([string]$Name)
    if ($Name -notmatch '^[A-Za-z0-9_.\-]{1,100}$') { return $null }
    try { return (Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction Stop | Select-Object -First 1) } catch { return $null }
}

function Get-WpaServiceExe {
    # Extrae el ejecutable de PathName (con o sin comillas) y expande variables.
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    $t = $PathName.Trim()
    if ($t.StartsWith('"')) { $e = $t.IndexOf('"', 1); if ($e -gt 1) { $t = $t.Substring(1, $e - 1) } }
    else { $i = $t.ToLowerInvariant().IndexOf('.exe'); if ($i -ge 0) { $t = $t.Substring(0, $i + 4) } }
    return [Environment]::ExpandEnvironmentVariables($t)
}

function Get-WpaUninstallEntry {
    # Lee la entrada de desinstalacion (solo lectura) desde su ruta de registro exacta.
    param([string]$KeyPath)
    if ($KeyPath -notmatch '^(HKLM|HKCU):\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$') { return $null }
    try { return (Get-ItemProperty -LiteralPath $KeyPath -ErrorAction Stop) } catch { return $null }
}

function Get-WpaAppFingerprint {
    param($Entry)
    return (Get-WpaStringHash (('{0}|{1}|{2}' -f (Get-WpaValue $Entry 'DisplayName' ''), (Get-WpaValue $Entry 'DisplayVersion' ''), (Get-WpaValue $Entry 'UninstallString' ''))))
}

# ---------------------------------------------------------------------------
# Verificacion de resultados (solo lectura)
# ---------------------------------------------------------------------------

function Test-WpaRestorePointEvidence {
    <#
      Logica pura. Ok si existe el punto nuevo con la descripcion indicada. Si no,
      y $AllowRecent (ningun cambio previo en la sesion), acepta el punto mas
      reciente creado en las 24 h anteriores al inicio de la accion.
    #>
    param([object[]]$Points, [string]$Description, [int64]$StartedUnix, [bool]$AllowRecent)
    $new = @($Points | Where-Object { $_.Description -eq $Description -and [int64]$_.Unix -ge ($StartedUnix - 120) })
    if ($new.Count -gt 0) { return [pscustomobject]@{ Ok = $true; Reused = $false; Detail = ("Punto de restauracion verificado: {0} (secuencia {1})" -f $Description, $new[0].Seq) } }
    if ($AllowRecent) {
        $recent = @($Points | Where-Object { [int64]$_.Unix -le $StartedUnix -and [int64]$_.Unix -ge ($StartedUnix - 86400) } | Sort-Object Unix -Descending)
        if ($recent.Count -gt 0) {
            $r = $recent[0]
            $hours = [Math]::Round(($StartedUnix - [int64]$r.Unix) / 3600, 1)
            return [pscustomobject]@{ Ok = $true; Reused = $true; Detail = ("Windows no permite crear otro punto antes de 24 h. Se usa el punto existente #{0} '{1}', creado hace {2} h, ANTES de cualquier cambio de esta sesion." -f $r.Seq, $r.Description, $hours) } }
    }
    return [pscustomobject]@{ Ok = $false; Reused = $false; Detail = 'NO se verifico ningun punto de restauracion utilizable: NO existe respaldo.' }
}

function Test-WpaActionOutcome {
    <#
      Verifica el estado posterior a una accion o su reversion.
      $Backup = contenido de backup-<ActionId>.json; $Mode = 'apply' | 'rollback'.
    #>
    param($Action, $Backup, [string]$Mode = 'apply', $ExitCode = $null)
    $details = New-Object System.Collections.ArrayList
    $ok = $true
    $type = [string](Get-WpaValue $Action 'Type')
    $targets = @(Get-WpaValue $Action 'Targets' @())
    $t0 = if ($targets.Count) { [string]$targets[0] } else { '' }
    $detail = Get-WpaValue $Action 'Detail'
    switch ($type) {
        'POWER-SET-SCHEME' {
            $active = Get-WpaActivePowerScheme
            $expected = if ($Mode -eq 'rollback') { [string](Get-WpaValue $Backup 'PreviousScheme') } else { $t0 }
            $ok = ($active -eq $expected)
            [void]$details.Add(("Plan activo: {0}; esperado: {1}" -f $active, $expected))
        }
        { $_ -in @('STARTUP-DISABLE-USER-RUN', 'STARTUP-DISABLE-MACHINE-RUN', 'STARTUP-DISABLE-USER-FOLDER', 'STARTUP-DISABLE-COMMON-FOLDER') } {
            $isFolder = ($type -like '*-FOLDER')
            $hive = if ($type -in @('STARTUP-DISABLE-USER-RUN', 'STARTUP-DISABLE-USER-FOLDER')) { 'HKCU' } else { 'HKLM' }
            $sub = if ($isFolder) { 'StartupFolder' } elseif ($type -eq 'STARTUP-DISABLE-USER-RUN') { 'Run' } else { [string](Get-WpaValue $detail 'Sub' 'Run') }
            $val = Get-WpaStartupApprovedValue -Name $t0 -Hive $hive -Sub $sub
            if ($isFolder) {
                if ($null -eq (Get-WpaStartupFolderFile -Hive $hive -Name $t0)) { $ok = $false; [void]$details.Add('El acceso directo original ya no existe.') }
            } elseif ($null -eq (Get-WpaRunEntry -Name $t0 -Hive $hive -Sub $sub)) { $ok = $false; [void]$details.Add('La entrada Run original ya no existe.') }
            if ($Mode -eq 'rollback') {
                if ([bool](Get-WpaValue $Backup 'PreviousExisted' $false)) {
                    $prev = @(Get-WpaValue $Backup 'PreviousValue' @()) -join ','
                    $same = ($null -ne $val) -and ((@($val) -join ',') -eq $prev)
                    if (-not $same) { $ok = $false }
                    [void]$details.Add(("StartupApproved restaurado: {0}" -f $same))
                } else {
                    if ($null -ne $val) { $ok = $false }
                    [void]$details.Add(("StartupApproved ausente como antes: {0}" -f ($null -eq $val)))
                }
            } else {
                $disabled = ($null -ne $val) -and ($val.Length -ge 1) -and (($val[0] -band 1) -eq 1)
                if (-not $disabled) { $ok = $false }
                [void]$details.Add(("StartupApproved deshabilitado: {0}" -f $disabled))
            }
        }
        'VISUAL-EFFECTS-PERFORMANCE' {
            foreach ($s in $script:WpaVisualSettings) {
                $cur = Get-WpaRegValue $s.Path $s.Name
                if ($Mode -eq 'rollback') {
                    $prev = @(Get-WpaValue $Backup 'Previous' @()) | Where-Object { $_.Name -eq $s.Name } | Select-Object -First 1
                    $match = if ($prev -and [bool]$prev.Exists) { $cur.Exists -and ([string]$cur.Value -eq [string]$prev.Value) } else { -not $cur.Exists }
                } else {
                    $match = $cur.Exists -and ([string]$cur.Value -eq [string]$s.Value)
                }
                if (-not $match) { $ok = $false }
                [void]$details.Add(("{0}: {1}" -f $s.Name, $(if ($match) { 'ok' } else { 'no coincide' })))
            }
        }
        'HIBERNATION-OFF' {
            $h = Get-WpaHibernateEnabled
            $expected = ($Mode -eq 'rollback')
            $ok = ($h -eq $expected)
            [void]$details.Add(("Hibernacion habilitada: {0}; esperado: {1}" -f $h, $expected))
        }
        'TASK-DISABLE-ORPHAN' {
            $i = $t0.LastIndexOf('\')
            $st = $null
            try { $st = [string](Get-ScheduledTask -TaskPath $t0.Substring(0, $i + 1) -TaskName $t0.Substring($i + 1) -ErrorAction Stop).State } catch { }
            $expected = if ($Mode -eq 'rollback') { [string](Get-WpaValue $Backup 'PreviousState' '') } else { 'Disabled' }
            $ok = ($st -eq $expected) -or ($Mode -eq 'rollback' -and $st -ne 'Disabled' -and $expected -ne 'Disabled')
            [void]$details.Add(("Estado de la tarea: {0}; esperado: {1}" -f $st, $expected))
        }
        'SERVICE-DISABLE-ORPHAN' {
            $svc = Get-WpaServiceInfo $t0
            $startMode = if ($svc) { [string]$svc.StartMode } else { $null }
            $expected = if ($Mode -eq 'rollback') { [string](Get-WpaValue $Backup 'PreviousStartMode' '') } else { 'Disabled' }
            $ok = ($startMode -eq $expected)
            [void]$details.Add(("Tipo de inicio: {0}; esperado: {1}" -f $startMode, $expected))
        }
        'CREATE-RESTORE-POINT' {
            $since = [int64](Get-WpaValue $Backup 'StartedUnix' 0)
            $points = @()
            try {
                $points = @(Get-ComputerRestorePoint -ErrorAction Stop | ForEach-Object {
                    [pscustomobject]@{ Seq = $_.SequenceNumber; Description = [string]$_.Description; Unix = (ConvertTo-WpaUnix ([Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime))) }
                })
            } catch { [void]$details.Add('No se pudo consultar puntos de restauracion: ' + $_.Exception.Message) }
            $res = Test-WpaRestorePointEvidence -Points $points -Description $t0 -StartedUnix $since -AllowRecent ([bool](Get-WpaValue $Backup 'AllowRecentFallback' $false))
            $ok = $res.Ok
            [void]$details.Add($res.Detail)
        }
        'STARTUP-DISABLE-PACKAGED' {
            $cur = Get-WpaRegValue (Join-Path $script:WpaPackagedStartupBase $t0) 'State'
            $expected = if ($Mode -eq 'rollback') { [int](Get-WpaValue $Backup 'PreviousState' -1) } else { 1 }
            $ok = ($cur.Exists -and [int]$cur.Value -eq $expected)
            [void]$details.Add(("State: {0}; esperado: {1}" -f $(if ($cur.Exists) { $cur.Value } else { 'ausente' }), $expected))
        }
        'BACKGROUND-APP-DISABLE' {
            $k = Join-Path $script:WpaBackgroundKey $t0
            foreach ($n in @('Disabled', 'DisabledByUser')) {
                $cur = Get-WpaRegValue $k $n
                if ($Mode -eq 'rollback') {
                    $prev = @(Get-WpaValue $Backup 'Previous' @()) | Where-Object { $_.Name -eq $n } | Select-Object -First 1
                    $match = if ($prev -and [bool]$prev.Exists) { $cur.Exists -and ([string]$cur.Value -eq [string]$prev.Value) } else { -not $cur.Exists }
                } else { $match = $cur.Exists -and ([int]$cur.Value -eq 1) }
                if (-not $match) { $ok = $false }
                [void]$details.Add(("{0}: {1}" -f $n, $(if ($match) { 'ok' } else { 'no coincide' })))
            }
        }
        'DEFENDER-SCAN' {
            try {
                $mp = Get-MpComputerStatus -ErrorAction Stop
                $ok = ([int]$mp.QuickScanAge -eq 0)
                [void]$details.Add(("Antiguedad del analisis rapido: {0} dias" -f $mp.QuickScanAge))
                $th = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge [DateTime]::Now.AddHours(-2) })
                [void]$details.Add(("Amenazas detectadas en el analisis: {0}" -f $th.Count))
            } catch { $ok = $false; [void]$details.Add('No se pudo consultar Defender.') }
        }
        'APP-UNINSTALL' {
            $gone = ($null -eq (Get-WpaUninstallEntry $t0))
            if (-not $gone) { $ok = $false; [void]$details.Add('El programa sigue registrado (desinstalacion cancelada o incompleta).') }
            else { [void]$details.Add('El programa ya no figura en Windows.') }
            $before = @(Get-WpaValue $Backup 'InstalledKeys' @())
            $parent = [string](Get-WpaValue $Backup 'DisplayName' '')
            $parentLoc = ([string](Get-WpaValue $Backup 'InstallLocation' '')).TrimEnd('')
            $missing = @()
            foreach ($k in $before) {
                $kp = [string]$k.KeyPath
                if ($kp -eq $t0) { continue }
                if ($null -eq (Get-WpaUninstallEntry $kp)) {
                    # Componentes propios del programa (mismo nombre o dentro de su carpeta) pueden irse con el.
                    $kLoc = ([string](Get-WpaValue $k 'InstallLocation' '')).TrimEnd('')
                    $related = ($parent -and ([string]$k.DisplayName).IndexOf($parent, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                               ($parentLoc -and $kLoc -and (($kLoc -ieq $parentLoc) -or (Test-WpaIsUnder $kLoc $parentLoc)))
                    if (-not $related) { $missing += [string]$k.DisplayName }
                }
            }
            if ($missing.Count -gt 0) { $ok = $false; [void]$details.Add(('REGRESION: desaparecieron otros programas: ' + ($missing -join ', '))) }
            $drvBefore = [int](Get-WpaValue $Backup 'ProblemDevices' 0)
            $drvNow = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' -ErrorAction SilentlyContinue).Count
            if ($drvNow -gt $drvBefore) { $ok = $false; [void]$details.Add(("REGRESION: dispositivos con error {0} -> {1}" -f $drvBefore, $drvNow)) }
        }
        default {
            $okCodes = @(0)
            $ok = ($null -ne $ExitCode -and $okCodes -contains [int]$ExitCode)
            [void]$details.Add(("Codigo de salida: {0}. Revisar la validacion indicada en el plan." -f $ExitCode))
        }
    }
    return [pscustomobject]@{ Ok = [bool]$ok; Details = @($details) }
}

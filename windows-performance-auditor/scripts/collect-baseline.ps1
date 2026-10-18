#Requires -Version 5.1
<#
.SYNOPSIS
  Recopila una linea base de rendimiento de Windows 10/11. SOLO LECTURA.

.DESCRIPTION
  - No modifica servicios, tareas, registro, archivos del sistema ni configuracion.
  - No realiza llamadas de red. No instala nada.
  - No recopila contrasenas, cookies, tokens, historial, contenido de documentos,
    credenciales Wi-Fi ni lineas de comando de procesos (pueden contener secretos).
  - Se ejecuta sin privilegios administrativos; las metricas que requieren
    administrador se informan como "no disponible".
  - Unica escritura: baseline.json y audit-log.jsonl en -OutputDir, carpeta que
    el usuario debe haber elegido y creado previamente.
  - -LeakWatchMinutes N (0-30): observa N minutos la memoria privada de los 20
    procesos de mayor consumo para detectar fugas (crecimiento sostenido).
  - -IncludeAppUsage (requiere consentimiento del usuario): inventario de programas
    con fecha de ultimo uso por programa, calculada en memoria a partir de Prefetch
    (solo con administrador) y UserAssist. No se guarda historial de ejecuciones.

.EXAMPLE
  powershell.exe -NoProfile -File .\collect-baseline.ps1 -OutputDir 'D:\Auditoria\2026-10-18'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [ValidateRange(3, 60)][int]$SampleSeconds = 10,
    [ValidateRange(1, 90)][int]$EventDays = 14,
    [string]$FileName = 'baseline.json',
    [switch]$SkipEvents,
    [switch]$IncludeAppUsage,
    [ValidateRange(0, 30)][int]$LeakWatchMinutes = 0
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$scriptName = 'collect-baseline'

try {
    $OutputDir = Assert-WpaOutputDir $OutputDir
} catch {
    Write-WpaError $_.Exception.Message
    exit 2
}

$unavailable = New-Object System.Collections.ArrayList
Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation 'start' -Result 'audit-only' -Details ("SampleSeconds={0}; EventDays={1}; elevado={2}" -f $SampleSeconds, $EventDays, (Test-WpaIsAdmin))
if (Test-WpaIsAdmin) { Write-Output 'AVISO: la consola esta elevada (administrador). La recoleccion sigue siendo de solo lectura; se recomienda auditar sin elevar.' }

function P {
    param([string]$Name, [scriptblock]$Block)
    return Invoke-WpaProbe -Name $Name -ScriptBlock $Block -Unavailable $unavailable -OutputDir $OutputDir -ScriptName $scriptName
}

$GB = 1GB
$isAdmin = Test-WpaIsAdmin

# --- Sistema operativo -------------------------------------------------------
$os = P 'os' {
    $o = Get-CimInstance -ClassName Win32_OperatingSystem
    $boot = $o.LastBootUpTime
    [pscustomobject]@{
        Caption         = [string]$o.Caption
        Version         = [string]$o.Version
        Build           = [string]$o.BuildNumber
        Architecture    = [string]$o.OSArchitecture
        InstallDateUnix = (ConvertTo-WpaUnix $o.InstallDate)
        LastBootUnix    = (ConvertTo-WpaUnix $boot)
        UptimeHours     = [Math]::Round(([DateTime]::Now - $boot).TotalHours, 1)
        TotalRamGB      = [Math]::Round(([double]$o.TotalVisibleMemorySize * 1KB) / $GB, 2)
        FreeRamGB       = [Math]::Round(([double]$o.FreePhysicalMemory * 1KB) / $GB, 2)
    }
}

$device = P 'device-context' { Get-WpaDeviceContext }

$computer = P 'computer' {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $chassis = @()
    try { $chassis = @((Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop | Select-Object -First 1).ChassisTypes) } catch { }
    $hasBattery = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue).Count -gt 0
    $laptopTypes = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
    $desktopTypes = @(3, 4, 5, 6, 7, 13, 15, 16, 24, 35, 36)
    $form = 'desconocido'
    if ([int]$cs.PCSystemType -eq 2 -or $hasBattery -or @($chassis | Where-Object { $laptopTypes -contains [int]$_ }).Count -gt 0) { $form = 'portatil' }
    elseif (@($chassis | Where-Object { $desktopTypes -contains [int]$_ }).Count -gt 0) { $form = 'escritorio' }
    [pscustomobject]@{
        Manufacturer = [string]$cs.Manufacturer
        Model        = [string]$cs.Model
        PCSystemType = [int]$cs.PCSystemType
        ChassisTypes = @($chassis | ForEach-Object { [int]$_ })
        FormFactor   = $form
    }
}

# --- Hardware ----------------------------------------------------------------
$cpu = P 'cpu' {
    $c = @(Get-CimInstance -ClassName Win32_Processor)
    [pscustomobject]@{
        Name              = [string]$c[0].Name.Trim()
        Sockets           = $c.Count
        Cores             = [int](($c | Measure-Object -Property NumberOfCores -Sum).Sum)
        LogicalProcessors = [int](($c | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum)
        MaxClockMHz       = [int]$c[0].MaxClockSpeed
    }
}

$gpu = P 'gpu' {
    @(Get-CimInstance -ClassName Win32_VideoController | ForEach-Object {
        [pscustomobject]@{
            Name          = [string]$_.Name
            DriverVersion = [string]$_.DriverVersion
            DriverDate    = if ($_.DriverDate) { ([DateTime]$_.DriverDate).ToString('yyyy-MM') } else { $null }
            Status        = [string]$_.Status
            ErrorCode     = [int]$_.ConfigManagerErrorCode
        }
    })
}

$disks = P 'physical-disks' {
    @(Get-PhysicalDisk | ForEach-Object {
        [pscustomobject]@{
            DeviceId          = [string]$_.DeviceId
            FriendlyName      = [string]$_.FriendlyName
            MediaType         = [string]$_.MediaType
            BusType           = [string]$_.BusType
            SizeGB            = [Math]::Round([double]$_.Size / $GB, 1)
            HealthStatus      = [string]$_.HealthStatus
            OperationalStatus = [string]($_.OperationalStatus -join ',')
        }
    })
}

$systemDiskNumber = P 'system-disk' {
    $part = Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) -ErrorAction Stop
    [string]$part.DiskNumber
}

$volumes = P 'volumes' {
    @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        $size = [double]$_.Size
        $free = [double]$_.FreeSpace
        [pscustomobject]@{
            DriveLetter = [string]$_.DeviceID
            FileSystem  = [string]$_.FileSystem
            SizeGB      = [Math]::Round($size / $GB, 1)
            FreeGB      = [Math]::Round($free / $GB, 1)
            FreePercent = if ($size -gt 0) { [Math]::Round(100 * $free / $size, 1) } else { $null }
            IsSystem    = ($_.DeviceID -eq $env:SystemDrive)
        }
    })
}

# --- Memoria y paginacion ----------------------------------------------------
$memory = P 'memory-counters' {
    $m = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory
    $commit = [double]$m.CommittedBytes
    $limit = [double]$m.CommitLimit
    [pscustomobject]@{
        AvailableGB    = [Math]::Round([double]$m.AvailableBytes / $GB, 2)
        CommittedGB    = [Math]::Round($commit / $GB, 2)
        CommitLimitGB  = [Math]::Round($limit / $GB, 2)
        CommitPercent  = if ($limit -gt 0) { [Math]::Round(100 * $commit / $limit, 1) } else { $null }
        PagesPerSec    = [int]$m.PagesPersec
        PageFaultsPerSec = [int]$m.PageFaultsPersec
        CompressedNote = 'La memoria comprimida forma parte del proceso "Memory Compression".'
    }
}

$pageFile = P 'pagefile' {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $usage = @(Get-CimInstance -ClassName Win32_PageFileUsage | ForEach-Object {
        [pscustomobject]@{
            Name          = [string]$_.Name
            AllocatedMB   = [int]$_.AllocatedBaseSize
            CurrentUsageMB = [int]$_.CurrentUsage
            PeakUsageMB   = [int]$_.PeakUsage
        }
    })
    [pscustomobject]@{
        AutomaticManaged = [bool]$cs.AutomaticManagedPagefile
        Files            = $usage
        Present          = ($usage.Count -gt 0)
    }
}

# --- Muestreo de CPU, disco y procesos ---------------------------------------
$sampling = P 'cpu-disk-sampling' {
    $procStart = @{}
    foreach ($p in Get-Process) {
        try { $procStart[$p.Id] = @{ Name = $p.ProcessName; Cpu = $p.TotalProcessorTime.TotalSeconds } } catch { }
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $cpuVals = @(); $perfVals = @(); $freqVals = @(); $queueVals = @(); $diskTimeVals = @()
    $iterations = [Math]::Max(3, [int]($SampleSeconds / 1))
    for ($i = 0; $i -lt $iterations; $i++) {
        try {
            $pt = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'"
            $cpuVals += [double]$pt.PercentProcessorTime
        } catch { }
        try {
            $pi = Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'"
            $perfVals += [double]$pi.PercentProcessorPerformance
            $freqVals += [double]$pi.PercentofMaximumFrequency
        } catch { }
        try {
            $dk = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'"
            $queueVals += [double]$dk.AvgDiskQueueLength
            $diskTimeVals += [double]$dk.PercentDiskTime
        } catch { }
        Start-Sleep -Milliseconds 900
    }
    $elapsed = $sw.Elapsed.TotalSeconds
    $logical = [Environment]::ProcessorCount
    $groups = @{}
    foreach ($p in Get-Process) {
        $name = $p.ProcessName
        if (-not $groups.ContainsKey($name)) {
            $groups[$name] = @{ Name = $name; Count = 0; CpuDelta = 0.0; WorkingSet = 0.0; Private = 0.0 }
        }
        $g = $groups[$name]
        $g.Count++
        $g.WorkingSet += [double]$p.WorkingSet64
        $g.Private += [double]$p.PrivateMemorySize64
        try {
            $now = $p.TotalProcessorTime.TotalSeconds
            if ($procStart.ContainsKey($p.Id) -and $procStart[$p.Id].Name -eq $name) {
                $g.CpuDelta += [Math]::Max(0, $now - $procStart[$p.Id].Cpu)
            }
        } catch { }
    }
    $rows = foreach ($g in $groups.Values) {
        [pscustomobject]@{
            Name         = $g.Name
            Count        = $g.Count
            CpuPercent   = [Math]::Round(100 * $g.CpuDelta / ($elapsed * $logical), 1)
            WorkingSetMB = [Math]::Round($g.WorkingSet / 1MB, 0)
            PrivateMB    = [Math]::Round($g.Private / 1MB, 0)
        }
    }
    $avg = { param($a) if (@($a).Count -gt 0) { [Math]::Round((($a | Measure-Object -Average).Average), 1) } else { $null } }
    $max = { param($a) if (@($a).Count -gt 0) { [Math]::Round((($a | Measure-Object -Maximum).Maximum), 1) } else { $null } }
    [pscustomobject]@{
        SampleSeconds                = [Math]::Round($elapsed, 1)
        CpuAvgPercent                = (& $avg $cpuVals)
        CpuMaxPercent                = (& $max $cpuVals)
        ProcessorPerformanceAvg      = (& $avg $perfVals)
        PercentOfMaxFrequencyAvg     = (& $avg $freqVals)
        DiskQueueAvg                 = (& $avg $queueVals)
        DiskTimeAvgPercent           = (& $avg $diskTimeVals)
        ProcessCount                 = @(Get-Process).Count
        TopByCpu                     = @($rows | Sort-Object CpuPercent -Descending | Select-Object -First 12)
        TopByMemory                  = @($rows | Sort-Object PrivateMB -Descending | Select-Object -First 12)
    }
}

# --- Inicio ------------------------------------------------------------------
$startup = P 'startup' {
    $items = New-Object System.Collections.ArrayList
    $approvedState = {
        param([string]$Hive, [string]$Sub, [string]$Name)
        try {
            $v = (Get-ItemProperty -LiteralPath ("{0}:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{1}" -f $Hive, $Sub) -Name $Name -ErrorAction Stop).$Name
            if (([byte[]]$v)[0] -band 1) { return 'Deshabilitado' } else { return 'Habilitado' }
        } catch { return 'Habilitado' }
    }
    $keys = @(
        @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Scope = 'Usuario'; Hive = 'HKCU'; Sub = 'Run' },
        @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'; Scope = 'Equipo'; Hive = 'HKLM'; Sub = 'Run' },
        @{ Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Scope = 'Equipo'; Hive = 'HKLM'; Sub = 'Run32' }
    )
    foreach ($k in $keys) {
        if (-not (Test-Path -LiteralPath $k.Path)) { continue }
        $props = Get-ItemProperty -LiteralPath $k.Path
        foreach ($pr in $props.PSObject.Properties) {
            if ($pr.Name -like 'PS*') { continue }
            $cmd = [string]$pr.Value
            $exePath = [Environment]::ExpandEnvironmentVariables(([regex]::Match($cmd, '^\s*"?([^"]+?\.exe)', 'IgnoreCase').Groups[1].Value))
            [void]$items.Add([pscustomobject]@{
                Name           = $pr.Name
                Location       = $k.Path
                Scope          = $k.Scope
                Hive           = $k.Hive
                Sub            = $k.Sub
                Executable     = $(if ($exePath) { [IO.Path]::GetFileName($exePath) } else { '' })
                ExecutablePath = $exePath
                CommandHash    = (Get-WpaStringHash $cmd)
                State          = (& $approvedState $k.Hive $k.Sub $pr.Name)
            })
        }
    }
    $folders = @(
        @{ Path = [Environment]::GetFolderPath('Startup'); Scope = 'Usuario'; Hive = 'HKCU' },
        @{ Path = [Environment]::GetFolderPath('CommonStartup'); Scope = 'Equipo'; Hive = 'HKLM' }
    )
    foreach ($f in $folders) {
        if (-not $f.Path -or -not (Test-Path -LiteralPath $f.Path)) { continue }
        foreach ($file in Get-ChildItem -LiteralPath $f.Path -File -Force -ErrorAction SilentlyContinue) {
            if ($file.Name -ieq 'desktop.ini') { continue }
            [void]$items.Add([pscustomobject]@{
                Name           = $file.Name
                Location       = 'Carpeta Inicio (' + $f.Scope + ')'
                Scope          = $f.Scope
                Hive           = $f.Hive
                Sub            = 'StartupFolder'
                Executable     = $file.Name
                ExecutablePath = $null
                CommandHash    = $null
                State          = (& $approvedState $f.Hive 'StartupFolder' $file.Name)
            })
        }
    }
    @($items)
}

$tasks = P 'scheduled-tasks' {
    $all = @(Get-ScheduledTask)
    $nonMs = @($all | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' })
    [pscustomobject]@{
        Total               = $all.Count
        NonMicrosoftEnabled = $nonMs.Count
        Items               = @($nonMs | Select-Object -First 40 | ForEach-Object {
            [pscustomobject]@{ TaskName = $_.TaskName; TaskPath = $_.TaskPath; State = [string]$_.State }
        })
    }
}

# Servicios: solo informativo. Esta skill nunca deshabilita servicios.
$services = P 'services' {
    $svc = @(Get-CimInstance -ClassName Win32_Service)
    $autoStopped = @($svc | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' -and $_.ExitCode -ne 0 })
    [pscustomobject]@{
        Total              = $svc.Count
        Running            = @($svc | Where-Object { $_.State -eq 'Running' }).Count
        AutoStartFailed    = @($autoStopped | Select-Object -First 20 | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; ExitCode = [int]$_.ExitCode }
        })
        Note               = 'Informativo. La skill no deshabilita servicios.'
    }
}

# --- Seguridad y actualizaciones --------------------------------------------
$defender = P 'defender' {
    $mp = Get-MpComputerStatus
    [pscustomobject]@{
        AMServiceEnabled          = [bool]$mp.AMServiceEnabled
        AntivirusEnabled          = [bool]$mp.AntivirusEnabled
        RealTimeProtectionEnabled = [bool]$mp.RealTimeProtectionEnabled
        SignatureAgeDays          = [int]$mp.AntivirusSignatureAge
        QuickScanAgeDays          = [int]$mp.QuickScanAge
    }
}

$avProducts = P 'security-center' {
    @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.displayName; ProductState = [int]$_.productState }
    })
}

$firewall = P 'firewall' {
    @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Profile = [string]$_.Name; Enabled = [bool]$_.Enabled } })
}

$update = P 'windows-update' {
    $hf = @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    $last = if ($hf.Count -gt 0) { [DateTime]$hf[0].InstalledOn } else { $null }
    $pending = (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
               (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    $wu = Get-Service -Name wuauserv
    [pscustomobject]@{
        LastHotfixUnix     = (ConvertTo-WpaUnix $last)
        DaysSinceLastHotfix = if ($last) { [int]([DateTime]::Now - $last).TotalDays } else { $null }
        PendingReboot      = [bool]$pending
        ServiceStartType   = [string]$wu.StartType
        Note               = 'Basado en Get-HotFix local; no se consulto Windows Update en linea.'
    }
}

# --- Controladores con problemas ---------------------------------------------
$drivers = P 'driver-problems' {
    @(Get-CimInstance -ClassName Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.Name; Class = [string]$_.PNPClass; ErrorCode = [int]$_.ConfigManagerErrorCode }
    })
}

# --- Energia -----------------------------------------------------------------
$power = P 'power' {
    $schemes = Get-WpaPowerSchemes
    $active = Get-WpaActivePowerScheme
    $onBattery = $null
    try {
        $bs = Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryStatus -ErrorAction Stop | Select-Object -First 1
        if ($bs) { $onBattery = -not [bool]$bs.PowerOnline }
    } catch { }
    [pscustomobject]@{
        ActiveSchemeGuid = $active
        ActiveSchemeName = (@($schemes | Where-Object { $_.Guid -eq $active } | ForEach-Object { $_.Name }) + @($null))[0]
        Schemes          = $schemes
        OnBattery        = $onBattery
    }
}

# --- Eventos -----------------------------------------------------------------
$events = $null
if (-not $SkipEvents) {
    $events = P 'events' {
        $start = (Get-Date).AddDays(-$EventDays)
        $map = @(
            @{ Cat = 'Disco';        Log = 'System'; Provider = 'disk';                                       Ids = @(7, 11, 51, 52, 153, 157); ErrorsOnly = $true },
            @{ Cat = 'Disco';        Log = 'System'; Provider = 'Ntfs';                                       Ids = @(55, 98, 137, 140); ErrorsOnly = $true },
            @{ Cat = 'Disco';        Log = 'System'; Provider = 'Microsoft-Windows-Ntfs';                     Ids = @(55, 98, 137, 140); ErrorsOnly = $true },
            @{ Cat = 'Disco';        Log = 'System'; Provider = 'stornvme';                                   Ids = @(11, 129) },
            @{ Cat = 'Disco';        Log = 'System'; Provider = 'storahci';                                   Ids = @(129) },
            @{ Cat = 'Hardware';     Log = 'System'; Provider = 'Microsoft-Windows-WHEA-Logger';              Ids = @() },
            @{ Cat = 'Memoria';      Log = 'System'; Provider = 'Microsoft-Windows-MemoryDiagnostics-Results'; Ids = @() },
            @{ Cat = 'Memoria';      Log = 'System'; Provider = 'Microsoft-Windows-Resource-Exhaustion-Detector'; Ids = @(2004) },
            @{ Cat = 'Energia';      Log = 'System'; Provider = 'Microsoft-Windows-Kernel-Power';             Ids = @(41) },
            @{ Cat = 'Energia';      Log = 'System'; Provider = 'EventLog';                                   Ids = @(6008) },
            @{ Cat = 'Termico';      Log = 'System'; Provider = 'Microsoft-Windows-Kernel-Processor-Power';   Ids = @(37) },
            @{ Cat = 'Controlador';  Log = 'System'; Provider = 'Display';                                    Ids = @(4101) },
            @{ Cat = 'Controlador';  Log = 'System'; Provider = 'Microsoft-Windows-Kernel-PnP';               Ids = @(219) },
            @{ Cat = 'Aplicacion';   Log = 'Application'; Provider = 'Application Error';                     Ids = @(1000) },
            @{ Cat = 'Aplicacion';   Log = 'Application'; Provider = 'Application Hang';                      Ids = @(1002) }
        )
        $counts = [ordered]@{}
        $byKey = [ordered]@{}
        $recent = New-Object System.Collections.ArrayList
        $appCrashes = @{}
        foreach ($m in $map) {
            $filter = @{ LogName = $m.Log; ProviderName = $m.Provider; StartTime = $start }
            if ($m.Ids.Count -gt 0) { $filter['Id'] = $m.Ids }
            # Ntfs 98 tambien se registra como informativo ("el volumen es correcto"): solo cuentan niveles 1-3.
            if ($m.ContainsKey('ErrorsOnly')) { $filter['Level'] = @(1, 2, 3) }
            $ev = @()
            try { $ev = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 300 -ErrorAction Stop) } catch { $ev = @() }
            if (-not $counts.Contains($m.Cat)) { $counts[$m.Cat] = 0 }
            $counts[$m.Cat] += $ev.Count
            foreach ($e in $ev) {
                $key = '{0}/{1}' -f $m.Provider, $e.Id
                if (-not $byKey.Contains($key)) { $byKey[$key] = 0 }
                $byKey[$key]++
                if ($m.Cat -eq 'Aplicacion') {
                    # Solo el nombre de la aplicacion (primer parametro del evento).
                    $app = $null
                    try { $app = [string]$e.Properties[0].Value } catch { }
                    if ($app) { if (-not $appCrashes.ContainsKey($app)) { $appCrashes[$app] = 0 }; $appCrashes[$app]++ }
                    continue
                }
                if ($recent.Count -lt 60) {
                    [void]$recent.Add([pscustomobject]@{
                        TimeUnix = (ConvertTo-WpaUnix $e.TimeCreated)
                        Category = $m.Cat
                        Provider = $m.Provider
                        Id       = [int]$e.Id
                        Level    = [string]$e.LevelDisplayName
                    })
                }
            }
        }
        [pscustomobject]@{
            WindowDays  = $EventDays
            Counts      = [pscustomobject]$counts
            ByProviderId = [pscustomobject]$byKey
            AppCrashes  = @($appCrashes.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object {
                [pscustomobject]@{ App = $_.Key; Count = $_.Value }
            })
            Recent      = @($recent)
        }
    }
}

# --- Arranque, confiabilidad, hibernacion, mantenimiento de disco -----------
$boot = P 'boot-performance' {
    # Sin administrador Windows niega el acceso a este registro y Get-WinEvent lo reporta como "sin eventos".
    try { [void](Get-WinEvent -ListLog 'Microsoft-Windows-Diagnostics-Performance/Operational' -ErrorAction Stop) }
    catch { throw 'el registro de rendimiento de arranque requiere administrador' }
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100 } -MaxEvents 10 -ErrorAction Stop)
    $rows = @(foreach ($e in $ev) {
        $x = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in @($x.Event.EventData.Data)) { $data[[string]$d.Name] = [string]$d.InnerText }
        $sec = { param($n) if ($data.ContainsKey($n) -and $data[$n]) { [Math]::Round([double]$data[$n] / 1000, 1) } else { $null } }
        [pscustomobject]@{ TimeUnix = (ConvertTo-WpaUnix $e.TimeCreated); BootSec = (& $sec 'BootTime'); MainPathSec = (& $sec 'MainPathBootTime'); PostBootSec = (& $sec 'BootPostBootTime') }
    })
    $sorted = @($rows | Where-Object { $null -ne $_.BootSec } | ForEach-Object { $_.BootSec } | Sort-Object)
    [pscustomobject]@{
        LastBootSec     = $(if ($rows.Count) { $rows[0].BootSec } else { $null })
        MedianBootSec   = $(if ($sorted.Count) { $sorted[[int][Math]::Floor($sorted.Count / 2)] } else { $null })
        LastPostBootSec = $(if ($rows.Count) { $rows[0].PostBootSec } else { $null })
        Samples         = $rows
        Note            = 'Evento 100 de Diagnostics-Performance. PostBoot = tiempo hasta escritorio usable.'
    }
}

$reliability = P 'reliability-index' {
    $m = Get-CimInstance -ClassName Win32_ReliabilityStabilityMetrics -ErrorAction Stop | Sort-Object TimeGenerated -Descending | Select-Object -First 1
    if (-not $m) { throw 'sin datos de confiabilidad' }
    [pscustomobject]@{ StabilityIndex = [Math]::Round([double]$m.SystemStabilityIndex, 2); TimeUnix = (ConvertTo-WpaUnix $m.TimeGenerated) }
}

$hibernation = P 'hibernation' {
    $hib = Get-WpaHibernateEnabled
    $fast = Get-WpaRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled'
    $size = $null
    try { $size = [Math]::Round((Get-Item -LiteralPath (Join-Path $env:SystemDrive 'hiberfil.sys') -Force -ErrorAction Stop).Length / 1GB, 1) } catch { }
    [pscustomobject]@{ HibernateEnabled = $hib; FastStartupEnabled = $(if ($fast.Exists) { [int]$fast.Value -eq 1 } else { $null }); HiberfilGB = $size }
}

$diskMaint = P 'disk-maintenance' {
    $info = Get-ScheduledTaskInfo -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction Stop
    $last = $info.LastRunTime
    $valid = ($null -ne $last -and $last.Year -gt 2000)
    [pscustomobject]@{
        LastOptimizeUnix  = $(if ($valid) { ConvertTo-WpaUnix $last } else { $null })
        DaysSinceOptimize = $(if ($valid) { [int]([DateTime]::Now - $last).TotalDays } else { $null })
        LastResult        = [int64]$info.LastTaskResult
    }
}

# --- Categorias de limpieza (solo medicion) ----------------------------------
$cleanup = P 'cleanup-sizes' {
    $res = [ordered]@{}
    foreach ($type in @('CLEANUP-USER-TEMP', 'CLEANUP-WINDOWS-TEMP', 'CLEANUP-WER')) {
        $roots = @(Get-WpaCleanupRoots $type)
        $readable = $true
        foreach ($r in $roots) {
            if (Test-Path -LiteralPath $r -PathType Container) {
                try { [void]([IO.Directory]::GetFileSystemEntries($r)) } catch { $readable = $false }
            }
        }
        if (-not $readable) { $res[$type] = [pscustomobject]@{ Available = $false; Files = $null; MB = $null; Note = 'requiere administrador' }; continue }
        $files = @(Get-WpaCleanupFiles -Roots $roots -MinAgeDays 7)
        $sum = ($files | Measure-Object -Property Bytes -Sum).Sum
        if ($null -eq $sum) { $sum = 0 }
        $res[$type] = [pscustomobject]@{ Available = $true; Files = $files.Count; MB = [Math]::Round([double]$sum / 1MB, 1); Note = 'archivos con mas de 7 dias' }
    }
    [pscustomobject]$res
}

# --- Huerfanos y aplicaciones ---------------------------------------------------
$orphans = P 'orphans' {
    [pscustomobject]@{ Tasks = @(Get-WpaOrphanTasks); Services = @(Get-WpaOrphanServices) }
}

$apps = $null
if ($IncludeAppUsage) {
    $apps = P 'app-inventory' { Get-WpaAppInventory -Startup @($startup) }
}
$backgroundApps = P 'background-apps' { @(Get-WpaBackgroundStoreApps) }
$packagedStartup = P 'packaged-startup' { @(Get-WpaPackagedStartupTasks) }
$bootDegradation = P 'boot-degradation' {
    try { [void](Get-WinEvent -ListLog 'Microsoft-Windows-Diagnostics-Performance/Operational' -ErrorAction Stop) }
    catch { throw 'el registro de rendimiento de arranque requiere administrador' }
    @(Get-WpaBootDegradation -Days 30)
}
$leakWatch = $null
if ($LeakWatchMinutes -gt 0) {
    Write-Output ("Observando el crecimiento de memoria durante {0} min (solo lectura)..." -f $LeakWatchMinutes)
    $leakWatch = P 'memory-leak-watch' { Measure-WpaMemoryGrowth -Minutes $LeakWatchMinutes }
}
$winget = P 'winget' {
    $w = Get-WpaWingetPath
    [pscustomobject]@{ Available = [bool]$w; Path = $w; Note = 'Solo se verifico la presencia; la consulta de actualizaciones usa red y requiere aprobacion (APP-UPDATE-CHECK).' }
}

# --- Ensamblar ---------------------------------------------------------------
$baseline = [ordered]@{
    SchemaVersion   = 1
    Tool            = "windows-performance-auditor $script:WpaVersion"
    Mode            = 'audit-only'
    CollectedUnix   = (Get-WpaUnixNow)
    CollectedLocal  = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    IsAdmin         = $isAdmin
    OS              = $os
    Device          = $device
    Computer        = $computer
    CPU             = $cpu
    GPU             = @(Get-WpaList $gpu)
    Disks           = @(Get-WpaList $disks)
    SystemDiskNumber = $systemDiskNumber
    Volumes         = @(Get-WpaList $volumes)
    Memory          = $memory
    PageFile        = $pageFile
    Sampling        = $sampling
    Startup         = @(Get-WpaList $startup)
    ScheduledTasks  = $tasks
    Services        = $services
    Security        = [ordered]@{ Defender = $defender; AntivirusProducts = @(Get-WpaList $avProducts); Firewall = @(Get-WpaList $firewall); WindowsUpdate = $update }
    DriverProblems  = @(Get-WpaList $drivers)
    Power           = $power
    Events          = $events
    Boot            = $boot
    Reliability     = $reliability
    Hibernation     = $hibernation
    DiskMaintenance = $diskMaint
    Cleanup         = $cleanup
    Orphans         = $orphans
    Apps            = $apps
    BackgroundApps  = @(Get-WpaList $backgroundApps)
    PackagedStartup = @(Get-WpaList $packagedStartup)
    BootDegradation = @(Get-WpaList $bootDegradation)
    LeakWatch       = $leakWatch
    Winget          = $winget
    Unavailable     = @($unavailable)
}

try {
    $json = $baseline | ConvertTo-Json -Depth 8
    $path = Write-WpaFile -OutputDir $OutputDir -Name $FileName -Content $json
    Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation 'end' -Result 'ok' -ExitCode 0 -Details ("no disponibles: {0}" -f $unavailable.Count)
    Write-Output ("Linea base guardada en: {0}" -f $path)
    Write-Output ("Metricas no disponibles: {0}" -f $unavailable.Count)
    exit 0
} catch {
    Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation 'end' -Result 'error' -ExitCode 1 -Details $_.Exception.Message
    Write-WpaError $_.Exception.Message
    exit 1
}

#Requires -Version 5.1
<#
.SYNOPSIS
  Paso 1: identifica el equipo y sus componentes y propone como orientar el
  diagnostico. SOLO LECTURA, sin administrador, sin red, en pocos segundos.

.DESCRIPTION
  Identifica: fabricante y modelo, tipo de equipo, Windows (edicion, version,
  compilacion, fecha de instalacion), BIOS (version y antiguedad), CPU, RAM
  (modulos, velocidad, ranuras libres), GPU y controlador, discos (incluida la
  deteccion de HDD acelerado con Optane), espacio de la unidad del sistema,
  bateria, contexto administrado y si la consola esta elevada.

  A partir de eso calcula el perfil de componentes y un plan de diagnostico:
  en que enfocarse y que opciones usar en collect-baseline.ps1 y
  hardware-health.ps1 para ese equipo.

  No recopila numeros de serie. Sin -OutputDir solo muestra el resumen; con
  -OutputDir (carpeta elegida por el usuario) guarda system-profile.json.
#>
[CmdletBinding()]
param([string]$OutputDir, [switch]$Json)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$scriptName = 'identify-system'

if ($OutputDir) { try { $OutputDir = Assert-WpaOutputDir $OutputDir } catch { Write-WpaError $_.Exception.Message; exit 2 } }
$unavailable = New-Object System.Collections.ArrayList
function P {
    param([string]$Name, [scriptblock]$Block)
    return Invoke-WpaProbe -Name $Name -ScriptBlock $Block -Unavailable $unavailable -OutputDir $OutputDir -ScriptName $scriptName
}

$system = P 'system' {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $chassis = @()
    try { $chassis = @((Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop | Select-Object -First 1).ChassisTypes | ForEach-Object { [int]$_ }) } catch { }
    $hasBattery = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue).Count -gt 0
    [pscustomobject]@{
        Manufacturer = [string]$cs.Manufacturer
        Model        = [string]$cs.Model
        Family       = [string]$cs.SystemFamily
        FormFactor   = (Get-WpaFormFactor -PCSystemType ([int]$cs.PCSystemType) -ChassisTypes $chassis -HasBattery $hasBattery)
        HasBattery   = $hasBattery
        RamGB        = [Math]::Round([double]$cs.TotalPhysicalMemory / 1GB, 1)
    }
}

$bios = P 'bios' {
    $b = Get-CimInstance -ClassName Win32_BIOS
    $date = $b.ReleaseDate
    [pscustomobject]@{
        Manufacturer = [string]$b.Manufacturer
        Version      = [string]$b.SMBIOSBIOSVersion
        ReleaseDate  = $(if ($date) { ([DateTime]$date).ToString('yyyy-MM-dd') } else { $null })
        AgeYears     = $(if ($date) { [Math]::Round(([DateTime]::Now - [DateTime]$date).TotalDays / 365.25, 1) } else { $null })
    }
}

$os = P 'os' {
    $o = Get-CimInstance -ClassName Win32_OperatingSystem
    $dv = Get-WpaRegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion'
    [pscustomobject]@{
        Caption        = [string]$o.Caption
        DisplayVersion = $(if ($dv.Exists) { [string]$dv.Value } else { '' })
        Build          = [string]$o.BuildNumber
        Architecture   = [string]$o.OSArchitecture
        InstallDate    = $(if ($o.InstallDate) { ([DateTime]$o.InstallDate).ToString('yyyy-MM-dd') } else { $null })
        UptimeHours    = [Math]::Round(([DateTime]::Now - $o.LastBootUpTime).TotalHours, 1)
        TotalRamGB     = [Math]::Round(([double]$o.TotalVisibleMemorySize * 1KB) / 1GB, 1)
    }
}

$cpu = P 'cpu' {
    $c = @(Get-CimInstance -ClassName Win32_Processor)
    [pscustomobject]@{
        Name              = ([string]$c[0].Name).Trim()
        Cores             = [int](($c | Measure-Object -Property NumberOfCores -Sum).Sum)
        LogicalProcessors = [int](($c | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum)
        MaxClockMHz       = [int]$c[0].MaxClockSpeed
    }
}

$memory = P 'memory' {
    $mods = @(Get-CimInstance -ClassName Win32_PhysicalMemory | ForEach-Object {
        [pscustomobject]@{ CapacityGB = [Math]::Round([double]$_.Capacity / 1GB, 1); SpeedMHz = $_.Speed; ConfiguredMHz = $_.ConfiguredClockSpeed; Manufacturer = ([string]$_.Manufacturer).Trim(); FormFactor = [int]$_.FormFactor }
    })
    $slots = $null
    try { $slots = [int]((Get-CimInstance -ClassName Win32_PhysicalMemoryArray -ErrorAction Stop | Measure-Object -Property MemoryDevices -Sum).Sum) } catch { }
    [pscustomobject]@{
        TotalGB     = [Math]::Round((($mods | Measure-Object -Property CapacityGB -Sum).Sum), 1)
        Modules     = $mods
        SlotsTotal  = $slots
        SlotsUsed   = $mods.Count
        UpgradeHint = (Get-WpaRamUpgradeHint -SlotsTotal $slots -SlotsUsed $mods.Count)
    }
}

$gpu = P 'gpu' {
    @(Get-CimInstance -ClassName Win32_VideoController | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.Name; DriverVersion = [string]$_.DriverVersion; DriverDate = $(if ($_.DriverDate) { ([DateTime]$_.DriverDate).ToString('yyyy-MM') } else { $null }) }
    })
}

$sysDiskNumber = P 'system-disk' { [string](Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) -ErrorAction Stop).DiskNumber }

$disks = P 'disks' {
    @(Get-PhysicalDisk | ForEach-Object {
        $fname = [string]$_.FriendlyName; $bus = [string]$_.BusType; $media = [string]$_.MediaType
        $class = if (Test-WpaOptaneHybrid -FriendlyName $fname -BusType $bus) { 'HDD-Optane' } elseif ($media -eq 'HDD') { 'HDD' } elseif ($bus -eq 'NVMe') { 'NVMe' } elseif ($media -eq 'SSD') { 'SSD' } else { 'desconocido' }
        [pscustomobject]@{
            DeviceId = [string]$_.DeviceId; FriendlyName = $fname; MediaType = $media; BusType = $bus; Class = $class
            SizeGB = [Math]::Round([double]$_.Size / 1GB, 0); HealthStatus = [string]$_.HealthStatus; IsSystem = ([string]$_.DeviceId -eq [string]$sysDiskNumber)
        }
    })
}

$volume = P 'system-volume' {
    $v = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive)
    [pscustomobject]@{ SizeGB = [Math]::Round([double]$v.Size / 1GB, 0); FreeGB = [Math]::Round([double]$v.FreeSpace / 1GB, 1); FreePercent = [Math]::Round(100 * [double]$v.FreeSpace / [double]$v.Size, 1) }
}

$battery = P 'battery' {
    if (-not [bool](Get-WpaValue $system 'HasBattery' $false)) { return [pscustomobject]@{ Present = $false } }
    $health = $null
    try {
        $design = [double](@(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryStaticData -ErrorAction Stop)[0].DesignedCapacity)
        $full = [double](@(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryFullChargedCapacity -ErrorAction Stop)[0].FullChargedCapacity)
        if ($design -gt 0) { $health = ('{0}% de la capacidad de diseno' -f [Math]::Round(100 * $full / $design, 0)) }
    } catch { }
    [pscustomobject]@{ Present = $true; Health = $health }
}

$ctx = P 'context' { $d = Get-WpaDeviceContext; [pscustomobject]@{ IsManaged = [bool]$d.IsManaged; ManagedReasons = @($d.ManagedReasons); IsAdmin = (Test-WpaIsAdmin) } }

# Perfil de componentes (misma logica que usa el analisis)
$pseudoBaseline = [pscustomobject]@{
    SystemDiskNumber = $sysDiskNumber
    Disks    = @(Get-WpaList $disks)
    OS       = [pscustomobject]@{ TotalRamGB = (Get-WpaValue $os 'TotalRamGB' 0) }
    CPU      = [pscustomobject]@{ LogicalProcessors = (Get-WpaValue $cpu 'LogicalProcessors' 0) }
    Computer = [pscustomobject]@{ FormFactor = (Get-WpaValue $system 'FormFactor' '') }
    GPU      = @(Get-WpaList $gpu)
}
$pseudoHardware = [pscustomobject]@{ Memory = [pscustomobject]@{ SlotsTotal = (Get-WpaValue $memory 'SlotsTotal'); SlotsUsed = (Get-WpaValue $memory 'SlotsUsed') }; Battery = [pscustomobject]@{ Present = (Get-WpaValue $system 'HasBattery' $false) } }
$compProfile = Get-WpaHardwareProfile -Baseline $pseudoBaseline -Hardware $pseudoHardware

$identity = [ordered]@{
    SchemaVersion = 1
    Tool          = "windows-performance-auditor $script:WpaVersion"
    Mode          = 'audit-only'
    IdentifiedUnix = (Get-WpaUnixNow)
    System        = $system
    Os            = $os
    Bios          = $bios
    Cpu           = $cpu
    Memory        = $memory
    Gpu           = @(Get-WpaList $gpu)
    Disks         = @(Get-WpaList $disks)
    SystemVolume  = $volume
    Battery       = $battery
    Context       = $ctx
    Profile       = $compProfile
    Unavailable   = @($unavailable)
}
$identity.DiagnosticPlan = Get-WpaDiagnosticPlan -Identity ([pscustomobject]$identity)

if ($OutputDir) {
    try {
        [void](Write-WpaFile -OutputDir $OutputDir -Name 'system-profile.json' -Content ($identity | ConvertTo-Json -Depth 8))
        Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation 'identify' -Result 'ok' -ExitCode 0
    } catch { Write-WpaError $_.Exception.Message; exit 1 }
}

if ($Json) { $identity | ConvertTo-Json -Depth 8; exit 0 }

Write-Output '=== IDENTIFICACION DEL EQUIPO (solo lectura) ==='
Format-WpaSystemSummary -Identity ([pscustomobject]$identity) | ForEach-Object { Write-Output $_ }
Write-Output ''
Write-Output '=== ESTRATEGIA SEGUN COMPONENTES ==='
foreach ($s in @($compProfile.Strategy)) { Write-Output ('- ' + $s) }
Write-Output ''
Write-Output '=== PLAN DE DIAGNOSTICO PARA ESTE EQUIPO ==='
foreach ($f in @($identity.DiagnosticPlan.Focus)) { Write-Output ('- ' + $f) }
Write-Output ('- collect-baseline.ps1: ' + (@($identity.DiagnosticPlan.CollectArgs) -join ' '))
if (@($identity.DiagnosticPlan.HardwareArgs).Count) { Write-Output ('- hardware-health.ps1: ' + (@($identity.DiagnosticPlan.HardwareArgs) -join ' ')) }
foreach ($n in @($identity.DiagnosticPlan.Notes)) { Write-Output ('! ' + $n) }
if ($unavailable.Count) { Write-Output ('No disponible: ' + ((@($unavailable) | ForEach-Object { $_.Metric }) -join ', ')) }
exit 0

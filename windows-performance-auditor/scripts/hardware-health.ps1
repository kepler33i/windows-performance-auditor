#Requires -Version 5.1
<#
.SYNOPSIS
  Recopila indicadores de salud fisica: almacenamiento (SMART/confiabilidad),
  memoria (WHEA, diagnostico), bateria y throttling. SOLO LECTURA.

.DESCRIPTION
  - No instala herramientas. Si un dato no esta disponible sin software
    adicional o sin administrador, se informa como "no disponible".
  - No se leen zonas termicas ACPI: en la mayoria de los equipos entregan valores
    fijos o ficticios. El throttling se detecta por el evento 37 y la frecuencia.
  - Los numeros de serie NO se recopilan.
  - -IncludeBatteryReport ejecuta 'powercfg /batteryreport' escribiendo
    unicamente en -OutputDir (informe local; no modifica el sistema).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [ValidateRange(1, 90)][int]$EventDays = 30,
    [string]$FileName = 'hardware-health.json',
    [switch]$IncludeBatteryReport
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$scriptName = 'hardware-health'

try { $OutputDir = Assert-WpaOutputDir $OutputDir } catch { Write-WpaError $_.Exception.Message; exit 2 }

$unavailable = New-Object System.Collections.ArrayList
Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation 'start' -Result 'audit-only'

function P {
    param([string]$Name, [scriptblock]$Block)
    return Invoke-WpaProbe -Name $Name -ScriptBlock $Block -Unavailable $unavailable -OutputDir $OutputDir -ScriptName $scriptName
}

function Get-EventCount {
    param([string]$Provider, [int[]]$Ids = @(), [string]$Log = 'System', [switch]$ErrorsOnly)
    $filter = @{ LogName = $Log; ProviderName = $Provider; StartTime = (Get-Date).AddDays(-$EventDays) }
    if ($Ids.Count -gt 0) { $filter['Id'] = $Ids }
    if ($ErrorsOnly) { $filter['Level'] = @(1, 2, 3) }
    try { return @(Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction Stop).Count } catch { return 0 }
}

# --- Almacenamiento ----------------------------------------------------------
$storage = P 'storage-health' {
    $predict = @{}
    try {
        foreach ($fp in @(Get-CimInstance -Namespace 'root\wmi' -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop)) {
            $predict[[string]$fp.InstanceName] = [bool]$fp.PredictFailure
        }
    } catch {
        [void]$unavailable.Add([pscustomobject]@{ Metric = 'smart-failure-predict'; Reason = 'requiere administrador o no soportado por el controlador' })
    }
    @(Get-PhysicalDisk | ForEach-Object {
        $d = $_
        $rel = $null
        try {
            $r = $d | Get-StorageReliabilityCounter -ErrorAction Stop
            $rel = [pscustomobject]@{
                Available              = $true
                WearPercentUsed        = $r.Wear
                TemperatureC           = $r.Temperature
                TemperatureMaxC        = $r.TemperatureMax
                ReadErrorsUncorrected  = $r.ReadErrorsUncorrected
                ReadErrorsTotal        = $r.ReadErrorsTotal
                WriteErrorsUncorrected = $r.WriteErrorsUncorrected
                PowerOnHours           = $r.PowerOnHours
            }
        } catch {
            $rel = [pscustomobject]@{ Available = $false; Reason = 'requiere administrador o no soportado' }
        }
        [pscustomobject]@{
            DeviceId          = [string]$d.DeviceId
            FriendlyName      = [string]$d.FriendlyName
            MediaType         = [string]$d.MediaType
            BusType           = [string]$d.BusType
            SizeGB            = [Math]::Round([double]$d.Size / 1GB, 1)
            HealthStatus      = [string]$d.HealthStatus
            OperationalStatus = [string]($d.OperationalStatus -join ',')
            Reliability       = $rel
            FailurePredictAny = if ($predict.Count -gt 0) { [bool]($predict.Values -contains $true) } else { $null }
        }
    })
}

$diskEvents = P 'disk-events' {
    [pscustomobject]@{
        WindowDays      = $EventDays
        BadBlock        = (Get-EventCount 'disk' @(7) -ErrorsOnly)
        ControllerError = (Get-EventCount 'disk' @(11) -ErrorsOnly)
        PagingError     = (Get-EventCount 'disk' @(51) -ErrorsOnly)
        IoRetried       = (Get-EventCount 'disk' @(153) -ErrorsOnly)
        NtfsCorruption  = (Get-EventCount 'Ntfs' @(55, 98) -ErrorsOnly) + (Get-EventCount 'Microsoft-Windows-Ntfs' @(55, 98) -ErrorsOnly)
        NvmeReset       = (Get-EventCount 'stornvme' @(11, 129) -ErrorsOnly)
    }
}

# --- Memoria -----------------------------------------------------------------
$memoryHw = P 'memory-hardware' {
    $mods = @(Get-CimInstance -ClassName Win32_PhysicalMemory | ForEach-Object {
        [pscustomobject]@{
            CapacityGB        = [Math]::Round([double]$_.Capacity / 1GB, 1)
            SpeedMHz          = $_.Speed
            ConfiguredMHz     = $_.ConfiguredClockSpeed
            Manufacturer      = [string]$_.Manufacturer
            FormFactor        = [int]$_.FormFactor
        }
    })
    $slots = $null
    try { $slots = [int]((Get-CimInstance -ClassName Win32_PhysicalMemoryArray | Measure-Object -Property MemoryDevices -Sum).Sum) } catch { }
    [pscustomobject]@{
        Modules          = $mods
        SlotsTotal       = $slots
        SlotsUsed        = $mods.Count
        TotalGB          = [Math]::Round((($mods | Measure-Object -Property CapacityGB -Sum).Sum), 1)
        WheaEvents       = (Get-EventCount 'Microsoft-Windows-WHEA-Logger')
        Whea             = (Get-WpaWheaSummary -Days $EventDays)
        MemDiagEvents    = (Get-EventCount 'Microsoft-Windows-MemoryDiagnostics-Results')
        Note             = 'Soldada vs. ampliable no se puede determinar con certeza por software; verificar manual del fabricante.'
    }
}

# --- Bateria -----------------------------------------------------------------
$battery = P 'battery' {
    $wb = @(Get-CimInstance -ClassName Win32_Battery)
    if ($wb.Count -eq 0) { return [pscustomobject]@{ Present = $false } }
    $design = $null; $full = $null; $cycles = $null; $source = 'no disponible'
    try {
        $design = [double](@(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryStaticData -ErrorAction Stop)[0].DesignedCapacity)
        $full = [double](@(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryFullChargedCapacity -ErrorAction Stop)[0].FullChargedCapacity)
        $source = 'root\wmi'
        try { $cycles = [int](@(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryCycleCount -ErrorAction Stop)[0].CycleCount) } catch { }
    } catch { }
    if ($IncludeBatteryReport -and (-not $design -or -not $full)) {
        $xmlPath = Join-Path $OutputDir 'battery-report.xml'
        $exe = Join-Path $env:SystemRoot 'System32\powercfg.exe'
        & $exe /batteryreport /xml /output $xmlPath | Out-Null
        Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation 'command' -Command ('"{0}" /batteryreport /xml /output "{1}"' -f $exe, $xmlPath) -Result 'ejecutado' -ExitCode $LASTEXITCODE
        if (Test-Path -LiteralPath $xmlPath) {
            [xml]$x = [IO.File]::ReadAllText($xmlPath)
            $ns = New-Object Xml.XmlNamespaceManager($x.NameTable)
            $ns.AddNamespace('b', $x.DocumentElement.NamespaceURI)
            $node = $x.SelectSingleNode('//b:Batteries/b:Battery', $ns)
            if ($node) {
                $design = [double]$node.DesignCapacity
                $full = [double]$node.FullChargeCapacity
                $cycles = [int]$node.CycleCount
                $source = 'powercfg /batteryreport'
            }
        }
    }
    $health = $null
    if ($design -gt 0 -and $full -gt 0) { $health = [Math]::Round(100 * $full / $design, 1) }
    [pscustomobject]@{
        Present                = $true
        Status                 = [string]$wb[0].Status
        EstimatedChargePercent = [int]$wb[0].EstimatedChargeRemaining
        DesignCapacitymWh      = $design
        FullChargeCapacitymWh  = $full
        HealthPercent          = $health
        CycleCount             = $cycles
        Source                 = $source
    }
}

# --- Throttling --------------------------------------------------------------
$throttling = P 'throttling' {
    $freq = @()
    for ($i = 0; $i -lt 5; $i++) {
        try {
            $pi = Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'"
            $freq += [double]$pi.PercentofMaximumFrequency
        } catch { }
        Start-Sleep -Milliseconds 800
    }
    [pscustomobject]@{
        FirmwareLimitEvents   = (Get-EventCount 'Microsoft-Windows-Kernel-Processor-Power' @(37))
        PercentOfMaxFrequency = if ($freq.Count) { [Math]::Round((($freq | Measure-Object -Average).Average), 1) } else { $null }
        Note                  = 'Evento 37 (Kernel-Processor-Power): el firmware limita la velocidad del procesador (termico o energia).'
    }
}

$powerEvents = P 'power-events' {
    [pscustomobject]@{
        KernelPower41       = (Get-EventCount 'Microsoft-Windows-Kernel-Power' @(41))
        UnexpectedShutdown  = (Get-EventCount 'EventLog' @(6008))
        WindowDays          = $EventDays
    }
}

$hw = [ordered]@{
    SchemaVersion = 1
    Tool          = "windows-performance-auditor $script:WpaVersion"
    Mode          = 'audit-only'
    CollectedUnix = (Get-WpaUnixNow)
    IsAdmin       = (Test-WpaIsAdmin)
    Storage       = @(Get-WpaList $storage)
    DiskEvents    = $diskEvents
    Memory        = $memoryHw
    Battery       = $battery
    Throttling    = $throttling
    PowerEvents   = $powerEvents
    Unavailable   = @($unavailable)
}

try {
    $path = Write-WpaFile -OutputDir $OutputDir -Name $FileName -Content ($hw | ConvertTo-Json -Depth 8)
    Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation 'end' -Result 'ok' -ExitCode 0
    Write-Output ("Salud de hardware guardada en: {0}" -f $path)
    exit 0
} catch {
    Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation 'end' -Result 'error' -ExitCode 1 -Details $_.Exception.Message
    Write-WpaError $_.Exception.Message
    exit 1
}

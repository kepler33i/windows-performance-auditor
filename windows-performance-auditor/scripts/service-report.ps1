#Requires -Version 5.1
<#
.SYNOPSIS
  Genera el informe de servicio (antes/despues). SOLO LECTURA de los JSON de la carpeta.

.DESCRIPTION
  Lee de -OutputDir: baseline.json, baseline-after.json (opcional), findings.json,
  action-plan.json, executed-actions.json y validation-*.json.
  Escribe service-report.html (local) y service-report-shareable.html (sanitizado).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$Client = '',
    [string]$Technician = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$scriptName = 'service-report'

try {
    $OutputDir = Assert-WpaOutputDir $OutputDir
    $before = Read-WpaJson (Join-Path $OutputDir 'baseline.json')
    $findings = Read-WpaJson (Join-Path $OutputDir 'findings.json')
} catch { Write-WpaError ("Faltan datos de la auditoria: " + $_.Exception.Message); exit 2 }
$afterPath = Join-Path $OutputDir 'baseline-after.json'
$after = if (Test-Path -LiteralPath $afterPath) { Read-WpaJson $afterPath } else { $null }
$planPath = Join-Path $OutputDir 'action-plan.json'
$plan = if (Test-Path -LiteralPath $planPath) { Read-WpaJson $planPath } else { $null }
$ledger = @(Read-WpaJsonArray (Join-Path $OutputDir 'executed-actions.json'))

$e = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

# --- Metricas antes / despues --------------------------------------------------
$metrics = @(
    @{ L = 'Ultimo arranque, total (s)'; P = 'Boot.LastBootSec'; Better = 'lower' },
    @{ L = 'Arranque, mediana de los ultimos 10 (s)'; P = 'Boot.MedianBootSec'; Better = 'lower' },
    @{ L = 'Tiempo hasta escritorio usable (s)'; P = 'Boot.LastPostBootSec'; Better = 'lower' },
    @{ L = 'CPU promedio en reposo (%)'; P = 'Sampling.CpuAvgPercent'; Better = 'lower' },
    @{ L = 'Memoria comprometida (%)'; P = 'Memory.CommitPercent'; Better = 'lower' },
    @{ L = 'Memoria disponible (GB)'; P = 'Memory.AvailableGB'; Better = 'higher' },
    @{ L = 'Indice de confiabilidad (0-10)'; P = 'Reliability.StabilityIndex'; Better = 'higher' }
)
$rows = foreach ($m in $metrics) {
    $b = Get-WpaValue $before $m.P
    $a = if ($after) { Get-WpaValue $after $m.P } else { $null }
    $trend = ''
    if ($null -ne $b -and $null -ne $a) {
        $d = [double]$a - [double]$b
        $good = if ($m.Better -eq 'lower') { $d -lt 0 } else { $d -gt 0 }
        $trend = if ([Math]::Abs($d) -lt 0.05) { '=' } elseif ($good) { 'mejora' } else { 'empeora' }
    }
    '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td class="t-{3}">{3}</td></tr>' -f (& $e $m.L), (& $e $(if ($null -eq $b) { 'no disponible' } else { $b })), (& $e $(if ($null -eq $a) { $(if ($after) { 'no disponible' } else { 'sin medicion posterior' }) } else { $a })), (& $e $trend)
}
$startB = @((Get-WpaList (Get-WpaValue $before 'Startup' @())) | Where-Object { $_.State -ne 'Deshabilitado' }).Count
$startA = if ($after) { @((Get-WpaList (Get-WpaValue $after 'Startup' @())) | Where-Object { $_.State -ne 'Deshabilitado' }).Count } else { $null }
$rows += '<tr><td>Programas de inicio habilitados</td><td>{0}</td><td>{1}</td><td></td></tr>' -f $startB, $(if ($null -eq $startA) { 'sin medicion posterior' } else { $startA })
$volB = @((Get-WpaList (Get-WpaValue $before 'Volumes' @())) | Where-Object { $_.IsSystem }) | Select-Object -First 1
$volA = if ($after) { @((Get-WpaList (Get-WpaValue $after 'Volumes' @())) | Where-Object { $_.IsSystem }) | Select-Object -First 1 } else { $null }
$rows += '<tr><td>Espacio libre en unidad del sistema (GB)</td><td>{0}</td><td>{1}</td><td></td></tr>' -f $(if ($volB) { $volB.FreeGB } else { 'no disponible' }), $(if ($volA) { $volA.FreeGB } else { 'sin medicion posterior' })

# --- Acciones ------------------------------------------------------------------
$actRows = @()
if ($plan) {
    foreach ($a in @($plan.Actions)) {
        $entries = @($ledger | Where-Object { $_.ActionId -eq $a.ActionId })
        $status = if ($entries.Count -eq 0) { 'no aprobada / no ejecutada' } else { (@($entries | ForEach-Object { '{0}: {1}' -f $_.Mode, $_.Result }) -join '; ') }
        $actRows += '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (& $e $a.ActionId), (& $e $a.Title), (& $e (@($a.Targets) -join ', ')), (& $e $status)
    }
}
$applied = @($ledger | Where-Object { $_.Mode -eq 'apply' -and $_.Result -eq 'validado' }).Count

# --- Hardware y recomendaciones manuales ----------------------------------------
$hwItems = @($findings.Findings | Where-Object { $_.Category -in @('posible-hardware', 'limitacion-estructural', 'capacidad-insuficiente') } | ForEach-Object {
    '<li><b>{0}</b> - {1}{2}</li>' -f (& $e $_.Title), (& $e $_.Recommendation), $(if ($_.ManualTest) { ' <i>Prueba: ' + (& $e $_.ManualTest) + '</i>' } else { '' })
})
$manual = @($findings.Findings | Where-Object { @($_.ProposedActionTypes).Count -eq 0 -and $_.Category -in @('software-corregible', 'configuracion-optimizable') -and $_.Severity -ne 'info' } | ForEach-Object {
    '<li><b>{0}</b> - {1}</li>' -f (& $e $_.Title), (& $e $_.Recommendation)
})
$prof = Get-WpaValue $findings 'HardwareProfile'
$profHtml = if ($prof) { '<ul>' + ((@($prof.Strategy) | ForEach-Object { '<li>' + (& $e $_) + '</li>' }) -join '') + '</ul>' } else { '' }

function Build-Report {
    param([string]$Title)
    $tpl = [IO.File]::ReadAllText((Join-Path (Split-Path $PSScriptRoot -Parent) 'assets\service-report-template.html'))
    $sys = $findings.System
    $vals = [ordered]@{
        '{{TITLE}}'      = (& $e $Title)
        '{{GENERATED}}'  = (& $e (Get-Date).ToString('yyyy-MM-dd HH:mm'))
        '{{CLIENT}}'     = (& $e $(if ($Client) { $Client } else { '-' }))
        '{{TECHNICIAN}}' = (& $e $(if ($Technician) { $Technician } elseif ($plan) { [string](Get-WpaValue $plan 'Technician' '-') } else { '-' }))
        '{{TICKET}}'     = (& $e $(if ($plan -and (Get-WpaValue $plan 'Ticket' '')) { $plan.Ticket } else { '-' }))
        '{{SYSTEM}}'     = ('{0}<br>{1}<br>RAM: {2} GB<br>{3}' -f (& $e $sys.OS), (& $e $sys.CPU), (& $e $sys.RamGB), (& $e $sys.Model))
        '{{PROFILE}}'    = $profHtml
        '{{METRICS}}'    = ($rows -join '')
        '{{ACTIONS}}'    = $(if ($actRows.Count) { $actRows -join '' } else { '<tr><td colspan="4">Sin plan de acciones.</td></tr>' })
        '{{APPLIED}}'    = [string]$applied
        '{{HARDWARE}}'   = $(if ($hwItems.Count) { $hwItems -join '' } else { '<li>Sin limitaciones fisicas detectadas con la evidencia disponible.</li>' })
        '{{MANUAL}}'     = $(if ($manual.Count) { $manual -join '' } else { '<li>Sin recomendaciones manuales pendientes.</li>' })
    }
    $out = $tpl
    foreach ($k in $vals.Keys) { $out = $out.Replace($k, [string]$vals[$k]) }
    return $out
}

try {
    $p1 = Write-WpaFile -OutputDir $OutputDir -Name 'service-report.html' -Content (Build-Report 'Informe de servicio - optimizacion de equipo')
    $shared = ConvertTo-WpaSanitizedText (Build-Report 'Informe de servicio (compartible, sanitizado)')
    [void](Write-WpaFile -OutputDir $OutputDir -Name 'service-report-shareable.html' -Content $shared)
    Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation 'report' -Result 'ok' -ExitCode 0
    Write-Output ("Informe de servicio: {0}" -f $p1)
    exit 0
} catch {
    Write-WpaError $_.Exception.Message
    exit 1
}

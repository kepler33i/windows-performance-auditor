#Requires -Version 5.1
<#
.SYNOPSIS
  Valida resultados. SOLO LECTURA. Dos modos:

  1) Comparacion de lineas base:  -BeforePath baseline.json -AfterPath baseline-after.json
     Detecta regresiones (CPU, memoria, inicio, controladores, seguridad, espacio).
  2) Verificacion de una accion:   -PlanPath action-plan.json -ActionId A-xxxxxxxx-NNN
     Relee el estado del sistema y lo compara con lo esperado (y con el respaldo).

  Codigos de salida: 0 sin regresion | 5 regresion o validacion fallida (detenerse
  y proponer reversion) | 2 entrada invalida.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BeforePath,
    [string]$AfterPath,
    [string]$PlanPath,
    [string]$ActionId
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$scriptName = 'validate-results'

try { $OutputDir = Assert-WpaOutputDir $OutputDir } catch { Write-WpaError $_.Exception.Message; exit 2 }

$regressions = New-Object System.Collections.ArrayList
$improvements = New-Object System.Collections.ArrayList
$notes = New-Object System.Collections.ArrayList
$modeName = $null

if ($BeforePath -and $AfterPath) {
    $modeName = 'compare'
    try {
        $b = [IO.File]::ReadAllText($BeforePath) | ConvertFrom-Json
        $a = [IO.File]::ReadAllText($AfterPath) | ConvertFrom-Json
    } catch { Write-WpaError ("Entrada invalida: " + $_.Exception.Message); exit 2 }

    function Cmp {
        param([string]$Label, [string]$Path, [double]$WorseBy, [switch]$HigherIsBetter)
        $x = Get-WpaValue $b $Path; $y = Get-WpaValue $a $Path
        if ($null -eq $x -or $null -eq $y) { [void]$notes.Add(("{0}: no disponible en ambas mediciones" -f $Label)); return }
        $delta = [double]$y - [double]$x
        if ($HigherIsBetter) { $delta = -$delta }
        $line = ("{0}: antes {1}, despues {2}" -f $Label, $x, $y)
        if ($delta -ge $WorseBy) { [void]$regressions.Add($line) }
        elseif ($delta -le -$WorseBy) { [void]$improvements.Add($line) }
        else { [void]$notes.Add($line + ' (sin cambio significativo)') }
    }
    Cmp 'CPU promedio (%)' 'Sampling.CpuAvgPercent' 15
    Cmp 'Memoria comprometida (%)' 'Memory.CommitPercent' 10
    Cmp 'Memoria disponible (GB)' 'Memory.AvailableGB' 1 -HigherIsBetter
    Cmp 'Tiempo de disco (%)' 'Sampling.DiskTimeAvgPercent' 20
    Cmp 'Arranque, mediana (s)' 'Boot.MedianBootSec' 10
    Cmp 'Indice de confiabilidad' 'Reliability.StabilityIndex' 1 -HigherIsBetter

    $sb = @((Get-WpaList (Get-WpaValue $b 'Startup' @())) | Where-Object { $_.State -ne 'Deshabilitado' }).Count
    $sa = @((Get-WpaList (Get-WpaValue $a 'Startup' @())) | Where-Object { $_.State -ne 'Deshabilitado' }).Count
    if ($sa -gt $sb) { [void]$regressions.Add(("Programas de inicio habilitados: {0} -> {1}" -f $sb, $sa)) }
    elseif ($sa -lt $sb) { [void]$improvements.Add(("Programas de inicio habilitados: {0} -> {1}" -f $sb, $sa)) }

    $db = @(Get-WpaList (Get-WpaValue $b 'DriverProblems' @())).Count
    $da = @(Get-WpaList (Get-WpaValue $a 'DriverProblems' @())).Count
    if ($da -gt $db) { [void]$regressions.Add(("Dispositivos con problemas: {0} -> {1}" -f $db, $da)) }

    $rb = Get-WpaValue $b 'Security.Defender.RealTimeProtectionEnabled'
    $ra = Get-WpaValue $a 'Security.Defender.RealTimeProtectionEnabled'
    if ($rb -eq $true -and $ra -eq $false) { [void]$regressions.Add('Proteccion en tiempo real de Defender paso a desactivada') }
    foreach ($p in @(Get-WpaList (Get-WpaValue $b 'Security.Firewall' @()))) {
        $after = @((Get-WpaList (Get-WpaValue $a 'Security.Firewall' @())) | Where-Object { $_.Profile -eq $p.Profile }) | Select-Object -First 1
        if ($p.Enabled -and $after -and -not $after.Enabled) { [void]$regressions.Add(("Firewall perfil {0} paso a desactivado" -f $p.Profile)) }
    }
    $vb = @((Get-WpaList (Get-WpaValue $b 'Volumes' @())) | Where-Object { $_.IsSystem }) | Select-Object -First 1
    $va = @((Get-WpaList (Get-WpaValue $a 'Volumes' @())) | Where-Object { $_.IsSystem }) | Select-Object -First 1
    if ($vb -and $va) {
        $d = [double]$va.FreeGB - [double]$vb.FreeGB
        if ($d -le -5) { [void]$regressions.Add(("Espacio libre del sistema: {0} -> {1} GB" -f $vb.FreeGB, $va.FreeGB)) }
        elseif ($d -ge 1) { [void]$improvements.Add(("Espacio libre del sistema: {0} -> {1} GB" -f $vb.FreeGB, $va.FreeGB)) }
    }
    [void]$notes.Add('Una sola muestra por medicion: las variaciones de CPU/memoria pueden deberse a la carga del momento.')
}
elseif ($PlanPath -and $ActionId) {
    $modeName = 'action'
    try {
        $plan = [IO.File]::ReadAllText($PlanPath) | ConvertFrom-Json
        $planDir = [IO.Path]::GetDirectoryName($PlanPath)
        $action = @((Get-WpaList (Get-WpaValue $plan 'Actions' @())) | Where-Object { $_.ActionId -eq $ActionId }) | Select-Object -First 1
        if (-not $action) { throw "ActionId no existe en el plan" }
        $backup = $null
        $bp = Join-Path $planDir ('backup-{0}.json' -f $ActionId)
        if (Test-Path -LiteralPath $bp) { $backup = [IO.File]::ReadAllText($bp) | ConvertFrom-Json }
        $ledger = @()
        $lp = Join-Path $planDir 'executed-actions.json'
        if (Test-Path -LiteralPath $lp) { $ledger = @(([IO.File]::ReadAllText($lp) | ConvertFrom-Json) | ForEach-Object { $_ }) }
    } catch { Write-WpaError ("Entrada invalida: " + $_.Exception.Message); exit 2 }
    $last = @($ledger | Where-Object { $_.ActionId -eq $ActionId }) | Select-Object -Last 1
    if (-not $last) {
        [void]$notes.Add('La accion no figura como ejecutada; no hay nada que validar.')
    } else {
        $outcome = Test-WpaActionOutcome -Action $action -Backup $backup -Mode ([string]$last.Mode) -ExitCode $last.ExitCode
        foreach ($d in $outcome.Details) { [void]$notes.Add($d) }
        if (-not $outcome.Ok) { [void]$regressions.Add(("Estado de {0} no coincide con lo esperado tras '{1}'" -f $ActionId, $last.Mode)) }
        else { [void]$improvements.Add(("Estado de {0} confirmado tras '{1}'" -f $ActionId, $last.Mode)) }
    }
}
else {
    Write-WpaError 'Use -BeforePath y -AfterPath, o -PlanPath y -ActionId.'
    exit 2
}

$status = if ($regressions.Count -gt 0) { 'regresion' } else { 'sin-regresion' }
$report = [ordered]@{
    Mode         = $modeName
    Status       = $status
    ValidatedUnix = (Get-WpaUnixNow)
    Regressions  = @($regressions)
    Improvements = @($improvements)
    Notes        = @($notes)
    NextStep     = $(if ($regressions.Count -gt 0) { 'DETENERSE. No aplicar mas acciones. Proponer reversion al usuario y esperar aprobacion explicita.' } else { 'Continuar solo con acciones ya aprobadas explicitamente.' })
}
$name = 'validation-{0}.json' -f (Get-Date).ToString('yyyyMMdd-HHmmss')
[void](Write-WpaFile -OutputDir $OutputDir -Name $name -Content ($report | ConvertTo-Json -Depth 5))
Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation $modeName -Result $status -ExitCode $(if ($regressions.Count -gt 0) { 5 } else { 0 })

Write-Output ("Validacion: {0}" -f $status)
foreach ($r in $regressions) { Write-Output ("  REGRESION: " + $r) }
foreach ($i in $improvements) { Write-Output ("  Mejora: " + $i) }
if ($regressions.Count -gt 0) { exit 5 }
exit 0

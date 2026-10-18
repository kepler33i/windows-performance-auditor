#Requires -Version 5.1
<#
.SYNOPSIS
  Genera un plan de acciones PROPUESTAS a partir de findings.json. No ejecuta nada.

.DESCRIPTION
  - Solo tipos de la allowlist (lib/catalog.ps1). Cada accion muestra: identificador,
    hallazgo y evidencia, comando exacto, elementos afectados, beneficio, riesgo,
    administrador/reinicio/red, respaldo, reversion (y si es confiable) y validacion.
  - El plan pertenece a una sesion, expira y lleva hash de integridad.
  - Modos de operacion:
      asistido (predeterminado): aprobacion por identificador o por el paquete P-...
      tecnico: igual, pero exige -Ticket (trazabilidad de soporte).
    El paquete agrupa solo acciones de riesgo bajo, sin red y reversibles, y se
    aprueba escribiendo su identificador P-... literal.
  - El plan incluye una seccion de recomendaciones manuales (hallazgos sin
    accion en la allowlist: drivers, BIOS, ASPM, hardware).
  - Si se propone una desinstalacion o reparacion se antepone un punto de
    restauracion obligatorio.
  - Equipos administrados: solo verificaciones, salvo autorizacion corporativa
    verificable (archivo protegido por ACL, dominio/tenant, ticket, tipos permitidos).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$FindingsPath,
    [Parameter(Mandatory = $true)][string]$BaselinePath,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [ValidateRange(1, 12)][int]$ValidHours = 4,
    [ValidateSet('asistido', 'tecnico')][string]$OperationMode = 'asistido',
    [string]$Ticket = '',
    [string]$Technician = '',
    [string]$OrgAuthorizationPath = '',
    [string]$WingetUpgradesPath = '',
    [switch]$IncludeRestorePoint,
    [switch]$SfcViolationsConfirmed,
    [switch]$ComponentStoreCorrupted
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$scriptName = 'propose-actions'

try {
    $OutputDir = Assert-WpaOutputDir $OutputDir
    $findingsDoc = Read-WpaJson $FindingsPath
    $baseline = Read-WpaJson $BaselinePath
    $wingetRows = @()
    if ($WingetUpgradesPath) { $wingetRows = @(Read-WpaJsonArray $WingetUpgradesPath) }
} catch {
    Write-WpaError ("Entrada invalida: " + $_.Exception.Message)
    exit 2
}
if ($Ticket -and $Ticket -notmatch '^[A-Za-z0-9][A-Za-z0-9._/\-]{1,60}$') { Write-WpaError 'Ticket con formato invalido.'; exit 2 }
if ($OperationMode -eq 'tecnico' -and -not $Ticket) { Write-WpaError 'El modo tecnico exige -Ticket.'; exit 2 }

$catalog = Get-WpaActionCatalog
$sessionId = [guid]::NewGuid().ToString('N')
$prefix = $sessionId.Substring(0, 8)
$now = Get-WpaUnixNow

# Contexto: linea base + deteccion en vivo (cualquiera de las dos bloquea).
$liveCtx = $null
try { $liveCtx = Get-WpaDeviceContext } catch { }
$isManaged = [bool](Get-WpaValue $baseline 'Device.IsManaged' $false) -or [bool](Get-WpaValue $liveCtx 'IsManaged' $false)
$reasons = @(@(Get-WpaValue $baseline 'Device.ManagedReasons' @()) + @(Get-WpaValue $liveCtx 'ManagedReasons' @()) | ForEach-Object { [string]$_ } | Select-Object -Unique)
$devCtx = [ordered]@{
    IsManaged  = $isManaged
    Reasons    = @($reasons)
    DomainName = [string](Get-WpaValue $liveCtx 'DomainName' (Get-WpaValue $baseline 'Device.DomainName' ''))
    TenantIds  = @((Get-WpaValue $liveCtx 'TenantIds' (Get-WpaValue $baseline 'Device.TenantIds' @())) | ForEach-Object { [string]$_ })
}

$specs = New-Object System.Collections.ArrayList
$skipped = New-Object System.Collections.ArrayList
$orgUsed = $false

function Add-Spec {
    param([string]$Type, $Finding, [string[]]$Targets, [string]$Fingerprint = $null, $Detail = $null, [string]$Extra = '')
    $def = $catalog[$Type]
    if ($null -eq $def) { [void]$skipped.Add("Tipo fuera de allowlist: $Type"); return }
    if ($isManaged -and $def.Modifies) {
        $auth = Test-WpaOrgAuthorization -Path $OrgAuthorizationPath -DeviceContext ([pscustomobject]$devCtx) -ActionType $Type -Ticket $Ticket
        if (-not $auth.Ok) {
            [void]$skipped.Add(("{0} omitida: equipo administrado sin autorizacion corporativa valida ({1})" -f $Type, $auth.Reason))
            return
        }
        $script:orgUsed = $true
    }
    try { $cmd = Get-WpaActionCommand -Type $Type -Targets $Targets -Detail $Detail } catch { [void]$skipped.Add(("{0} omitida: {1}" -f $Type, $_.Exception.Message)); return }
    [void]$specs.Add([pscustomobject]@{ Type = $Type; Finding = $Finding; Targets = @($Targets); Fingerprint = $Fingerprint; Detail = $Detail; Extra = $Extra; Command = $cmd })
}

$sysDrive = [string]$env:SystemDrive
foreach ($f in @(Get-WpaValue $findingsDoc 'Findings' @())) {
    $targets = @(Get-WpaValue $f 'ActionTargets' @())
    foreach ($type in @(Get-WpaValue $f 'ProposedActionTypes' @())) {
        switch ([string]$type) {
            'POWER-SET-SCHEME' {
                $g = [string]$targets[0]
                if ($script:WpaPowerSchemes.ContainsKey($g)) { Add-Spec -Type $type -Finding $f -Targets @($g) } else { [void]$skipped.Add("POWER-SET-SCHEME: GUID no reconocido $g") }
            }
            'STARTUP-DISABLE' {
                foreach ($t in $targets) {
                    $name = [string](Get-WpaValue $t 'Name' '')
                    if ($name -eq '' -or $name.Length -gt 200) { continue }
                    $hive = [string](Get-WpaValue $t 'Hive' 'HKCU'); $sub = [string](Get-WpaValue $t 'Sub' 'Run')
                    $extra = ' Ejecutable: ' + [string](Get-WpaValue $t 'Executable' '')
                    if ($sub -eq 'StartupFolder') {
                        $ftype = if ($hive -eq 'HKLM') { 'STARTUP-DISABLE-COMMON-FOLDER' } else { 'STARTUP-DISABLE-USER-FOLDER' }
                        Add-Spec -Type $ftype -Finding $f -Targets @($name) -Extra ' Acceso directo de la carpeta Inicio.'
                    }
                    elseif ($hive -eq 'HKLM') { Add-Spec -Type 'STARTUP-DISABLE-MACHINE-RUN' -Finding $f -Targets @($name) -Fingerprint ([string]$t.CommandHash) -Detail ([ordered]@{ Sub = $sub }) -Extra $extra }
                    else { Add-Spec -Type 'STARTUP-DISABLE-USER-RUN' -Finding $f -Targets @($name) -Fingerprint ([string]$t.CommandHash) -Extra $extra }
                }
            }
            'STARTUP-DISABLE-USER-RUN' {
                # Compatibilidad con findings de la version 1
                foreach ($t in $targets) { $name = [string](Get-WpaValue $t 'Name' ''); if ($name) { Add-Spec -Type $type -Finding $f -Targets @($name) -Fingerprint ([string](Get-WpaValue $t 'CommandHash' '')) } }
            }
            'DISK-OPTIMIZE' {
                $t = $targets[0]
                $drive = [string](Get-WpaValue $t 'Drive' '')
                if ($drive -notmatch '^[A-Za-z]:$') { [void]$skipped.Add('DISK-OPTIMIZE: unidad invalida'); continue }
                Add-Spec -Type $type -Finding $f -Targets @($drive.ToUpperInvariant()) -Detail ([ordered]@{ Mode = [string](Get-WpaValue $t 'Mode' '') })
            }
            { $_ -in @('CLEANUP-USER-TEMP', 'CLEANUP-WINDOWS-TEMP', 'CLEANUP-WER') } {
                $roots = (@(Get-WpaCleanupRoots $type) -join ';')
                if ([string]$targets[0] -ne $roots) { [void]$skipped.Add(("{0}: raices distintas a las del catalogo" -f $type)); continue }
                Add-Spec -Type $type -Finding $f -Targets @($roots)
            }
            'TASK-DISABLE-ORPHAN' {
                foreach ($t in $targets) {
                    $tp = [string]$t
                    if ($tp -notmatch '^\\[^*?]+\\?[^\\*?]+$' -or $tp -like '\Microsoft\*') { [void]$skipped.Add("Tarea descartada: $tp"); continue }
                    Add-Spec -Type $type -Finding $f -Targets @($tp)
                }
            }
            'STARTUP-DISABLE-PACKAGED' {
                foreach ($t in $targets) {
                    $tg = [string]$t
                    if (-not (Test-WpaPackagedStartupTarget $tg) -or $tg -match $script:WpaProtectedPackagePattern) { [void]$skipped.Add("Inicio de app descartado: $tg"); continue }
                    Add-Spec -Type $type -Finding $f -Targets @($tg)
                }
            }
            'BACKGROUND-APP-DISABLE' {
                foreach ($t in $targets) {
                    $pfn = [string]$t
                    if (-not (Test-WpaPackageFamilyName $pfn) -or $pfn -match $script:WpaProtectedPackagePattern) { [void]$skipped.Add("App descartada: $pfn"); continue }
                    Add-Spec -Type $type -Finding $f -Targets @($pfn)
                }
            }
            'SERVICE-DISABLE-ORPHAN' {
                foreach ($t in $targets) {
                    $n = [string]$t
                    if ($n -notmatch '^[A-Za-z0-9_.\-]{1,100}$') { [void]$skipped.Add("Servicio descartado: $n"); continue }
                    Add-Spec -Type $type -Finding $f -Targets @($n)
                }
            }
            'APP-UNINSTALL' {
                foreach ($t in $targets) {
                    $kp = [string](Get-WpaValue $t 'KeyPath' '')
                    $detail = [ordered]@{
                        DisplayName = [string](Get-WpaValue $t 'DisplayName' ''); Version = [string](Get-WpaValue $t 'Version' ''); Publisher = [string](Get-WpaValue $t 'Publisher' '')
                        InstallLocation = [string](Get-WpaValue $t 'InstallLocation' ''); Kind = [string](Get-WpaValue $t 'Kind' '')
                        Exe = [string](Get-WpaValue $t 'Exe' ''); Args = [string](Get-WpaValue $t 'Args' '')
                        LastUseUnix = [string](Get-WpaValue $t 'LastUseUnix' ''); Evidence = [string](Get-WpaValue $t 'Evidence' ''); Source = [string](Get-WpaValue $t 'Source' ''); SizeMB = [string](Get-WpaValue $t 'SizeMB' '')
                    }
                    if ($kp -notmatch '^(HKLM|HKCU):\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$') { [void]$skipped.Add("Programa descartado (clave invalida): $kp"); continue }
                    $extra = (' Programa: {0} {1} ({2}); ultimo uso: {3}; evidencia: {4} ({5}); tamano: {6} MB.' -f $detail.DisplayName, $detail.Version, $detail.Publisher,
                        $(if ($detail.LastUseUnix) { ([DateTime]'1970-01-01').AddSeconds([double]$detail.LastUseUnix).ToString('yyyy-MM') } else { 'sin ejecuciones registradas' }), $detail.Evidence, $detail.Source, $detail.SizeMB)
                    Add-Spec -Type $type -Finding $f -Targets @($kp) -Fingerprint ([string](Get-WpaValue $t 'Fingerprint' '')) -Detail $detail -Extra $extra
                }
            }
            { $_ -in @('VERIFY-SFC', 'VERIFY-DISM-CHECKHEALTH') } {
                Add-Spec -Type $type -Finding $f -Targets @('SYSTEM')
                if ($type -eq 'VERIFY-SFC') { Add-Spec -Type 'DISK-SCAN' -Finding $f -Targets @($sysDrive) }
            }
            { $_ -in @('VISUAL-EFFECTS-PERFORMANCE', 'HIBERNATION-OFF', 'DEFENDER-SCAN', 'COMPONENT-CLEANUP', 'CLEANUP-DELIVERY-OPTIMIZATION', 'APP-UPDATE-CHECK') } {
                Add-Spec -Type $type -Finding $f -Targets @([string]$targets[0])
            }
            default { [void]$skipped.Add("Tipo no soportado por propose-actions: $type") }
        }
    }
}

foreach ($w in $wingetRows) {
    $id = [string](Get-WpaValue $w 'Id' '')
    if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9.\-_+]{1,120}$') { [void]$skipped.Add("Actualizacion descartada (Id invalido): $id"); continue }
    $wf = [pscustomobject]@{ Id = 'WINGET'; Title = 'Actualizacion disponible'; Evidence = @(('{0}: {1} -> {2}' -f (Get-WpaValue $w 'Name' ''), (Get-WpaValue $w 'Version' ''), (Get-WpaValue $w 'Available' ''))) }
    Add-Spec -Type 'APP-UPDATE' -Finding $wf -Targets @($id) -Detail ([ordered]@{ Name = [string](Get-WpaValue $w 'Name' ''); Version = [string](Get-WpaValue $w 'Version' ''); Available = [string](Get-WpaValue $w 'Available' '') })
}
$manual = [pscustomobject]@{ Id = 'MANUAL'; Title = 'Confirmado por el usuario a partir de una verificacion previa'; Evidence = @() }
if ($ComponentStoreCorrupted) { Add-Spec -Type 'REPAIR-DISM-RESTOREHEALTH' -Finding $manual -Targets @('SYSTEM') }
if ($SfcViolationsConfirmed) { Add-Spec -Type 'REPAIR-SFC-SCANNOW' -Finding $manual -Targets @('SYSTEM') }

# Punto de restauracion: obligatorio antes de desinstalar o reparar; opcional en otros cambios.
$needRp = @($specs | Where-Object { $catalog[$_.Type].RequiresRestorePoint }).Count -gt 0
$anyMod = @($specs | Where-Object { $catalog[$_.Type].Modifies }).Count -gt 0
if ($needRp -or ($IncludeRestorePoint -and $anyMod)) {
    $rpF = [pscustomobject]@{ Id = 'BACKUP'; Title = 'Respaldo previo a cambios'; Evidence = @($(if ($needRp) { 'Obligatorio: se proponen desinstalaciones o reparaciones' } else { 'Solicitado por el usuario' })) }
    $before = $specs.Count
    Add-Spec -Type 'CREATE-RESTORE-POINT' -Finding $rpF -Targets @('WPA ' + $prefix)
    if ($specs.Count -gt $before) { $rp = $specs[$specs.Count - 1]; $specs.RemoveAt($specs.Count - 1); $specs.Insert(0, $rp) }
}

$actions = New-Object System.Collections.ArrayList
foreach ($sp in $specs) {
    $def = $catalog[$sp.Type]
    $id = ('A-{0}-{1:d3}' -f $prefix, ($actions.Count + 1))
    [void]$actions.Add([ordered]@{
        ActionId             = $id
        Type                 = $sp.Type
        Title                = $def.Title
        FindingId            = [string](Get-WpaValue $sp.Finding 'Id' '')
        Finding              = [string](Get-WpaValue $sp.Finding 'Title' '')
        Evidence             = @((Get-WpaValue $sp.Finding 'Evidence' @()) | Select-Object -First 8 | ForEach-Object { [string]$_ })
        Command              = $sp.Command
        Targets              = @($sp.Targets)
        TargetFingerprint    = $sp.Fingerprint
        Detail               = $sp.Detail
        Affects              = ($def.Affects + $sp.Extra)
        Benefit              = $def.Benefit
        Risk                 = $def.Risk
        Modifies             = [bool]$def.Modifies
        RequiresAdmin        = [bool]$def.RequiresAdmin
        RequiresReboot       = [bool]$def.RequiresReboot
        RequiresRestorePoint = [bool]$def.RequiresRestorePoint
        Network              = [bool]$def.Network
        Backup               = $def.Backup
        Rollback             = $def.Rollback
        RollbackReliable     = [bool]$def.RollbackReliable
        Validation           = $def.Validation
        ApprovalRule         = $(if ($def.Risk -eq 'Low') { 'identificador explicito' } else { 'aprobacion individual: unico identificador en el mensaje' })
    })
}

$bundles = @()
# Paquete de bajo riesgo en ambos modos: sigue exigiendo escribir su identificador P-... literal.
if ($true) {
    $eligible = @($actions | Where-Object { Test-WpaBundleEligible ([pscustomobject]$_) } | ForEach-Object { $_.ActionId })
    if ($eligible.Count -gt 0) {
        $bundles = @([ordered]@{ BundleId = ('P-{0}-01' -f $prefix); Description = 'Acciones de riesgo bajo, sin red y con reversion confiable'; ActionIds = @($eligible) })
    }
}

$plan = [ordered]@{
    SchemaVersion    = 2
    Mode             = 'audit-only'
    Notice           = 'PLAN PROPUESTO. Nada se ha ejecutado. Ninguna accion se aplica sin aprobacion explicita en esta sesion.'
    SessionId        = $sessionId
    CreatedUnix      = $now
    ExpiresUnix      = ($now + ($ValidHours * 3600))
    OperationMode    = $OperationMode
    Ticket           = $Ticket
    Technician       = $Technician
    DeviceContext    = $devCtx
    OrgAuthorization = [ordered]@{ Used = [bool]$orgUsed; Path = $(if ($orgUsed) { $(if ($OrgAuthorizationPath) { $OrgAuthorizationPath } else { $script:WpaOrgAuthDefaultPath }) } else { '' }) }
    Actions          = @($actions)
    Bundles          = @($bundles)
    Skipped          = @($skipped)
    PlanHash         = ''
}
$roundTrip = ($plan | ConvertTo-Json -Depth 10) | ConvertFrom-Json
$plan.PlanHash = Get-WpaPlanHash $roundTrip

# --- Version legible ------------------------------------------------------------
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine('# Plan de acciones propuestas (audit-only)')
[void]$md.AppendLine('')
[void]$md.AppendLine(('Sesion: `{0}` - modo: **{1}** - expira en {2} h - hash `{3}`' -f $sessionId, $OperationMode, $ValidHours, $plan.PlanHash.Substring(0, 16)))
if ($Ticket) { [void]$md.AppendLine(('Ticket: `{0}` - tecnico: {1}' -f $Ticket, $Technician)) }
[void]$md.AppendLine('')
[void]$md.AppendLine('**Nada se ha ejecutado.** Cada accion requiere aprobacion explicita.')
if ($isManaged) { [void]$md.AppendLine(''); [void]$md.AppendLine('> Equipo administrado (' + ($reasons -join '; ') + '). Cambios solo con autorizacion corporativa valida: ' + $(if ($orgUsed) { 'verificada.' } else { 'no presente; solo verificaciones.' })) }
foreach ($a in $actions) {
    [void]$md.AppendLine('')
    [void]$md.AppendLine(('## {0} - {1}' -f $a.ActionId, $a.Title))
    [void]$md.AppendLine(('- **Hallazgo:** {0} {1}' -f $a.FindingId, $a.Finding))
    [void]$md.AppendLine(('- **Evidencia:** {0}' -f ($a.Evidence -join ' | ')))
    [void]$md.AppendLine('- **Comando exacto:**')
    [void]$md.AppendLine('```')
    [void]$md.AppendLine($a.Command)
    [void]$md.AppendLine('```')
    [void]$md.AppendLine(('- **Objetivo exacto:** `{0}`' -f ($a.Targets -join '`, `')))
    [void]$md.AppendLine(('- **Afecta:** {0}' -f $a.Affects))
    [void]$md.AppendLine(('- **Beneficio esperado:** {0}' -f $a.Benefit))
    [void]$md.AppendLine(('- **Riesgo:** {0} ({1})' -f $a.Risk, $a.ApprovalRule))
    [void]$md.AppendLine(('- **Administrador:** {0} - **Reinicio:** {1} - **Usa red:** {2} - **Requiere punto de restauracion:** {3}' -f $a.RequiresAdmin, $a.RequiresReboot, $a.Network, $a.RequiresRestorePoint))
    [void]$md.AppendLine(('- **Respaldo / estado previo:** {0}' -f $a.Backup))
    $rel = if ($a.RollbackReliable) { '' } else { ' **[SIN REVERSION CONFIABLE]**' }
    [void]$md.AppendLine(('- **Reversion:** {0}{1}' -f $a.Rollback, $rel))
    [void]$md.AppendLine(('- **Validacion posterior:** {0}' -f $a.Validation))
}
foreach ($b in $bundles) {
    [void]$md.AppendLine('')
    [void]$md.AppendLine(('## Paquete {0}' -f $b.BundleId))
    [void]$md.AppendLine(('{0}: {1}' -f $b.Description, ($b.ActionIds -join ', ')))
    [void]$md.AppendLine(('Para aprobarlo completo: `Apruebo paquete {0}`. Las acciones de riesgo medio, con red o con punto de restauracion obligatorio NUNCA se incluyen.' -f $b.BundleId))
}
$manualRecs = @((Get-WpaList (Get-WpaValue $findingsDoc 'Findings' @())) | Where-Object {
    @(Get-WpaList $_.ProposedActionTypes).Count -eq 0 -and $_.Severity -in @('critical', 'high', 'medium') })
if ($manualRecs.Count -gt 0) {
    [void]$md.AppendLine(''); [void]$md.AppendLine('## Recomendaciones manuales (fuera del catalogo; el agente no las ejecuta)')
    foreach ($r in $manualRecs) {
        [void]$md.AppendLine(('- **{0} [{1}]** {2}. {3}' -f $r.RuleId, $r.Category, $r.Title, $r.Recommendation))
    }
}
if ($skipped.Count -gt 0) {
    [void]$md.AppendLine(''); [void]$md.AppendLine('## Omitidas')
    foreach ($s in $skipped) { [void]$md.AppendLine('- ' + $s) }
}
[void]$md.AppendLine('')
[void]$md.AppendLine('Para autorizar: `Apruebo A-' + $prefix + '-00N`. Riesgo medio: un identificador por mensaje. "Optimiza", "si", "todo" o "haz lo que recomiendes" no autorizan ninguna accion.')

try {
    $p1 = Write-WpaFile -OutputDir $OutputDir -Name 'action-plan.json' -Content ($plan | ConvertTo-Json -Depth 10)
    $p2 = Write-WpaFile -OutputDir $OutputDir -Name 'action-plan.md' -Content $md.ToString()
    Write-WpaAuditLog -OutputDir $OutputDir -Script $scriptName -Operation 'plan' -Result 'propuesto' -ExitCode 0 -Details ("sesion {0}; modo {1}; acciones {2}; paquetes {3}; omitidas {4}" -f $sessionId, $OperationMode, $actions.Count, @($bundles).Count, $skipped.Count)
    Write-Output ("Plan propuesto (NO ejecutado): {0}" -f $p2)
    Write-Output ("Sesion: {0}  Acciones: {1}  Paquetes: {2}  Omitidas: {3}" -f $sessionId, $actions.Count, @($bundles).Count, $skipped.Count)
    exit 0
} catch {
    Write-WpaError $_.Exception.Message
    exit 1
}

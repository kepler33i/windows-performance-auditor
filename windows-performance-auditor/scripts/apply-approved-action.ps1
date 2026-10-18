#Requires -Version 5.1
<#
.SYNOPSIS
  Ejecuta UNA accion previamente propuesta y aprobada explicitamente.

.DESCRIPTION
  Requisitos simultaneos para ejecutar:
    -Apply          interruptor explicito (sin el: simulacion, nada se ejecuta)
    -PlanPath       action-plan.json generado por propose-actions.ps1
    -SessionId      debe coincidir con el plan (la autorizacion no se reutiliza en otra sesion)
    -ActionId       un solo identificador presente en el plan
    -Target         objetivo EXACTO del plan
    -ApprovalText   texto literal del usuario que nombra el ActionId o su paquete P-...

  Controles:
    - Plan no expirado, hash valido; comando regenerado desde la allowlist igual al del plan.
    - Riesgo/red/administrador/punto de restauracion del plan iguales al catalogo.
    - Riesgo medio: aprobacion individual. Paquetes: solo riesgo bajo, sin red y reversibles.
    - No reutilizacion (executed-actions.json). No se autoeleva.
    - Equipo administrado: autorizacion corporativa verificada en el momento de ejecutar.
    - Desinstalar/reparar exige un CREATE-RESTORE-POINT validado en esta sesion.
    - Revalidacion en vivo del objetivo; estado previo guardado y verificado antes de ejecutar.
    - Validacion posterior; ante falla: detenerse y proponer reversion.

  -Rollback revierte acciones con reversion automatica confiable, con aprobacion
  explicita de "revertir <ActionId>".

  Codigos: 0 aplicado y validado | 2 entrada invalida | 3 rechazado | 4 ejecutado
  pero la validacion fallo (detenerse) | 10 simulacion sin -Apply | 99 ejecucion
  suprimida por WPA_NO_EXECUTE=1 (pruebas).
#>
[CmdletBinding()]
param(
    [string]$PlanPath,
    [string]$ActionId,
    [string]$SessionId,
    [string]$Target,
    [string]$ApprovalText,
    [string]$OrgAuthorizationPath = '',
    [switch]$Apply,
    [switch]$Rollback
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$scriptName = 'apply-approved-action'
$planDir = $null
$rollbackTypes = @('POWER-SET-SCHEME', 'STARTUP-DISABLE-USER-RUN', 'STARTUP-DISABLE-MACHINE-RUN', 'VISUAL-EFFECTS-PERFORMANCE',
                   'HIBERNATION-OFF', 'TASK-DISABLE-ORPHAN', 'SERVICE-DISABLE-ORPHAN', 'BACKGROUND-APP-DISABLE', 'STARTUP-DISABLE-PACKAGED',
                   'STARTUP-DISABLE-USER-FOLDER', 'STARTUP-DISABLE-COMMON-FOLDER')

function Stop-Wpa {
    param([int]$Code, [string]$Message)
    if ($planDir) {
        Write-WpaAuditLog -OutputDir $planDir -Script $scriptName -Operation $(if ($Rollback) { 'rollback' } else { 'apply' }) `
            -Command $ActionId -Result 'rechazado' -ExitCode $Code -Details $Message
    }
    Write-Output ("RECHAZADO ({0}): {1}" -f $Code, $Message)
    exit $Code
}

# --- 1. Parametros (sin prompts interactivos) -----------------------------------
if ([string]::IsNullOrWhiteSpace($PlanPath))     { Stop-Wpa 2 'Falta -PlanPath.' }
if ([string]::IsNullOrWhiteSpace($ActionId))     { Stop-Wpa 2 'Falta -ActionId.' }
if ($ActionId -notmatch '^A-[0-9a-f]{8}-\d{3}$') { Stop-Wpa 2 'ActionId con formato invalido (se acepta un unico identificador A-xxxxxxxx-NNN).' }
if ([string]::IsNullOrWhiteSpace($SessionId))    { Stop-Wpa 2 'Falta -SessionId.' }
if ([string]::IsNullOrEmpty($Target))            { Stop-Wpa 2 'Falta -Target con el objetivo exacto.' }
if ([string]::IsNullOrWhiteSpace($ApprovalText)) { Stop-Wpa 2 'Falta -ApprovalText con la aprobacion literal del usuario.' }

# --- 2. Plan e integridad ----------------------------------------------------------
$syn = Test-WpaPathSyntax $PlanPath
if (-not $syn.Ok) { Stop-Wpa 2 ("PlanPath invalido: " + $syn.Reason) }
try {
    $planDir = Assert-WpaOutputDir ([IO.Path]::GetDirectoryName($PlanPath))
    $chk = Test-WpaNoReparseChain $PlanPath
    if (-not $chk.Ok) { throw $chk.Reason }
    $plan = Read-WpaJson $PlanPath
} catch {
    $planDir = $null
    Stop-Wpa 2 ("No se pudo leer el plan: " + $_.Exception.Message)
}
if ([string](Get-WpaValue $plan 'Mode') -ne 'audit-only') { Stop-Wpa 3 'Plan con modo inesperado.' }
if ([string](Get-WpaValue $plan 'PlanHash') -ne (Get-WpaPlanHash $plan)) { Stop-Wpa 3 'Hash de integridad del plan no coincide: el plan fue modificado.' }
if ([string](Get-WpaValue $plan 'SessionId') -ne $SessionId) { Stop-Wpa 3 'SessionId no coincide: una autorizacion no puede reutilizarse en otra sesion.' }
$now = Get-WpaUnixNow
if ($now -gt [int64](Get-WpaValue $plan 'ExpiresUnix' 0)) { Stop-Wpa 3 'El plan expiro. Genere un nuevo plan y solicite aprobacion nuevamente.' }
if ([int64](Get-WpaValue $plan 'CreatedUnix' 0) -gt ($now + 300)) { Stop-Wpa 3 'Fecha de creacion del plan en el futuro.' }

$action = @((Get-WpaValue $plan 'Actions' @()) | Where-Object { $_.ActionId -eq $ActionId })
if ($action.Count -ne 1) { Stop-Wpa 3 ("ActionId no existe en el plan: " + $ActionId) }
$action = $action[0]
$type = [string]$action.Type
$detail = Get-WpaValue $action 'Detail'

# --- 3. Allowlist ---------------------------------------------------------------------
$catalog = Get-WpaActionCatalog
if (-not $catalog.Contains($type)) { Stop-Wpa 3 ("Tipo fuera de la allowlist: " + $type) }
$def = $catalog[$type]
foreach ($f in @('Risk', 'Modifies', 'RequiresAdmin', 'Network', 'RequiresRestorePoint', 'RollbackReliable')) {
    if ([string](Get-WpaValue $action $f '') -ne [string]$def.$f) { Stop-Wpa 3 ("El campo {0} del plan no coincide con la allowlist." -f $f) }
}

# --- 4. Objetivo exacto y comando -----------------------------------------------------
$planTargets = @($action.Targets | ForEach-Object { [string]$_ })
if ($planTargets.Count -ne 1 -or -not [string]::Equals($planTargets[0], $Target, [StringComparison]::Ordinal)) {
    Stop-Wpa 3 'El objetivo no coincide exactamente con el aprobado en el plan.'
}
$t0 = $planTargets[0]
try { $regenerated = Get-WpaActionCommand -Type $type -Targets $planTargets -Detail $detail } catch { Stop-Wpa 3 ("No se pudo regenerar el comando: " + $_.Exception.Message) }
if ($regenerated -ne [string]$action.Command) { Stop-Wpa 3 'El comando del plan no coincide con el generado por la allowlist.' }

# --- 5. Aprobacion explicita ----------------------------------------------------------
$approvals = Get-WpaExplicitApprovals -Text $ApprovalText -Actions @($plan.Actions) -Bundles @(Get-WpaValue $plan 'Bundles' @())
$mine = @($approvals | Where-Object { $_.ActionId -eq $ActionId })
if ($mine.Count -ne 1 -or -not $mine[0].Approved) {
    $why = if ($mine.Count -eq 1) { $mine[0].Reason } else { 'sin aprobacion' }
    Stop-Wpa 3 ("Aprobacion no valida para {0}: {1}" -f $ActionId, $why)
}
if ($Rollback -and $ApprovalText -notmatch '(?i)\b(revertir|revierte|rollback)\b') { Stop-Wpa 3 'La reversion requiere una aprobacion explicita de revertir.' }

# --- 6. Registro de ejecuciones -----------------------------------------------------------
$ledgerPath = Join-Path $planDir 'executed-actions.json'
try { $ledger = @(Read-WpaJsonArray $ledgerPath) } catch { Stop-Wpa 3 'executed-actions.json ilegible; se detiene por seguridad.' }
$mineLedger = @($ledger | Where-Object { $_.ActionId -eq $ActionId })
$backupName = ('backup-{0}.json' -f $ActionId)
$backupPath = Join-Path $planDir $backupName
if ($Rollback) {
    if ($rollbackTypes -notcontains $type) { Stop-Wpa 3 ("{0} no tiene reversion automatica confiable: {1}" -f $type, $def.Rollback) }
    if (@($mineLedger | Where-Object { $_.Mode -eq 'apply' -and $_.Executed }).Count -eq 0) { Stop-Wpa 3 'No hay registro de que la accion se haya aplicado.' }
    if (@($mineLedger | Where-Object { $_.Mode -eq 'rollback' }).Count -gt 0) { Stop-Wpa 3 'La accion ya fue revertida.' }
    if (-not (Test-Path -LiteralPath $backupPath)) { Stop-Wpa 3 'No existe el respaldo del estado previo; no se puede revertir con confianza.' }
} elseif (@($mineLedger | Where-Object { $_.Mode -eq 'apply' }).Count -gt 0) {
    Stop-Wpa 3 'Esta accion ya se ejecuto; la autorizacion no se reutiliza.'
}

# --- 7. Equipo administrado, privilegios y prerequisitos --------------------------------
if ($def.Modifies) {
    $live = $null
    try { $live = Get-WpaDeviceContext } catch { }
    if ([bool](Get-WpaValue $plan 'DeviceContext.IsManaged' $false) -or [bool](Get-WpaValue $live 'IsManaged' $false)) {
        $auth = Test-WpaOrgAuthorization -Path $OrgAuthorizationPath -DeviceContext $live -ActionType $type -Ticket ([string](Get-WpaValue $plan 'Ticket' ''))
        if (-not $auth.Ok) { Stop-Wpa 3 ('Equipo administrado sin autorizacion corporativa verificable: ' + $auth.Reason) }
    }
}
if ($def.RequiresRestorePoint -and -not $Rollback) {
    $rpIds = @((Get-WpaValue $plan 'Actions' @()) | Where-Object { $_.Type -eq 'CREATE-RESTORE-POINT' } | ForEach-Object { $_.ActionId })
    $rpOk = @($ledger | Where-Object { $rpIds -contains $_.ActionId -and $_.Mode -eq 'apply' -and $_.Result -eq 'validado' })
    if ($rpOk.Count -eq 0) { Stop-Wpa 3 'Se requiere un punto de restauracion VERIFICADO en esta sesion antes de esta accion (ejecute primero CREATE-RESTORE-POINT).' }
}
if ($def.RequiresAdmin -and -not (Test-WpaIsAdmin)) {
    Stop-Wpa 3 'La accion requiere administrador. El script no se autoeleva: el usuario debe abrir una consola elevada y repetir la aprobacion.'
}
if ($type -eq 'CREATE-RESTORE-POINT' -and $PSVersionTable.PSVersion.Major -ge 6) { Stop-Wpa 3 'Checkpoint-Computer solo existe en Windows PowerShell 5.1.' }
# --- 8. Validacion en vivo del objetivo ------------------------------------------------
$uninstallExe = $null; $uninstallArgs = @(); $wingetExe = $null
switch ($type) {
    'POWER-SET-SCHEME' {
        if (-not $script:WpaPowerSchemes.ContainsKey($t0)) { Stop-Wpa 3 'GUID de plan de energia no integrado.' }
        if (@(Get-WpaPowerSchemes | Where-Object { $_.Guid -eq $t0 }).Count -ne 1) { Stop-Wpa 3 'El plan de energia objetivo no existe en este equipo.' }
    }
    { $_ -in @('STARTUP-DISABLE-USER-RUN', 'STARTUP-DISABLE-MACHINE-RUN') } {
        $hive = if ($type -eq 'STARTUP-DISABLE-USER-RUN') { 'HKCU' } else { 'HKLM' }
        $sub = if ($type -eq 'STARTUP-DISABLE-USER-RUN') { 'Run' } else { [string](Get-WpaValue $detail 'Sub' '') }
        $cmd = Get-WpaRunEntry -Name $t0 -Hive $hive -Sub $sub
        if ($null -eq $cmd) { Stop-Wpa 3 'La entrada de inicio ya no existe.' }
        if ((Get-WpaStringHash $cmd) -ne [string]$action.TargetFingerprint) { Stop-Wpa 3 'La entrada de inicio cambio desde la auditoria (huella distinta).' }
        if (-not (Test-Path -LiteralPath $script:WpaApprovedKeys[$hive + '|' + $sub])) { Stop-Wpa 3 'No existe la clave StartupApproved correspondiente; use el Administrador de tareas manualmente.' }
    }
    { $_ -in @('STARTUP-DISABLE-USER-FOLDER', 'STARTUP-DISABLE-COMMON-FOLDER') } {
        $hive = if ($type -eq 'STARTUP-DISABLE-USER-FOLDER') { 'HKCU' } else { 'HKLM' }
        $sub = 'StartupFolder'
        $lnk = Get-WpaStartupFolderFile -Hive $hive -Name $t0
        if ($null -eq $lnk) { Stop-Wpa 3 'El acceso directo ya no existe en la carpeta Inicio.' }
        if (-not (Test-WpaNoReparseChain $lnk).Ok) { Stop-Wpa 3 'El acceso directo esta en una ruta con enlaces o sincronizada.' }
        if (-not (Test-Path -LiteralPath $script:WpaApprovedKeys[$hive + '|' + $sub])) { Stop-Wpa 3 'No existe la clave StartupApproved\StartupFolder; use el Administrador de tareas manualmente.' }
    }
    'VISUAL-EFFECTS-PERFORMANCE' {
        foreach ($s in $script:WpaVisualSettings) { if (-not (Test-Path -LiteralPath $s.Path)) { Stop-Wpa 3 ("No existe la clave {0}; no se crean claves nuevas." -f $s.Path) } }
    }
    'STARTUP-DISABLE-PACKAGED' {
        if (-not (Test-WpaPackagedStartupTarget $t0) -or $t0 -match $script:WpaProtectedPackagePattern) { Stop-Wpa 3 'Tarea de inicio invalida o protegida.' }
        $pkgKey = Join-Path $script:WpaPackagedStartupBase $t0
        $pkgState = Get-WpaRegValue $pkgKey 'State'
        if (-not $pkgState.Exists) { Stop-Wpa 3 'La tarea de inicio ya no existe; no se crean claves nuevas.' }
        if ([int]$pkgState.Value -ne 2) { Stop-Wpa 3 ('La tarea de inicio no esta habilitada por el usuario (State={0}).' -f $pkgState.Value) }
    }
    'BACKGROUND-APP-DISABLE' {
        if ($t0 -match $script:WpaProtectedPackagePattern) { Stop-Wpa 3 'Paquete protegido (sistema, controlador o seguridad).' }
        $bgKey = Join-Path $script:WpaBackgroundKey $t0
        if (-not (Test-Path -LiteralPath $bgKey)) { Stop-Wpa 3 'No existe la clave de permisos de la app; no se crean claves nuevas.' }
    }
    'HIBERNATION-OFF' {
        if (@(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue).Count -gt 0) { Stop-Wpa 3 'Equipo con bateria: no se desactiva la hibernacion en portatiles.' }
        if ((Get-WpaHibernateEnabled) -ne $true) { Stop-Wpa 3 'La hibernacion ya esta desactivada.' }
    }
    'TASK-DISABLE-ORPHAN' {
        $i = $t0.LastIndexOf('\')
        if ($t0 -like '\Microsoft\*' -or $i -lt 0) { Stop-Wpa 3 'Tarea no permitida.' }
        $task = $null
        try { $task = Get-ScheduledTask -TaskPath $t0.Substring(0, $i + 1) -TaskName $t0.Substring($i + 1) -ErrorAction Stop } catch { Stop-Wpa 3 'La tarea ya no existe.' }
        $stillOrphan = $false
        foreach ($a in @($task.Actions)) {
            $exe = [Environment]::ExpandEnvironmentVariables(([string]$a.Execute).Trim().Trim('"'))
            if ([IO.Path]::IsPathRooted($exe) -and -not (Test-Path -LiteralPath $exe -PathType Leaf)) { $stillOrphan = $true }
        }
        if (-not $stillOrphan) { Stop-Wpa 3 'El ejecutable de la tarea existe: ya no es huerfana.' }
    }
    'SERVICE-DISABLE-ORPHAN' {
        $svc = Get-WpaServiceInfo $t0
        if (-not $svc) { Stop-Wpa 3 'El servicio ya no existe.' }
        $exe = Get-WpaServiceExe $svc.PathName
        if ([string]$svc.State -ne 'Stopped') { Stop-Wpa 3 'El servicio esta en ejecucion: no se modifica.' }
        if ([string]$svc.StartMode -eq 'Disabled') { Stop-Wpa 3 'El servicio ya esta deshabilitado.' }
        if (-not $exe -or (Test-WpaIsUnder $exe $env:SystemRoot) -or (Test-Path -LiteralPath $exe -PathType Leaf)) { Stop-Wpa 3 'El servicio no es un huerfano de terceros.' }
    }
    { $_ -in @('DISK-OPTIMIZE', 'DISK-SCAN') } {
        if ($t0 -notmatch '^[A-Z]:$') { Stop-Wpa 3 'Unidad invalida.' }
        if (-not (Test-Path -LiteralPath ($t0 + '\'))) { Stop-Wpa 3 'La unidad no existe.' }
        if ($type -eq 'DISK-OPTIMIZE') {
            $media = $null; $pd = $null
            try {
                $part = Get-Partition -DriveLetter $t0.TrimEnd(':') -ErrorAction Stop
                $pd = Get-PhysicalDisk -ErrorAction Stop | Where-Object { [string]$_.DeviceId -eq [string]$part.DiskNumber } | Select-Object -First 1
                $media = [string]$pd.MediaType
            } catch { }
            if ($pd -and ([string]$pd.BusType -eq 'RAID' -or (Test-WpaOptaneHybrid -FriendlyName ([string]$pd.FriendlyName) -BusType ([string]$pd.BusType)))) {
                Stop-Wpa 3 'Volumen RAID o acelerado con Intel Optane: Windows no informa el tipo real del disco; no se aplica TRIM ni desfragmentacion.'
            }
            $mode = [string](Get-WpaValue $detail 'Mode' '')
            if ($mode -eq 'Defrag' -and $media -ne 'HDD') { Stop-Wpa 3 ('No se desfragmenta: el disco no es HDD confirmado (' + $media + ').') }
            if ($mode -eq 'ReTrim' -and $media -ne 'SSD') { Stop-Wpa 3 ('TRIM solo en SSD confirmado (' + $media + ').') }
        }
    }
    { $_ -in @('CLEANUP-USER-TEMP', 'CLEANUP-WINDOWS-TEMP', 'CLEANUP-WER') } {
        if ($t0 -ne (@(Get-WpaCleanupRoots $type) -join ';')) { Stop-Wpa 3 'Las raices de limpieza no coinciden con el catalogo.' }
    }
    'APP-UNINSTALL' {
        $entry = Get-WpaUninstallEntry $t0
        if ($null -eq $entry) { Stop-Wpa 3 'El programa ya no esta registrado.' }
        if ((Get-WpaAppFingerprint $entry) -ne [string]$action.TargetFingerprint) { Stop-Wpa 3 'El programa cambio desde la auditoria (version o desinstalador distinto).' }
        $loc = [string](Get-WpaValue $detail 'InstallLocation' '')
        $appLive = [pscustomobject]@{ UninstallString = [string](Get-WpaValue $entry 'UninstallString' ''); KeyName = ($t0.Substring($t0.LastIndexOf('\') + 1))
            WindowsInstaller = ([int](Get-WpaValue $entry 'WindowsInstaller' 0) -eq 1); NoRemove = ([int](Get-WpaValue $entry 'NoRemove' 0) -eq 1); InstallLocation = $loc }
        $u = Resolve-WpaUninstallCommand $appLive
        if (-not $u.Ok) { Stop-Wpa 3 ('Desinstalador no valido: ' + $u.Reason) }
        if ($u.Exe -ne [string]$detail.Exe -or $u.Args -ne [string]$detail.Args) { Stop-Wpa 3 'El desinstalador registrado no coincide con el aprobado.' }
        if ($loc) {
            foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { $pp = $null; try { $pp = $p.Path } catch { }; if ($pp -and (Test-WpaIsUnder $pp $loc)) { Stop-Wpa 3 ('El programa esta en ejecucion (' + $p.ProcessName + '). Cierrelo y repita.') } }
            foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) { $e = Get-WpaServiceExe $s.PathName; if ($e -and (Test-WpaIsUnder $e $loc)) { Stop-Wpa 3 'El programa tiene servicios instalados: no se desinstala automaticamente.' } }
        }
        $uninstallExe = $u.Exe
        $uninstallArgs = @(ConvertTo-WpaArgList $u.Args)
    }
    { $_ -in @('APP-UPDATE-CHECK', 'APP-UPDATE') } {
        $wingetExe = Get-WpaWingetPath
        if (-not $wingetExe) { Stop-Wpa 3 'winget no esta disponible; no se instala.' }
    }
}

# --- 9. Simulacion ----------------------------------------------------------------------
$verb = if ($Rollback) { 'REVERTIR' } else { 'APLICAR' }
if (-not $Apply) {
    Write-WpaAuditLog -OutputDir $planDir -Script $scriptName -Operation 'dry-run' -Command $ActionId -Result 'simulacion' -ExitCode 10
    Write-Output ("SIMULACION ({0} {1}): validaciones superadas. No se ejecuto nada porque falta -Apply." -f $verb, $ActionId)
    Write-Output ("Comando que se ejecutaria:{0}{1}" -f [Environment]::NewLine, $regenerated)
    exit 10
}
if ($env:WPA_NO_EXECUTE -eq '1') {
    Write-WpaAuditLog -OutputDir $planDir -Script $scriptName -Operation 'suppressed' -Command $ActionId -Result 'ejecucion suprimida (WPA_NO_EXECUTE)' -ExitCode 99
    Write-Output ("SUPRIMIDO: validaciones superadas para {0}; WPA_NO_EXECUTE=1 impide ejecutar." -f $ActionId)
    exit 99
}

function Add-LedgerEntry {
    param([string]$Mode, [bool]$Executed, [string]$Result, $ExitCode)
    $entry = [pscustomobject]@{ ActionId = $ActionId; Type = $type; Mode = $Mode; Executed = $Executed; Result = $Result; ExitCode = $ExitCode; Unix = (Get-WpaUnixNow); SessionId = $SessionId }
    [void](Write-WpaFile -OutputDir $planDir -Name 'executed-actions.json' -Content (ConvertTo-Json -InputObject @(@($ledger) + @($entry)) -Depth 5))
}

# --- 10. Estado previo (verificado antes de ejecutar) ---------------------------------
if (-not $Rollback) {
    $state = [ordered]@{ ActionId = $ActionId; Type = $type; StartedUnix = (Get-WpaUnixNow) }
    switch ($type) {
        'POWER-SET-SCHEME' {
            $prev = Get-WpaActivePowerScheme
            if (-not $prev) { Stop-Wpa 3 'No se pudo leer el plan de energia activo; sin estado previo no se ejecuta.' }
            $state.PreviousScheme = $prev
        }
        { $_ -in @('STARTUP-DISABLE-USER-RUN', 'STARTUP-DISABLE-MACHINE-RUN', 'STARTUP-DISABLE-USER-FOLDER', 'STARTUP-DISABLE-COMMON-FOLDER') } {
            $prevVal = Get-WpaStartupApprovedValue -Name $t0 -Hive $hive -Sub $sub
            $state.Hive = $hive; $state.Sub = $sub
            $state.PreviousExisted = ($null -ne $prevVal)
            $state.PreviousValue = if ($null -ne $prevVal) { @($prevVal | ForEach-Object { [int]$_ }) } else { @() }
        }
        'VISUAL-EFFECTS-PERFORMANCE' {
            $state.Previous = @($script:WpaVisualSettings | ForEach-Object { $r = Get-WpaRegValue $_.Path $_.Name; [pscustomobject]@{ Path = $_.Path; Name = $_.Name; Type = $_.Type; Exists = $r.Exists; Value = $r.Value } })
        }
        'HIBERNATION-OFF' { $state.PreviousEnabled = $true }
        'STARTUP-DISABLE-PACKAGED' { $state.PreviousState = [int]$pkgState.Value }
        'BACKGROUND-APP-DISABLE' {
            $state.Previous = @(@('Disabled', 'DisabledByUser') | ForEach-Object { $r = Get-WpaRegValue $bgKey $_; [pscustomobject]@{ Name = $_; Exists = $r.Exists; Value = $r.Value } })
        }
        'CREATE-RESTORE-POINT' {
            # Solo se acepta un punto reciente existente si NINGUN cambio de esta sesion lo precede.
            $prior = @($ledger | Where-Object { $_.Executed -and $_.Type -and $catalog.Contains([string]$_.Type) -and $catalog[[string]$_.Type].Modifies -and [string]$_.Type -ne 'CREATE-RESTORE-POINT' })
            $state.AllowRecentFallback = ($prior.Count -eq 0)
        }
        'TASK-DISABLE-ORPHAN' { $state.PreviousState = [string]$task.State }
        'SERVICE-DISABLE-ORPHAN' { $state.PreviousStartMode = [string]$svc.StartMode }
        'APP-UNINSTALL' {
            $state.DisplayName = [string]$detail.DisplayName
            $state.InstallLocation = [string]$detail.InstallLocation
            $state.InstalledKeys = @(Get-WpaInstalledApps | ForEach-Object { [pscustomobject]@{ KeyPath = $_.KeyPath; DisplayName = $_.DisplayName; InstallLocation = $_.InstallLocation } })
            $state.ProblemDevices = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' -ErrorAction SilentlyContinue).Count
        }
    }
    try {
        [void](Write-WpaFile -OutputDir $planDir -Name $backupName -Content ($state | ConvertTo-Json -Depth 6))
        $backup = Read-WpaJson $backupPath
        if ([string]$backup.ActionId -ne $ActionId) { throw 'contenido inesperado' }
    } catch { Stop-Wpa 3 ("No se pudo guardar y verificar el estado previo: " + $_.Exception.Message) }
} else {
    $backup = Read-WpaJson $backupPath
}

# --- 11. Ejecucion (solo ramas de la allowlist, argumentos fijos) -----------------------
$exitCode = $null
$executedCommand = $regenerated
try {
    if ($Rollback) {
        switch ($type) {
            'POWER-SET-SCHEME' {
                $prev = [string]$backup.PreviousScheme
                if ($prev -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { throw 'GUID previo invalido en respaldo' }
                $executedCommand = ('"{0}" /setactive {1}' -f $def.Exe, $prev)
                & $def.Exe /setactive $prev
                $exitCode = $LASTEXITCODE
            }
            { $_ -in @('STARTUP-DISABLE-USER-RUN', 'STARTUP-DISABLE-MACHINE-RUN', 'STARTUP-DISABLE-USER-FOLDER', 'STARTUP-DISABLE-COMMON-FOLDER') } {
                $key = $script:WpaApprovedKeys[[string]$backup.Hive + '|' + [string]$backup.Sub]
                if ([bool]$backup.PreviousExisted) {
                    $bytes = [byte[]]@($backup.PreviousValue | ForEach-Object { [byte]$_ })
                    $executedCommand = ("Set-ItemProperty -LiteralPath '{0}' -Name '{1}' -Value ([byte[]]({2})) -Type Binary" -f $key, $t0, ($bytes -join ','))
                    Set-ItemProperty -LiteralPath $key -Name $t0 -Value $bytes -Type Binary
                } else {
                    $executedCommand = ("Remove-ItemProperty -LiteralPath '{0}' -Name '{1}'" -f $key, $t0)
                    Remove-ItemProperty -LiteralPath $key -Name $t0
                }
                $exitCode = 0
            }
            'VISUAL-EFFECTS-PERFORMANCE' {
                $lines = @()
                foreach ($p in @($backup.Previous)) {
                    $known = @($script:WpaVisualSettings | Where-Object { $_.Path -eq $p.Path -and $_.Name -eq $p.Name })
                    if ($known.Count -ne 1) { throw 'ajuste de respaldo fuera del catalogo' }
                    if ([bool]$p.Exists) {
                        Set-ItemProperty -LiteralPath $p.Path -Name $p.Name -Value $p.Value -Type $known[0].Type
                        $lines += ("Set-ItemProperty -LiteralPath '{0}' -Name '{1}' -Value '{2}' -Type {3}" -f $p.Path, $p.Name, $p.Value, $known[0].Type)
                    } else {
                        Remove-ItemProperty -LiteralPath $p.Path -Name $p.Name -ErrorAction SilentlyContinue
                        $lines += ("Remove-ItemProperty -LiteralPath '{0}' -Name '{1}'" -f $p.Path, $p.Name)
                    }
                }
                $executedCommand = $lines -join [Environment]::NewLine
                $exitCode = 0
            }
            'HIBERNATION-OFF' {
                $executedCommand = ('"{0}" /hibernate on' -f $def.Exe)
                & $def.Exe /hibernate on
                $exitCode = $LASTEXITCODE
            }
            'STARTUP-DISABLE-PACKAGED' {
                $prevState = [int]$backup.PreviousState
                if ($prevState -notin @(0, 1, 2)) { throw 'estado previo fuera de rango' }
                $pk = Join-Path $script:WpaPackagedStartupBase $t0
                $executedCommand = ("Set-ItemProperty -LiteralPath '{0}' -Name 'State' -Value {1} -Type DWord" -f $pk, $prevState)
                Set-ItemProperty -LiteralPath $pk -Name 'State' -Value $prevState -Type DWord
                $exitCode = 0
            }
            'BACKGROUND-APP-DISABLE' {
                $bk = Join-Path $script:WpaBackgroundKey $t0
                $lines = @()
                foreach ($p in @($backup.Previous)) {
                    if ($p.Name -notin @('Disabled', 'DisabledByUser')) { throw 'valor de respaldo fuera del catalogo' }
                    if ([bool]$p.Exists) { Set-ItemProperty -LiteralPath $bk -Name $p.Name -Value ([int]$p.Value) -Type DWord; $lines += ("Set-ItemProperty -LiteralPath '{0}' -Name '{1}' -Value {2} -Type DWord" -f $bk, $p.Name, $p.Value) }
                    else { Remove-ItemProperty -LiteralPath $bk -Name $p.Name -ErrorAction SilentlyContinue; $lines += ("Remove-ItemProperty -LiteralPath '{0}' -Name '{1}'" -f $bk, $p.Name) }
                }
                $executedCommand = $lines -join [Environment]::NewLine
                $exitCode = 0
            }
            'TASK-DISABLE-ORPHAN' {
                $i = $t0.LastIndexOf('\')
                $executedCommand = ("Enable-ScheduledTask -TaskPath '{0}' -TaskName '{1}'" -f $t0.Substring(0, $i + 1), $t0.Substring($i + 1))
                [void](Enable-ScheduledTask -TaskPath $t0.Substring(0, $i + 1) -TaskName $t0.Substring($i + 1))
                $exitCode = 0
            }
            'SERVICE-DISABLE-ORPHAN' {
                $map = @{ 'Auto' = 'Automatic'; 'Manual' = 'Manual' }
                $prevMode = $map[[string]$backup.PreviousStartMode]
                if (-not $prevMode) { throw 'tipo de inicio previo no restaurable' }
                $executedCommand = ("Set-Service -Name '{0}' -StartupType {1}" -f $t0, $prevMode)
                Set-Service -Name $t0 -StartupType $prevMode
                $exitCode = 0
            }
        }
    } else {
        switch ($type) {
            { $_ -in @('VERIFY-SFC', 'VERIFY-DISM-CHECKHEALTH', 'COMPONENT-CLEANUP', 'REPAIR-SFC-SCANNOW', 'REPAIR-DISM-RESTOREHEALTH') } {
                $out = & $def.Exe @($def.Args) 2>&1
                $exitCode = $LASTEXITCODE
                $text = (($out | ForEach-Object { [string]$_ }) -join ' ') -replace "`0", ''
                if ($text.Length -gt 1500) { $text = $text.Substring($text.Length - 1500) }
                Write-WpaAuditLog -OutputDir $planDir -Script $scriptName -Operation 'output' -Command $ActionId -Result 'salida' -ExitCode $exitCode -Details (ConvertTo-WpaSanitizedText $text)
            }
            'DISK-SCAN' {
                $out = & $def.Exe $t0 '/scan' 2>&1
                $exitCode = $LASTEXITCODE
                Write-WpaAuditLog -OutputDir $planDir -Script $scriptName -Operation 'output' -Command $ActionId -Result 'salida' -ExitCode $exitCode -Details (ConvertTo-WpaSanitizedText ((($out | Select-Object -Last 15) | ForEach-Object { [string]$_ }) -join ' '))
            }
            'POWER-SET-SCHEME' { & $def.Exe /setactive $t0; $exitCode = $LASTEXITCODE }
            'HIBERNATION-OFF' { & $def.Exe /hibernate off; $exitCode = $LASTEXITCODE }
            { $_ -in @('STARTUP-DISABLE-USER-RUN', 'STARTUP-DISABLE-MACHINE-RUN', 'STARTUP-DISABLE-USER-FOLDER', 'STARTUP-DISABLE-COMMON-FOLDER') } {
                Set-ItemProperty -LiteralPath $script:WpaApprovedKeys[$hive + '|' + $sub] -Name $t0 -Value ([byte[]](3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) -Type Binary
                $exitCode = 0
            }
            'VISUAL-EFFECTS-PERFORMANCE' {
                foreach ($s in $script:WpaVisualSettings) { Set-ItemProperty -LiteralPath $s.Path -Name $s.Name -Value $s.Value -Type $s.Type }
                $exitCode = 0
            }
            'TASK-DISABLE-ORPHAN' {
                $i = $t0.LastIndexOf('\')
                [void](Disable-ScheduledTask -TaskPath $t0.Substring(0, $i + 1) -TaskName $t0.Substring($i + 1))
                $exitCode = 0
            }
            'SERVICE-DISABLE-ORPHAN' { Set-Service -Name $t0 -StartupType Disabled; $exitCode = 0 }
            'STARTUP-DISABLE-PACKAGED' {
                Set-ItemProperty -LiteralPath $pkgKey -Name 'State' -Value 1 -Type DWord
                $exitCode = 0
            }
            'BACKGROUND-APP-DISABLE' {
                Set-ItemProperty -LiteralPath $bgKey -Name 'Disabled' -Value 1 -Type DWord
                Set-ItemProperty -LiteralPath $bgKey -Name 'DisabledByUser' -Value 1 -Type DWord
                $exitCode = 0
            }
            'CREATE-RESTORE-POINT' {
                $rpWarn = $null
                Checkpoint-Computer -Description $t0 -RestorePointType MODIFY_SETTINGS -WarningVariable rpWarn -WarningAction SilentlyContinue
                if ($rpWarn) { Write-WpaAuditLog -OutputDir $planDir -Script $scriptName -Operation 'restore-point' -Command $ActionId -Result 'aviso de Windows' -Details (@($rpWarn | ForEach-Object { [string]$_ }) -join ' ') }
                $exitCode = 0
            }
            'DISK-OPTIMIZE' {
                $letter = $t0.TrimEnd(':')
                if ([string]$detail.Mode -eq 'Defrag') { Optimize-Volume -DriveLetter $letter -Defrag } else { Optimize-Volume -DriveLetter $letter -ReTrim }
                $exitCode = 0
            }
            'DEFENDER-SCAN' { Update-MpSignature; Start-MpScan -ScanType QuickScan; $exitCode = 0 }
            { $_ -in @('CLEANUP-USER-TEMP', 'CLEANUP-WINDOWS-TEMP', 'CLEANUP-WER') } {
                $roots = @(Get-WpaCleanupRoots $type)
                $deleted = New-Object System.Collections.ArrayList
                $failed = 0; $bytes = [int64]0
                foreach ($fobj in @(Get-WpaCleanupFiles -Roots $roots -MinAgeDays 7)) {
                    $p = [string]$fobj.Path
                    $under = $false; foreach ($r in $roots) { if (Test-WpaIsUnder $p $r) { $under = $true } }
                    if (-not $under) { $failed++; continue }
                    try {
                        if (([int][IO.File]::GetAttributes($p) -band 0x400) -ne 0) { $failed++; continue }
                        Remove-Item -LiteralPath $p -Force
                        [void]$deleted.Add($p); $bytes += [int64]$fobj.Bytes
                    } catch { $failed++ }
                }
                [void](Write-WpaFile -OutputDir $planDir -Name ('cleanup-{0}.json' -f $ActionId) -Content (ConvertTo-Json -InputObject ([ordered]@{ Roots = $roots; DeletedCount = $deleted.Count; FreedMB = [Math]::Round($bytes / 1MB, 1); Failed = $failed; Deleted = @($deleted) }) -Depth 4))
                Write-WpaAuditLog -OutputDir $planDir -Script $scriptName -Operation 'cleanup' -Command $ActionId -Result ('eliminados {0}; omitidos/en uso {1}; {2} MB' -f $deleted.Count, $failed, [Math]::Round($bytes / 1MB, 1)) -ExitCode 0
                $exitCode = 0
            }
            'CLEANUP-DELIVERY-OPTIMIZATION' { Delete-DeliveryOptimizationCache -Force; $exitCode = 0 }
            'APP-UNINSTALL' {
                # Out-Null obliga a esperar el cierre de desinstaladores con interfaz grafica.
                & $uninstallExe @uninstallArgs | Out-Null
                $exitCode = $LASTEXITCODE
                $waited = 0
                while ($null -ne (Get-WpaUninstallEntry $t0) -and $waited -lt 900) { Start-Sleep -Seconds 5; $waited += 5 }
                Write-WpaAuditLog -OutputDir $planDir -Script $scriptName -Operation 'uninstall' -Command $regenerated -Result ('espera {0} s' -f $waited) -ExitCode $exitCode
            }
            'APP-UPDATE-CHECK' {
                $out = & $wingetExe upgrade --include-unknown --accept-source-agreements --disable-interactivity 2>&1
                $exitCode = $LASTEXITCODE
                $lines = @($out | ForEach-Object { [string]$_ })
                [void](Write-WpaFile -OutputDir $planDir -Name 'winget-upgrades.txt' -Content ($lines -join [Environment]::NewLine))
                $rows = @(ConvertFrom-WpaWingetTable $lines)
                [void](Write-WpaFile -OutputDir $planDir -Name 'winget-upgrades.json' -Content (ConvertTo-Json -InputObject @($rows) -Depth 3))
                if ($rows.Count -gt 0 -or $exitCode -eq 0) { $exitCode = 0 }
                Write-Output ("Actualizaciones encontradas: {0}. Proponerlas con propose-actions.ps1 -WingetUpgradesPath winget-upgrades.json" -f $rows.Count)
            }
            'APP-UPDATE' {
                & $wingetExe upgrade --id $t0 --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Null
                $exitCode = $LASTEXITCODE
            }
            default { throw "Rama no implementada: $type" }
        }
    }
} catch {
    $msg = $_.Exception.Message
    Write-WpaAuditLog -OutputDir $planDir -Script $scriptName -Operation $(if ($Rollback) { 'rollback' } else { 'apply' }) -Command $executedCommand -Result 'error' -ExitCode 1 -Details $msg
    Add-LedgerEntry -Mode $(if ($Rollback) { 'rollback' } else { 'apply' }) -Executed $true -Result ('error: ' + $msg) -ExitCode 1
    Write-Output ("ERROR al {0} {1}: {2}" -f $verb, $ActionId, $msg)
    Write-Output ("DETENERSE. Reversion propuesta (requiere nueva aprobacion): {0}" -f $def.Rollback)
    exit 4
}

$mode = if ($Rollback) { 'rollback' } else { 'apply' }
Write-WpaAuditLog -OutputDir $planDir -Script $scriptName -Operation $mode -Command $executedCommand -Result 'ejecutado' -ExitCode $exitCode -Details ("ticket: {0}; aprobacion: {1}" -f (Get-WpaValue $plan 'Ticket' ''), (ConvertTo-WpaSanitizedText $ApprovalText))

# --- 12. Validacion posterior --------------------------------------------------------------
$outcome = Test-WpaActionOutcome -Action $action -Backup $backup -Mode $mode -ExitCode $exitCode
$result = if ($outcome.Ok) { 'validado' } else { 'validacion fallida' }
Add-LedgerEntry -Mode $mode -Executed $true -Result $result -ExitCode $exitCode
Write-WpaAuditLog -OutputDir $planDir -Script $scriptName -Operation 'validate' -Command $ActionId -Result $result -ExitCode $(if ($outcome.Ok) { 0 } else { 4 }) -Details ($outcome.Details -join ' | ')

Write-Output ("{0} {1}: {2}" -f $verb, $ActionId, $result)
foreach ($d in $outcome.Details) { Write-Output ("  - " + $d) }
if (-not $outcome.Ok) {
    Write-Output 'DETENERSE: la validacion no confirma el resultado esperado. No ejecutar mas acciones.'
    Write-Output ("Reversion propuesta (requiere aprobacion explicita): {0}" -f $def.Rollback)
    exit 4
}
exit 0

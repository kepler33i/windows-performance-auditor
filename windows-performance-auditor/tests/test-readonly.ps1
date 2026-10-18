#Requires -Version 5.1
<#
.SYNOPSIS
  Pruebas no destructivas de windows-performance-auditor.

.DESCRIPTION
  - Solo datos simulados. NO ejecuta collect-baseline.ps1 ni hardware-health.ps1
    contra el equipo anfitrion.
  - apply-approved-action.ps1 se prueba por rechazos y simulaciones (sin -Apply).
    Los unicos caminos con -Apply se ejecutan con WPA_NO_EXECUTE=1 y solo si el
    objetivo coincide con el estado actual del equipo (cambio nulo aun si el
    guardia fallara).
  - Escribe solo en %LOCALAPPDATA%\Temp\wpa-test-<guid>, que se elimina al final
    salvo -KeepArtifacts.
#>
[CmdletBinding()]
param([switch]$KeepArtifacts, [switch]$SyntaxOnly)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$env:WPA_NO_EXECUTE = '1'

$skillRoot = Split-Path $PSScriptRoot -Parent
$scripts = Join-Path $skillRoot 'scripts'
$script:pass = 0; $script:fail = 0; $script:skip = 0
$script:failures = New-Object System.Collections.ArrayList
$script:skips = New-Object System.Collections.ArrayList

function Assert {
    param([string]$Name, [bool]$Condition, [string]$Info = '')
    if ($Condition) { $script:pass++; Write-Host ("  [PASS] " + $Name) }
    else { $script:fail++; [void]$script:failures.Add("$Name $Info"); Write-Host ("  [FAIL] " + $Name + " " + $Info) -ForegroundColor Red }
}
function Skip { param([string]$Name, [string]$Why) $script:skip++; [void]$script:skips.Add("$Name - $Why"); Write-Host ("  [SKIP] {0} - {1}" -f $Name, $Why) -ForegroundColor Yellow }
function Section { param([string]$T) Write-Host ""; Write-Host ("== " + $T) -ForegroundColor Cyan }

$scriptFiles = @(Get-ChildItem -LiteralPath $scripts -Filter '*.ps1' -File -Recurse)
$allPs1 = $scriptFiles + @(Get-Item -LiteralPath $PSCommandPath)

# ---------------------------------------------------------------------------
Section 'Estructura'
foreach ($rel in @('SKILL.md', 'scripts\identify-system.ps1', 'scripts\collect-baseline.ps1', 'scripts\analyze-performance.ps1', 'scripts\hardware-health.ps1',
                   'scripts\propose-actions.ps1', 'scripts\apply-approved-action.ps1', 'scripts\validate-results.ps1',
                   'scripts\service-report.ps1', 'scripts\common.ps1', 'scripts\lib\core.ps1', 'scripts\lib\plan.ps1',
                   'scripts\lib\catalog.ps1', 'scripts\lib\inventory.ps1',
                   'references\safety-policy.md', 'references\risk-matrix.md', 'references\hardware-limitations.md',
                   'references\diagnostic-rules.md', 'references\optimization-profiles.md', 'references\uninstall-policy.md',
                   'assets\report-template.html', 'assets\service-report-template.html',
                   'tests\test-readonly.ps1', 'tests\prompts.json')) {
    Assert ("existe " + $rel) (Test-Path -LiteralPath (Join-Path $skillRoot $rel))
}

# ---------------------------------------------------------------------------
Section ('Sintaxis (PowerShell {0})' -f $PSVersionTable.PSVersion)
foreach ($f in $allPs1) {
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
    Assert ("sin errores de sintaxis: " + $f.Name) (@($errors).Count -eq 0) (($errors | ForEach-Object { $_.Message }) -join '; ')
    $nonAscii = @([IO.File]::ReadAllBytes($f.FullName) | Where-Object { $_ -gt 127 }).Count
    Assert ("solo ASCII (compatibilidad 5.1): " + $f.Name) ($nonAscii -eq 0) ("bytes no ASCII: $nonAscii")
}
if ($SyntaxOnly) {
    Write-Host ("RESULTADO SINTAXIS: {0} aprobadas, {1} fallidas" -f $script:pass, $script:fail)
    if ($script:fail -gt 0) { exit 1 } else { exit 0 }
}
$pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
if ($pwsh -and $PSVersionTable.PSVersion.Major -lt 6) {
    $out = & $pwsh.Source -NoProfile -NonInteractive -File $PSCommandPath -SyntaxOnly 2>&1
    Assert 'sintaxis valida en PowerShell 7' ($LASTEXITCODE -eq 0) (($out | Select-Object -Last 3) -join ' ')
} elseif (-not $pwsh) { Skip 'sintaxis en PowerShell 7' 'pwsh no esta instalado (no se instala para pruebas)' }

# ---------------------------------------------------------------------------
Section 'Analisis estatico de seguridad'
function Get-Ast { param([string]$Path) return [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null) }
function Get-CommandNames {
    param([string]$Path)
    return @((Get-Ast $Path).FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
}

$forbiddenCommands = @(
    'Invoke-Expression', 'iex', 'Set-ExecutionPolicy', 'Invoke-WebRequest', 'iwr', 'Invoke-RestMethod', 'irm', 'curl', 'wget',
    'Start-BitsTransfer', 'Install-Module', 'Install-Package', 'Install-Script', 'Register-PSRepository', 'Save-Module',
    'Stop-Service', 'Suspend-Service', 'Unregister-ScheduledTask', 'Set-ScheduledTask',
    'Set-MpPreference', 'Add-MpPreference', 'Remove-MpPreference', 'Set-NetFirewallProfile', 'Disable-NetFirewallRule',
    'New-NetFirewallRule', 'Remove-NetFirewallRule', 'Format-Volume', 'Clear-Disk', 'Initialize-Disk', 'Remove-Partition',
    'Disable-ComputerRestore', 'Enable-ComputerRestore', 'Restart-Computer', 'Stop-Computer', 'Stop-Process', 'Start-Process',
    'Set-CimInstance', 'Invoke-CimMethod', 'Remove-CimInstance', 'Invoke-WmiMethod', 'Set-WmiInstance', 'Remove-WmiObject',
    'takeown', 'takeown.exe', 'icacls', 'icacls.exe', 'bcdedit', 'bcdedit.exe', 'reg', 'reg.exe', 'wmic', 'wmic.exe',
    'winget', 'winget.exe', 'choco', 'msiexec', 'msiexec.exe', 'Set-Acl', 'Disable-BitLocker', 'Suspend-BitLocker', 'Remove-AppxPackage',
    'Remove-AppxProvisionedPackage', 'Disable-WindowsOptionalFeature', 'netsh', 'netsh.exe', 'cipher', 'del', 'rd', 'rmdir', 'erase',
    'Set-MpComputerStatus', 'Disable-WindowsErrorReporting'
)
$mutatingCommands = @('Set-ItemProperty', 'Remove-ItemProperty', 'New-ItemProperty', 'Remove-Item', 'Checkpoint-Computer', 'Move-Item',
    'Rename-Item', 'New-Item', 'Copy-Item', 'Set-Content', 'Add-Content', 'Out-File', 'Clear-Content', 'Clear-Item', 'Set-Item',
    'Disable-ScheduledTask', 'Enable-ScheduledTask', 'Set-Service', 'Optimize-Volume', 'Start-MpScan', 'Update-MpSignature',
    'Delete-DeliveryOptimizationCache')

foreach ($f in $scriptFiles) {
    $names = Get-CommandNames $f.FullName
    $bad = @($names | Where-Object { $forbiddenCommands -contains $_ })
    Assert ("sin comandos prohibidos: " + $f.Name) ($bad.Count -eq 0) ($bad -join ', ')
    if ($f.Name -ne 'apply-approved-action.ps1') {
        $mut = @($names | Where-Object { $mutatingCommands -contains $_ })
        Assert ("solo lectura (sin comandos que modifiquen): " + $f.Name) ($mut.Count -eq 0) ($mut -join ', ')
    }
    $text = [IO.File]::ReadAllText($f.FullName)
    $patterns = [ordered]@{
        'codigo codificado/ofuscado' = '(?i)-EncodedCommand|FromBase64String|\s-enc\s|-e\s+[A-Za-z0-9+/=]{20,}'
        'descargas'                  = '(?i)DownloadString|DownloadFile|Net\.WebClient|System\.Net\.Http|Invoke-WebRequest|Start-BitsTransfer|https?://'
        'red directa'                = '(?i)Test-Connection|Test-NetConnection|Resolve-DnsName|Net\.Sockets'
        'pipe a iex'                 = '(?i)\|\s*(iex|Invoke-Expression)\b'
        'scriptblock dinamico'       = '(?i)\[scriptblock\]::Create|NewScriptBlock|AddScript\('
        'paginacion'                 = '(?i)PageFileSetting.*(Delete|Put)|AutomaticManagedPagefile\s*=\s*\$false'
        'Remove-Item recursivo'      = '(?i)Remove-Item[^\r\n]*-Recurse'
        'borrado .NET de carpetas'   = '(?i)Directory\]::Delete'
        'autoelevacion'              = '(?i)-Verb\s+RunAs'
    }
    foreach ($k in $patterns.Keys) { Assert ("sin {0}: {1}" -f $k, $f.Name) (-not ($text -match $patterns[$k])) }
    if ($f.Name -ne 'core.ps1') {
        Assert ("escrituras .NET solo via lib/core.ps1: " + $f.Name) (-not ($text -match '(?i)\]::(WriteAllText|AppendAllText|WriteAllBytes|Delete|Move)\('))
    }
}
$applyPath = Join-Path $scripts 'apply-approved-action.ps1'
$applyAst = Get-Ast $applyPath
foreach ($c in @($applyAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Remove-Item' }, $true))) {
    $t = $c.Extent.Text
    Assert ("Remove-Item usa -LiteralPath sin -Recurse: " + $t) (($t -match '-LiteralPath') -and ($t -notmatch '(?i)-Recurse') -and ($t -notmatch '[\*\?]'))
}
$allowedNative = @('$def.Exe', '$uninstallExe', '$wingetExe')
foreach ($n in @($applyAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq 'Ampersand' }, $true))) {
    Assert ("apply invoca solo ejecutables validados: " + $n.Extent.Text) ($allowedNative -contains $n.CommandElements[0].Extent.Text)
}
$catText = [IO.File]::ReadAllText((Join-Path $scripts 'lib\catalog.ps1'))
foreach ($m in [regex]::Matches($catText, '&\s*\$exe[^\r\n]*')) {
    Assert ("catalog invoca powercfg solo para consultar: " + $m.Value) ($m.Value -match '/getactivescheme|/list')
}
foreach ($n in @('collect-baseline.ps1', 'hardware-health.ps1', 'analyze-performance.ps1', 'validate-results.ps1', 'service-report.ps1', 'propose-actions.ps1')) {
    $t = [IO.File]::ReadAllText((Join-Path $scripts $n))
    Assert ("sin cambios de energia ni ejecucion de winget: " + $n) (-not ($t -match '(?i)/setactive|/change|/hibernate|/delete|/import|setacvalueindex|&\s*\$winget'))
}
$applyParams = $applyAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }
Assert 'apply no tiene parametros de comando/script' (-not (@($applyParams) | Where-Object { $_ -match '(?i)command|script|expression|code|exe' }))
Assert 'apply valida formato de un unico ActionId' ([IO.File]::ReadAllText($applyPath) -match [regex]::Escape('''^A-[0-9a-f]{8}-\d{3}$'''))

# ---------------------------------------------------------------------------
Section 'Rutas, sanitizacion y MDM'
. (Join-Path $scripts 'common.ps1')
$rejects = @('', 'C:\', 'C:', 'C:\*', 'C:\Temp\*.tmp', 'C:\Users\%USERNAME%\x.txt', 'C:\$env:TEMP\x', '..\x', 'relative\x',
             '\\server\share\x', '\\?\C:\x', 'C:\Windows\..\x', 'C:\a\file.txt:ads', 'C:\PROGRA~1\x', 'C:\a\b?.txt',
             'C:/Windows/x', 'C:\a\\b', 'C:\a\CON', 'C:\a\b. ')
foreach ($r in $rejects) { Assert ("rechaza ruta '{0}'" -f $r) (-not (Test-WpaPathSyntax $r).Ok) }
Assert 'acepta ruta absoluta exacta' ((Test-WpaPathSyntax 'C:\Users\Someone\AppData\Local\Temp\old.tmp').Ok)
if (Test-Path -LiteralPath 'C:\Documents and Settings') { Assert 'rechaza junction (C:\Documents and Settings)' (-not (Test-WpaNoReparseChain 'C:\Documents and Settings').Ok) }
else { Skip 'junction' 'C:\Documents and Settings no existe' }
Assert 'MDM: Intune cuenta como administrado' (Test-WpaMdmProvider 'MS DM Server')
Assert 'MDM: proveedor desconocido cuenta como administrado' (Test-WpaMdmProvider 'Contoso MDM')
Assert 'MDM: autoridades integradas de Windows no cuentan' (-not ((Test-WpaMdmProvider 'Deploy Authority') -or (Test-WpaMdmProvider 'Cloud Authority') -or (Test-WpaMdmProvider 'Local Authority') -or (Test-WpaMdmProvider '')))
Assert 'detecta OneDrive por segmento' (Test-WpaInSyncRoot 'C:\Users\x\OneDrive\doc.txt')
Assert 'detecta OneDrive empresarial' (Test-WpaInSyncRoot 'C:\Users\x\OneDrive - Contoso\doc.txt')
foreach ($bad in @('C:\', $env:SystemRoot, (Join-Path $env:SystemRoot 'Temp'), $env:USERPROFILE, (Join-Path $env:USERPROFILE 'Documents'), 'C:\no-existe-wpa-xyz')) {
    $threw = $false; try { [void](Assert-WpaOutputDir $bad) } catch { $threw = $true }
    Assert ("OutputDir rechazado: " + $bad) $threw
}
$san = ConvertTo-WpaSanitizedText ("C:\Users\{0}\x on {1} ip 203.0.113.50 lan 192.168.1.10 mail a.b@example.com S-1-5-21-1-2-3-1001" -f $env:USERNAME, $env:COMPUTERNAME)
Assert 'sanitiza usuario' ($san -notmatch [regex]::Escape($env:USERNAME))
Assert 'sanitiza equipo' ($san -notmatch [regex]::Escape($env:COMPUTERNAME))
Assert 'sanitiza IP publica y conserva privada' (($san -notmatch '203\.0\.113\.50') -and ($san -match '192\.168\.1\.10'))
Assert 'sanitiza correo y SID' (($san -notmatch 'example\.com') -and ($san -notmatch 'S-1-5-21-1-2-3'))
$sj = ConvertTo-WpaSanitizedJson '{"SerialNumber":"ABC123XYZ","DomainName":"corp.contoso.com","TenantIds":"x","Name":"ok"}'
Assert 'redacta seriales y dominio en JSON' (($sj -notmatch 'ABC123XYZ') -and ($sj -notmatch 'contoso') -and ($sj -match '"Name":"ok"'))

# ---------------------------------------------------------------------------
Section 'Catalogo (allowlist)'
$cat = Get-WpaActionCatalog
foreach ($k in $cat.Keys) {
    $a = $cat[$k]
    $missing = @('Title', 'Benefit', 'Affects', 'Backup', 'Rollback', 'Validation', 'Risk') | Where-Object { [string]::IsNullOrWhiteSpace([string]$a.$_) }
    Assert ("{0}: campos completos" -f $k) (@($missing).Count -eq 0) (@($missing) -join ',')
    Assert ("{0}: riesgo valido (sin 'High' automatizado)" -f $k) ($a.Risk -in @('Low', 'Medium'))
    if ($a.Modifies -and -not $a.RollbackReliable) { Assert ("{0}: sin reversion => riesgo medio" -f $k) ($a.Risk -eq 'Medium') }
    if ($a.RequiresRestorePoint) { Assert ("{0}: punto de restauracion => riesgo medio" -f $k) ($a.Risk -eq 'Medium') }
}
Assert 'catalogo no incluye VERIFY-DISM-SCANHEALTH (eliminado)' (-not $cat.Contains('VERIFY-DISM-SCANHEALTH'))
Assert 'catalogo no incluye borrado de temporales por archivo (eliminado)' (-not $cat.Contains('CLEAN-USER-TEMP-FILES'))
Assert 'APP-UNINSTALL exige punto de restauracion' ($cat['APP-UNINSTALL'].RequiresRestorePoint)
foreach ($t in @('CLEANUP-USER-TEMP', 'CLEANUP-WINDOWS-TEMP', 'CLEANUP-WER')) {
    $roots = @(Get-WpaCleanupRoots $t)
    Assert ("{0}: raices fijas y validas" -f $t) ($roots.Count -ge 1 -and @($roots | Where-Object { -not (Test-WpaPathSyntax $_).Ok }).Count -eq 0) ($roots -join ';')
}
Assert 'paquete excluye acciones con red' (-not (Test-WpaBundleEligible ([pscustomobject]@{ Risk = 'Low'; Network = $true; RollbackReliable = $true; RequiresRestorePoint = $false })))
Assert 'paquete excluye riesgo medio' (-not (Test-WpaBundleEligible ([pscustomobject]@{ Risk = 'Medium'; Network = $false; RollbackReliable = $true; RequiresRestorePoint = $false })))
Assert 'paquete acepta bajo, sin red y reversible' (Test-WpaBundleEligible ([pscustomobject]@{ Risk = 'Low'; Network = $false; RollbackReliable = $true; RequiresRestorePoint = $false }))

# ---------------------------------------------------------------------------
Section 'Aprobaciones explicitas y paquetes (prompts.json)'
$prompts = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'prompts.json')) | ConvertFrom-Json
$map = @{ A1 = 'A-deadbeef-001'; A2 = 'A-deadbeef-002'; M1 = 'A-deadbeef-003'; N1 = 'A-deadbeef-004'; B1 = 'P-deadbeef-01' }
$mockActions = @(
    [pscustomobject]@{ ActionId = $map.A1; Risk = 'Low'; Network = $false; RollbackReliable = $true; RequiresRestorePoint = $false },
    [pscustomobject]@{ ActionId = $map.A2; Risk = 'Low'; Network = $false; RollbackReliable = $true; RequiresRestorePoint = $false },
    [pscustomobject]@{ ActionId = $map.M1; Risk = 'Medium'; Network = $false; RollbackReliable = $false; RequiresRestorePoint = $false },
    [pscustomobject]@{ ActionId = $map.N1; Risk = 'Low'; Network = $true; RollbackReliable = $true; RequiresRestorePoint = $false }
)
$mockBundles = @([pscustomobject]@{ BundleId = $map.B1; ActionIds = @($map.A1, $map.A2, $map.M1, $map.N1) })
foreach ($c in $prompts.approval_cases) {
    $text = [string]$c.text
    foreach ($k in $map.Keys) { $text = $text -replace ('\b' + $k + '\b'), $map[$k] }
    $got = @(Get-WpaExplicitApprovals -Text $text -Actions $mockActions -Bundles $mockBundles | Where-Object { $_.Approved } | ForEach-Object { $_.ActionId } | Sort-Object)
    $exp = @(@($c.approved) | ForEach-Object { $map[[string]$_] } | Sort-Object)
    Assert ("{0}: '{1}' aprueba [{2}]" -f $c.id, $c.text, (@($c.approved) -join ',')) ((@($got) -join ',') -eq (@($exp) -join ',')) ("obtenido: " + (@($got) -join ','))
}
Assert 'prompts: >= 8 de activacion' (@($prompts.activation).Count -ge 8)
Assert 'prompts: >= 5 de no activacion' (@($prompts.non_activation).Count -ge 5)
Assert 'prompts: >= 15 casos limite' (@($prompts.edge_cases).Count -ge 15)
Assert 'prompts: toda activacion espera audit-only' (@($prompts.activation | Where-Object { $_.expectedMode -ne 'audit-only' }).Count -eq 0)
Assert 'prompts: no activacion espera expectTrigger=false' (@($prompts.non_activation | Where-Object { $_.expectTrigger -ne $false }).Count -eq 0)

# ---------------------------------------------------------------------------
Section 'Autorizacion corporativa'
$auth = [pscustomobject]@{ Organization = 'Contoso'; AllowedDomains = @('corp.contoso.com'); AllowedTenantIds = @('11111111-2222-3333-4444-555555555555')
    Technician = 'tec01'; Ticket = 'INC-100'; ValidUntil = '2099-12-31'; AllowedActionTypes = @('POWER-SET-SCHEME', 'APP-UNINSTALL') }
$ctxDom = [pscustomobject]@{ DomainName = 'CORP.contoso.com'; TenantIds = @() }
$ctxTen = [pscustomobject]@{ DomainName = ''; TenantIds = @('11111111-2222-3333-4444-555555555555') }
$ctxOther = [pscustomobject]@{ DomainName = 'otra.com'; TenantIds = @() }
Assert 'autorizacion valida por dominio' ((Test-WpaOrgAuthorizationData -Auth $auth -DeviceContext $ctxDom -ActionType 'POWER-SET-SCHEME' -Ticket 'INC-100').Ok)
Assert 'autorizacion valida por tenant' ((Test-WpaOrgAuthorizationData -Auth $auth -DeviceContext $ctxTen -ActionType 'APP-UNINSTALL' -Ticket 'INC-100').Ok)
Assert 'rechaza dominio no autorizado' (-not (Test-WpaOrgAuthorizationData -Auth $auth -DeviceContext $ctxOther -ActionType 'POWER-SET-SCHEME' -Ticket 'INC-100').Ok)
Assert 'rechaza ticket distinto' (-not (Test-WpaOrgAuthorizationData -Auth $auth -DeviceContext $ctxDom -ActionType 'POWER-SET-SCHEME' -Ticket 'INC-999').Ok)
Assert 'rechaza tipo no permitido' (-not (Test-WpaOrgAuthorizationData -Auth $auth -DeviceContext $ctxDom -ActionType 'CLEANUP-WER' -Ticket 'INC-100').Ok)
$expired = $auth.PSObject.Copy(); $expired.ValidUntil = '2020-01-01'
Assert 'rechaza autorizacion expirada' (-not (Test-WpaOrgAuthorizationData -Auth $expired -DeviceContext $ctxDom -ActionType 'POWER-SET-SCHEME' -Ticket 'INC-100').Ok)

# ---------------------------------------------------------------------------
Section 'SKILL.md y referencias'
$skillMd = [IO.File]::ReadAllText((Join-Path $skillRoot 'SKILL.md'))
$fm = [regex]::Match($skillMd, '(?s)^---\r?\n(.*?)\r?\n---')
Assert 'frontmatter presente' $fm.Success
$nameLine = [regex]::Match($fm.Groups[1].Value, '(?m)^name:\s*(.+)$').Groups[1].Value.Trim()
$descLine = [regex]::Match($fm.Groups[1].Value, '(?m)^description:\s*(.+)$').Groups[1].Value.Trim()
Assert 'name coincide con la carpeta y es kebab-case' (($nameLine -eq (Split-Path $skillRoot -Leaf)) -and ($nameLine -match '^[a-z0-9-]{1,64}$'))
Assert 'description presente y <= 1024 caracteres' ($descLine.Length -gt 50 -and $descLine.Length -le 1024) ("largo: " + $descLine.Length)
Assert 'SKILL.md declara audit-only y que optimizar no es autorizacion' (($skillMd -match 'audit-only') -and ($skillMd -match '(?i)optimiza mi computador'))
foreach ($s in @('identify-system.ps1', 'collect-baseline.ps1', 'hardware-health.ps1', 'analyze-performance.ps1', 'propose-actions.ps1', 'apply-approved-action.ps1', 'validate-results.ps1', 'service-report.ps1',
                 'uninstall-policy.md', 'optimization-profiles.md', 'safety-policy.md')) {
    Assert ("SKILL.md referencia " + $s) ($skillMd -match [regex]::Escape($s))
}
foreach ($k in (Get-WpaActionCatalog).Keys) {
    Assert ("tipo documentado en SKILL.md y risk-matrix: " + $k) (($skillMd -match [regex]::Escape(($k -split '-')[0])) -and ([IO.File]::ReadAllText((Join-Path $skillRoot 'references\risk-matrix.md')) -match [regex]::Escape($k)))
}
$rulesMd = [IO.File]::ReadAllText((Join-Path $skillRoot 'references\diagnostic-rules.md'))
$analyzeText = [IO.File]::ReadAllText((Join-Path $scripts 'analyze-performance.ps1'))
foreach ($r in @([regex]::Matches($analyzeText, "-RuleId '([A-Z0-9-]+)'") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)) {
    Assert ("regla documentada: " + $r) ($rulesMd -match ('\|\s*' + [regex]::Escape($r) + '\s*\|'))
}

# ---------------------------------------------------------------------------
Section 'Identificacion del equipo y plan de diagnostico'
Assert 'tipo de equipo: portatil por bateria o chasis' (((Get-WpaFormFactor -ChassisTypes @(10)) -eq 'portatil') -and ((Get-WpaFormFactor -HasBattery $true) -eq 'portatil') -and ((Get-WpaFormFactor -ChassisTypes @(3)) -eq 'escritorio') -and ((Get-WpaFormFactor) -eq 'desconocido'))
Assert 'ampliacion de RAM: ranuras libres / ocupadas / no determinables' (((Get-WpaRamUpgradeHint 2 1) -match '1 de 2 ranuras') -and ((Get-WpaRamUpgradeHint 2 2) -match 'ocupadas') -and ((Get-WpaRamUpgradeHint $null 1) -match 'no determinables'))
$idLow = [pscustomobject]@{
    System = [pscustomobject]@{ Manufacturer = 'Contoso'; Model = 'Laptop 14' }
    Os = [pscustomobject]@{ Caption = 'Microsoft Windows 11 Home'; DisplayVersion = '24H2'; Build = '26100'; InstallDate = '2024-01-01' }
    Bios = [pscustomobject]@{ Manufacturer = 'Contoso'; Version = '1.0'; ReleaseDate = '2020-01-01'; AgeYears = 6.8 }
    Cpu = [pscustomobject]@{ Name = 'CPU de prueba'; Cores = 2; LogicalProcessors = 4; MaxClockMHz = 2400 }
    Memory = [pscustomobject]@{ TotalGB = 4; Modules = @([pscustomobject]@{ CapacityGB = 4; SpeedMHz = 2400 }); UpgradeHint = (Get-WpaRamUpgradeHint 2 1) }
    Gpu = @([pscustomobject]@{ Name = 'GPU integrada'; DriverVersion = '1.0'; DriverDate = '2023-01' })
    Disks = @([pscustomobject]@{ DeviceId = '0'; FriendlyName = 'Intel Optane+1TBHDD'; Class = 'HDD-Optane'; SizeGB = 1000; HealthStatus = 'Healthy'; IsSystem = $true })
    SystemVolume = [pscustomobject]@{ SizeGB = 930; FreeGB = 80; FreePercent = 8.6 }
    Battery = [pscustomobject]@{ Present = $true; Health = $null }
    Context = [pscustomobject]@{ IsManaged = $false; IsAdmin = $false }
    Profile = [pscustomobject]@{ StorageClass = 'HDD-Optane'; IsMechanical = $true; RamTier = 'bajo'; CpuTier = 'bajo'; FormFactor = 'portatil'; GpuClass = 'integrada'; LowEnd = $true }
}
$planLow = Get-WpaDiagnosticPlan -Identity $idLow
Assert 'plan: portatil -> informe de bateria' (@($planLow.HardwareArgs) -contains '-IncludeBatteryReport')
Assert 'plan: RAM baja -> observacion de fugas' (@($planLow.CollectArgs) -contains '-LeakWatchMinutes 10')
Assert 'plan: disco mecanico, BIOS antigua y poco espacio en foco' ((@($planLow.Focus) -join ' ') -match 'mecanico' -and (@($planLow.Focus) -join ' ') -match 'BIOS' -and (@($planLow.Focus) -join ' ') -match 'espacio')
Assert 'plan: sin administrador avisa que datos faltaran' ((@($planLow.Notes) -join ' ') -match 'Sin administrador')
Assert 'plan: inventario de programas solo con consentimiento' ((@($planLow.CollectArgs) -join ' ') -match 'consentimiento')
$sumLow = @(Format-WpaSystemSummary -Identity $idLow)
Assert 'resumen identifica equipo, BIOS, RAM con ranuras, disco y perfil' (($sumLow -join "`n") -match 'EQUIPO +Contoso Laptop 14' -and ($sumLow -join "`n") -match 'BIOS' -and ($sumLow -join "`n") -match '1 de 2 ranuras' -and ($sumLow -join "`n") -match 'HDD-Optane' -and ($sumLow -join "`n") -match 'GAMA BAJA')
$idHigh = [pscustomobject]@{ Profile = [pscustomobject]@{ StorageClass = 'NVMe'; IsMechanical = $false; RamTier = 'alto'; CpuTier = 'alto'; FormFactor = 'escritorio' }; Context = [pscustomobject]@{ IsManaged = $false; IsAdmin = $true }; Bios = [pscustomobject]@{ AgeYears = 1 } }
$planHigh = Get-WpaDiagnosticPlan -Identity $idHigh
Assert 'plan gama alta: sin observacion de fugas ni bateria, foco en programas' ((@($planHigh.CollectArgs) -notcontains '-LeakWatchMinutes 10') -and (@($planHigh.HardwareArgs).Count -eq 0) -and ((@($planHigh.Focus) -join ' ') -match 'SSD'))

# ---------------------------------------------------------------------------
Section 'Perfil de hardware'
$pLow = Get-WpaHardwareProfile -Baseline ([pscustomobject]@{ SystemDiskNumber = '0'; Disks = @([pscustomobject]@{ DeviceId = '0'; MediaType = 'HDD'; BusType = 'SATA' }); OS = [pscustomobject]@{ TotalRamGB = 4 }; CPU = [pscustomobject]@{ LogicalProcessors = 2 }; Computer = [pscustomobject]@{ FormFactor = 'portatil' }; GPU = @([pscustomobject]@{ Name = 'Intel UHD Graphics' }) })
Assert 'gama baja: HDD, RAM baja, CPU baja, portatil' ($pLow.LowEnd -and $pLow.StorageClass -eq 'HDD' -and $pLow.RamTier -eq 'bajo' -and $pLow.CpuTier -eq 'bajo' -and $pLow.GpuClass -eq 'integrada')
Assert 'estrategia HDD recomienda SSD' (@($pLow.Strategy | Where-Object { $_ -match 'SSD' }).Count -ge 1)
$pHigh = Get-WpaHardwareProfile -Baseline ([pscustomobject]@{ SystemDiskNumber = '1'; Disks = @([pscustomobject]@{ DeviceId = '1'; MediaType = 'SSD'; BusType = 'NVMe' }); OS = [pscustomobject]@{ TotalRamGB = 32 }; CPU = [pscustomobject]@{ LogicalProcessors = 16 }; Computer = [pscustomobject]@{ FormFactor = 'escritorio' }; GPU = @([pscustomobject]@{ Name = 'NVIDIA GeForce RTX 4070' }) })
Assert 'gama alta: NVMe, sin LowEnd, GPU dedicada' ((-not $pHigh.LowEnd) -and $pHigh.StorageClass -eq 'NVMe' -and $pHigh.GpuClass -eq 'dedicada')
Assert 'estrategia SSD nunca desfragmenta' (@($pHigh.Strategy | Where-Object { $_ -match 'nunca desfragmentar' }).Count -ge 1)

# ---------------------------------------------------------------------------
Section 'Segundo plano, fugas de memoria y punto de restauracion reciente'
Assert 'PFN desde carpeta de WindowsApps' ((ConvertTo-WpaPackageFamilyName 'Microsoft.YourPhone_1.0.0.0_x64__8wekyb3d8bbwe') -eq 'Microsoft.YourPhone_8wekyb3d8bbwe')
Assert 'PFN desde ruta de proceso' ((ConvertFrom-WpaWindowsAppsPath 'C:\Program Files\WindowsApps\Microsoft.YourPhone_1.0.0.0_x64__8wekyb3d8bbwe\PhoneExperienceHost.exe') -eq 'Microsoft.YourPhone_8wekyb3d8bbwe')
Assert 'ruta fuera de WindowsApps: sin PFN' ($null -eq (ConvertFrom-WpaWindowsAppsPath 'C:\Windows\explorer.exe'))
Assert 'PFN invalido rechazado' (($null -eq (ConvertTo-WpaPackageFamilyName '..\evil')) -and -not (Test-WpaPackageFamilyName 'a*b_8wekyb3d8bbwe'))
Assert 'paquetes del sistema y controladores protegidos' (('MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy' -match $script:WpaProtectedPackagePattern) -and ('AppUp.IntelArcSoftware_8j3eq9eme6ctt' -match $script:WpaProtectedPackagePattern))
Assert 'app de usuario no protegida' ('Microsoft.YourPhone_8wekyb3d8bbwe' -notmatch $script:WpaProtectedPackagePattern)
Assert 'fuga: crecimiento sostenido detectado' (Test-WpaLeakSuspect -Samples @(500, 560, 630, 700, 760, 830) -Minutes 10)
Assert 'fuga: oscilacion normal no detectada' (-not (Test-WpaLeakSuspect -Samples @(500, 900, 450, 950, 480, 720) -Minutes 10))
Assert 'fuga: crecimiento pequeno no detectado' (-not (Test-WpaLeakSuspect -Samples @(500, 510, 520, 530, 540) -Minutes 10))
$nowR = Get-WpaUnixNow
$pts = @([pscustomobject]@{ Seq = 216; Description = 'Visual C++'; Unix = ($nowR - 3600) })
Assert 'punto reciente aceptado si no hubo cambios previos' ((Test-WpaRestorePointEvidence -Points $pts -Description 'WPA x' -StartedUnix $nowR -AllowRecent $true).Reused)
Assert 'punto reciente rechazado si hubo cambios previos' (-not (Test-WpaRestorePointEvidence -Points $pts -Description 'WPA x' -StartedUnix $nowR -AllowRecent $false).Ok)
Assert 'punto de mas de 24 h rechazado' (-not (Test-WpaRestorePointEvidence -Points @([pscustomobject]@{ Seq = 1; Description = 'viejo'; Unix = ($nowR - 90000) }) -Description 'WPA x' -StartedUnix $nowR -AllowRecent $true).Ok)
Assert 'punto nuevo verificado' ((Test-WpaRestorePointEvidence -Points @([pscustomobject]@{ Seq = 217; Description = 'WPA x'; Unix = $nowR }) -Description 'WPA x' -StartedUnix $nowR -AllowRecent $false).Ok)

# ---------------------------------------------------------------------------
Section 'winget (interpretacion de tabla)'
$es = @('   - ', 'Nombre                Id                        Version      Disponible   Origen', '------------------------------------------------------------------------------',
        'Mozilla Firefox (x64) Mozilla.Firefox           118.0        119.0        winget', '7-Zip 22.01            7zip.7zip                 22.01        23.01        winget',
        'Basura                 id con espacios          1            2            winget', '2 actualizaciones disponibles.')
$rows = @(ConvertFrom-WpaWingetTable $es)
Assert 'winget ES: 2 filas validas' ($rows.Count -eq 2) (($rows | ForEach-Object { $_.Id }) -join ',')
Assert 'winget ES: Id y versiones correctos' ($rows.Count -ge 1 -and $rows[0].Id -eq 'Mozilla.Firefox' -and $rows[0].Version -eq '118.0' -and $rows[0].Available -eq '119.0')
$en = @('Name         Id               Version Available Source', '------------------------------------------------------', 'Git          Git.Git          2.40.0  2.42.0    winget')
Assert 'winget EN: 1 fila' (@(ConvertFrom-WpaWingetTable $en).Count -eq 1)
Assert 'winget sin tabla: 0 filas' (@(ConvertFrom-WpaWingetTable @('No se encontraron actualizaciones.')).Count -eq 0)

# ---------------------------------------------------------------------------
Section 'Flujo con datos simulados'
$tempRoot = Get-WpaTempRoot
$work = Join-Path $tempRoot ('wpa-test-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $work)
$psExe = Join-Path $PSHOME 'powershell.exe'
if ($PSVersionTable.PSVersion.Major -ge 6) { $psExe = (Get-Process -Id $PID).Path }

function Invoke-Child {
    param([string]$Script, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $out = & $psExe -NoProfile -NonInteractive -File (Join-Path $scripts $Script) @Arguments 2>&1
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = (($out | ForEach-Object { [string]$_ }) -join "`n") }
}
function Save-Json { param([string]$Dir, [string]$Name, $Obj) $p = Join-Path $Dir $Name; [IO.File]::WriteAllText($p, ($Obj | ConvertTo-Json -Depth 12)); return $p }
function New-Dir { param([string]$Name) $d = Join-Path $work $Name; [void](New-Item -ItemType Directory -Path $d); return $d }

try {
    # --- Unidades: desinstalacion segura -------------------------------------
    Section 'Regla de desinstalacion (> 6 meses sin uso, sin romper nada)'
    $appDir = New-Dir 'FakeApp'
    $fakeUninst = Join-Path $appDir 'uninst.exe'
    [IO.File]::WriteAllText($fakeUninst, 'no ejecutable')
    $u = Resolve-WpaUninstallCommand ([pscustomobject]@{ UninstallString = ('"{0}" /S' -f $fakeUninst); InstallLocation = $appDir; KeyName = 'FakeApp' })
    Assert 'desinstalador EXE en carpeta del programa: valido' ($u.Ok -and $u.Kind -eq 'EXE' -and $u.Args -eq '/S') $u.Reason
    $u = Resolve-WpaUninstallCommand ([pscustomobject]@{ UninstallString = 'MsiExec.exe /I{12345678-1234-1234-1234-1234567890AB}'; WindowsInstaller = $true; KeyName = '{12345678-1234-1234-1234-1234567890AB}' })
    Assert 'MSI: msiexec /x {GUID} /passive /norestart' ($u.Ok -and $u.Kind -eq 'MSI' -and $u.Args -eq '/x {12345678-1234-1234-1234-1234567890AB} /passive /norestart')
    foreach ($badU in @('rundll32.exe C:\x\y.dll,Uninstall', 'cmd.exe /c del C:\x', '"C:\Windows\Temp\evil.exe" /S', ('"{0}" /S & calc' -f $fakeUninst), '"C:\Program Files\NoExiste\uninst.exe"')) {
        $r = Resolve-WpaUninstallCommand ([pscustomobject]@{ UninstallString = $badU; InstallLocation = $appDir })
        Assert ("desinstalador rechazado: " + $badU) (-not $r.Ok) $r.Reason
    }
    $nowU = Get-WpaUnixNow; $day = 86400
    $good = [pscustomobject]@{ DisplayName = 'Juego Viejo'; Publisher = 'Indie Studio'; InstallLocation = $appDir; InstallDateUnix = ($nowU - 400 * $day)
        Uninstall = [pscustomobject]@{ Ok = $true; Exe = $fakeUninst; Args = '/S'; Kind = 'EXE' }
        Usage = [pscustomobject]@{ LastUseUnix = ($nowU - 250 * $day); Evidence = 'alta'; NoRunsInCoverageDays = $null }
        Signals = [pscustomobject]@{ RunningNow = $false; HasServiceOrDriver = $false; SharedFolder = $false; StartupEnabled = $false } }
    $ctxU = [pscustomobject]@{ NowUnix = $nowU; OemManufacturer = 'LENOVO' }
    Assert 'elegible: 250 dias sin uso, evidencia alta, sin dependencias' ((Test-WpaUninstallCandidate -App $good -Context $ctxU).Eligible)
    function Copy-App { param($App, [scriptblock]$Change) $c = $App | ConvertTo-Json -Depth 5 | ConvertFrom-Json; & $Change $c; return $c }
    $cases = [ordered]@{
        'usado hace 30 dias'           = { param($c) $c.Usage.LastUseUnix = $nowU - 30 * $day }
        'uso desconocido'              = { param($c) $c.Usage.Evidence = 'desconocida'; $c.Usage.LastUseUnix = $null }
        'instalado hace 60 dias'       = { param($c) $c.InstallDateUnix = $nowU - 60 * $day }
        'runtime protegido'            = { param($c) $c.DisplayName = 'Microsoft Visual C++ 2015 Redistributable' }
        'publicado por Microsoft'      = { param($c) $c.Publisher = 'Microsoft Corporation' }
        'utilidad del fabricante'      = { param($c) $c.Publisher = 'LENOVO'; $c.DisplayName = 'Vantage Service' }
        'en ejecucion'                 = { param($c) $c.Signals.RunningNow = $true }
        'con servicio o driver'        = { param($c) $c.Signals.HasServiceOrDriver = $true }
        'carpeta compartida'           = { param($c) $c.Signals.SharedFolder = $true }
        'se inicia con Windows'        = { param($c) $c.Signals.StartupEnabled = $true }
        'sin desinstalador valido'     = { param($c) $c.Uninstall.Ok = $false }
        'sin carpeta de instalacion'   = { param($c) $c.InstallLocation = '' }
        'cobertura Prefetch < 6 meses' = { param($c) $c.Usage.LastUseUnix = $null; $c.Usage.NoRunsInCoverageDays = 90 }
        'VPN protegida'                = { param($c) $c.DisplayName = 'Contoso VPN Client' }
        'actualizado hace poco (se ejecuto)' = { param($c) $c.Usage | Add-Member -NotePropertyName RecentlyUpdated -NotePropertyValue $true -Force }
        'servidor local XAMPP'         = { param($c) $c.DisplayName = 'XAMPP 8.2.12-0'; $c.Publisher = 'Apache Friends' }
        'guarda datos del usuario'     = { param($c) $c.Signals | Add-Member -NotePropertyName HasUserData -NotePropertyValue $true -Force }
        'anclado a la barra de tareas' ={ param($c) $c.Signals | Add-Member -NotePropertyName Pinned -NotePropertyValue $true -Force }
    }
    foreach ($k in $cases.Keys) {
        $c = Copy-App $good $cases[$k]
        Assert ("no elegible: " + $k) (-not (Test-WpaUninstallCandidate -App $c -Context $ctxU).Eligible)
    }
    $dataDir = New-Dir 'AppConDatos'
    [void](New-Item -ItemType Directory -Path (Join-Path $dataDir 'htdocs'))
    [IO.File]::WriteAllText((Join-Path $dataDir 'htdocs\index.php'), 'x')
    Assert 'detecta datos del usuario en la carpeta del programa (htdocs)' (Test-WpaAppHasUserData $dataDir)
    Assert 'carpeta sin datos del usuario' (-not (Test-WpaAppHasUserData $appDir))
    $noRuns = Copy-App $good { param($c) $c.Usage.LastUseUnix = $null; $c.Usage.NoRunsInCoverageDays = 365 }
    Assert 'elegible: sin ejecuciones en 365 dias de cobertura Prefetch' ((Test-WpaUninstallCandidate -App $noRuns -Context $ctxU).Eligible)

    # --- Fixtures ----------------------------------------------------------------
    $saver = 'a1841308-3541-4fab-bc81-f71556f20b4a'; $balanced = '381b4222-f694-41f0-9685-ff5bb260df2e'
    $hkcuRun = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; $hklmRun = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    function New-Startup { param($n, $exe, $loc = $hkcuRun) [pscustomobject]@{ Name = $n; Location = $loc; Scope = $(if ($loc -like 'HKLM*') { 'Equipo' } else { 'Usuario' }); Executable = $exe; ExecutablePath = $exe; CommandHash = '0123456789abcdef'; State = 'Habilitado' } }
    $userExe = ('C:\Users\{0}\AppData\Roaming\App\app.exe' -f $env:USERNAME)
    $goodApp = [pscustomobject]@{ KeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FakeApp'; KeyName = 'FakeApp'; DisplayName = 'Juego Viejo'; DisplayVersion = '1.0'; Publisher = 'Indie Studio'
        InstallDateUnix = ($nowU - 400 * $day); InstallLocation = $appDir; EstimatedSizeMB = 850; Fingerprint = 'abcdef0123456789'
        Uninstall = [pscustomobject]@{ Ok = $true; Exe = $fakeUninst; Args = '/S'; Kind = 'EXE'; Reason = '' }
        Usage = [pscustomobject]@{ LastUseUnix = ($nowU - 300 * $day); Evidence = 'alta'; Source = 'Prefetch'; NoRunsInCoverageDays = $null }
        Signals = [pscustomobject]@{ RunningNow = $false; HasServiceOrDriver = $false; SharedFolder = $false; StartupEnabled = $false } }
    $runtimeApp = Copy-App $goodApp { param($c) $c.DisplayName = 'Microsoft Visual C++ 2019 Redistributable'; $c.KeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VC' }
    $recentApp = Copy-App $goodApp { param($c) $c.DisplayName = 'Editor Usado'; $c.Usage.LastUseUnix = $nowU - 3 * $day; $c.KeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Ed' }
    $unknownApp = Copy-App $goodApp { param($c) $c.DisplayName = 'Herramienta X'; $c.Usage.Evidence = 'desconocida'; $c.Usage.LastUseUnix = $null; $c.KeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\X' }

    $stressed = [ordered]@{
        SchemaVersion = 1; Mode = 'audit-only'; CollectedUnix = $nowU
        OS = @{ Caption = 'Microsoft Windows 11 Home'; Build = '26200'; TotalRamGB = 8; FreeRamGB = 0.4; UptimeHours = 300 }
        Device = @{ IsManaged = $false; ManagedReasons = @() }
        Computer = @{ Manufacturer = 'Contoso'; Model = 'Desktop 500'; FormFactor = 'escritorio' }
        Bios = @{ Manufacturer = 'Contoso'; Version = '1.02'; ReleaseDate = '2019-05-01'; AgeYears = 7.5 }
        CPU = @{ Name = 'Fake CPU 4C'; Cores = 2; LogicalProcessors = 4 }
        GPU = @(@{ Name = 'Intel UHD Graphics' })
        Memory = @{ AvailableGB = 0.5; CommittedGB = 13; CommitLimitGB = 14; CommitPercent = 93; PagesPerSec = 1500 }
        PageFile = @{ AutomaticManaged = $true; Present = $true }
        Sampling = @{ SampleSeconds = 10; CpuAvgPercent = 85; CpuMaxPercent = 100; PercentOfMaxFrequencyAvg = 45; DiskQueueAvg = 3; DiskTimeAvgPercent = 95
                      TopByCpu = @(@{ Name = 'Teams'; CpuPercent = 40; Count = 5 }); TopByMemory = @(@{ Name = 'chrome'; PrivateMB = 3000; Count = 25 }) }
        Disks = @(@{ DeviceId = '0'; FriendlyName = 'Fake HDD 500'; MediaType = 'HDD'; BusType = 'SATA'; SizeGB = 465; HealthStatus = 'Healthy' })
        SystemDiskNumber = '0'
        Volumes = @(@{ DriveLetter = 'C:'; SizeGB = 465; FreeGB = 20; FreePercent = 4.3; IsSystem = $true })
        Startup = @((New-Startup 'Spotify' $userExe), (New-Startup 'Discord' $userExe), (New-Startup 'OneDrive' 'OneDrive.exe'),
                    (New-Startup 'SecurityHealth' 'SecurityHealthSystray.exe' $hklmRun), (New-Startup 'Steam' $userExe), (New-Startup 'Zoom' $userExe),
                    (New-Startup 'Slack' $userExe), (New-Startup 'VendorTray' 'C:\Program Files\Vendor\tray.exe' $hklmRun), (New-Startup 'Updater' $userExe))
        ScheduledTasks = @{ Total = 200; NonMicrosoftEnabled = 30 }
        Security = @{ Defender = @{ RealTimeProtectionEnabled = $true; QuickScanAgeDays = 30; SignatureAgeDays = 2 }; AntivirusProducts = @(); Firewall = @(@{ Profile = 'Public'; Enabled = $true }); WindowsUpdate = @{ DaysSinceLastHotfix = 10; PendingReboot = $true } }
        DriverProblems = @(@{ Name = 'Dispositivo desconocido 203.0.113.50'; Class = 'Unknown'; ErrorCode = 28 })
        Power = @{ ActiveSchemeGuid = $saver; ActiveSchemeName = 'Economizador'; Schemes = @(@{ Guid = $saver; Name = 'Economizador' }, @{ Guid = $balanced; Name = 'Equilibrado' }) }
        Events = @{ WindowDays = 14; Counts = @{ Hardware = 0 }; ByProviderId = @{ 'Display/4101' = 2; 'Microsoft-Windows-Kernel-Processor-Power/37' = 5 }; AppCrashes = @(@{ App = 'Teams.exe'; Count = 7 }) }
        Boot = @{ MedianBootSec = 140; LastBootSec = 150; LastPostBootSec = 60 }
        Reliability = @{ StabilityIndex = 3.2 }
        Hibernation = @{ HibernateEnabled = $true; FastStartupEnabled = $true; HiberfilGB = 3.2 }
        DiskMaintenance = @{ DaysSinceOptimize = 90 }
        Cleanup = @{ 'CLEANUP-USER-TEMP' = @{ Available = $true; Files = 400; MB = 900 }; 'CLEANUP-WINDOWS-TEMP' = @{ Available = $false; Files = $null; MB = $null }; 'CLEANUP-WER' = @{ Available = $true; Files = 3; MB = 10 } }
        Orphans = @{ Tasks = @(@{ FullPath = '\Vendor\OldUpdater'; TaskPath = '\Vendor\'; TaskName = 'OldUpdater'; Execute = 'C:\Program Files\Old\upd.exe' }); Services = @(@{ Name = 'OldSvc'; DisplayName = 'Old Service'; StartMode = 'Auto'; Exe = 'C:\Program Files\Old\svc.exe' }) }
        Apps = @{ PrefetchAvailable = $true; PrefetchCoverageDays = 400; UserAssistAvailable = $true; Count = 4; Items = @($goodApp, $runtimeApp, $recentApp, $unknownApp) }
        Winget = @{ Available = $true }
        BackgroundApps = @(@{ Pfn = 'Microsoft.YourPhone_8wekyb3d8bbwe'; Processes = @('PhoneExperienceHost'); PrivateMB = 180; HasWindow = $false; KeyExists = $true; Disabled = $false; Protected = $false },
                           @{ Pfn = 'AppUp.IntelArcSoftware_8j3eq9eme6ctt'; Processes = @('IntelGraphicsSoftware.Service'); PrivateMB = 90; HasWindow = $false; KeyExists = $true; Disabled = $false; Protected = $true },
                           @{ Pfn = 'Contoso.Editor_abcdefghijklm'; Processes = @('Editor'); PrivateMB = 300; HasWindow = $true; KeyExists = $true; Disabled = $false; Protected = $false })
        PackagedStartup = @(@{ Target = 'Contoso.ChatApp_abcdefghijklm\App'; Pfn = 'Contoso.ChatApp_abcdefghijklm'; TaskId = 'App'; State = 2; Enabled = $true; Protected = $false },
                            @{ Target = 'AppUp.IntelGraphicsDemo_aaaaaaaaaaaaa\GraphicsStartup'; Pfn = 'AppUp.IntelGraphicsDemo_aaaaaaaaaaaaa'; TaskId = 'GraphicsStartup'; State = 2; Enabled = $true; Protected = $true },
                            @{ Target = 'Fabrikam.Assistant_nopqrstuvwxyz\AssistantStartup'; Pfn = 'Fabrikam.Assistant_nopqrstuvwxyz'; TaskId = 'AssistantStartup'; State = 0; Enabled = $false; Protected = $false })
        BootDegradation = @(@{ Item = 'ChatApp'; Count = 3; AvgDegradationSec = 45 }, @{ Item = 'Microsoft Edge WebView2'; Count = 8; AvgDegradationSec = 30 })
        LeakWatch = @{ Minutes = 10; Tracked = 20; Suspects = @(@{ Name = 'LeakyApp'; Id = 4242; StartMB = 500; EndMB = 830; GrowthMB = 330; RateMBPerMin = 33; GrowingIntervalsPct = 100 }) }
        Unavailable = @(@{ Metric = 'smart'; Reason = 'requiere administrador' })
    }
    $hwFail = [ordered]@{
        Storage = @(@{ FriendlyName = 'FakeSSD 256'; MediaType = 'SSD'; HealthStatus = 'Warning'; SerialNumber = 'SN-SECRET-999'; Reliability = @{ Available = $true; WearPercentUsed = 95; ReadErrorsUncorrected = 3 }; FailurePredictAny = $false })
        DiskEvents = @{ BadBlock = 2; PagingError = 0; NtfsCorruption = 1; ControllerError = 0 }
        Memory = @{ WheaEvents = 4; SlotsTotal = 2; SlotsUsed = 1; Modules = @(@{ CapacityGB = 8; SpeedMHz = 2666 }) }
        Battery = @{ Present = $true; HealthPercent = 45; DesignCapacitymWh = 50000; FullChargeCapacitymWh = 22500; CycleCount = 900 }
        Throttling = @{ FirmwareLimitEvents = 12 }
        PowerEvents = @{ KernelPower41 = 4 }
        Unavailable = @()
    }
    $healthy = [ordered]@{
        SchemaVersion = 1; Mode = 'audit-only'
        OS = @{ Caption = 'Microsoft Windows 11 Pro'; TotalRamGB = 16; UptimeHours = 20 }
        Device = @{ IsManaged = $false }
        Computer = @{ FormFactor = 'portatil' }
        CPU = @{ Name = 'Fake CPU 8C'; LogicalProcessors = 16 }
        Memory = @{ AvailableGB = 9; CommitPercent = 40; PagesPerSec = 10 }
        PageFile = @{ AutomaticManaged = $true; Present = $true }
        Sampling = @{ CpuAvgPercent = 8; TopByCpu = @(); TopByMemory = @(@{ Name = 'explorer'; PrivateMB = 200; Count = 1 }); DiskQueueAvg = 0.1; DiskTimeAvgPercent = 3 }
        Disks = @(@{ DeviceId = '0'; FriendlyName = 'Fake NVMe'; MediaType = 'SSD'; BusType = 'NVMe'; SizeGB = 1000; HealthStatus = 'Healthy' }); SystemDiskNumber = '0'
        Volumes = @(@{ DriveLetter = 'C:'; SizeGB = 930; FreeGB = 500; FreePercent = 53; IsSystem = $true })
        Startup = @((New-Startup 'Spotify' 'x.exe'))
        Security = @{ Defender = @{ RealTimeProtectionEnabled = $true; QuickScanAgeDays = 1; SignatureAgeDays = 0 }; Firewall = @(@{ Profile = 'Public'; Enabled = $true }); WindowsUpdate = @{ DaysSinceLastHotfix = 5; PendingReboot = $false } }
        DriverProblems = @()
        Power = @{ ActiveSchemeGuid = $balanced }
        Events = @{ ByProviderId = @{}; AppCrashes = @() }
        Boot = @{ MedianBootSec = 25 }; Reliability = @{ StabilityIndex = 9.5 }
        Hibernation = @{ HibernateEnabled = $true }; DiskMaintenance = @{ DaysSinceOptimize = 3 }
        Cleanup = @{ 'CLEANUP-USER-TEMP' = @{ Available = $true; Files = 10; MB = 20 } }
        Orphans = @{ Tasks = @(); Services = @() }
        Apps = @{ PrefetchAvailable = $true; PrefetchCoverageDays = 400; UserAssistAvailable = $true; Count = 1; Items = @($recentApp) }
        Winget = @{ Available = $false }
        Unavailable = @()
    }
    $hwOk = [ordered]@{ Storage = @(@{ FriendlyName = 'Fake NVMe'; HealthStatus = 'Healthy'; Reliability = @{ Available = $true; WearPercentUsed = 3; ReadErrorsUncorrected = 0 } })
                        DiskEvents = @{ BadBlock = 0; PagingError = 0; NtfsCorruption = 0; ControllerError = 0 }; Memory = @{ WheaEvents = 0 }
                        Battery = @{ Present = $true; HealthPercent = 95 }; Throttling = @{ FirmwareLimitEvents = 0 }; PowerEvents = @{ KernelPower41 = 0 }; Unavailable = @() }

    # --- Escenario estresado ---------------------------------------------------
    Section 'Analisis: equipo de escritorio de gama baja con problemas'
    $d1 = New-Dir 'stressed'
    $b1 = Save-Json $d1 'baseline.json' $stressed
    $h1 = Save-Json $d1 'hardware-health.json' $hwFail
    $r = Invoke-Child 'analyze-performance.ps1' @('-BaselinePath', $b1, '-HardwarePath', $h1, '-OutputDir', $d1)
    Assert 'analyze termina con 0' ($r.Code -eq 0) $r.Output
    $fd = Read-WpaJson (Join-Path $d1 'findings.json')
    $rules = @($fd.Findings | ForEach-Object { $_.RuleId })
    $cats = @($fd.Findings | ForEach-Object { $_.Category } | Select-Object -Unique)
    Assert 'findings en modo audit-only' ($fd.Mode -eq 'audit-only')
    Assert 'todas las categorias son validas' (@($cats | Where-Object { $script:WpaCategories -notcontains $_ }).Count -eq 0)
    foreach ($expected in @('MEM-01', 'PWR-01', 'HW-THROTTLE', 'DSK-01', 'DSK-02', 'HW-DISK', 'HW-DISK-EVENTS', 'HW-WHEA', 'HW-BATTERY', 'HW-POWER',
                            'STARTUP-01', 'DRV-01', 'GPU-01', 'APP-01', 'SYS-INTEGRITY', 'SYS-REBOOT', 'EVID-01', 'TASK-01', 'CPU-01',
                            'PROFILE', 'BOOT-01', 'REL-01', 'VISUAL-01', 'DISKOPT-01', 'HIBER-01', 'DEF-01', 'CLEANUP-01', 'CLEANUP-02',
                            'ORPHAN-01', 'ORPHAN-02', 'APP-UNUSED-01', 'APP-REVIEW', 'APPUPD-01', 'BGAPP-01', 'MEM-LEAK-01', 'STARTUP-02', 'BIOS-01')) {
        Assert ("detecta " + $expected) ($rules -contains $expected)
    }
    Assert 'regla termica ACPI eliminada' ($rules -notcontains 'HW-THERMAL')
    foreach ($c in $script:WpaCategories) { Assert ("categoria presente: " + $c) ($cats -contains $c) }
    Assert 'perfil: HDD, RAM medio, CPU bajo, escritorio, gama baja' ($fd.HardwareProfile.StorageClass -eq 'HDD' -and $fd.HardwareProfile.CpuTier -eq 'bajo' -and $fd.HardwareProfile.FormFactor -eq 'escritorio' -and $fd.HardwareProfile.LowEnd)
    $diskOpt = @($fd.Findings | Where-Object { $_.RuleId -eq 'DISKOPT-01' })[0]
    Assert 'HDD: optimizacion por desfragmentacion' ($diskOpt.ActionTargets[0].Mode -eq 'Defrag')
    $unused = @($fd.Findings | Where-Object { $_.RuleId -eq 'APP-UNUSED-01' })[0]
    $unusedNames = @($unused.ActionTargets | ForEach-Object { $_.DisplayName })
    Assert 'desinstalacion: solo el programa sin uso > 6 meses' ($unusedNames.Count -eq 1 -and $unusedNames[0] -eq 'Juego Viejo') ($unusedNames -join ',')
    $hwF = @($fd.Findings | Where-Object { $_.Category -eq 'posible-hardware' })
    Assert 'hardware declara limites del agente' (@($hwF | Where-Object { -not $_.AgentLimits }).Count -eq 0)
    Assert 'hardware no propone acciones automaticas' (@($hwF | Where-Object { @($_.ProposedActionTypes).Count -gt 0 }).Count -eq 0)
    Assert 'disco degradado recomienda respaldo' (@($fd.Findings | Where-Object { $_.RuleId -eq 'HW-DISK' -and $_.BackupRecommended }).Count -ge 1)
    $stCand = @(@($fd.Findings | Where-Object { $_.RuleId -eq 'STARTUP-01' })[0].ActionTargets | ForEach-Object { $_.Name })
    Assert 'inicio excluye seguridad y sincronizacion' (($stCand -notcontains 'OneDrive') -and ($stCand -notcontains 'SecurityHealth'))
    Assert 'inicio incluye entrada de equipo (HKLM)' ($stCand -contains 'VendorTray')
    $share = [IO.File]::ReadAllText((Join-Path $d1 'report-shareable.html'))
    Assert 'reporte compartible sin usuario ni IP publica' (($share -notmatch ('(?i)' + [regex]::Escape($env:USERNAME))) -and ($share -notmatch '203\.0\.113\.50'))
    Assert 'reporte HTML sin scripts ni recursos externos' ($share -notmatch '(?i)<script|https?://')
    Assert 'reporte incluye estrategia por componentes' ($share -match 'Perfil y estrategia')
    Assert 'reporte incluye inventario de componentes (BIOS, CPU, RAM, discos)' (($share -match 'BIOS: Contoso 1.02') -and ($share -match 'CPU: Fake CPU 4C') -and ($share -match 'ranuras de RAM') -and ($share -match 'Disco: Fake HDD 500'))
    Assert 'estrategia incluye posibilidad de ampliar RAM' (@($fd.HardwareProfile.Strategy | Where-Object { $_ -match 'Ampliacion de RAM' }).Count -eq 1)

    Section 'Propuesta: modo asistido'
    $r = Invoke-Child 'propose-actions.ps1' @('-FindingsPath', (Join-Path $d1 'findings.json'), '-BaselinePath', $b1, '-OutputDir', $d1)
    Assert 'propose termina con 0' ($r.Code -eq 0) $r.Output
    $planPath = Join-Path $d1 'action-plan.json'
    $plan = Read-WpaJson $planPath
    $types = @($plan.Actions | ForEach-Object { $_.Type })
    Assert 'plan en modo audit-only y asistido' ($plan.Mode -eq 'audit-only' -and $plan.OperationMode -eq 'asistido')
    Assert 'hash de integridad valido' ((Get-WpaPlanHash $plan) -eq $plan.PlanHash)
    $abundle = @($plan.Bundles)[0]
    $abIn = @($plan.Actions | Where-Object { $abundle -and @($abundle.ActionIds) -contains $_.ActionId })
    Assert 'asistido: paquete de bajo riesgo disponible y solo con acciones elegibles' ($null -ne $abundle -and $abIn.Count -gt 0 -and @($abIn | Where-Object { $_.Risk -ne 'Low' -or $_.Network -or -not $_.RollbackReliable -or $_.RequiresRestorePoint }).Count -eq 0)
    Assert 'plan incluye recomendaciones manuales fuera del catalogo' ([IO.File]::ReadAllText((Join-Path $d1 'action-plan.md')) -match 'Recomendaciones manuales')
    Assert 'punto de restauracion antepuesto (hay desinstalacion)' ($types[0] -eq 'CREATE-RESTORE-POINT')
    foreach ($t in @('APP-UNINSTALL', 'STARTUP-DISABLE-USER-RUN', 'STARTUP-DISABLE-MACHINE-RUN', 'VISUAL-EFFECTS-PERFORMANCE', 'DISK-OPTIMIZE', 'HIBERNATION-OFF',
                     'DEFENDER-SCAN', 'CLEANUP-USER-TEMP', 'COMPONENT-CLEANUP', 'CLEANUP-DELIVERY-OPTIMIZATION', 'TASK-DISABLE-ORPHAN', 'SERVICE-DISABLE-ORPHAN',
                     'VERIFY-SFC', 'VERIFY-DISM-CHECKHEALTH', 'DISK-SCAN', 'APP-UPDATE-CHECK', 'POWER-SET-SCHEME', 'BACKGROUND-APP-DISABLE')) {
        Assert ("plan incluye " + $t) ($types -contains $t)
    }
    Assert 'no se propone limpieza de categorias por debajo del umbral' ($types -notcontains 'CLEANUP-WER')
    $bgT = @($plan.Actions | Where-Object { $_.Type -eq 'BACKGROUND-APP-DISABLE' } | ForEach-Object { [string]$_.Targets[0] })
    Assert 'segundo plano: solo app de usuario sin ventana (excluye protegidas y abiertas)' ($bgT.Count -eq 1 -and $bgT[0] -eq 'Microsoft.YourPhone_8wekyb3d8bbwe') ($bgT -join ',')
    $pkT = @($plan.Actions | Where-Object { $_.Type -eq 'STARTUP-DISABLE-PACKAGED' } | ForEach-Object { [string]$_.Targets[0] })
    Assert 'inicio de apps de la Tienda: solo habilitadas y no protegidas' ($pkT.Count -eq 1 -and $pkT[0] -eq 'Contoso.ChatApp_abcdefghijklm\App') ($pkT -join ',')
    Assert 'arranque lento lista culpables identificados por Windows' (@(@($fd.Findings | Where-Object { $_.RuleId -eq 'BOOT-01' })[0].Evidence | Where-Object { $_ -match 'Retrasa el arranque: ChatApp' }).Count -eq 1)
    Assert 'formato de objetivo de inicio empaquetado' ((Test-WpaPackagedStartupTarget 'Contoso.ChatApp_abcdefghijklm\App') -and -not (Test-WpaPackagedStartupTarget 'Contoso.ChatApp_abcdefghijklm\..\x') -and -not (Test-WpaPackagedStartupTarget 'sinbarra'))
    Assert 'fuga de memoria: sin accion automatica' (@(@($fd.Findings | Where-Object { $_.RuleId -eq 'MEM-LEAK-01' })[0].ProposedActionTypes).Count -eq 0)
    $required = @('ActionId', 'Finding', 'Evidence', 'Command', 'Targets', 'Affects', 'Benefit', 'Risk', 'RequiresAdmin', 'RequiresReboot', 'Network', 'Backup', 'Rollback', 'RollbackReliable', 'Validation')
    foreach ($a in $plan.Actions) {
        $missing = @($required | Where-Object { $null -eq $a.PSObject.Properties[$_] -or [string]::IsNullOrEmpty([string]$a.$_) })
        Assert ("{0} ({1}) muestra todos los campos" -f $a.ActionId, $a.Type) ($missing.Count -eq 0) ($missing -join ',')
        Assert ("{0} un objetivo exacto" -f $a.ActionId) (@($a.Targets).Count -eq 1)
        Assert ("{0} comando regenerable desde la allowlist" -f $a.ActionId) ((Get-WpaActionCommand -Type $a.Type -Targets @($a.Targets) -Detail $a.Detail) -eq $a.Command)
    }
    $un = @($plan.Actions | Where-Object { $_.Type -eq 'APP-UNINSTALL' })[0]
    Assert 'desinstalacion: riesgo medio, sin reversion confiable, exige punto de restauracion' ($un.Risk -eq 'Medium' -and -not $un.RollbackReliable -and $un.RequiresRestorePoint)
    Assert 'desinstalacion muestra programa, ultimo uso y evidencia' ($un.Affects -match 'Juego Viejo' -and $un.Affects -match 'evidencia: alta')
    $dop = @($plan.Actions | Where-Object { $_.Type -eq 'DISK-OPTIMIZE' })[0]
    Assert 'comando de optimizacion: Defrag en HDD' ($dop.Command -match '-Defrag$')
    Assert 'acciones con red marcadas' (@($plan.Actions | Where-Object { $_.Type -in @('DEFENDER-SCAN', 'APP-UPDATE-CHECK') -and -not $_.Network }).Count -eq 0)
    Assert 'nada se ejecuto al proponer' (-not (Test-Path -LiteralPath (Join-Path $d1 'executed-actions.json')) -and @(Get-ChildItem -LiteralPath $d1 -Filter 'backup-*.json').Count -eq 0)
    $md = [IO.File]::ReadAllText((Join-Path $d1 'action-plan.md'))
    Assert 'plan legible: nada se ejecuto y SIN REVERSION CONFIABLE' (($md -match 'Nada se ha ejecutado') -and ($md -match 'SIN REVERSION CONFIABLE'))
    $gen = @(Get-WpaExplicitApprovals -Text 'optimiza mi computador' -Actions @($plan.Actions) | Where-Object { $_.Approved })
    Assert '"optimiza mi computador" no aprueba ninguna accion' ($gen.Count -eq 0)

    Section 'Propuesta: modo tecnico y paquetes'
    $d6 = New-Dir 'tecnico'
    $b6 = Save-Json $d6 'baseline.json' $stressed
    [IO.File]::WriteAllText((Join-Path $d6 'findings.json'), [IO.File]::ReadAllText((Join-Path $d1 'findings.json')))
    $r = Invoke-Child 'propose-actions.ps1' @('-FindingsPath', (Join-Path $d6 'findings.json'), '-BaselinePath', $b6, '-OutputDir', $d6, '-OperationMode', 'tecnico')
    Assert 'modo tecnico sin ticket: rechazado (2)' ($r.Code -eq 2) $r.Output
    $r = Invoke-Child 'propose-actions.ps1' @('-FindingsPath', (Join-Path $d6 'findings.json'), '-BaselinePath', $b6, '-OutputDir', $d6, '-OperationMode', 'tecnico', '-Ticket', 'INC-2041', '-Technician', 'tec01')
    Assert 'modo tecnico con ticket: 0' ($r.Code -eq 0) $r.Output
    $tplan = Read-WpaJson (Join-Path $d6 'action-plan.json')
    $bundle = @($tplan.Bundles)[0]
    $inBundle = @($tplan.Actions | Where-Object { @($bundle.ActionIds) -contains $_.ActionId })
    Assert 'paquete creado con ticket' ($null -ne $bundle -and $tplan.Ticket -eq 'INC-2041')
    Assert 'paquete solo con riesgo bajo, sin red, reversibles y sin punto de restauracion obligatorio' (@($inBundle | Where-Object { $_.Risk -ne 'Low' -or $_.Network -or -not $_.RollbackReliable -or $_.RequiresRestorePoint }).Count -eq 0)
    Assert 'paquete excluye desinstalaciones y limpiezas' (@($inBundle | Where-Object { $_.Type -in @('APP-UNINSTALL', 'CLEANUP-USER-TEMP', 'SERVICE-DISABLE-ORPHAN', 'DEFENDER-SCAN') }).Count -eq 0)

    # --- apply: rechazos ------------------------------------------------------
    Section 'apply-approved-action (rechazos y simulaciones)'
    $hostScheme = Get-WpaActivePowerScheme
    if ([bool]$plan.DeviceContext.IsManaged) {
        Skip 'pruebas de apply' ('el anfitrion se detecto como administrado: ' + (@($plan.DeviceContext.Reasons) -join '; '))
    } else {
        $pw = @($plan.Actions | Where-Object { $_.Type -eq 'POWER-SET-SCHEME' })[0]
        $sid = $plan.SessionId
        $base = @('-PlanPath', $planPath, '-SessionId', $sid, '-ActionId', $pw.ActionId, '-Target', $balanced)
        $okText = 'Apruebo ' + $pw.ActionId
        $r = Invoke-Child 'apply-approved-action.ps1' ($base + @('-ApprovalText', $okText))
        Assert 'sin -Apply: solo simulacion (10)' ($r.Code -eq 10) $r.Output
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $planPath, '-SessionId', $sid, '-Target', $balanced, '-ApprovalText', $okText, '-Apply')
        Assert 'sin ActionId: rechazado (2)' ($r.Code -eq 2) $r.Output
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $planPath, '-SessionId', $sid, '-ActionId', $pw.ActionId, '-ApprovalText', $okText, '-Apply')
        Assert 'sin Target: rechazado (2)' ($r.Code -eq 2) $r.Output
        foreach ($txt in @('optimiza mi computador', 'si, apruebo todo', ('No apruebo ' + $pw.ActionId), $pw.ActionId)) {
            $r = Invoke-Child 'apply-approved-action.ps1' ($base + @('-ApprovalText', $txt, '-Apply'))
            Assert ("aprobacion invalida '{0}': rechazado (3)" -f $txt) ($r.Code -eq 3) $r.Output
        }
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $planPath, '-SessionId', $sid, '-ActionId', ('A-{0}-999' -f $sid.Substring(0, 8)), '-Target', $balanced, '-ApprovalText', ('Apruebo A-{0}-999' -f $sid.Substring(0, 8)), '-Apply')
        Assert 'ActionId inexistente: rechazado (3)' ($r.Code -eq 3) $r.Output
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $planPath, '-SessionId', $sid, '-ActionId', ($pw.ActionId + ';Remove-Item C:\x'), '-Target', $balanced, '-ApprovalText', $okText, '-Apply')
        Assert 'ActionId con inyeccion: rechazado (2)' ($r.Code -eq 2) $r.Output
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $planPath, '-SessionId', $sid, '-ActionId', $pw.ActionId, '-Target', $saver, '-ApprovalText', $okText, '-Apply')
        Assert 'objetivo distinto: rechazado (3)' ($r.Code -eq 3) $r.Output
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $planPath, '-SessionId', ([guid]::NewGuid().ToString('N')), '-ActionId', $pw.ActionId, '-Target', $balanced, '-ApprovalText', $okText, '-Apply')
        Assert 'otra sesion: rechazado (3)' ($r.Code -eq 3) $r.Output

        $cl = @($plan.Actions | Where-Object { $_.Type -eq 'CLEANUP-USER-TEMP' })[0]
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $planPath, '-SessionId', $sid, '-ActionId', $cl.ActionId, '-Target', [string]$cl.Targets[0], '-ApprovalText', ('Apruebo {0} y {1}' -f $cl.ActionId, $pw.ActionId), '-Apply')
        Assert 'riesgo medio aprobado en grupo: rechazado (3)' ($r.Code -eq 3 -and $r.Output -match 'individual') $r.Output
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $planPath, '-SessionId', $sid, '-ActionId', $cl.ActionId, '-Target', [string]$cl.Targets[0], '-ApprovalText', ('Apruebo ' + $cl.ActionId))
        Assert 'limpieza aprobada individualmente sin -Apply: simulacion (10)' ($r.Code -eq 10) $r.Output
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $planPath, '-SessionId', $sid, '-ActionId', $cl.ActionId, '-Target', [string]$cl.Targets[0], '-ApprovalText', ('Apruebo revertir ' + $cl.ActionId), '-Apply', '-Rollback')
        Assert 'reversion de limpieza (sin reversion): rechazada (3)' ($r.Code -eq 3) $r.Output
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $planPath, '-SessionId', $sid, '-ActionId', $un.ActionId, '-Target', [string]$un.Targets[0], '-ApprovalText', ('Apruebo ' + $un.ActionId), '-Apply')
        Assert 'desinstalar sin punto de restauracion verificado: rechazado (3)' ($r.Code -eq 3 -and $r.Output -match 'punto de restauracion') $r.Output

        # Paquete en modo tecnico
        $tpw = @($tplan.Actions | Where-Object { $_.Type -eq 'POWER-SET-SCHEME' })[0]
        $tcl = @($tplan.Actions | Where-Object { $_.Type -eq 'CLEANUP-USER-TEMP' })[0]
        $tPath = Join-Path $d6 'action-plan.json'
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $tPath, '-SessionId', $tplan.SessionId, '-ActionId', $tcl.ActionId, '-Target', [string]$tcl.Targets[0], '-ApprovalText', ('Apruebo paquete ' + $bundle.BundleId), '-Apply')
        Assert 'paquete no aprueba riesgo medio: rechazado (3)' ($r.Code -eq 3) $r.Output
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $tPath, '-SessionId', $tplan.SessionId, '-ActionId', $tpw.ActionId, '-Target', $balanced, '-ApprovalText', ('Apruebo paquete ' + $bundle.BundleId))
        Assert 'paquete aprueba accion de riesgo bajo (simulacion 10)' ($r.Code -eq 10) $r.Output

        # Plan manipulado
        $d2 = New-Dir 'tampered'
        $tp = Join-Path $d2 'action-plan.json'
        $t1 = Read-WpaJson $planPath
        @($t1.Actions | Where-Object { $_.ActionId -eq $pw.ActionId })[0].Command = 'Invoke-Expression (malicioso)'
        [IO.File]::WriteAllText($tp, ($t1 | ConvertTo-Json -Depth 12))
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $tp, '-SessionId', $sid, '-ActionId', $pw.ActionId, '-Target', $balanced, '-ApprovalText', $okText, '-Apply')
        Assert 'plan manipulado sin rehacer hash: rechazado (3)' ($r.Code -eq 3 -and $r.Output -match 'Hash') $r.Output
        $t1.PlanHash = Get-WpaPlanHash $t1
        [IO.File]::WriteAllText($tp, ($t1 | ConvertTo-Json -Depth 12))
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $tp, '-SessionId', $sid, '-ActionId', $pw.ActionId, '-Target', $balanced, '-ApprovalText', $okText, '-Apply')
        Assert 'plan manipulado con hash recalculado: comando no coincide (3)' ($r.Code -eq 3 -and $r.Output -match 'allowlist') $r.Output
        $t2 = Read-WpaJson $planPath
        $ua = @($t2.Actions | Where-Object { $_.ActionId -eq $un.ActionId })[0]
        $ua.Risk = 'Low'; $ua.RequiresRestorePoint = $false
        $t2.PlanHash = Get-WpaPlanHash $t2
        [IO.File]::WriteAllText($tp, ($t2 | ConvertTo-Json -Depth 12))
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $tp, '-SessionId', $sid, '-ActionId', $un.ActionId, '-Target', [string]$un.Targets[0], '-ApprovalText', ('Apruebo {0} y {1}' -f $un.ActionId, $pw.ActionId), '-Apply')
        Assert 'riesgo rebajado en el plan: rechazado (3)' ($r.Code -eq 3 -and $r.Output -match 'allowlist') $r.Output
        $t3 = Read-WpaJson $planPath
        $ud = @($t3.Actions | Where-Object { $_.ActionId -eq $un.ActionId })[0]
        $ud.Detail.Exe = 'C:\Windows\System32\cmd.exe'; $ud.Detail.Args = '/c whoami'
        $t3.PlanHash = Get-WpaPlanHash $t3
        [IO.File]::WriteAllText($tp, ($t3 | ConvertTo-Json -Depth 12))
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $tp, '-SessionId', $sid, '-ActionId', $un.ActionId, '-Target', [string]$un.Targets[0], '-ApprovalText', ('Apruebo ' + $un.ActionId), '-Apply')
        Assert 'desinstalador sustituido en el plan: rechazado (3)' ($r.Code -eq 3 -and $r.Output -match 'allowlist') $r.Output
        $t4 = Read-WpaJson $planPath
        $t4.ExpiresUnix = 1000; $t4.CreatedUnix = 900
        $t4.PlanHash = Get-WpaPlanHash $t4
        [IO.File]::WriteAllText($tp, ($t4 | ConvertTo-Json -Depth 12))
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $tp, '-SessionId', $sid, '-ActionId', $pw.ActionId, '-Target', $balanced, '-ApprovalText', $okText, '-Apply')
        Assert 'plan expirado: rechazado (3)' ($r.Code -eq 3 -and $r.Output -match 'expir') $r.Output

        # Reutilizacion
        $d3 = New-Dir 'ledger'
        $lp = Join-Path $d3 'action-plan.json'
        [IO.File]::WriteAllText($lp, [IO.File]::ReadAllText($planPath))
        [IO.File]::WriteAllText((Join-Path $d3 'executed-actions.json'), (ConvertTo-Json -InputObject @([pscustomobject]@{ ActionId = $pw.ActionId; Mode = 'apply'; Executed = $true; Result = 'validado' })))
        $r = Invoke-Child 'apply-approved-action.ps1' @('-PlanPath', $lp, '-SessionId', $sid, '-ActionId', $pw.ActionId, '-Target', $balanced, '-ApprovalText', $okText, '-Apply')
        Assert 'accion ya ejecutada: rechazada (3)' ($r.Code -eq 3 -and $r.Output -match 'ya se ejecuto') $r.Output

        if ($hostScheme -eq $balanced) {
            $r = Invoke-Child 'apply-approved-action.ps1' ($base + @('-ApprovalText', $okText, '-Apply'))
            Assert 'camino valido con WPA_NO_EXECUTE=1: suprimido (99)' ($r.Code -eq 99) $r.Output
        } else { Skip 'camino valido suprimido' 'el plan de energia del equipo no es Equilibrado; se evita cualquier posibilidad de cambio' }
        Assert 'plan de energia del equipo sin cambios' ((Get-WpaActivePowerScheme) -eq $hostScheme)
        Assert 'ninguna ejecucion registrada' (-not (Test-Path -LiteralPath (Join-Path $d1 'executed-actions.json')) -and -not (Test-Path -LiteralPath (Join-Path $d6 'executed-actions.json')))
        Assert 'ningun respaldo ni lista de limpieza creados' (@(Get-ChildItem -LiteralPath $d1 -Filter 'backup-*.json').Count -eq 0 -and @(Get-ChildItem -LiteralPath $d1 -Filter 'cleanup-*.json').Count -eq 0)
        Assert 'bitacora registra rechazos' ([IO.File]::ReadAllText((Join-Path $d1 'audit-log.jsonl')) -match 'rechazado')
    }

    # --- Equipo administrado --------------------------------------------------
    Section 'Equipo administrado'
    $d4 = New-Dir 'managed'
    $managed = $stressed; $managed.Device = @{ IsManaged = $true; ManagedReasons = @('unido a dominio Active Directory'); DomainName = 'corp.contoso.com' }
    $b4 = Save-Json $d4 'baseline.json' $managed
    $h4 = Save-Json $d4 'hardware-health.json' $hwFail
    [void](Invoke-Child 'analyze-performance.ps1' @('-BaselinePath', $b4, '-HardwarePath', $h4, '-OutputDir', $d4, '-NoHtml'))
    $fakeAuth = Join-Path $d4 'org-authorization.json'
    [IO.File]::WriteAllText($fakeAuth, ($auth | ConvertTo-Json))
    $r = Invoke-Child 'propose-actions.ps1' @('-FindingsPath', (Join-Path $d4 'findings.json'), '-BaselinePath', $b4, '-OutputDir', $d4, '-Ticket', 'INC-100', '-OrgAuthorizationPath', $fakeAuth)
    $mp = Read-WpaJson (Join-Path $d4 'action-plan.json')
    Assert 'administrado: autorizacion en carpeta escribible por el usuario es rechazada' (@($mp.Actions | Where-Object { $_.Modifies }).Count -eq 0)
    Assert 'administrado: motivo de omision informado' (@($mp.Skipped | Where-Object { $_ -match 'autorizacion corporativa' }).Count -gt 0)
    Assert 'administrado: hallazgo CTX-MANAGED' (@((Read-WpaJson (Join-Path $d4 'findings.json')).Findings | Where-Object { $_.RuleId -eq 'CTX-MANAGED' }).Count -eq 1)
    Assert 'archivo de autorizacion escribible: rechazado' (-not (Test-WpaOrgAuthorizationFile $fakeAuth).Ok)

    # --- Equipo sano ---------------------------------------------------------
    Section 'Equipo sano (portatil NVMe)'
    $d5 = New-Dir 'healthy'
    $b5 = Save-Json $d5 'baseline.json' $healthy
    $h5 = Save-Json $d5 'hardware-health.json' $hwOk
    [void](Invoke-Child 'analyze-performance.ps1' @('-BaselinePath', $b5, '-HardwarePath', $h5, '-OutputDir', $d5, '-NoHtml'))
    $hf = Read-WpaJson (Join-Path $d5 'findings.json')
    Assert 'sano: sin hallazgos de severidad media o mayor' (@($hf.Findings | Where-Object { $_.Severity -in @('medium', 'high', 'critical') }).Count -eq 0) ((@($hf.Findings) | ForEach-Object { $_.RuleId }) -join ',')
    Assert 'portatil: no se propone desactivar hibernacion' (@($hf.Findings | Where-Object { $_.RuleId -eq 'HIBER-01' }).Count -eq 0)
    Assert 'programa usado hace 3 dias: no se propone desinstalar' (@($hf.Findings | Where-Object { $_.RuleId -eq 'APP-UNUSED-01' }).Count -eq 0)
    [void](Invoke-Child 'propose-actions.ps1' @('-FindingsPath', (Join-Path $d5 'findings.json'), '-BaselinePath', $b5, '-OutputDir', $d5))
    Assert 'sano: no se proponen acciones' (@((Read-WpaJson (Join-Path $d5 'action-plan.json')).Actions).Count -eq 0)

    # --- Casos limite: eventos ruidosos que no son fallas -----------------------
    Section 'Casos limite: portatil sano con eventos ruidosos'
    $d7 = New-Dir 'noisy-events'
    $calib = ($healthy | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
    $calib.Events = [pscustomobject]@{ WindowDays = 14; ByProviderId = [pscustomobject]@{ 'Microsoft-Windows-Kernel-Processor-Power/37' = 300 }; AppCrashes = @([pscustomobject]@{ App = 'AppConFallos.exe'; Count = 120 }) }
    $calib.DriverProblems = @([pscustomobject]@{ Name = 'Adaptador VPN virtual'; Class = 'Net'; ErrorCode = 22 })
    $calib.Sampling.CpuAvgPercent = 8
    $calib.Sampling | Add-Member -NotePropertyName PercentOfMaxFrequencyAvg -NotePropertyValue 55 -Force
    $b7 = Save-Json $d7 'baseline.json' $calib
    $h7 = Save-Json $d7 'hardware-health.json' $hwOk
    [void](Invoke-Child 'analyze-performance.ps1' @('-BaselinePath', $b7, '-HardwarePath', $h7, '-OutputDir', $d7, '-NoHtml'))
    $cf = Read-WpaJson (Join-Path $d7 'findings.json')
    $thr = @($cf.Findings | Where-Object { $_.RuleId -eq 'HW-THROTTLE' })
    Assert 'evento 37 sin caida bajo carga: evidencia insuficiente, no hardware' ($thr.Count -eq 1 -and $thr[0].Category -eq 'evidencia-insuficiente' -and $thr[0].Severity -eq 'low')
    Assert 'dispositivo deshabilitado (codigo 22) no es falla de controlador' (@($cf.Findings | Where-Object { $_.RuleId -eq 'DRV-01' }).Count -eq 0)
    Assert 'fallos de una sola aplicacion: APP-01 si, SYS-INTEGRITY no' ((@($cf.Findings | Where-Object { $_.RuleId -eq 'APP-01' }).Count -eq 1) -and (@($cf.Findings | Where-Object { $_.RuleId -eq 'SYS-INTEGRITY' }).Count -eq 0))
    $thrS = @($fd.Findings | Where-Object { $_.RuleId -eq 'HW-THROTTLE' })
    Assert 'frecuencia baja bajo carga: posible hardware (alto)' ($thrS.Count -eq 1 -and $thrS[0].Category -eq 'posible-hardware' -and $thrS[0].Severity -eq 'high')

    # --- Casos limite: colecciones vacias, Optane+HDD, inicio en gama baja, WHEA PCIe ---
    Section 'Casos limite: colecciones vacias, Optane+HDD, inicio en gama baja, WHEA PCIe'
    $d8 = New-Dir 'low-end'
    $ip = ($healthy | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
    $ip.OS.TotalRamGB = 8
    $ip.CPU.LogicalProcessors = 8
    $ip.Disks = @([pscustomobject]@{ DeviceId = '0'; FriendlyName = 'Intel Optane+1TBHDD'; MediaType = 'SSD'; BusType = 'RAID'; SizeGB = 1000; HealthStatus = 'Healthy' })
    $ip.DriverProblems = [pscustomobject]@{}
    $ip.Boot = [pscustomobject]@{ MedianBootSec = 100; LastBootSec = 110; LastPostBootSec = 60 }
    $ip.DiskMaintenance = [pscustomobject]@{ DaysSinceOptimize = 90 }
    $ip.Security | Add-Member -NotePropertyName AntivirusProducts -NotePropertyValue @([pscustomobject]@{ Name = 'Windows Defender'; ProductState = 397568 }) -Force
    $ip.Startup = @((New-Startup 'McAfee Security Scan Plus' 'C:\Program Files\McAfee Security Scan\SSScheduler.exe'), (New-Startup 'App1' 'a1.exe'), (New-Startup 'App2' 'a2.exe'),
                    [pscustomobject]@{ Name = 'Herramienta.lnk'; Location = 'Carpeta Inicio (Usuario)'; Scope = 'Usuario'; Hive = 'HKCU'; Sub = 'StartupFolder'; Executable = 'Herramienta.lnk'; ExecutablePath = $null; CommandHash = $null; State = 'Habilitado' })
    $ip.Orphans = [pscustomobject]@{ Tasks = [pscustomobject]@{}; Services = $null }
    $b8 = Save-Json $d8 'baseline.json' $ip
    $hw8 = ($hwOk | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
    $hw8.Memory | Add-Member -NotePropertyName Whea -NotePropertyValue ([pscustomobject]@{ Total = 500; Capped = $true; FirstUnix = ($nowU - 10 * $day); LastUnix = $nowU; SpanDays = 10; PerDay = 50
        Groups = @([pscustomobject]@{ Id = 17; Component = 'PCIe'; Fatal = $false; Count = 500; VenDev = '8086:A110'; Device = 'PCI Express Root Port'; ChildDevices = @('Adaptador Wi-Fi 802.11ac') })
        PcieCorrected = 500; MemoryCorrected = 0; CpuCorrected = 0; Fatal = 0 }) -Force
    $h8 = Save-Json $d8 'hardware-health.json' $hw8
    $r = Invoke-Child 'analyze-performance.ps1' @('-BaselinePath', $b8, '-HardwarePath', $h8, '-OutputDir', $d8, '-NoHtml')
    Assert 'colecciones vacias ({}) no rompen el analisis (exit 0)' ($r.Code -eq 0) $r.Output
    $if = Read-WpaJson (Join-Path $d8 'findings.json')
    $ir = @($if.Findings | ForEach-Object { $_.RuleId })
    Assert 'Optane+HDD clasificado como HDD-Optane (mecanico)' ($if.HardwareProfile.StorageClass -eq 'HDD-Optane' -and $if.HardwareProfile.IsMechanical)
    Assert 'Optane+HDD: limitacion estructural (DSK-02) y sin TRIM ni Defrag (sin DISKOPT-01)' (($ir -contains 'DSK-02') -and ($ir -notcontains 'DISKOPT-01'))
    Assert 'Optane+HDD: umbral de arranque de HDD (100 s no supera 120 s)' ($ir -notcontains 'BOOT-01')
    Assert 'Optane: Test-WpaOptaneHybrid' ((Test-WpaOptaneHybrid -FriendlyName 'Intel Optane+1TBHDD' -BusType 'RAID') -and -not (Test-WpaOptaneHybrid -FriendlyName 'Generic NVMe SSD' -BusType 'NVMe'))
    $st8 = @($if.Findings | Where-Object { $_.RuleId -eq 'STARTUP-01' })
    Assert 'gama baja: STARTUP-01 con 4 programas (umbral reducido)' ($st8.Count -eq 1)
    $st8Names = @($st8 | ForEach-Object { $_.ActionTargets } | ForEach-Object { $_.Name })
    Assert 'McAfee Security Scan Plus es candidato (no hay antivirus McAfee registrado)' ($st8Names -contains 'McAfee Security Scan Plus') ($st8Names -join ',')
    Assert 'acceso directo de la carpeta Inicio es candidato' ($st8Names -contains 'Herramienta.lnk')
    Assert 'WHEA PCIe corregido: WHEA-PCIE-01, no HW-WHEA (no es RAM/CPU)' (($ir -contains 'WHEA-PCIE-01') -and ($ir -notcontains 'HW-WHEA'))
    Assert 'WHEA PCIe identifica el dispositivo conectado' (@(@($if.Findings | Where-Object { $_.RuleId -eq 'WHEA-PCIE-01' })[0].Evidence | Where-Object { $_ -match 'Adaptador Wi-Fi' }).Count -ge 1)
    Assert 'WHEA componente: PCIe / Memoria / CPU' (((Get-WpaWheaComponent 'Component: PCI Express Root Port') -eq 'PCIe') -and ((Get-WpaWheaComponent 'Componente: Memoria') -eq 'Memoria') -and ((Get-WpaWheaComponent 'Component: Processor Core') -eq 'CPU'))
    $r = Invoke-Child 'propose-actions.ps1' @('-FindingsPath', (Join-Path $d8 'findings.json'), '-BaselinePath', $b8, '-OutputDir', $d8)
    Assert 'propuesta con colecciones vacias (exit 0)' ($r.Code -eq 0) $r.Output
    $p8 = Read-WpaJson (Join-Path $d8 'action-plan.json')
    Assert 'acceso directo propuesto como STARTUP-DISABLE-USER-FOLDER' (@($p8.Actions | Where-Object { $_.Type -eq 'STARTUP-DISABLE-USER-FOLDER' -and $_.Targets[0] -eq 'Herramienta.lnk' }).Count -eq 1)
    Assert 'Optane: ninguna accion DISK-OPTIMIZE propuesta' (@($p8.Actions | Where-Object { $_.Type -eq 'DISK-OPTIMIZE' }).Count -eq 0)
    $md8 = [IO.File]::ReadAllText((Join-Path $d8 'action-plan.md'))
    Assert 'recomendacion manual WHEA/ASPM incluida en el plan' ($md8 -match 'WHEA-PCIE-01')
    Assert 'Get-WpaList descarta objetos vacios y nulos' ((@(Get-WpaList @([pscustomobject]@{}, $null, [pscustomobject]@{ A = 1 }))).Count -eq 1)

    Section 'validate-results e informe de servicio'
    $after = $healthy; $after.Security = @{ Defender = @{ RealTimeProtectionEnabled = $false }; Firewall = @(@{ Profile = 'Public'; Enabled = $false }); WindowsUpdate = @{} }
    $after.Sampling = @{ CpuAvgPercent = 60 }; $after.Boot = @{ MedianBootSec = 60 }
    $a5 = Save-Json $d5 'baseline-after.json' $after
    $r = Invoke-Child 'validate-results.ps1' @('-OutputDir', $d5, '-BeforePath', $b5, '-AfterPath', $a5)
    Assert 'detecta regresion (5)' ($r.Code -eq 5 -and $r.Output -match 'REGRESION') $r.Output
    $r = Invoke-Child 'validate-results.ps1' @('-OutputDir', $d5, '-BeforePath', $b5, '-AfterPath', $b5)
    Assert 'sin regresion con mediciones iguales (0)' ($r.Code -eq 0) $r.Output
    $r = Invoke-Child 'validate-results.ps1' @('-OutputDir', $d5, '-PlanPath', $planPath, '-ActionId', ([string]@($plan.Actions)[0].ActionId))
    Assert 'validacion de accion no ejecutada no reporta regresion' ($r.Code -eq 0) $r.Output
    $improved = $stressed; $improved.Boot = @{ MedianBootSec = 70; LastPostBootSec = 20 }
    [void](Save-Json $d1 'baseline-after.json' $improved)
    $r = Invoke-Child 'service-report.ps1' @('-OutputDir', $d1, '-Client', 'Cliente Demo', '-Technician', 'tec01')
    Assert 'informe de servicio generado (0)' ($r.Code -eq 0) $r.Output
    $sr = [IO.File]::ReadAllText((Join-Path $d1 'service-report.html'))
    Assert 'informe muestra mejora de arranque 140 -> 70' (($sr -match '140') -and ($sr -match '70') -and ($sr -match 't-mejora'))
    Assert 'informe lista acciones del plan' ($sr -match [regex]::Escape([string]@($plan.Actions)[0].ActionId))
    $srs = [IO.File]::ReadAllText((Join-Path $d1 'service-report-shareable.html'))
    Assert 'informe compartible sin usuario' ($srs -notmatch ('(?i)' + [regex]::Escape($env:USERNAME)))

    $r = Invoke-Child 'collect-baseline.ps1' @('-OutputDir', 'C:\')
    Assert 'collect-baseline rechaza OutputDir raiz antes de recolectar (2)' ($r.Code -eq 2) $r.Output
    $r = Invoke-Child 'hardware-health.ps1' @('-OutputDir', 'C:\no-existe-wpa-xyz')
    Assert 'hardware-health rechaza OutputDir inexistente (2)' ($r.Code -eq 2) $r.Output
}
finally {
    if (-not $KeepArtifacts -and $work -and (Test-Path -LiteralPath $work)) {
        if ((Split-Path $work -Parent) -eq $tempRoot -and (Split-Path $work -Leaf) -match '^wpa-test-[0-9a-f]{32}$') {
            Remove-Item -LiteralPath $work -Recurse -Force
        }
    } elseif ($work) { Write-Host ("Artefactos conservados en: " + $work) }
}

Write-Host ""
Write-Host ("RESULTADO: {0} aprobadas, {1} fallidas, {2} omitidas" -f $script:pass, $script:fail, $script:skip) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
foreach ($f in $script:failures) { Write-Host ("  FALLA: " + $f) -ForegroundColor Red }
foreach ($s in $script:skips) { Write-Host ("  OMITIDA: " + $s) -ForegroundColor Yellow }
if ($script:fail -gt 0) { exit 1 }
exit 0

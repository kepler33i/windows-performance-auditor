#Requires -Version 5.1
<#
  lib/plan.ps1 - Integridad del plan, interpretacion de aprobaciones (incluidos
  paquetes de bajo riesgo) y autorizacion corporativa verificable. Solo lectura.
#>

# ---------------------------------------------------------------------------
# Serializacion canonica y hash
# ---------------------------------------------------------------------------

function ConvertTo-WpaCanonicalJson {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [string] -or $Value -is [char]) {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('"')
        foreach ($ch in ([string]$Value).ToCharArray()) {
            $code = [int]$ch
            if ($ch -eq '"') { [void]$sb.Append('\"') }
            elseif ($ch -eq '\') { [void]$sb.Append('\\') }
            elseif ($code -lt 32 -or $code -gt 126) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
            else { [void]$sb.Append($ch) }
        }
        [void]$sb.Append('"')
        return $sb.ToString()
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or
        $Value -is [double] -or $Value -is [decimal] -or $Value -is [single] -or $Value -is [uint32] -or $Value -is [uint64]) {
        return [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}', $Value)
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = foreach ($k in ($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object)) {
            (ConvertTo-WpaCanonicalJson $k) + ':' + (ConvertTo-WpaCanonicalJson $Value[$k])
        }
        return '{' + (@($parts) -join ',') + '}'
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $names = $Value.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object
        $parts = foreach ($k in $names) { (ConvertTo-WpaCanonicalJson $k) + ':' + (ConvertTo-WpaCanonicalJson $Value.$k) }
        return '{' + (@($parts) -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = foreach ($i in $Value) { ConvertTo-WpaCanonicalJson $i }
        return '[' + (@($parts) -join ',') + ']'
    }
    return (ConvertTo-WpaCanonicalJson ([string]$Value))
}

function Get-WpaPlanHash {
    param($Plan)
    $core = [ordered]@{
        SessionId     = (Get-WpaValue $Plan 'SessionId')
        CreatedUnix   = (Get-WpaValue $Plan 'CreatedUnix')
        ExpiresUnix   = (Get-WpaValue $Plan 'ExpiresUnix')
        OperationMode = (Get-WpaValue $Plan 'OperationMode')
        Ticket        = (Get-WpaValue $Plan 'Ticket')
        DeviceContext = (Get-WpaValue $Plan 'DeviceContext')
        Actions       = @(Get-WpaValue $Plan 'Actions' @())
        Bundles       = @(Get-WpaValue $Plan 'Bundles' @())
    }
    $json = ConvertTo-WpaCanonicalJson $core
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json)) } finally { $sha.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

# ---------------------------------------------------------------------------
# Paquetes y aprobaciones
# ---------------------------------------------------------------------------

function Test-WpaBundleEligible {
    # Solo acciones de riesgo bajo, sin red y con reversion confiable (o sin cambios).
    param($Action)
    return ([string](Get-WpaValue $Action 'Risk') -eq 'Low') -and
           (-not [bool](Get-WpaValue $Action 'Network' $false)) -and
           ([bool](Get-WpaValue $Action 'RollbackReliable' $false)) -and
           (-not [bool](Get-WpaValue $Action 'RequiresRestorePoint' $false))
}

function Get-WpaExplicitApprovals {
    <#
      Devuelve que ActionId quedan aprobados por el texto literal del usuario.
        - Verbo de aprobacion explicito y ninguna negacion.
        - Solo identificadores literales: acciones (A-xxxxxxxx-NNN) o paquetes (P-xxxxxxxx-NN).
        - "todo", "todas", "optimiza", "si" no aprueban nada.
        - Un paquete solo aprueba sus acciones elegibles (bajo riesgo, sin red, reversibles).
        - Riesgo medio/alto: solo si es el UNICO identificador del mensaje.
      Nota: es una verificacion de coherencia y trazabilidad (el agente transcribe
      el texto); la barrera real es que el usuario vea el plan y apruebe.
    #>
    param([string]$Text, [object[]]$Actions, [object[]]$Bundles = @())
    $result = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $verb = '(?i)\b(apruebo|autorizo|aprobado|autorizado|approve|approved|authorize|authorized|revertir|revierte|rollback)\b'
    $neg  = '(?i)\b(no|not|nunca|never|don''t|dont)\s+(lo\s+|la\s+|el\s+)?(apruebo|autorizo|approve|authorize|revertir|revierte)\b'
    $hasVerb = $Text -match $verb
    $hasNeg  = $Text -match $neg
    $ids = @([regex]::Matches($Text, 'A-[0-9a-f]{8}-\d{3}') | ForEach-Object { $_.Value } | Select-Object -Unique)
    $bundleIds = @([regex]::Matches($Text, 'P-[0-9a-f]{8}-\d{2}') | ForEach-Object { $_.Value } | Select-Object -Unique)
    $viaBundle = @{}
    foreach ($b in @($Bundles)) {
        $bid = [string](Get-WpaValue $b 'BundleId')
        if ($bundleIds -contains $bid) { foreach ($x in @(Get-WpaValue $b 'ActionIds' @())) { $viaBundle[[string]$x] = $bid } }
    }
    $totalIds = $ids.Count + $bundleIds.Count
    foreach ($act in @($Actions)) {
        $id = [string](Get-WpaValue $act 'ActionId')
        $risk = [string](Get-WpaValue $act 'Risk')
        $approved = $false
        $reason = ''
        $literal = $ids -contains $id
        $inBundle = $viaBundle.ContainsKey($id)
        if (-not $literal -and -not $inBundle) { $reason = 'identificador no mencionado explicitamente' }
        elseif (-not $hasVerb) { $reason = 'no hay verbo de aprobacion explicito' }
        elseif ($hasNeg) { $reason = 'el mensaje contiene una negacion' }
        elseif (-not $literal -and $inBundle -and -not (Test-WpaBundleEligible $act)) { $reason = 'no elegible para paquete (requiere aprobacion propia)' }
        elseif (($risk -eq 'Medium' -or $risk -eq 'High') -and ($totalIds -gt 1 -or -not $literal)) { $reason = 'riesgo medio/alto requiere aprobacion individual (un solo identificador por mensaje)' }
        else { $approved = $true; $reason = $(if ($literal) { 'aprobado explicitamente' } else { 'aprobado via paquete ' + $viaBundle[$id] }) }
        [void]$result.Add([pscustomobject]@{ ActionId = $id; Risk = $risk; Approved = $approved; Reason = $reason })
    }
    return $result.ToArray()
}

# ---------------------------------------------------------------------------
# Autorizacion corporativa verificable
# ---------------------------------------------------------------------------

$script:WpaOrgAuthDefaultPath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'WindowsPerformanceAuditor\org-authorization.json'

function Test-WpaOrgAuthorizationData {
    <#
      Logica pura: el contenido de la autorizacion corresponde a este equipo,
      ticket y tipo de accion, y no expiro. Devuelve { Ok; Reason }.
      Campos: Organization, AllowedDomains[], AllowedTenantIds[], Technician,
      Ticket, ValidUntil (yyyy-MM-dd), AllowedActionTypes[].
    #>
    param($Auth, $DeviceContext, [string]$ActionType, [string]$Ticket, [DateTime]$Now = [DateTime]::Now)
    foreach ($f in @('Organization', 'Technician', 'Ticket', 'ValidUntil')) {
        if ([string]::IsNullOrWhiteSpace([string](Get-WpaValue $Auth $f ''))) { return New-WpaCheck $false ("autorizacion sin campo " + $f) }
    }
    $until = [DateTime]::MinValue
    if (-not [DateTime]::TryParseExact([string]$Auth.ValidUntil, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, 'None', [ref]$until)) {
        return New-WpaCheck $false 'ValidUntil con formato invalido (yyyy-MM-dd)'
    }
    if ($Now.Date -gt $until.Date) { return New-WpaCheck $false 'autorizacion expirada' }
    if ([string]::IsNullOrWhiteSpace($Ticket) -or [string]$Auth.Ticket -ne $Ticket) { return New-WpaCheck $false 'el ticket del plan no coincide con la autorizacion' }
    $domains = @((Get-WpaValue $Auth 'AllowedDomains' @()) | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $tenants = @((Get-WpaValue $Auth 'AllowedTenantIds' @()) | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $devDomain = ([string](Get-WpaValue $DeviceContext 'DomainName' '')).ToLowerInvariant()
    $devTenants = @((Get-WpaValue $DeviceContext 'TenantIds' @()) | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $match = ($devDomain -and ($domains -contains $devDomain))
    foreach ($t in $devTenants) { if ($tenants -contains $t) { $match = $true } }
    if (-not $match) { return New-WpaCheck $false 'el dominio/tenant del equipo no esta autorizado' }
    $types = @((Get-WpaValue $Auth 'AllowedActionTypes' @()) | ForEach-Object { [string]$_ })
    if ($types -notcontains $ActionType) { return New-WpaCheck $false ("tipo de accion no autorizado por la organizacion: " + $ActionType) }
    return New-WpaCheck $true ''
}

function Test-WpaOrgAuthorizationFile {
    <#
      Verifica que el archivo de autorizacion este protegido: propietario
      Administradores o SYSTEM y sin permisos de escritura para usuarios
      estandar. Asi un usuario o un agente sin elevacion no puede fabricarlo.
    #>
    param([string]$Path)
    $syn = Test-WpaPathSyntax $Path
    if (-not $syn.Ok) { return $syn }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return New-WpaCheck $false 'no existe el archivo de autorizacion' }
    $chain = Test-WpaNoReparseChain $Path
    if (-not $chain.Ok) { return $chain }
    try { $acl = Get-Acl -LiteralPath $Path } catch { return New-WpaCheck $false 'no se pudo leer la ACL' }
    $owner = [string]$acl.Owner
    if ($owner -notmatch '(?i)(\\Administrators|\\Administradores|NT AUTHORITY\\SYSTEM|AUTORIDAD NT\\SYSTEM)$') {
        return New-WpaCheck $false ("propietario no confiable: " + $owner)
    }
    $writeMask = [int]([Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::WriteAttributes)
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $untrusted = @('S-1-1-0', 'S-1-5-11', 'S-1-5-4', 'S-1-5-32-545', $me)
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $sid = $null
        try { $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
        if ($untrusted -contains $sid -and (([int]$ace.FileSystemRights -band $writeMask) -ne 0)) {
            return New-WpaCheck $false ("usuarios no administradores pueden modificar el archivo: " + $ace.IdentityReference)
        }
    }
    return New-WpaCheck $true ''
}

function Test-WpaOrgAuthorization {
    param([string]$Path, $DeviceContext, [string]$ActionType, [string]$Ticket)
    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = $script:WpaOrgAuthDefaultPath }
    $file = Test-WpaOrgAuthorizationFile $Path
    if (-not $file.Ok) { return $file }
    try { $auth = [IO.File]::ReadAllText($Path) | ConvertFrom-Json } catch { return New-WpaCheck $false 'autorizacion ilegible' }
    return (Test-WpaOrgAuthorizationData -Auth $auth -DeviceContext $DeviceContext -ActionType $ActionType -Ticket $Ticket)
}

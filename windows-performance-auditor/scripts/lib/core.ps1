#Requires -Version 5.1
<#
  lib/core.ps1 - Utilidades base: fechas, rutas seguras, escritura de reportes,
  bitacora, sondas de solo lectura, sanitizacion y contexto del equipo.
  No modifica el sistema: solo escribe reportes en la carpeta elegida por el usuario.
#>

Set-StrictMode -Version 2.0

$script:WpaVersion = '2.0.0'
$script:WpaCategories = @(
    'software-corregible',
    'configuracion-optimizable',
    'capacidad-insuficiente',
    'posible-hardware',
    'limitacion-estructural',
    'evidencia-insuficiente'
)

# GUIDs de planes de energia integrados de Windows (no dependen del idioma).
$script:WpaPowerSchemes = @{
    'a1841308-3541-4fab-bc81-f71556f20b4a' = 'Economizador (Power saver)'
    '381b4222-f694-41f0-9685-ff5bb260df2e' = 'Equilibrado (Balanced)'
    '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' = 'Alto rendimiento (High performance)'
}

# ---------------------------------------------------------------------------
# Utilidades generales
# ---------------------------------------------------------------------------

function Get-WpaUnixNow {
    return [int64][Math]::Floor(([DateTime]::UtcNow - [DateTime]'1970-01-01').TotalSeconds)
}

function ConvertTo-WpaUnix {
    param($Date)
    if ($null -eq $Date) { return $null }
    try {
        $d = [DateTime]$Date
        return [int64][Math]::Floor(($d.ToUniversalTime() - [DateTime]'1970-01-01').TotalSeconds)
    } catch { return $null }
}

function Write-WpaError {
    # Escribe en stderr sin lanzar excepcion (Write-Error con 'Stop' impediria el 'exit <codigo>' posterior).
    param([string]$Message)
    [Console]::Error.WriteLine('ERROR: ' + $Message)
}

function Test-WpaIsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-WpaValue {
    # Lectura segura de propiedades anidadas ('A.B.C') compatible con StrictMode.
    param($Object, [string]$Path, $Default = $null)
    $cur = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $cur) { return $Default }
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains($part)) { $cur = $cur[$part] } else { return $Default }
        } else {
            $prop = $cur.PSObject.Properties[$part]
            if ($null -eq $prop) { return $Default }
            $cur = $prop.Value
        }
    }
    if ($null -eq $cur) { return $Default }
    return $cur
}

# ---------------------------------------------------------------------------
# Validacion de rutas
# ---------------------------------------------------------------------------

function New-WpaCheck {
    param([bool]$Ok, [string]$Reason = '')
    return [pscustomobject]@{ Ok = $Ok; Reason = $Reason }
}

function Test-WpaPathSyntax {
    <#
      Validacion puramente textual, sin tocar el disco.
      Rechaza: vacio, relativas, UNC/dispositivo, raiz, comodines, variables
      sin resolver, nombres cortos 8.3 (~), '..', flujos alternos (ADS),
      caracteres invalidos y espacios/puntos finales.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return New-WpaCheck $false 'ruta vacia' }
    if ($Path.Length -gt 400) { return New-WpaCheck $false 'ruta demasiado larga' }
    if ($Path -match '[\*\?]') { return New-WpaCheck $false 'contiene comodines' }
    if ($Path -match '%[^%]*%' -or $Path.Contains('$')) { return New-WpaCheck $false 'contiene variables sin resolver' }
    if ($Path.Contains('~')) { return New-WpaCheck $false 'contiene nombre corto 8.3 o ~ ambiguo' }
    if ($Path -match '^\\\\') { return New-WpaCheck $false 'rutas UNC o de dispositivo no permitidas' }
    if ($Path -notmatch '^[A-Za-z]:\\') { return New-WpaCheck $false 'debe ser una ruta absoluta local (X:\...)' }
    if ($Path -match '^[A-Za-z]:\\*$') { return New-WpaCheck $false 'ruta raiz no permitida' }
    if ($Path.IndexOf(':', 2) -ge 0) { return New-WpaCheck $false 'flujos alternos (ADS) no permitidos' }
    if ($Path -match '(^|\\)\.{1,2}(\\|$)') { return New-WpaCheck $false 'segmentos . o .. no permitidos' }
    if ($Path -match '/') { return New-WpaCheck $false 'usar separador \ ' }
    if ($Path -match '\\\\') { return New-WpaCheck $false 'separadores duplicados' }
    foreach ($c in [IO.Path]::GetInvalidPathChars()) {
        if ($Path.IndexOf($c) -ge 0) { return New-WpaCheck $false 'caracteres invalidos' }
    }
    foreach ($seg in $Path.Substring(3).Split('\')) {
        if ($seg -eq '') { continue }
        if ($seg -match '[ \.]$') { return New-WpaCheck $false 'segmento con espacio o punto final' }
        if ($seg -match '^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\..*)?$') { return New-WpaCheck $false 'nombre reservado de dispositivo' }
    }
    return New-WpaCheck $true ''
}

function Get-WpaSyncRoots {
    # Carpetas sincronizadas conocidas (OneDrive). Solo lectura de variables de entorno.
    $roots = @()
    foreach ($n in @('OneDrive', 'OneDriveConsumer', 'OneDriveCommercial')) {
        $v = [Environment]::GetEnvironmentVariable($n)
        if (-not [string]::IsNullOrWhiteSpace($v)) { $roots += $v.TrimEnd('\') }
    }
    return $roots
}

function Test-WpaInSyncRoot {
    param([string]$Path)
    foreach ($r in (Get-WpaSyncRoots)) {
        if ($Path.Equals($r, [StringComparison]::OrdinalIgnoreCase) -or
            $Path.StartsWith($r + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    foreach ($seg in $Path.Split('\')) {
        if ($seg -match '^OneDrive( -|$)') { return $true }
    }
    return $false
}

function Test-WpaNoReparseChain {
    <#
      Verifica que la ruta y cada uno de sus ancestros existan y que ninguno sea
      reparse point (junction, symlink, placeholder de nube). Tambien rechaza
      atributos de archivos en la nube (Offline, RecallOnOpen/DataAccess, Pinned/Unpinned).
    #>
    param([string]$Path)
    # 0x400 ReparsePoint, 0x1000 Offline, 0x40000 RecallOnOpen, 0x80000 Pinned,
    # 0x100000 Unpinned, 0x400000 RecallOnDataAccess
    $badMask = 0x400 -bor 0x1000 -bor 0x40000 -bor 0x80000 -bor 0x100000 -bor 0x400000
    $cur = $Path
    while ($cur -and $cur.Length -gt 3) {
        try {
            $item = Get-Item -LiteralPath $cur -Force -ErrorAction Stop
        } catch {
            return New-WpaCheck $false ("no existe o no es accesible: " + $cur)
        }
        $attr = [int]$item.Attributes
        if (($attr -band $badMask) -ne 0) {
            return New-WpaCheck $false ("enlace, reparse point o archivo en la nube: " + $cur)
        }
        $cur = [IO.Path]::GetDirectoryName($cur)
    }
    return New-WpaCheck $true ''
}

function Get-WpaProtectedPaths {
    $list = @()
    foreach ($v in @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
                     $env:USERPROFILE, $env:PUBLIC, $env:APPDATA, $env:LOCALAPPDATA)) {
        if (-not [string]::IsNullOrWhiteSpace($v)) { $list += $v.TrimEnd('\') }
    }
    if ($env:SystemDrive) { $list += ($env:SystemDrive + '\Users') }
    if ($env:USERPROFILE) {
        foreach ($sub in @('Documents', 'Desktop', 'Downloads', 'Pictures', 'Music', 'Videos', 'Favorites')) {
            $list += (Join-Path $env:USERPROFILE $sub)
        }
    }
    return $list
}

function Test-WpaIsProtectedPath {
    # True si la ruta ES una carpeta protegida (no si esta dentro de una).
    param([string]$Path)
    $p = $Path.TrimEnd('\')
    foreach ($x in (Get-WpaProtectedPaths)) {
        if ($p.Equals($x, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Test-WpaIsUnder {
    param([string]$Path, [string]$Root)
    $r = $Root.TrimEnd('\') + '\'
    return $Path.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-WpaOutputDir {
    <#
      Valida la carpeta de reportes elegida por el usuario. Debe existir
      previamente (no se crea), no ser raiz, no ser carpeta del sistema y no
      contener enlaces en su cadena. Lanza excepcion si no es valida.
    #>
    param([string]$OutputDir)
    $syn = Test-WpaPathSyntax $OutputDir
    if (-not $syn.Ok) { throw "OutputDir invalido: $($syn.Reason)" }
    $full = $OutputDir.TrimEnd('\')
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        throw "OutputDir debe existir y haber sido elegido por el usuario: $full"
    }
    $chain = Test-WpaNoReparseChain $full
    if (-not $chain.Ok) { throw "OutputDir rechazado: $($chain.Reason)" }
    foreach ($sys in @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($sys -and (($full -ieq $sys.TrimEnd('\')) -or (Test-WpaIsUnder $full $sys))) {
            throw "OutputDir no puede estar dentro de carpetas del sistema: $full"
        }
    }
    if (Test-WpaIsProtectedPath $full) {
        throw "OutputDir no puede ser directamente una carpeta personal o del sistema; use una subcarpeta dedicada: $full"
    }
    return $full
}

# ---------------------------------------------------------------------------
# Escritura de reportes y bitacora (unicas escrituras permitidas)
# ---------------------------------------------------------------------------

function Write-WpaFile {
    param([string]$OutputDir, [string]$Name, [string]$Content)
    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$') { throw "Nombre de archivo de reporte invalido: $Name" }
    $dir = Assert-WpaOutputDir $OutputDir
    $path = Join-Path $dir $Name
    if (Test-Path -LiteralPath $path) {
        $chk = Test-WpaNoReparseChain $path
        if (-not $chk.Ok) { throw "Archivo de reporte rechazado: $($chk.Reason)" }
    }
    $enc = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($path, $Content, $enc)
    return $path
}

function Write-WpaAuditLog {
    # Registra cada comando/operacion con resultado y codigo de salida (JSON Lines).
    param(
        [string]$OutputDir,
        [string]$Script,
        [string]$Operation,
        [string]$Command = '',
        [string]$Result = '',
        $ExitCode = $null,
        [string]$Details = ''
    )
    try {
        $dir = Assert-WpaOutputDir $OutputDir
        $entry = [ordered]@{
            utc       = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
            script    = $Script
            operation = $Operation
            command   = $Command
            result    = $Result
            exitCode  = $ExitCode
            details   = $Details
            elevated  = (Test-WpaIsAdmin)
        }
        $line = ($entry | ConvertTo-Json -Compress -Depth 4) + [Environment]::NewLine
        $enc = New-Object System.Text.UTF8Encoding($false)
        [IO.File]::AppendAllText((Join-Path $dir 'audit-log.jsonl'), $line, $enc)
    } catch {
        Write-Warning ("No se pudo escribir la bitacora: " + $_.Exception.Message)
    }
}

function Invoke-WpaProbe {
    <#
      Ejecuta una sonda de SOLO LECTURA. Nunca propaga excepciones: si falla,
      registra la metrica como 'no disponible' en lugar de inferir datos.
    #>
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock,
        [System.Collections.ArrayList]$Unavailable,
        [string]$OutputDir,
        [string]$ScriptName
    )
    try {
        $value = & $ScriptBlock
        if ($OutputDir) { Write-WpaAuditLog -OutputDir $OutputDir -Script $ScriptName -Operation 'probe' -Command $Name -Result 'ok' -ExitCode 0 }
        return $value
    } catch {
        $msg = $_.Exception.Message
        if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
        if ($null -ne $Unavailable) {
            [void]$Unavailable.Add([pscustomobject]@{ Metric = $Name; Reason = (ConvertTo-WpaSanitizedText $msg) })
        }
        if ($OutputDir) { Write-WpaAuditLog -OutputDir $OutputDir -Script $ScriptName -Operation 'probe' -Command $Name -Result 'no disponible' -ExitCode 1 -Details (ConvertTo-WpaSanitizedText $msg) }
        return $null
    }
}

# ---------------------------------------------------------------------------
# Sanitizacion para reportes compartibles
# ---------------------------------------------------------------------------

function Test-WpaPrivateIPv4 {
    param([string]$Ip)
    $o = $Ip.Split('.') | ForEach-Object { [int]$_ }
    if ($o[0] -eq 10 -or $o[0] -eq 127 -or $o[0] -eq 0) { return $true }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $true }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $true }
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return $true }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $true }
    if ($o[0] -ge 224) { return $true }
    return $false
}

function ConvertTo-WpaSanitizedText {
    param([string]$Text, [string[]]$ExtraTerms = @())
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $out = $Text
    $terms = @()
    if ($env:USERNAME) { $terms += $env:USERNAME }
    if ($env:USERPROFILE) { $terms += (Split-Path -Leaf $env:USERPROFILE) }
    if ($env:COMPUTERNAME) { $terms += $env:COMPUTERNAME }
    if ($env:USERDNSDOMAIN) { $terms += $env:USERDNSDOMAIN }
    if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) { $terms += $env:USERDOMAIN }
    $terms += $ExtraTerms
    $terms = $terms | Where-Object { $_ -and $_.Length -ge 3 } | Sort-Object Length -Descending -Unique
    foreach ($t in $terms) {
        $out = [regex]::Replace($out, '(?i)(?<![A-Za-z0-9])' + [regex]::Escape($t) + '(?![A-Za-z0-9])', '[REDACTADO]')
    }
    # Perfiles de usuario restantes
    $out = [regex]::Replace($out, '(?i)(Users\\{1,2})(?!Public\b|Default\b|\[REDACTADO\])[^\\"]+', '$1[USUARIO]')
    # Correos
    $out = [regex]::Replace($out, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '[CORREO]')
    # IPv4 publicas
    $out = [regex]::Replace($out, '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b', {
        param($m)
        if (Test-WpaPrivateIPv4 $m.Value) { return $m.Value } else { return '[IP-PUBLICA]' }
    })
    # SIDs
    $out = [regex]::Replace($out, 'S-1-5-21-\d+-\d+-\d+(-\d+)?', '[SID]')
    return $out
}

function ConvertTo-WpaSanitizedJson {
    # Redacta valores de campos sensibles y luego aplica sanitizacion de texto.
    param([string]$Json)
    $keys = 'SerialNumber|Serial|UniqueId|UUID|SID|MacAddress|MAC|ProductId|ProductKey|Domain|DomainName|Tenant|TenantId|TenantIds|TenantName|ComputerName|UserName|Owner|IPAddress|Organization|Technician|Ticket'
    $out = [regex]::Replace($Json, '("(?:' + $keys + ')"\s*:\s*)"[^"]*"', '$1"[REDACTADO]"')
    $out = [regex]::Replace($out, '("(?:' + $keys + ')"\s*:\s*)\[[^\]]*\]', '$1["[REDACTADO]"]')
    return (ConvertTo-WpaSanitizedText $out)
}

# ---------------------------------------------------------------------------
# Contexto del equipo (deteccion de equipos administrados) - solo lectura
# ---------------------------------------------------------------------------

function Test-WpaMdmProvider {
    <#
      True si un ProviderID de HKLM\SOFTWARE\Microsoft\Enrollments indica un MDM
      real. Windows 11 crea en equipos personales autoridades integradas
      ('Deploy Authority', 'Cloud Authority', 'Local Authority') que no implican
      administracion externa. Cualquier otro proveedor (p. ej. 'MS DM Server' de
      Intune) se considera MDM: ante la duda, se bloquean las modificaciones.
    #>
    param([string]$ProviderId)
    if ([string]::IsNullOrWhiteSpace($ProviderId)) { return $false }
    return ($ProviderId.Trim() -notmatch '^(Deploy|Cloud|Local) Authority$')
}

function Get-WpaDeviceContext {
    $reasons = New-Object System.Collections.ArrayList
    $partOfDomain = $null
    $domainName = $null
    $edition = $null
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $partOfDomain = [bool]$cs.PartOfDomain
        if ($partOfDomain) { $domainName = [string]$cs.Domain }
        if ($partOfDomain) { [void]$reasons.Add('unido a dominio Active Directory') }
    } catch { [void]$reasons.Add('no se pudo determinar pertenencia a dominio') }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $edition = [string]$os.Caption
        if ($edition -match 'Enterprise|Education|Empresa|Educaci') { [void]$reasons.Add('edicion Enterprise/Education') }
    } catch { }
    $aad = $false
    $tenants = @()
    try {
        $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
        if (Test-Path -LiteralPath $k) {
            foreach ($j in @(Get-ChildItem -LiteralPath $k -ErrorAction Stop)) {
                $aad = $true
                try { $t = (Get-ItemProperty -LiteralPath $j.PSPath -Name TenantId -ErrorAction Stop).TenantId; if ($t) { $tenants += [string]$t } } catch { }
            }
            if ($aad) { [void]$reasons.Add('unido a Entra ID / Azure AD') }
        }
    } catch { }
    $mdm = $false
    try {
        $k = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
        if (Test-Path -LiteralPath $k) {
            foreach ($sub in @(Get-ChildItem -LiteralPath $k -ErrorAction Stop)) {
                if ($sub.PSChildName -notmatch '^[0-9A-Fa-f-]{36}$') { continue }
                $provider = $null
                try { $provider = (Get-ItemProperty -LiteralPath $sub.PSPath -Name ProviderID -ErrorAction Stop).ProviderID } catch { }
                if (Test-WpaMdmProvider $provider) { $mdm = $true }
            }
            if ($mdm) { [void]$reasons.Add('inscrito en MDM') }
        }
    } catch { }
    $gpo = $false
    try {
        if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate') { $gpo = $true; [void]$reasons.Add('politicas de Windows Update presentes') }
    } catch { }
    $managed = [bool]($partOfDomain -or $aad -or $mdm -or ($edition -match 'Enterprise|Education|Empresa|Educaci'))
    return [pscustomobject]@{
        PartOfDomain   = $partOfDomain
        DomainName     = $domainName
        AzureAdJoined  = $aad
        TenantIds      = @($tenants)
        MdmEnrolled    = $mdm
        PolicyPresent  = $gpo
        Edition        = $edition
        IsManaged      = $managed
        ManagedReasons = @($reasons)
    }
}

function Get-WpaStringHash {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $b = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$Text)) } finally { $sha.Dispose() }
    return (($b | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 16)
}

function Get-WpaTempRoot {
    # Ruta larga (sin nombres 8.3) de la carpeta temporal del usuario.
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { return $null }
    return (Join-Path $env:LOCALAPPDATA 'Temp')
}

function Get-WpaList {
    <#
      Normaliza una coleccion leida de JSON o devuelta por una sonda: descarta
      $null y objetos vacios ({}), que aparecen cuando una consulta no devuelve
      nada. Usar siempre como @(Get-WpaList $x).
    #>
    param($Value)
    foreach ($i in @($Value)) {
        if ($null -eq $i) { continue }
        if ($i -is [System.Management.Automation.PSCustomObject] -and @($i.PSObject.Properties).Count -eq 0) { continue }
        if ($i -is [System.Collections.IDictionary] -and $i.Count -eq 0) { continue }
        $i
    }
}

function Read-WpaJson {
    # Lee un JSON local. Los arreglos de nivel superior se devuelven desenrollados.
    param([string]$Path)
    $obj = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    return $obj
}

function Read-WpaJsonArray {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    return @(([IO.File]::ReadAllText($Path) | ConvertFrom-Json) | ForEach-Object { $_ })
}

#Requires -Version 5.1
<#
  lib/inventory.ps1 - Inventario (solo lectura) y reglas puras:
    - Programas instalados, evidencia de uso y candidatos a desinstalar
      (regla: > 6 meses sin uso y sin riesgo de romper otros componentes).
    - Perfil de hardware para elegir la estrategia de optimizacion.
    - Tareas y servicios huerfanos.
    - Interpretacion de la tabla de 'winget upgrade'.

  Privacidad: la evidencia de uso (Prefetch, UserAssist) se usa solo en memoria
  para calcular la fecha de ultimo uso POR PROGRAMA. No se guarda el historial.
#>

$script:WpaUnusedDays = 180

$script:WpaProtectedAppPattern = '(?i)redistributable|runtime|\.net\b|framework|directx|visual c\+\+|vc\+\+|vcredist|\bsdk\b|driver|controlador|chipset|firmware|\bbios\b|\bintel\b|\bamd\b|nvidia|geforce|radeon|realtek|synaptics|\belan\b|dolby|waves|conexant|thunderbolt|bluetooth|wi-?fi|wireless|security|seguridad|antivirus|anti-malware|defender|firewall|\bvpn\b|backup|respaldo|onedrive|dropbox|google drive|icloud|\boffice\b|microsoft 365|teams|outlook|\bedge\b|webview|windows|update|actualiza|python|\bjava\b|\bjdk\b|\bjre\b|node\.js|\bgit\b|powershell|visual studio|sql server|accessib|accesibil|password|bitwarden|1password|keepass|printer|impresora|scanner|escaner|vmware|virtualbox|hyper-v|docker|\bwsl\b|smart ?card|lector|citrix|anydesk|teamviewer|rustdesk|xampp|wamp|mamp|laragon|apache|mysql|mariadb|postgres|mongodb|sqlite|database|base de datos|servidor|\bserver\b'
$script:WpaOemPattern = '(?i)lenovo|hewlett|\bhp\b|dell|asus|acer|\bmsi\b|samsung|toshiba|dynabook|huawei|xiaomi|gigabyte|razer|alienware|microsoft surface|panasonic|fujitsu|lg electronics'

# ---------------------------------------------------------------------------
# Programas instalados
# ---------------------------------------------------------------------------

function Get-WpaInstalledApps {
    $keys = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'HKLM' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'HKLM' },
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'HKCU' }
    )
    $apps = New-Object System.Collections.ArrayList
    foreach ($k in $keys) {
        if (-not (Test-Path -LiteralPath $k.Path)) { continue }
        foreach ($sub in @(Get-ChildItem -LiteralPath $k.Path -ErrorAction SilentlyContinue)) {
            $p = $null
            try { $p = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction Stop } catch { continue }
            $name = [string](Get-WpaValue $p 'DisplayName' '')
            if (-not $name) { continue }
            if ([int](Get-WpaValue $p 'SystemComponent' 0) -eq 1) { continue }
            if ([string](Get-WpaValue $p 'ParentKeyName' '') -or [string](Get-WpaValue $p 'ReleaseType' '') -match '(?i)update|hotfix|patch') { continue }
            $installDate = $null
            $raw = [string](Get-WpaValue $p 'InstallDate' '')
            $d = [DateTime]::MinValue
            if ($raw -match '^\d{8}$' -and [DateTime]::TryParseExact($raw, 'yyyyMMdd', [Globalization.CultureInfo]::InvariantCulture, 'None', [ref]$d)) { $installDate = ConvertTo-WpaUnix $d }
            $loc = ([string](Get-WpaValue $p 'InstallLocation' '')).Trim().Trim('"').TrimEnd('\')
            if ($loc -and -not (Test-WpaPathSyntax $loc).Ok) { $loc = '' }
            if ($loc -and -not (Test-Path -LiteralPath $loc -PathType Container)) { $loc = '' }
            if (-not $installDate -and $loc) {
                try { $installDate = ConvertTo-WpaUnix ((Get-Item -LiteralPath $loc -Force).CreationTime) } catch { }
            }
            $keyPath = ('{0}\{1}' -f $k.Path, $sub.PSChildName)
            [void]$apps.Add([pscustomobject]@{
                KeyPath          = $keyPath
                KeyName          = [string]$sub.PSChildName
                Scope            = $k.Scope
                DisplayName      = $name
                DisplayVersion   = [string](Get-WpaValue $p 'DisplayVersion' '')
                Publisher        = [string](Get-WpaValue $p 'Publisher' '')
                InstallDateUnix  = $installDate
                InstallLocation  = $loc
                UninstallString  = [string](Get-WpaValue $p 'UninstallString' '')
                WindowsInstaller = ([int](Get-WpaValue $p 'WindowsInstaller' 0) -eq 1)
                NoRemove         = ([int](Get-WpaValue $p 'NoRemove' 0) -eq 1)
                EstimatedSizeMB  = [Math]::Round([double](Get-WpaValue $p 'EstimatedSize' 0) / 1024, 1)
                Fingerprint      = (Get-WpaAppFingerprint $p)
            })
        }
    }
    return $apps.ToArray()
}

function Get-WpaPrefetchIndex {
    # Requiere administrador. Devuelve { Available; CoverageDays; LastRun (exe -> DateTime) }.
    $dir = Join-Path $env:SystemRoot 'Prefetch'
    $idx = @{}
    try { $files = @(Get-ChildItem -LiteralPath $dir -Filter '*.pf' -File -ErrorAction Stop) } catch { return [pscustomobject]@{ Available = $false; CoverageDays = 0; LastRun = $idx } }
    if ($files.Count -eq 0) { return [pscustomobject]@{ Available = $false; CoverageDays = 0; LastRun = $idx } }
    $oldest = [DateTime]::MaxValue
    foreach ($f in $files) {
        $i = $f.Name.LastIndexOf('-')
        if ($i -lt 1) { continue }
        $exe = $f.Name.Substring(0, $i).ToUpperInvariant()
        if (-not $idx.ContainsKey($exe) -or $idx[$exe] -lt $f.LastWriteTime) { $idx[$exe] = $f.LastWriteTime }
        if ($f.LastWriteTime -lt $oldest) { $oldest = $f.LastWriteTime }
    }
    return [pscustomobject]@{ Available = $true; CoverageDays = [int]([DateTime]::Now - $oldest).TotalDays; LastRun = $idx }
}

function ConvertFrom-WpaRot13 {
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $Text.ToCharArray()) {
        $n = [int]$c
        if ($n -ge 65 -and $n -le 90) { $n = (($n - 65 + 13) % 26) + 65 }
        elseif ($n -ge 97 -and $n -le 122) { $n = (($n - 97 + 13) % 26) + 97 }
        [void]$sb.Append([char]$n)
    }
    return $sb.ToString()
}

function Get-WpaUserAssistIndex {
    # Ejecuciones de programas lanzados desde el Explorador (usuario actual). Solo en memoria.
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count'
    $folders = @{
        '{6D809377-6AF0-444B-8957-A3773F02200E}' = $(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles })
        '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' = ${env:ProgramFiles(x86)}
        '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' = $env:SystemRoot
        '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' = (Join-Path $env:SystemRoot 'System32')
    }
    $list = New-Object System.Collections.ArrayList
    try { $props = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).PSObject.Properties } catch { return [pscustomobject]@{ Available = $false; Items = @() } }
    foreach ($pr in $props) {
        if ($pr.Name -like 'PS*') { continue }
        $bytes = $pr.Value -as [byte[]]
        if ($null -eq $bytes -or $bytes.Length -lt 68) { continue }
        $ft = [BitConverter]::ToInt64($bytes, 60)
        if ($ft -le 0) { continue }
        $path = ConvertFrom-WpaRot13 $pr.Name
        foreach ($g in $folders.Keys) { if ($folders[$g] -and $path.StartsWith($g, [StringComparison]::OrdinalIgnoreCase)) { $path = $folders[$g] + $path.Substring($g.Length) } }
        try { [void]$list.Add([pscustomobject]@{ Path = $path; LastRun = [DateTime]::FromFileTime($ft) }) } catch { }
    }
    return [pscustomobject]@{ Available = $true; Items = $list.ToArray() }
}

function Get-WpaAppExeNames {
    # Ejecutables de la carpeta del programa (hasta 3 niveles, sin seguir enlaces). Excluye desinstaladores.
    param([string]$Folder)
    $names = New-Object System.Collections.ArrayList
    if (-not $Folder -or -not (Test-Path -LiteralPath $Folder -PathType Container)) { return @() }
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue(@((New-Object IO.DirectoryInfo($Folder)), 0))
    while ($queue.Count -gt 0 -and $names.Count -lt 300) {
        $item = $queue.Dequeue(); $dir = $item[0]; $depth = $item[1]
        try { $entries = $dir.GetFileSystemInfos() } catch { continue }
        foreach ($e in $entries) {
            if (($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            if ($e -is [IO.DirectoryInfo]) { if ($depth -lt 3) { $queue.Enqueue(@($e, ($depth + 1))) }; continue }
            if ($e.Extension -ieq '.exe' -and $e.Name -notmatch '(?i)^(unins|uninst)') { [void]$names.Add($e.Name.ToUpperInvariant()) }
        }
    }
    return @($names | Select-Object -Unique)
}

function Get-WpaNewestExeWrite {
    # Fecha (unix) del .exe modificado mas recientemente en la carpeta del programa (3 niveles, sin enlaces).
    param([string]$Folder)
    if (-not $Folder -or -not (Test-Path -LiteralPath $Folder -PathType Container)) { return $null }
    $newest = $null; $seen = 0
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue(@((New-Object IO.DirectoryInfo($Folder)), 0))
    while ($queue.Count -gt 0 -and $seen -lt 300) {
        $item = $queue.Dequeue(); $dir = $item[0]; $depth = $item[1]
        try { $entries = $dir.GetFileSystemInfos() } catch { continue }
        foreach ($e in $entries) {
            if (($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            if ($e -is [IO.DirectoryInfo]) { if ($depth -lt 3) { $queue.Enqueue(@($e, ($depth + 1))) }; continue }
            if ($e.Extension -ieq '.exe' -and $e.Name -notmatch '(?i)^(unins|uninst)') {
                $seen++
                if ($null -eq $newest -or $e.LastWriteTime -gt $newest) { $newest = $e.LastWriteTime }
            }
        }
    }
    if ($null -eq $newest) { return $null }
    return (ConvertTo-WpaUnix $newest)
}

$script:WpaUserDataFolders = @('htdocs', 'www', 'data', 'mysql\data', 'db', 'databases', 'database', 'projects', 'proyectos', 'workspace', 'saves', 'userdata', 'backups', 'vault')

function Test-WpaAppHasUserData {
    <#
      True si la carpeta del programa contiene subcarpetas tipicas de datos del
      usuario con archivos (sitios web locales, bases de datos, proyectos,
      partidas guardadas). Su desinstalador podria borrarlos. Solo lectura.
    #>
    param([string]$Folder)
    if (-not $Folder -or -not (Test-Path -LiteralPath $Folder -PathType Container)) { return $false }
    foreach ($sub in $script:WpaUserDataFolders) {
        $p = Join-Path $Folder $sub
        if (-not (Test-Path -LiteralPath $p -PathType Container)) { continue }
        try {
            $first = [IO.Directory]::EnumerateFiles($p, '*', [IO.SearchOption]::TopDirectoryOnly).GetEnumerator()
            if ($first.MoveNext()) { return $true }
            $dirs = [IO.Directory]::EnumerateDirectories($p).GetEnumerator()
            if ($dirs.MoveNext()) { return $true }
        } catch { return $true }
    }
    return $false
}

function Get-WpaPinnedTargets {
    # Destinos de accesos directos anclados a la barra de tareas (solo lectura; CreateShortcut no guarda nada).
    $dir = Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'
    $out = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $dir)) { return @() }
    try { $shell = New-Object -ComObject WScript.Shell } catch { return @() }
    foreach ($l in @(Get-ChildItem -LiteralPath $dir -Filter '*.lnk' -File -ErrorAction SilentlyContinue)) {
        try { $t = [string]$shell.CreateShortcut($l.FullName).TargetPath; if ($t) { [void]$out.Add($t) } } catch { }
    }
    return $out.ToArray()
}

function Get-WpaAppUsage {
    <#
      Ultimo uso de un programa a partir de Prefetch (alta) y UserAssist (media).
      Si no hay rastro y Prefetch cubre >= 180 dias, se concluye "sin ejecuciones"
      con evidencia alta. En cualquier otro caso: evidencia desconocida.
    #>
    param($App, $Prefetch, $UserAssist)
    $loc = [string](Get-WpaValue $App 'InstallLocation' '')
    $res = [ordered]@{ LastUseUnix = $null; Source = 'ninguna'; Evidence = 'desconocida'; NoRunsInCoverageDays = $null; ExeCount = 0 }
    if (-not $loc) { return [pscustomobject]$res }
    $exes = @(Get-WpaAppExeNames $loc)
    $res.ExeCount = $exes.Count
    $last = $null
    if ($Prefetch -and $Prefetch.Available) {
        foreach ($x in $exes) { if ($Prefetch.LastRun.ContainsKey($x) -and ($null -eq $last -or $Prefetch.LastRun[$x] -gt $last)) { $last = $Prefetch.LastRun[$x]; $res.Source = 'Prefetch' } }
    }
    if ($UserAssist -and $UserAssist.Available) {
        foreach ($u in $UserAssist.Items) {
            if (Test-WpaIsUnder $u.Path $loc) {
                if ($null -eq $last -or $u.LastRun -gt $last) { $last = $u.LastRun; if ($res.Source -eq 'ninguna') { $res.Source = 'UserAssist' } }
            }
        }
    }
    if ($null -ne $last) {
        $res.LastUseUnix = ConvertTo-WpaUnix $last
        $res.Evidence = $(if ($Prefetch -and $Prefetch.Available) { 'alta' } else { 'media' })
    } elseif ($Prefetch -and $Prefetch.Available -and $exes.Count -gt 0) {
        $res.NoRunsInCoverageDays = [int]$Prefetch.CoverageDays
        if ($Prefetch.CoverageDays -ge $script:WpaUnusedDays) { $res.Evidence = 'alta'; $res.Source = 'Prefetch (sin ejecuciones)' }
    }
    # Contraevidencia: muchas apps solo se actualizan mientras se ejecutan. Ejecutables
    # modificados en los ultimos 180 dias contradicen "sin uso" aunque Prefetch no lo registre.
    $res.NewestExeWriteUnix = Get-WpaNewestExeWrite $loc
    $res.RecentlyUpdated = ($null -ne $res.NewestExeWriteUnix -and $res.NewestExeWriteUnix -gt ((Get-WpaUnixNow) - ($script:WpaUnusedDays * 86400)))
    return [pscustomobject]$res
}

function Test-WpaUninstallCandidate {
    <#
      Regla pura de desinstalacion segura. Elegible solo si TODO se cumple:
        1. Desinstalador oficial valido.
        2. Carpeta de instalacion conocida (para verificar uso y dependencias).
        3. Instalado hace >= 180 dias.
        4. Evidencia alta/media de que no se usa hace >= 180 dias.
        5. No es runtime, driver, utilidad del fabricante, seguridad, sincronizacion,
           respaldo, VPN, acceso remoto, herramienta de desarrollo ni de Microsoft.
        6. Sin procesos en ejecucion, servicios o drivers en su carpeta, carpeta
           compartida con otro programa ni entrada de inicio habilitada.
    #>
    param($App, $Context)
    $reasons = New-Object System.Collections.ArrayList
    $now = [int64](Get-WpaValue $Context 'NowUnix' (Get-WpaUnixNow))
    $limit = $now - ($script:WpaUnusedDays * 86400)
    $name = [string](Get-WpaValue $App 'DisplayName' '')
    $pub = [string](Get-WpaValue $App 'Publisher' '')
    if (-not [bool](Get-WpaValue $App 'Uninstall.Ok' $false)) { [void]$reasons.Add('sin desinstalador oficial valido: ' + [string](Get-WpaValue $App 'Uninstall.Reason' '')) }
    if (-not [string](Get-WpaValue $App 'InstallLocation' '')) { [void]$reasons.Add('sin carpeta de instalacion: uso y dependencias no verificables') }
    $inst = Get-WpaValue $App 'InstallDateUnix'
    if ($null -eq $inst) { [void]$reasons.Add('fecha de instalacion desconocida') }
    elseif ([int64]$inst -gt $limit) { [void]$reasons.Add('instalado hace menos de 6 meses') }
    $ev = [string](Get-WpaValue $App 'Usage.Evidence' 'desconocida')
    $last = Get-WpaValue $App 'Usage.LastUseUnix'
    if ($ev -eq 'desconocida') { [void]$reasons.Add('uso desconocido: no hay evidencia suficiente') }
    elseif ($null -ne $last -and [int64]$last -gt $limit) { [void]$reasons.Add(('usado hace {0} dias' -f [int](($now - [int64]$last) / 86400))) }
    elseif ($null -eq $last -and [int](Get-WpaValue $App 'Usage.NoRunsInCoverageDays' 0) -lt $script:WpaUnusedDays) { [void]$reasons.Add('cobertura de evidencia menor a 6 meses') }
    if ([bool](Get-WpaValue $App 'Usage.RecentlyUpdated' $false)) { [void]$reasons.Add('se actualizo en los ultimos 6 meses (indica que se ejecuto)') }
    if ([bool](Get-WpaValue $App 'Signals.HasUserData' $false)) { [void]$reasons.Add('guarda datos del usuario en su carpeta (bases de datos, sitios, proyectos): desinstalarlo podria borrarlos') }
    if ([bool](Get-WpaValue $App 'Signals.Pinned' $false)) { [void]$reasons.Add('anclado a la barra de tareas (el usuario lo mantiene a mano)') }
    if ($name -match $script:WpaProtectedAppPattern -or $pub -match $script:WpaProtectedAppPattern) { [void]$reasons.Add('categoria protegida (runtime, driver, seguridad, sincronizacion, desarrollo...)') }
    if ($pub -match '(?i)^microsoft') { [void]$reasons.Add('publicado por Microsoft') }
    if ($pub -match $script:WpaOemPattern -or ($Context -and [string](Get-WpaValue $Context 'OemManufacturer' '') -and $pub -match [regex]::Escape(([string]$Context.OemManufacturer).Split(' ')[0]))) {
        [void]$reasons.Add('utilidad del fabricante del equipo (teclas, ventiladores, bateria)')
    }
    if ([bool](Get-WpaValue $App 'Signals.RunningNow' $false)) { [void]$reasons.Add('tiene procesos en ejecucion') }
    if ([bool](Get-WpaValue $App 'Signals.HasServiceOrDriver' $false)) { [void]$reasons.Add('tiene servicios o drivers instalados') }
    if ([bool](Get-WpaValue $App 'Signals.SharedFolder' $false)) { [void]$reasons.Add('comparte carpeta con otro programa') }
    if ([bool](Get-WpaValue $App 'Signals.StartupEnabled' $false)) { [void]$reasons.Add('se inicia con Windows (en uso en segundo plano)') }
    return [pscustomobject]@{ Eligible = ($reasons.Count -eq 0); Reasons = $reasons.ToArray() }
}

function Get-WpaAppInventory {
    <#
      Inventario completo con evidencia de uso y senales de dependencia.
      Solo lectura. Prefetch requiere administrador; sin el, la evidencia se
      limita a UserAssist (media) y mas programas quedaran como "uso desconocido".
    #>
    param($Startup = @())
    $apps = @(Get-WpaInstalledApps)
    $pf = Get-WpaPrefetchIndex
    $ua = Get-WpaUserAssistIndex
    $procPaths = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Path } catch { $null } } | Where-Object { $_ })
    $svcExes = @()
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) { $e = Get-WpaServiceExe $s.PathName; if ($e) { $svcExes += $e } }
    foreach ($s in @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue)) { $e = Get-WpaServiceExe $s.PathName; if ($e) { $svcExes += ($e -replace '^\\\?\?\\', '') } }
    $enabledStartup = @($Startup | Where-Object { $_.State -ne 'Deshabilitado' -and $_.ExecutablePath } | ForEach-Object { [string]$_.ExecutablePath })
    $pinnedTargets = @(Get-WpaPinnedTargets)
    $out = New-Object System.Collections.ArrayList
    foreach ($a in $apps) {
        $loc = $a.InstallLocation
        $running = $false; $svc = $false; $shared = $false; $startupOn = $false; $pinnedOn = $false
        if ($loc) {
            foreach ($p in $procPaths) { if (Test-WpaIsUnder $p $loc) { $running = $true; break } }
            foreach ($e in $svcExes) { if (Test-WpaIsUnder $e $loc) { $svc = $true; break } }
            foreach ($o in $apps) {
                if ($o.KeyPath -eq $a.KeyPath -or -not $o.InstallLocation) { continue }
                if ($o.InstallLocation -ieq $loc -or (Test-WpaIsUnder $o.InstallLocation $loc) -or (Test-WpaIsUnder $loc $o.InstallLocation)) { $shared = $true; break }
            }
            foreach ($x in $enabledStartup) { if (Test-WpaIsUnder $x $loc) { $startupOn = $true; break } }
            foreach ($x in $pinnedTargets) { if (Test-WpaIsUnder $x $loc) { $pinnedOn = $true; break } }
        }
        $a | Add-Member -NotePropertyName Usage -NotePropertyValue (Get-WpaAppUsage -App $a -Prefetch $pf -UserAssist $ua)
        $a | Add-Member -NotePropertyName Signals -NotePropertyValue ([pscustomobject]@{ RunningNow = $running; HasServiceOrDriver = $svc; SharedFolder = $shared; StartupEnabled = $startupOn; Pinned = $pinnedOn; HasUserData = (Test-WpaAppHasUserData $loc) })
        $a | Add-Member -NotePropertyName Uninstall -NotePropertyValue (Resolve-WpaUninstallCommand $a)
        [void]$out.Add($a)
    }
    return [pscustomobject]@{
        PrefetchAvailable   = [bool]$pf.Available
        PrefetchCoverageDays = [int]$pf.CoverageDays
        UserAssistAvailable = [bool]$ua.Available
        Count               = $out.Count
        Items               = $out.ToArray()
        Note                = 'Evidencia de uso calculada por programa; no se guarda historial de ejecuciones.'
    }
}

# ---------------------------------------------------------------------------
# Huerfanos
# ---------------------------------------------------------------------------

function Get-WpaOrphanTasks {
    $list = New-Object System.Collections.ArrayList
    foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        if ($t.TaskPath -like '\Microsoft\*' -or [string]$t.State -eq 'Disabled') { continue }
        foreach ($a in @($t.Actions)) {
            $ex = $null
            try { $ex = [string]$a.Execute } catch { }
            if (-not $ex) { continue }
            $exe = [Environment]::ExpandEnvironmentVariables($ex.Trim().Trim('"'))
            if ($exe.Contains('%') -or -not [IO.Path]::IsPathRooted($exe)) { continue }
            if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
                [void]$list.Add([pscustomobject]@{ FullPath = ($t.TaskPath + $t.TaskName); TaskPath = $t.TaskPath; TaskName = $t.TaskName; Execute = $exe; State = [string]$t.State })
                break
            }
        }
    }
    return $list.ToArray()
}

function Get-WpaOrphanServices {
    $list = New-Object System.Collections.ArrayList
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) {
        if ([string]$s.State -ne 'Stopped' -or [string]$s.StartMode -notin @('Auto', 'Manual')) { continue }
        $exe = Get-WpaServiceExe $s.PathName
        if (-not $exe -or -not [IO.Path]::IsPathRooted($exe)) { continue }
        if (Test-WpaIsUnder $exe $env:SystemRoot) { continue }
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
            [void]$list.Add([pscustomobject]@{ Name = [string]$s.Name; DisplayName = [string]$s.DisplayName; StartMode = [string]$s.StartMode; Exe = $exe })
        }
    }
    return $list.ToArray()
}

# ---------------------------------------------------------------------------
# Perfil de hardware
# ---------------------------------------------------------------------------

function Test-WpaOptaneHybrid {
    <#
      Volumen HDD acelerado con Intel Optane mediante RST: Windows expone un disco
      virtual con MediaType = SSD y BusType = RAID. No es un SSD real.
    #>
    param([string]$FriendlyName, [string]$BusType)
    return (($FriendlyName -match '(?i)optane' -and ($FriendlyName -match '(?i)hdd' -or $BusType -eq 'RAID')) -or
            ($BusType -eq 'RAID' -and $FriendlyName -match '(?i)hdd'))
}

function Get-WpaHardwareProfile {
    <#
      Clasifica el equipo para orientar la optimizacion segun sus componentes.
      Logica pura sobre baseline/hardware-health.
    #>
    param($Baseline, $Hardware = $null)
    $sysNum = [string](Get-WpaValue $Baseline 'SystemDiskNumber' '')
    $disk = @(Get-WpaList (Get-WpaValue $Baseline 'Disks' @())) | Where-Object { [string]$_.DeviceId -eq $sysNum } | Select-Object -First 1
    $media = [string](Get-WpaValue $disk 'MediaType' ''); $bus = [string](Get-WpaValue $disk 'BusType' '')
    $fname = [string](Get-WpaValue $disk 'FriendlyName' '')
    $storage = if (Test-WpaOptaneHybrid -FriendlyName $fname -BusType $bus) { 'HDD-Optane' }
               elseif ($media -eq 'HDD') { 'HDD' } elseif ($bus -eq 'NVMe') { 'NVMe' } elseif ($media -eq 'SSD') { 'SSD' } else { 'desconocido' }
    $mechanical = ($storage -in @('HDD', 'HDD-Optane'))
    $ram = [double](Get-WpaValue $Baseline 'OS.TotalRamGB' 0)
    $ramTier = if ($ram -le 0) { 'desconocido' } elseif ($ram -lt 7.5) { 'bajo' } elseif ($ram -lt 15.5) { 'medio' } else { 'alto' }
    $lp = [int](Get-WpaValue $Baseline 'CPU.LogicalProcessors' 0)
    $cpuTier = if ($lp -le 0) { 'desconocido' } elseif ($lp -le 4) { 'bajo' } elseif ($lp -le 8) { 'medio' } else { 'alto' }
    $form = [string](Get-WpaValue $Baseline 'Computer.FormFactor' '')
    if (-not $form) { $form = if ([bool](Get-WpaValue $Hardware 'Battery.Present' $false)) { 'portatil' } else { 'desconocido' } }
    $gpuNames = @(Get-WpaList (Get-WpaValue $Baseline 'GPU' @()) | ForEach-Object { [string](Get-WpaValue $_ 'Name' '') } | Where-Object { $_ })
    $dedicated = @($gpuNames | Where-Object { $_ -match '(?i)geforce|rtx|gtx|quadro|radeon (rx|pro)|\barc\b' }).Count -gt 0
    $gpu = if ($gpuNames.Count -eq 0) { 'desconocido' } elseif ($dedicated) { 'dedicada' } else { 'integrada' }
    $strategy = New-Object System.Collections.ArrayList
    switch ($storage) {
        'HDD' { [void]$strategy.Add('Disco mecanico: es el principal cuello de botella. Prioridad: recortar inicio y segundo plano, desfragmentar, liberar espacio. La mayor mejora posible es migrar a SSD.') }
        'HDD-Optane' { [void]$strategy.Add('HDD acelerado con Intel Optane (RST): sigue siendo un disco mecanico con cache. Windows lo reporta como SSD, pero no se aplica TRIM ni desfragmentacion (la cache la gestiona RST). Prioridad: recortar inicio y segundo plano. La mayor mejora posible es migrar a un SSD real.') }
        { $_ -in @('SSD', 'NVMe') } { [void]$strategy.Add('SSD: aplicar TRIM, nunca desfragmentar. El disco rara vez es el cuello de botella; enfocar en RAM, CPU y programas.') }
        default { [void]$strategy.Add('Tipo de disco no determinado: no se proponen optimizaciones de disco.') }
    }
    if ($ramTier -eq 'bajo') { [void]$strategy.Add('RAM baja: recortar programas de inicio, reducir efectos visuales, desinstalar lo que no se usa y evaluar ampliacion de memoria.') }
    elseif ($ramTier -eq 'medio') { [void]$strategy.Add('RAM media: suficiente para uso general; vigilar navegador con muchas pestanas y programas residentes.') }
    if ($cpuTier -eq 'bajo') { [void]$strategy.Add('CPU limitada: reducir efectos visuales, evitar tareas en segundo plano y mantener plan Equilibrado.') }
    if ($form -eq 'portatil') { [void]$strategy.Add('Portatil: mantener hibernacion y plan Equilibrado; revisar bateria, temperatura y cargador original.') }
    elseif ($form -eq 'escritorio') { [void]$strategy.Add('Escritorio: la hibernacion y el inicio rapido son prescindibles y pueden liberar espacio.') }
    if ($gpu -eq 'integrada' -and $ramTier -ne 'alto') { [void]$strategy.Add('GPU integrada: usa memoria RAM compartida; reducir efectos visuales ayuda.') }
    $lowEnd = $mechanical -or ($ramTier -eq 'bajo') -or ($cpuTier -eq 'bajo')
    return [pscustomobject]@{
        StorageClass = $storage; IsMechanical = $mechanical; RamGB = $ram; RamTier = $ramTier; LogicalProcessors = $lp; CpuTier = $cpuTier
        FormFactor = $form; GpuClass = $gpu; LowEnd = $lowEnd; Strategy = $strategy.ToArray()
    }
}

# ---------------------------------------------------------------------------
# winget
# ---------------------------------------------------------------------------

function ConvertFrom-WpaWingetTable {
    <#
      Interpreta la tabla de 'winget upgrade' sin depender del idioma: usa la
      linea de guiones y las posiciones de columna del encabezado.
      Devuelve { Name; Id; Version; Available }.
    #>
    param([string[]]$Lines)
    $clean = @($Lines | ForEach-Object { $s = [string]$_; $i = $s.LastIndexOf("`r"); if ($i -ge 0) { $s = $s.Substring($i + 1) }; $s.TrimEnd() })
    $dash = -1
    for ($i = 1; $i -lt $clean.Count; $i++) { if ($clean[$i] -match '^-{10,}$') { $dash = $i; break } }
    if ($dash -lt 1) { return @() }
    $header = $clean[$dash - 1]
    $starts = @([regex]::Matches($header, '\S+') | ForEach-Object { $_.Index })
    if ($starts.Count -lt 4) { return @() }
    $rows = New-Object System.Collections.ArrayList
    for ($i = $dash + 1; $i -lt $clean.Count; $i++) {
        $l = $clean[$i]
        if ([string]::IsNullOrWhiteSpace($l) -or $l.Length -le $starts[3]) { break }
        $cut = {
            param($a, $b)
            if ($a -ge $l.Length) { return '' }
            if ($null -eq $b -or $b -gt $l.Length) { return $l.Substring($a).Trim() }
            return $l.Substring($a, $b - $a).Trim()
        }
        $id = & $cut $starts[1] $starts[2]
        if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9.\-_+]{1,120}$') { continue }
        $endAvail = if ($starts.Count -gt 4) { $starts[4] } else { $null }
        [void]$rows.Add([pscustomobject]@{
            Name = (& $cut 0 $starts[1]); Id = $id; Version = (& $cut $starts[2] $starts[3]); Available = (& $cut $starts[3] $endAvail)
        })
    }
    return $rows.ToArray()
}

# ---------------------------------------------------------------------------
# Apps de la Tienda en segundo plano
# ---------------------------------------------------------------------------

$script:WpaBackgroundKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
# Componentes del sistema, runtimes, controladores y seguridad: nunca se proponen.
$script:WpaProtectedPackagePattern = '(?i)^(Microsoft\.Windows|MicrosoftWindows\.|Windows\.|Microsoft\.UI\.|Microsoft\.VCLibs|Microsoft\.NET|Microsoft\.Services\.Store|Microsoft\.SecHealthUI|Microsoft\.WindowsStore|Microsoft\.DesktopAppInstaller|MicrosoftCorporationII\.WinAppRuntime|Microsoft\.WindowsAppRuntime|Microsoft\.WidgetsPlatformRuntime|Microsoft\.LanguageExperiencePack|Microsoft\.AAD|Microsoft\.AccountsControl|Microsoft\.LockApp|Microsoft\.Win32WebViewHost|Microsoft\.WebView)|intel|amd|nvidia|realtek|audio|senary|dolby|waves|synaptics|elan|lenovo|hp\.|dell|asus|security|defender|antivirus|vpn|onedrive'

function ConvertTo-WpaPackageFamilyName {
    # 'Nombre_Version_Arq__IdPublicador' -> 'Nombre_IdPublicador'
    param([string]$FolderName)
    $m = [regex]::Match($FolderName, '^([A-Za-z0-9.\-]+)_[^_]*_[^_]*_[^_]*_([a-z0-9]{13})$')
    if (-not $m.Success) { return $null }
    return ('{0}_{1}' -f $m.Groups[1].Value, $m.Groups[2].Value)
}

function ConvertFrom-WpaWindowsAppsPath {
    # 'C:\Program Files\WindowsApps\<carpeta del paquete>\app.exe' -> PFN. Busqueda literal, sin regex.
    param([string]$Path)
    if (-not $Path) { return $null }
    $marker = '\WindowsApps\'
    $i = $Path.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase)
    if ($i -lt 0) { return $null }
    $folder = $Path.Substring($i + $marker.Length).Split([char]92)[0]
    return (ConvertTo-WpaPackageFamilyName $folder)
}

function Test-WpaPackageFamilyName {
    param([string]$Pfn)
    return ($Pfn -match '^[A-Za-z0-9.\-]{2,100}_[a-z0-9]{13}$')
}

function Get-WpaBackgroundStoreApps {
    <#
      Apps empaquetadas con procesos SIN ventana (ejecutandose en segundo plano)
      en el momento de la recoleccion. Solo lectura.
    #>
    $groups = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $path = $null
        try { $path = $p.Path } catch { }
        $pfn = ConvertFrom-WpaWindowsAppsPath $path
        if (-not $pfn) { continue }
        if (-not $groups.ContainsKey($pfn)) { $groups[$pfn] = @{ Pfn = $pfn; Processes = @(); Windowed = $false; PrivateMB = 0.0 } }
        $g = $groups[$pfn]
        $g.Processes += $p.ProcessName
        $g.PrivateMB += [double]$p.PrivateMemorySize64 / 1MB
        if ($p.MainWindowHandle -ne [IntPtr]::Zero) { $g.Windowed = $true }
    }
    $out = New-Object System.Collections.ArrayList
    foreach ($g in $groups.Values) {
        $key = Join-Path $script:WpaBackgroundKey $g.Pfn
        $disabled = $null
        if (Test-Path -LiteralPath $key) {
            $d = Get-WpaRegValue $key 'Disabled'
            $disabled = ($d.Exists -and [int]$d.Value -eq 1)
        }
        [void]$out.Add([pscustomobject]@{
            Pfn          = $g.Pfn
            Processes    = @($g.Processes | Select-Object -Unique)
            PrivateMB    = [Math]::Round($g.PrivateMB, 0)
            HasWindow    = $g.Windowed
            KeyExists    = (Test-Path -LiteralPath $key)
            Disabled     = $disabled
            Protected    = ($g.Pfn -match $script:WpaProtectedPackagePattern)
        })
    }
    return $out.ToArray()
}

# ---------------------------------------------------------------------------
# Deteccion de fugas de memoria (muestreo en el tiempo, solo lectura)
# ---------------------------------------------------------------------------

function Measure-WpaMemoryGrowth {
    <#
      Toma muestras de memoria privada de los procesos de mayor consumo durante
      $Minutes minutos. Sospecha de fuga: crecimiento >= 200 MB, ritmo >= 10 MB/min
      y crecimiento en al menos 80% de los intervalos, sin reiniciar el proceso.
    #>
    param([int]$Minutes = 5, [int]$IntervalSeconds = 30, [int]$Top = 20)
    $tracked = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue | Sort-Object PrivateMemorySize64 -Descending | Select-Object -First $Top)) {
        $start = $null; try { $start = $p.StartTime } catch { }
        $tracked[$p.Id] = @{ Name = $p.ProcessName; Start = $start; Samples = New-Object System.Collections.ArrayList }
        [void]$tracked[$p.Id].Samples.Add([double]$p.PrivateMemorySize64 / 1MB)
    }
    $rounds = [Math]::Max(1, [int](($Minutes * 60) / $IntervalSeconds))
    for ($i = 0; $i -lt $rounds; $i++) {
        Start-Sleep -Seconds $IntervalSeconds
        foreach ($id in @($tracked.Keys)) {
            $p = Get-Process -Id $id -ErrorAction SilentlyContinue
            $st = $null; if ($p) { try { $st = $p.StartTime } catch { } }
            if (-not $p -or ($tracked[$id].Start -and $st -and $st -ne $tracked[$id].Start)) { $tracked.Remove($id); continue }
            [void]$tracked[$id].Samples.Add([double]$p.PrivateMemorySize64 / 1MB)
        }
    }
    $suspects = New-Object System.Collections.ArrayList
    $all = New-Object System.Collections.ArrayList
    foreach ($id in $tracked.Keys) {
        $s = $tracked[$id].Samples
        if ($s.Count -lt 3) { continue }
        $growth = $s[$s.Count - 1] - $s[0]
        $ups = 0; for ($j = 1; $j -lt $s.Count; $j++) { if ($s[$j] -gt $s[$j - 1]) { $ups++ } }
        $mono = [Math]::Round(100 * $ups / ($s.Count - 1), 0)
        $rate = [Math]::Round($growth / [Math]::Max(1, $Minutes), 1)
        $row = [pscustomobject]@{ Name = $tracked[$id].Name; Id = $id; StartMB = [Math]::Round($s[0], 0); EndMB = [Math]::Round($s[$s.Count - 1], 0); GrowthMB = [Math]::Round($growth, 0); RateMBPerMin = $rate; GrowingIntervalsPct = $mono }
        [void]$all.Add($row)
        if ($growth -ge 200 -and $rate -ge 10 -and $mono -ge 80) { [void]$suspects.Add($row) }
    }
    return [pscustomobject]@{ Minutes = $Minutes; Tracked = $all.Count; Suspects = $suspects.ToArray(); Top = @($all | Sort-Object GrowthMB -Descending | Select-Object -First 5) }
}

function Test-WpaLeakSuspect {
    # Regla pura (usada por las pruebas y por Measure-WpaMemoryGrowth).
    param([double[]]$Samples, [double]$Minutes)
    if ($Samples.Count -lt 3) { return $false }
    $growth = $Samples[$Samples.Count - 1] - $Samples[0]
    $ups = 0; for ($j = 1; $j -lt $Samples.Count; $j++) { if ($Samples[$j] -gt $Samples[$j - 1]) { $ups++ } }
    return ($growth -ge 200 -and ($growth / [Math]::Max(1, $Minutes)) -ge 10 -and (100 * $ups / ($Samples.Count - 1)) -ge 80)
}

# ---------------------------------------------------------------------------
# Inicio de apps empaquetadas (StartupTask) y culpables del arranque
# ---------------------------------------------------------------------------

$script:WpaPackagedStartupBase = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData'

function Test-WpaPackagedStartupTarget {
    # Objetivo con formato '<PackageFamilyName>\<TaskId>'.
    param([string]$Target)
    $parts = $Target.Split([char]92)
    return ($parts.Count -eq 2 -and (Test-WpaPackageFamilyName $parts[0]) -and $parts[1] -match '^[A-Za-z0-9._\-]{1,100}$')
}

function Get-WpaPackagedStartupTasks {
    <#
      Tareas de inicio de apps de la Tienda (las que muestra el Administrador de
      tareas en la pestana Inicio). State: 0 deshabilitada, 1 deshabilitada por
      el usuario, 2 habilitada, 3/4 por politica. Solo lectura.
    #>
    $out = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $script:WpaPackagedStartupBase)) { return @() }
    foreach ($pkg in @(Get-ChildItem -LiteralPath $script:WpaPackagedStartupBase -ErrorAction SilentlyContinue)) {
        if (-not (Test-WpaPackageFamilyName $pkg.PSChildName)) { continue }
        foreach ($task in @(Get-ChildItem -LiteralPath $pkg.PSPath -ErrorAction SilentlyContinue)) {
            $st = Get-WpaRegValue $task.PSPath 'State'
            if (-not $st.Exists) { continue }
            [void]$out.Add([pscustomobject]@{
                Target    = ('{0}\{1}' -f $pkg.PSChildName, $task.PSChildName)
                Pfn       = $pkg.PSChildName
                TaskId    = $task.PSChildName
                State     = [int]$st.Value
                Enabled   = ([int]$st.Value -eq 2)
                Protected = ($pkg.PSChildName -match $script:WpaProtectedPackagePattern)
            })
        }
    }
    return $out.ToArray()
}

function Get-WpaBootDegradation {
    <#
      Elementos que Windows identifico como causantes de arranques lentos
      (Diagnostics-Performance 101-110). Requiere administrador. Solo lectura.
    #>
    param([int]$Days = 30)
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 101..110; StartTime = (Get-Date).AddDays(-$Days) } -MaxEvents 500 -ErrorAction Stop)
    $rows = foreach ($e in $ev) {
        $x = [xml]$e.ToXml(); $d = @{}
        foreach ($n in @($x.Event.EventData.Data)) { $d[[string]$n.Name] = [string]$n.InnerText }
        $item = @($d['FriendlyName'], $d['Name'], $d['FileName']) | Where-Object { $_ } | Select-Object -First 1
        if ($item) { [pscustomobject]@{ Item = $item; DegMs = [double]$d['DegradationTime'] } }
    }
    return @(@($rows) | Group-Object Item | ForEach-Object {
        [pscustomobject]@{ Item = $_.Name; Count = $_.Count; AvgDegradationSec = [Math]::Round((($_.Group | Measure-Object DegMs -Average).Average) / 1000, 1) }
    } | Sort-Object AvgDegradationSec -Descending | Select-Object -First 10)
}

# ---------------------------------------------------------------------------
# WHEA: clasificacion por componente y gravedad
# ---------------------------------------------------------------------------

function Get-WpaWheaComponent {
    # Logica pura: componente a partir del texto del evento (ingles o espanol).
    param([string]$Message)
    if ($Message -match '(?i)PCI ?Express|PCIe') { return 'PCIe' }
    if ($Message -match '(?i)Memor') { return 'Memoria' }
    if ($Message -match '(?i)Processor|Procesador|Core|Cache|Bus/Interconnect|Interconexi') { return 'CPU' }
    return 'Otro'
}

function Get-WpaWheaSummary {
    <#
      Agrupa eventos WHEA-Logger por Id, componente y gravedad; calcula rango de
      fechas y tasa diaria; para errores PCIe identifica el dispositivo del
      puerto y sus dispositivos hijos (p. ej. la tarjeta Wi-Fi). Solo lectura.
    #>
    param([int]$Days = 30, [int]$Max = 5000)
    $ev = @()
    try { $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = (Get-Date).AddDays(-$Days) } -MaxEvents $Max -ErrorAction Stop) } catch { $ev = @() }
    if ($ev.Count -eq 0) { return [pscustomobject]@{ Total = 0; Groups = @(); PcieCorrected = 0; MemoryCorrected = 0; CpuCorrected = 0; Fatal = 0; PerDay = 0; Capped = $false } }
    $groups = @{}
    foreach ($e in $ev) {
        $msg = [string]$e.Message
        $comp = Get-WpaWheaComponent $msg
        $fatal = ($e.Level -in @(1, 2))
        $vd = [regex]::Match($msg, '0x([0-9A-Fa-f]{4}):0x([0-9A-Fa-f]{4})')
        $venDev = if ($vd.Success) { ('{0}:{1}' -f $vd.Groups[1].Value.ToUpperInvariant(), $vd.Groups[2].Value.ToUpperInvariant()) } else { '' }
        $key = '{0}|{1}|{2}|{3}' -f $e.Id, $comp, $fatal, $venDev
        if (-not $groups.ContainsKey($key)) { $groups[$key] = @{ Id = [int]$e.Id; Component = $comp; Fatal = $fatal; VenDev = $venDev; Count = 0 } }
        $groups[$key].Count++
    }
    $first = ($ev | Measure-Object -Property TimeCreated -Minimum).Minimum
    $last = ($ev | Measure-Object -Property TimeCreated -Maximum).Maximum
    $spanDays = [Math]::Max(1, ($last - $first).TotalDays)
    $rows = foreach ($g in $groups.Values) {
        $port = ''; $children = @()
        if ($g.Component -eq 'PCIe' -and $g.VenDev) {
            $ven, $dev = $g.VenDev.Split(':')
            try {
                $pd = Get-PnpDevice -InstanceId ('PCI\VEN_{0}&DEV_{1}*' -f $ven, $dev) -ErrorAction Stop | Select-Object -First 1
                $port = [string]$pd.FriendlyName
                $kids = (Get-PnpDeviceProperty -InstanceId $pd.InstanceId -KeyName 'DEVPKEY_Device_Children' -ErrorAction Stop).Data
                foreach ($k in @($kids)) { try { $children += [string](Get-PnpDevice -InstanceId $k -ErrorAction Stop).FriendlyName } catch { } }
            } catch { }
        }
        [pscustomobject]@{ Id = $g.Id; Component = $g.Component; Fatal = $g.Fatal; Count = $g.Count; VenDev = $g.VenDev; Device = $port; ChildDevices = @($children | Where-Object { $_ }) }
    }
    $rows = @($rows | Sort-Object Count -Descending)
    $sum = { param($filter) $n = 0; foreach ($r in $rows) { if (& $filter $r) { $n += $r.Count } }; $n }
    return [pscustomobject]@{
        Total           = $ev.Count
        Capped          = ($ev.Count -ge $Max)
        FirstUnix       = (ConvertTo-WpaUnix $first)
        LastUnix        = (ConvertTo-WpaUnix $last)
        SpanDays        = [Math]::Round($spanDays, 1)
        PerDay          = [Math]::Round($ev.Count / $spanDays, 1)
        Groups          = $rows
        PcieCorrected   = (& $sum { param($r) $r.Component -eq 'PCIe' -and -not $r.Fatal })
        MemoryCorrected = (& $sum { param($r) $r.Component -eq 'Memoria' -and -not $r.Fatal })
        CpuCorrected    = (& $sum { param($r) $r.Component -eq 'CPU' -and -not $r.Fatal })
        Fatal           = (& $sum { param($r) $r.Fatal })
    }
}

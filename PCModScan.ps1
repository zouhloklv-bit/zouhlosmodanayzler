<#
.SYNOPSIS
    Whole-PC scanner for Minecraft cheat clients and suspicious mod jars.

.DESCRIPTION
    DEFAULT: scans your Minecraft mods folder(s). It asks for a path (press Enter
    to auto-detect: .minecraft, Prism/Modrinth/CurseForge/ATLauncher instances and
    the folder of the game that is currently running).
    With -WholePC it instead walks every fixed drive (or the -Roots you give it).

    Opens each .jar as a zip
    and looks for cheat-client packages, cheat module names, obfuscation
    patterns and malware-style behaviour (webhooks, credential files, runtime
    exec, hidden downloads). Also scans the Recycle Bin for deleted jars and
    checks the running Java process for agents/injection flags.

    LOCAL ONLY. Nothing leaves your PC unless you pass -OnlineVerify, which
    sends the SHA1 hash (not the file) of FLAGGED jars to the Modrinth API to
    weed out false positives.

    A flag means "look at this", not "this person cheated". Name matching can
    be evaded by renaming/obfuscating, so a clean result is not proof.

.PARAMETER ModsPath
    Mods folder (or instance folder) to scan. Skips the prompt.

.PARAMETER WholePC
    Scan every fixed drive instead of just the Minecraft mods folder(s).

.PARAMETER Roots
    Folders/drives to scan (implies whole-PC style scan).

.PARAMETER IncludeLibraries
    Also scan folders named libraries/runtime/jre/jdk/.gradle/.m2 (skipped by default for speed).

.PARAMETER OnlineVerify
    Look up flagged jars by SHA1 on Modrinth and downgrade known mods.

.PARAMETER MaxSizeMB
    Skip jars bigger than this (default 200).

.PARAMETER ReportPath
    Where to save the text report (default: Desktop).

.EXAMPLE
    .\PCModScan.ps1
.EXAMPLE
    .\PCModScan.ps1 -ModsPath "$env:APPDATA\.minecraft\mods"
.EXAMPLE
    .\PCModScan.ps1 -WholePC
.EXAMPLE
    .\PCModScan.ps1 -Roots 'C:\Users','D:\Games' -OnlineVerify
#>
[CmdletBinding()]
param(
    [string]$ModsPath,
    [switch]$WholePC,
    [string[]]$Roots,
    [switch]$IncludeLibraries,
    [switch]$OnlineVerify,
    [int]$MaxSizeMB = 200,
    [string]$ReportPath
)

$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$startTime = Get-Date
if (-not $ReportPath) {
    $desk = [Environment]::GetFolderPath('Desktop')
    if (-not $desk) { $desk = $env:TEMP }
    $ReportPath = Join-Path $desk ("MC-ModScan_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

# Tier 1: cheat-client package / project identifiers (high confidence)
$clientRaw = @(
    'meteordevelopment/meteorclient','meteor-client','net/wurstclient','wurstclient',
    'net/ccbluex','liquidbounce','com/rusherhack','rusherhack','me/alpha432/oyvey',
    'org/bleachhack','bleachhack','thunderhack','me/zeroeightsix/kami','today/opai',
    'cc/novoline','novoline','wtf/moonlight','dev/krypton','skid/krypton','xyz/greaj',
    'org/chainlibs','dev/gambleclient','doomsdayclient','prestigeclient','dqrkis',
    'vapeclient','vape.gg','novaclient','club/maxstats','com/alan/clients','riseclient',
    'aristois','impactclient','futureclient','konas','huzuni','fdp-client','pandaware',
    'dev/virel','walsky.optimizer','walksycrystaloptimizer'
)
$clientSigs = @()
foreach ($s in $clientRaw) {
    $clientSigs += $s
    if ($s -match '/') { $clientSigs += ($s -replace '/', '.') }
}
$clientSigs = $clientSigs | Select-Object -Unique

# Tier 2: cheat module names (medium confidence; 2+ distinct hits = high)
$moduleSigs = @(
    'AutoCrystal','AutoHitCrystal','CrystalAura','AutoAnchor','AnchorMacro','AnchorAura',
    'DoubleAnchor','SafeAnchor','AirAnchor','AutoTotem','HoverTotem','InventoryTotem',
    'LegitTotem','AutoPot','AutoPotRefill','AutoNethPot','AutoArmor','AutoDoubleHand',
    'AutoDtap','ShieldDisabler','ShieldBreaker','TriggerBot','AimAssist','AimBot',
    'SilentAim','KillAura','ClickAura','MultiAura','AutoClicker','AutoWeb','WebMacro',
    'AxeSpam','StunSlam','MaceSwap','AutoMace','AutoBreach','KeyPearl','PingSpoof',
    'FakeLag','SelfDestruct','ChestStealer','PopSwitch','Backtrack','HitboxExpand',
    'BedAura','AutoCrit','AlwaysCrit','ElytraSwap','LagReach','Antiknockback',
    'PackSpoof','AuthBypass','AutoTPA','WalksyOptimizer','WalskyOptimizer','SprintReset'
)

function New-SigRegex {
    param([string[]]$Names)
    $core = '(' + (($Names | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
    # not preceded / followed by a lowercase letter (case-sensitive), so AutoPotion != AutoPot
    $pat = '(?<!(?-i:[a-z]))' + $core + '(?!(?-i:[a-z]))'
    return [regex]::new($pat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
}
$ClientRx = New-SigRegex $clientSigs
$ModuleRx = New-SigRegex $moduleSigs
$FullwidthRx = [regex]::new('[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{4,}', [System.Text.RegularExpressions.RegexOptions]::Compiled)

$credStrings = @('launcher_accounts','Login Data','Local Storage/leveldb','Local Storage\leveldb')

$Rank = @{ 'NONE' = -1; 'INFO' = 0; 'LOW' = 1; 'MEDIUM' = 2; 'HIGH' = 3 }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Read-EntryBytes {
    param($Entry)
    try {
        $s = $Entry.Open()
        $ms = New-Object System.IO.MemoryStream
        $s.CopyTo($ms)
        $s.Dispose()
        $b = $ms.ToArray()
        $ms.Dispose()
        return ,$b
    } catch { return $null }
}

function New-State {
    return @{
        Client = New-Object 'System.Collections.Generic.HashSet[string]'
        Module = New-Object 'System.Collections.Generic.HashSet[string]'
        Fullwidth = New-Object 'System.Collections.Generic.HashSet[string]'
        Cls = 0; Num = 0; Uni = 0; Jp = 0; S1 = 0; S2 = 0; Conf = 0; PkgObf = 0
        Nested = 0
        RuntimeExec = $false; HttpDownload = $false; Webhook = $false; Credential = $false
    }
}

function Invoke-EntryScan {
    param($Zip, $State, [bool]$Outer)

    foreach ($e in $Zip.Entries) {
        $name = $e.FullName.Replace('\', '/')
        if ($name.EndsWith('/')) { continue }

        foreach ($m in $ClientRx.Matches($name)) { [void]$State.Client.Add($m.Value.ToLowerInvariant()) }
        foreach ($m in $ModuleRx.Matches($name)) { [void]$State.Module.Add($m.Value.ToLowerInvariant()) }

        $isClass = $name.EndsWith('.class')

        if ($isClass -and $Outer) {
            $State.Cls++
            $base = [System.IO.Path]::GetFileNameWithoutExtension($name)
            if ($base -match '^\d+$') { $State.Num++ }
            if ($base -match '[^\x00-\x7F]') { $State.Uni++ }
            if ($base -match '[\u3040-\u309F\u30A0-\u30FF]') { $State.Jp++ }
            if ($base -match '^[a-zA-Z]$') { $State.S1++ }
            if ($base -match '^[a-zA-Z]{2}$') { $State.S2++ }
            if ($base -match '^[Il1O0]+$' -or $base -match '^_+$') { $State.Conf++ }
            $run = 0; $max = 0
            foreach ($seg in ($name -split '/')) {
                if ($seg.Length -eq 1) { $run++; if ($run -gt $max) { $max = $run } } else { $run = 0 }
            }
            if ($max -ge 3) { $State.PkgObf++ }
        }

        if ($isClass -or $name.EndsWith('.json') -or $name.EndsWith('MANIFEST.MF')) {
            if ($e.Length -le 0 -or $e.Length -gt 2097152) { continue }
            $bytes = Read-EntryBytes $e
            if (-not $bytes -or $bytes.Length -eq 0) { continue }

            $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)

            foreach ($m in $ClientRx.Matches($ascii)) { [void]$State.Client.Add($m.Value.ToLowerInvariant()) }
            foreach ($m in $ModuleRx.Matches($ascii)) { [void]$State.Module.Add($m.Value.ToLowerInvariant()) }

            if ($ascii.Contains('discord.com/api/webhooks') -or $ascii.Contains('discordapp.com/api/webhooks')) { $State.Webhook = $true }
            foreach ($cs in $credStrings) { if ($ascii.Contains($cs)) { $State.Credential = $true; break } }

            if ($Outer -and $isClass) {
                if ($ascii.Contains('java/lang/Runtime') -and $ascii.Contains('getRuntime') -and $ascii.Contains('exec')) { $State.RuntimeExec = $true }
                if ($ascii.Contains('openConnection') -and $ascii.Contains('FileOutputStream')) { $State.HttpDownload = $true }
            }

            if ($bytes.Length -le 512000) {
                $utf8 = [System.Text.Encoding]::UTF8.GetString($bytes)
                foreach ($m in $FullwidthRx.Matches($utf8)) { [void]$State.Fullwidth.Add($m.Value) }
            }
        }
    }
}

function Get-Sha1 {
    param([string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA1).Hash.ToLower() } catch { return $null }
}

function Get-DownloadSource {
    param([string]$Path)
    try {
        $z = Get-Content -LiteralPath $Path -Stream Zone.Identifier -Raw -ErrorAction Stop
        if ($z -match 'HostUrl=(.+)') { return $matches[1].Trim() }
        if ($z -match 'ReferrerUrl=(.+)') { return $matches[1].Trim() }
    } catch { }
    return $null
}

function Get-RecycleOriginal {
    param([string]$Path)
    try {
        $leaf = [System.IO.Path]::GetFileName($Path)
        if (-not $leaf.StartsWith('$R')) { return $null }
        $meta = Join-Path ([System.IO.Path]::GetDirectoryName($Path)) ('$I' + $leaf.Substring(2))
        if (-not (Test-Path -LiteralPath $meta)) { return $null }
        $b = [System.IO.File]::ReadAllBytes($meta)
        $ver = [BitConverter]::ToInt64($b, 0)
        if ($ver -eq 2) {
            $len = [BitConverter]::ToInt32($b, 24)
            return [System.Text.Encoding]::Unicode.GetString($b, 28, ($len - 1) * 2)
        } elseif ($ver -eq 1) {
            return [System.Text.Encoding]::Unicode.GetString($b, 24, $b.Length - 24).TrimEnd([char]0)
        }
    } catch { }
    return $null
}

function Query-Modrinth {
    param([string]$Hash)
    try {
        $h = @{ 'User-Agent' = 'PCModScan/1.0 (local mod scanner)' }
        $v = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$Hash" -Headers $h -TimeoutSec 15 -ErrorAction Stop
        if ($v.project_id) {
            $p = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($v.project_id)" -Headers $h -TimeoutSec 15 -ErrorAction Stop
            return $p.title
        }
    } catch { }
    return $null
}

function Find-Jars {
    param([string]$Root, [System.Collections.Generic.HashSet[string]]$SkipNames, [System.Collections.Generic.HashSet[string]]$SkipFull)
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($dir, '*.jar')) {
                if ($f.EndsWith('.jar', [System.StringComparison]::OrdinalIgnoreCase)) { $f }
            }
        } catch { }
        try {
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($dir)) {
                if ($SkipFull.Contains($d)) { continue }
                if ($SkipNames.Contains([System.IO.Path]::GetFileName($d))) { continue }
                try {
                    $attr = [System.IO.File]::GetAttributes($d)
                    if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                } catch { continue }
                $stack.Push($d)
            }
        } catch { }
    }
}

function Add-Reason {
    param($F, [string]$Sev, [string]$Text)
    if ($Rank[$Sev] -gt $Rank[$F.Severity]) { $F.Severity = $Sev }
    [void]$F.Reasons.Add("[$Sev] $Text")
}

function Get-Pct { param($n, $t) if ($t -le 0) { return 0 } return [math]::Round(($n / $t) * 100) }

# ---------------------------------------------------------------------------
# Banner / setup
# ---------------------------------------------------------------------------

Clear-Host
Write-Host ''
Write-Host '  ==============================================================' -ForegroundColor Cyan
Write-Host '    PC MOD SCAN  -  Minecraft cheat / suspicious mod scanner      ' -ForegroundColor Cyan
Write-Host '  ==============================================================' -ForegroundColor Cyan
Write-Host '    Local only. Flags are leads, not verdicts.' -ForegroundColor DarkGray
Write-Host ''

function Resolve-ModsFolder {
    param([string]$P)
    if (-not $P) { return $null }
    $P = $P.Trim().Trim('"').Trim("'")
    if (-not (Test-Path -LiteralPath $P -PathType Container)) { return $null }
    if ((Split-Path $P -Leaf) -ieq 'mods') { return $P }
    foreach ($sub in @('mods', 'minecraft\mods', '.minecraft\mods')) {
        $c = Join-Path $P $sub
        if (Test-Path -LiteralPath $c -PathType Container) { return $c }
    }
    return $P
}

function Get-AutoModFolders {
    $c = New-Object 'System.Collections.Generic.List[string]'
    $ad = $env:APPDATA; $up = $env:USERPROFILE
    if ($ad) { $c.Add((Join-Path $ad '.minecraft\mods')) }

    # folder of the game that is running right now (--gameDir)
    try {
        foreach ($p in (Get-CimInstance Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'")) {
            $cl = $p.CommandLine
            if ($cl -and $cl -match '--gameDir\s+(?:"([^"]+)"|(\S+))') {
                $gd = $matches[1]; if (-not $gd) { $gd = $matches[2] }
                $c.Add((Join-Path $gd 'mods'))
            }
        }
    } catch { }

    # common launchers with one folder per instance
    $patterns = @()
    if ($ad) {
        $patterns += "$ad\PrismLauncher\instances\*\.minecraft\mods"
        $patterns += "$ad\PrismLauncher\instances\*\minecraft\mods"
        $patterns += "$ad\PolyMC\instances\*\.minecraft\mods"
        $patterns += "$ad\ModrinthApp\profiles\*\mods"
        $patterns += "$ad\ATLauncher\instances\*\mods"
        $patterns += "$ad\gdlauncher_next\instances\*\mods"
        $patterns += "$ad\gdlauncher_carbon\data\instances\*\instance\mods"
    }
    if ($up) {
        $patterns += "$up\curseforge\minecraft\Instances\*\mods"
        $patterns += "$up\.lunarclient\offline\*\mods"
    }
    foreach ($pat in $patterns) {
        try { foreach ($r in (Resolve-Path -Path $pat -ErrorAction SilentlyContinue)) { $c.Add($r.ProviderPath) } } catch { }
    }

    $seenF = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out = New-Object 'System.Collections.Generic.List[string]'
    foreach ($x in $c) {
        if ($x -and (Test-Path -LiteralPath $x -PathType Container) -and $seenF.Add($x)) { $out.Add($x) }
    }
    return $out.ToArray()
}

$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$jars = New-Object 'System.Collections.Generic.List[string]'
$skipNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$skipFull = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

$wholePcMode = ($WholePC -or ($Roots -and $Roots.Count -gt 0))

if (-not $wholePcMode) {
    # ---------------- MODS-FOLDER MODE (default) ----------------
    $folders = @()
    $typed = $ModsPath
    if (-not $typed) {
        Write-Host '  Enter path to the mods folder ' -NoNewline
        Write-Host '(press Enter to auto-detect)' -ForegroundColor DarkGray
        $typed = Read-Host 'PATH'
        Write-Host ''
    }
    if ($typed -and $typed.Trim()) {
        $rf = Resolve-ModsFolder $typed
        if (-not $rf) {
            Write-Host '  Invalid path - that folder does not exist.' -ForegroundColor Red
            Write-Host "  Tried: $typed" -ForegroundColor Gray
            return
        }
        $folders = @($rf)
    } else {
        $folders = @(Get-AutoModFolders)
        if ($folders.Count -eq 0) {
            Write-Host '  Could not find a Minecraft mods folder automatically.' -ForegroundColor Yellow
            Write-Host '  Run again and paste the path (e.g. C:\Users\you\AppData\Roaming\.minecraft\mods),' -ForegroundColor Yellow
            Write-Host '  or use -WholePC to scan the whole computer.' -ForegroundColor Yellow
            return
        }
    }
    Write-Host '  Mods folder(s) to scan:' -ForegroundColor White
    foreach ($f in $folders) { Write-Host "    $f" -ForegroundColor Gray }
    Write-Host ''
    Write-Host '  Finding .jar files...' -ForegroundColor Cyan
    foreach ($f in $folders) {
        foreach ($j in (Find-Jars -Root $f -SkipNames $skipNames -SkipFull $skipFull)) {
            if ($seen.Add($j)) { $jars.Add($j) }
        }
    }
} else {
    # ---------------- WHOLE-PC MODE ----------------
    $isAdmin = $false
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }
    if (-not $isAdmin) {
        Write-Host '  Note: not running as Administrator. Other users'' folders and parts of the' -ForegroundColor Yellow
        Write-Host '  Recycle Bin may be unreadable. Run PowerShell as administrator for full coverage.' -ForegroundColor Yellow
        Write-Host ''
    }
    if (-not $Roots -or $Roots.Count -eq 0) {
        $Roots = @()
        foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
            if ($d.DriveType -eq 'Fixed' -and $d.IsReady) { $Roots += $d.RootDirectory.FullName }
        }
    }
    $Roots = @($Roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($Roots.Count -eq 0) {
        Write-Host '  No valid roots to scan.' -ForegroundColor Red
        return
    }
    [void]$skipNames.Add('System Volume Information')
    [void]$skipNames.Add('WinSxS')
    [void]$skipNames.Add('WindowsApps')
    if (-not $IncludeLibraries) {
        foreach ($n in @('libraries', 'runtime', 'jre', 'jdk', '.gradle', '.m2')) { [void]$skipNames.Add($n) }
    }
    foreach ($r in $Roots) { [void]$skipFull.Add(($r.TrimEnd('\') + '\Windows')) }

    Write-Host '  Roots to scan:' -ForegroundColor White
    foreach ($r in $Roots) { Write-Host "    $r" -ForegroundColor Gray }
    Write-Host ''
    Write-Host '  Finding .jar files...' -ForegroundColor Cyan
    foreach ($r in $Roots) {
        foreach ($j in (Find-Jars -Root $r -SkipNames $skipNames -SkipFull $skipFull)) {
            if ($seen.Add($j)) { $jars.Add($j) }
        }
    }
}

Write-Host "  Found $($jars.Count) jar file(s)." -ForegroundColor Green
Write-Host ''

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

$findings = New-Object 'System.Collections.Generic.List[object]'
$unreadable = 0
$tooBig = 0
$i = 0
$total = $jars.Count

foreach ($path in $jars) {
    $i++
    if ($i % 5 -eq 0 -or $i -eq $total) {
        $short = [System.IO.Path]::GetFileName($path)
        Write-Progress -Activity 'Scanning jars' -Status "$i / $total  $short" -PercentComplete ([int](($i / [math]::Max($total, 1)) * 100))
    }

    $size = 0
    try { $size = (New-Object System.IO.FileInfo($path)).Length } catch { }
    if ($size -gt ($MaxSizeMB * 1MB)) { $tooBig++; continue }

    $zip = $null
    try { $zip = [System.IO.Compression.ZipFile]::OpenRead($path) } catch { $unreadable++; continue }
    if (-not $zip) { $unreadable++; continue }

    $st = New-State
    try {
        Invoke-EntryScan -Zip $zip -State $st -Outer $true

        $nested = @($zip.Entries | Where-Object { $_.FullName -match '^META-INF/jars/.+\.jar$' })
        $st.Nested = $nested.Count
        foreach ($nj in $nested) {
            if ($nj.Length -le 0 -or $nj.Length -gt 52428800) { continue }
            try {
                $nb = Read-EntryBytes $nj
                if ($nb -and $nb.Length -gt 0) {
                    $nms = [System.IO.MemoryStream]::new($nb)
                    $iz = [System.IO.Compression.ZipArchive]::new($nms, [System.IO.Compression.ZipArchiveMode]::Read)
                    Invoke-EntryScan -Zip $iz -State $st -Outer $false
                    $iz.Dispose(); $nms.Dispose()
                }
            } catch { }
        }
    } catch { } finally { $zip.Dispose() }

    $f = @{
        Path = $path; Size = $size; Severity = 'NONE'
        Reasons = New-Object 'System.Collections.Generic.List[string]'
        Hits = @(); Sha1 = $null; Source = $null; Verified = $null; Original = $null
    }

    if ($st.Client.Count -gt 0) {
        Add-Reason $f 'HIGH' ("Cheat-client identifiers: " + (($st.Client | Sort-Object) -join ', '))
    }
    if ($st.Module.Count -ge 2) {
        Add-Reason $f 'HIGH' ("Multiple cheat module names: " + (($st.Module | Sort-Object) -join ', '))
    } elseif ($st.Module.Count -eq 1) {
        Add-Reason $f 'MEDIUM' ("Cheat module name: " + (($st.Module | Sort-Object) -join ', '))
    }
    if ($st.Credential) { Add-Reason $f 'HIGH' 'References launcher/browser/Discord credential files (possible stealer)' }
    if ($st.Webhook) { Add-Reason $f 'MEDIUM' 'Contains a Discord webhook URL (data can be sent out)' }

    $obf = @()
    if ($st.Cls -ge 10) {
        $c = $st.Cls
        if ((Get-Pct $st.Num $c) -ge 20) { $obf += "numeric class names ($(Get-Pct $st.Num $c)%)" }
        if ((Get-Pct $st.Uni $c) -ge 10) { $obf += "non-ASCII class names ($(Get-Pct $st.Uni $c)%)" }
        if ($st.Jp -ge 5) { $obf += "hiragana/katakana class names ($($st.Jp) classes)" }
        if ((Get-Pct $st.S1 $c) -ge 15) { $obf += "single-letter class names ($(Get-Pct $st.S1 $c)%)" }
        if ((Get-Pct $st.S2 $c) -ge 20) { $obf += "two-letter class names ($(Get-Pct $st.S2 $c)%)" }
        if ((Get-Pct $st.Conf $c) -ge 3) { $obf += "Il1O0/underscore class names ($(Get-Pct $st.Conf $c)%)" }
        if ((Get-Pct $st.PkgObf $c) -ge 25) { $obf += "a/b/c style package paths ($(Get-Pct $st.PkgObf $c)%)" }
    }
    if ($obf.Count -gt 0) { Add-Reason $f 'LOW' ("Obfuscation: " + ($obf -join '; ')) }

    if ($st.RuntimeExec -and $obf.Count -gt 0) { Add-Reason $f 'MEDIUM' 'Runtime.exec() in obfuscated code (can run OS commands)' }
    if ($st.HttpDownload) {
        $dsev = 'LOW'; if ($obf.Count -gt 0) { $dsev = 'MEDIUM' }
        Add-Reason $f $dsev 'Opens HTTP connection and writes files (possible runtime downloader)'
    }
    if ($st.Nested -eq 1 -and $st.Cls -lt 3) { Add-Reason $f 'MEDIUM' 'Hollow shell: almost no own classes, wraps a single nested jar' }
    if ($st.Fullwidth.Count -gt 0) {
        Add-Reason $f 'LOW' ("Fullwidth-text strings (often used to dodge string scans): " + (($st.Fullwidth | Select-Object -First 3) -join ', '))
    }

    if ($f.Severity -ne 'NONE') {
        $f.Sha1 = Get-Sha1 $path
        $f.Source = Get-DownloadSource $path
        if ($path -match '\\\$Recycle\.Bin\\') {
            $f.Original = Get-RecycleOriginal $path
            Add-Reason $f 'INFO' 'Located in the Recycle Bin (deleted file)'
        }
        if ($OnlineVerify -and $f.Sha1) {
            $vn = Query-Modrinth $f.Sha1
            if ($vn) {
                $f.Verified = $vn
                if ($st.Client.Count -eq 0 -and -not $st.Credential) {
                    $f.Severity = 'INFO'
                    $f.Reasons.Insert(0, "[INFO] Hash matches Modrinth project '$vn' - probably a false positive")
                }
            }
        }
        $findings.Add($f)
    }
}
Write-Progress -Activity 'Scanning jars' -Completed

# ---------------------------------------------------------------------------
# JVM scan
# ---------------------------------------------------------------------------

$jvm = New-Object 'System.Collections.Generic.List[string]'
try {
    $procs = Get-CimInstance Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'"
    foreach ($p in $procs) {
        $cl = $p.CommandLine
        if (-not $cl) { continue }
        foreach ($m in [regex]::Matches($cl, '-javaagent:([^\s"]+)')) {
            $agent = [System.IO.Path]::GetFileName($m.Groups[1].Value.Trim('"'))
            if ($agent -notmatch 'jmxremote|yjp|jrebel|newrelic|jacoco|theseus') {
                $jvm.Add("PID $($p.ProcessId): -javaagent:$agent")
            }
        }
        foreach ($flag in @('-Xbootclasspath/p:', '-Xbootclasspath/a:', '-agentlib:jdwp', '-agentpath:')) {
            if ($cl.Contains($flag)) { $jvm.Add("PID $($p.ProcessId): suspicious JVM flag $flag") }
        }
    }
} catch { }

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

$lines = New-Object 'System.Collections.Generic.List[string]'
function Out-Both {
    param([string]$Text, [ConsoleColor]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
    $lines.Add($Text)
}

$real = @($findings | Where-Object { $_.Severity -ne 'INFO' } | Sort-Object { - $Rank[$_.Severity] }, { $_.Path })
$info = @($findings | Where-Object { $_.Severity -eq 'INFO' })
$colors = @{ 'HIGH' = 'Red'; 'MEDIUM' = 'Yellow'; 'LOW' = 'DarkYellow' }

Out-Both ''
Out-Both '==================== RESULTS ====================' Cyan
foreach ($f in $real) {
    Out-Both ''
    Out-Both ("[{0}] {1}" -f $f.Severity, $f.Path) $colors[$f.Severity]
    foreach ($r in $f.Reasons) { Out-Both ("    $r") Gray }
    if ($f.Original) { Out-Both ("    Original location before deletion: " + $f.Original) Magenta }
    if ($f.Source) { Out-Both ("    Downloaded from: " + $f.Source) DarkGray }
    if ($f.Sha1) { Out-Both ("    SHA1: " + $f.Sha1) DarkGray }
}

if ($jvm.Count -gt 0) {
    Out-Both ''
    Out-Both '---- Running Java process ----' Yellow
    foreach ($j in $jvm) { Out-Both "    $j" Yellow }
}

$elapsed = (Get-Date) - $startTime
Out-Both ''
Out-Both '==================== SUMMARY ====================' Cyan
Out-Both ("  Jars found:            {0}" -f $total)
Out-Both ("  HIGH:                  {0}" -f @($real | Where-Object { $_.Severity -eq 'HIGH' }).Count) Red
Out-Both ("  MEDIUM:                {0}" -f @($real | Where-Object { $_.Severity -eq 'MEDIUM' }).Count) Yellow
Out-Both ("  LOW:                   {0}" -f @($real | Where-Object { $_.Severity -eq 'LOW' }).Count) DarkYellow
if ($OnlineVerify) { Out-Both ("  Cleared via Modrinth:  {0}" -f $info.Count) Green }
Out-Both ("  JVM issues:            {0}" -f $jvm.Count)
Out-Both ("  Unreadable/corrupt:    {0}" -f $unreadable)
Out-Both ("  Skipped (too large):   {0}" -f $tooBig)
Out-Both ("  Time:                  {0:mm\:ss}" -f $elapsed)
Out-Both ''
Out-Both '  Reminder: flags are leads to review manually. Renamed/obfuscated clients can evade' DarkGray
Out-Both '  name matching, so a clean result is not proof of a clean PC.' DarkGray

try {
    $lines | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Host ''
    Write-Host "  Report saved to: $ReportPath" -ForegroundColor Green
} catch {
    Write-Host "  Could not save report: $_" -ForegroundColor Red
}
Write-Host ''

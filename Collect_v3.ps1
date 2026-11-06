<#
.SYNOPSIS
    Collect_v3.ps1 - Endpoint DFIR live-response / triage collection framework.

.DESCRIPTION
    Data-driven collection framework. Every artifact is a registered "collector"
    with a phase (order of volatility), a minimum profile level, and an output file.
    A single wrapper runs each collector with timing, error handling, exit-code capture,
    and records the result in the manifest.

    Profiles
      Quick    (1)  Volatile state only: time, network, processes, sessions, services, persistence,
                      event log channel config, ETW/AutoLogger sessions.
      Standard (2)  + VSS snapshot, registry hives, user hives, ALL event logs, prefetch, task XML,
                      Defender/firewall/system config, Autoruns, Handle, ListDlls, driver hashes + loaded
                      kernel modules, WFP filters, Sysmon config, SSH keys, PowerShell transcripts, Mark-of-the-Web.
      Deep     (3)  + SRUM, WMI repo, LNK/JumpLists, browser history, $MFT/$J/$LogFile (raw),
                      Sigcheck on user-writable paths, and Zimmerman parsers over the collected copies.
      Full     (4)  + KAPE (targets + !EZParser modules) and Velociraptor collections, pagefile/hiberfil/
                      swapfile, full Recycle Bin, Windows Search DB, Sigcheck over System32.

    Order of volatility (phases)
      1 Memory | 2 Time + network | 3 Processes/sessions/services | 4 System config
      5 VSS snapshot + disk artifacts | 6 Slow live tools | 7 Parsers | 8 KAPE / Velociraptor

    Run from an elevated prompt, ideally from removable media or a network share:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Collect_v3.ps1 `
          -CollectionProfile Standard -CaseId IR-2026-001 -OutputPath X:\Collections -NonInteractive

.PARAMETER CollectionProfile  Quick | Standard | Deep | Full. Prompted for if omitted (unless -NonInteractive).
.PARAMETER OutputPath         Base folder for collections. Default: <toolkit>\Collections.
.PARAMETER ToolsPath          Folder searched for tools. Default: <toolkit>\Tools if present, else <toolkit>.
.PARAMETER CaseId             Case / ticket identifier (recorded in folder name and manifest).
.PARAMETER Operator           Operator name (recorded in manifest).
.PARAMETER NonInteractive     Never prompt; fail instead of asking.
.PARAMETER Memory             Acquire RAM first (WinPmem / Magnet RAM Capture / DumpIt must be in the toolkit).
.PARAMETER AllowSystemDrive   Permit writing output to the system drive (overwrites evidence-bearing free space).
.PARAMETER Volumes            Extra volumes to collect besides the system drive, e.g. 'D:','F:'. Default: auto-detect
                              every INTERNAL disk volume (SATA/NVMe/SAS/RAID/SCSI/ATA/Storage Spaces; never USB,
                              SD/MMC or virtual disks), excluding the output and toolkit drives.
.PARAMETER SystemDriveOnly    Collect only the system drive (skip the extra internal volumes).
.PARAMETER NtpServer         Optional NTP server for a clock-skew check (w32tm /stripchart). Needs network.
.PARAMETER KapeTargets        KAPE target(s) for the Full profile. Default !SANS_Triage.
.PARAMETER KapeModules        KAPE module(s) to run after targets. Default !EZParser. Pass '' to skip modules.
.PARAMETER KapeVss            Make KAPE also collect from every existing Volume Shadow Copy (slow; can multiply size).
.PARAMETER KapeVolumeTargets  KAPE targets for each extra internal volume (Full). Default 'FileSystem,RecycleBin'.
.PARAMETER VelociraptorArtifact / VelociraptorArgs   Artifact and parameters for the Full profile.
                              VelociraptorArgs ('Name=Value') are passed to EVERY artifact.
.PARAMETER VelociraptorArtifactArgs  Per-artifact Velociraptor parameters, e.g.
                              @{ 'Windows.EventLogs.RDPAuth' = @('DateAfter=2026-01-01') }.
.PARAMETER YaraRules          Opt-in. Path to a .yar file. In the Full profile, runs Windows.Detection.Yara.Process with it
                              (slow; memory scanning can trigger EDR). The rules file is copied into Velociraptor\ and hashed.
.PARAMETER LolDriversCsv      Optional. Local copy of the LOLDrivers export (CSV or JSON from loldrivers.io). Every
                              MD5/SHA1/SHA256 in it is matched against the driver hashes. No network access is made.
.PARAMETER DefenderQuarantine Opt-in. Copy the Defender quarantine folder (RC4-obfuscated, but LIVE malware samples)
                              to Security\DefenderQuarantine\. Never enabled by any profile. Use with -Archive -ArchivePassword.
.PARAMETER Archive            Archive the collection when done (7-Zip if present, else Compress-Archive).
.PARAMETER ArchivePassword    SecureString; encrypts the 7-Zip archive (AES-256, headers encrypted).
                              NOTE: 7-Zip receives the password on its command line (visible to local admins).

.NOTES
    Version : 3.4.0
    Tested  : syntax-targeted at Windows PowerShell 5.1 (the common endpoint default).
    VERIFY  : Command-line syntax for third-party tools (memory imagers, RawCopy, Zimmerman tools,
              KAPE, Velociraptor) changes between versions. Test each against the exact versions
              in your toolkit on a lab machine before field use.
    FOOTPRINT: This script creates (and afterwards deletes) one VSS snapshot and one temporary
              directory symlink under %SystemRoot%\Temp for Standard+ profiles.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Quick', 'Standard', 'Deep', 'Full')]
    [string]$CollectionProfile,
    [string]$OutputPath,
    [string]$ToolsPath,
    [string]$CaseId = 'NOCASE',
    [string]$Operator = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME),
    [switch]$NonInteractive,
    [switch]$Memory,
    [switch]$AllowSystemDrive,
    [string[]]$Volumes,
    [switch]$SystemDriveOnly,
    [string]$NtpServer,
    [string]$KapeTargets = '!SANS_Triage',
    [string]$KapeModules = '!EZParser',
    [switch]$KapeVss,
    [string]$KapeVolumeTargets = 'FileSystem,RecycleBin',
    # Windows.KapeFiles.Targets is no longer built in (0.77.3); KAPE already does the file triage.
    # These built-in artifacts parse live state instead. Each runs separately into its own zip.
    # Browser artifacts output UTC times (unlike SQLECmd's browser maps, which use local time).
    # Chrome.Cookies is deliberately left out (no cookies, passwords or autofill are collected).
    [string[]]$VelociraptorArtifact = @(
        'Windows.System.Pslist', 'Windows.Network.NetstatEnriched', 'Windows.System.Services',
        'Windows.Sys.StartupItems', 'Windows.System.TaskScheduler', 'Windows.Persistence.PermanentWMIEvents',
        'Windows.Detection.Amcache', 'Windows.Registry.AppCompatCache', 'Windows.Registry.UserAssist',
        'Windows.Forensics.Shellbags', 'Windows.Forensics.Prefetch', 'Windows.Forensics.Lnk',
        'Windows.Forensics.SRUM', 'Windows.Forensics.Timeline', 'Windows.Forensics.RecycleBin',
        'Windows.Forensics.Usn', 'Windows.NTFS.MFT',
        'Windows.Applications.Chrome.History', 'Windows.Applications.Edge.History',
        'Windows.Applications.Chrome.Extensions', 'Windows.Applications.Firefox.History',
        'Windows.Applications.Firefox.Downloads', 'Windows.EventLogs.RDPAuth'),
    [string[]]$VelociraptorArgs = @(),            # passed to EVERY artifact (kept for backward compatibility)
    [hashtable]$VelociraptorArtifactArgs = @{},   # per-artifact: @{ 'Artifact.Name' = @('Param=Value', ...) }
    [string]$YaraRules,                           # opt-in: .yar file for Windows.Detection.Yara.Process (Full)
    [string]$LolDriversCsv,                       # optional: local LOLDrivers CSV/JSON export for hash matching
    [switch]$DefenderQuarantine,                  # opt-in: copy Defender quarantine (live malware samples)
    [switch]$Archive,
    [securestring]$ArchivePassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

$ScriptVersion  = '3.4.0'
$ScriptStartUtc = [DateTime]::UtcNow
$Inv            = [Globalization.CultureInfo]::InvariantCulture

# ===================================================================
# HELPERS
# ===================================================================

function Get-UtcStamp { [DateTime]::UtcNow.ToString('yyyy-MM-dd\THH:mm:ss\Z', $Inv) }

# Defensive date formatter: CIM/WMI date properties are not always plain [datetime]. Never throws.
function ConvertTo-IsoUtc {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return ([DateTime]$Value).ToUniversalTime().ToString('o') }
    catch { return [string]$Value }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK', 'SKIP')][string]$Level = 'INFO'
    )
    $color = @{ INFO = 'Gray'; WARN = 'Yellow'; ERROR = 'Red'; OK = 'Green'; SKIP = 'DarkYellow' }[$Level]
    Write-Host ('[{0}] [{1,-5}] {2}' -f (Get-UtcStamp), $Level, $Message) -ForegroundColor $color
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Confirm-Continue {
    param([string]$Question)
    if ($NonInteractive) { return $false }
    $a = Read-Host "$Question [y/N]"
    return ($a -match '^(y|yes)$')
}

function Get-FreeSpaceGB {
    param([string]$Path)
    try {
        $root = [IO.Path]::GetPathRoot($Path)
        if ($root.StartsWith('\\')) { return $null }   # UNC: cannot determine reliably
        [math]::Round((New-Object IO.DriveInfo($root)).AvailableFreeSpace / 1GB, 1)
    }
    catch { $null }
}

function New-Section { param([string]$Title) "`r`n=== $Title ===" }

# Run a block; on failure emit an ERROR line instead of aborting the whole collector.
function Invoke-Safe {
    param([scriptblock]$Block)
    try { & $Block } catch { "ERROR: $($_.Exception.Message)" }
}

# Re-encode UTF-16LE output (some tools write it when redirected) to UTF-8 for parser friendliness.
function Convert-ToUtf8IfUtf16 {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $fs = [IO.File]::OpenRead($Path)
    try { $b = New-Object byte[] 4; $n = $fs.Read($b, 0, 4) } finally { $fs.Dispose() }
    $bom   = ($n -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE)
    # Sigcheck -c writes UTF-16LE WITHOUT a BOM: ASCII text then looks like 'P',0,'a',0.
    $noBom = ($n -eq 4 -and $b[0] -ne 0 -and $b[1] -eq 0 -and $b[2] -ne 0 -and $b[3] -eq 0)
    if ($bom -or $noBom) {
        $t = [IO.File]::ReadAllText($Path, [Text.Encoding]::Unicode)
        [IO.File]::WriteAllText($Path, $t, (New-Object Text.UTF8Encoding($true)))
    }
}

function ConvertTo-ArgString {
    param([string[]]$Items)
    ($Items | ForEach-Object {
        if ($_ -eq '' -or $_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '
}

# Run an external tool with stdout/stderr capture and a hard timeout.
$script:LastExit = $null
function Invoke-External {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [Parameter(Mandatory)][string]$OutFile,
        [int]$TimeoutSec = 900,
        [string]$WorkingDirectory
    )
    if (-not $WorkingDirectory) { $WorkingDirectory = Split-Path -Parent $FilePath }  # tools find Maps/ etc. here
    $errFile = "$OutFile.err"
    [IO.Directory]::CreateDirectory((Split-Path -Parent $OutFile)) | Out-Null

    $sp = @{
        FilePath               = $FilePath
        NoNewWindow            = $true
        PassThru               = $true
        RedirectStandardOutput = $OutFile
        RedirectStandardError  = $errFile
        WorkingDirectory       = $WorkingDirectory
    }
    if ($ArgumentList.Count) { $sp.ArgumentList = (ConvertTo-ArgString $ArgumentList) }

    $p = Start-Process @sp
    $null = $p.Handle                       # PS 5.1 quirk: cache handle so ExitCode is readable
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        $script:LastExit = -1
        throw "Timed out after $TimeoutSec s: $FilePath"
    }
    $p.WaitForExit()
    $script:LastExit = $p.ExitCode

    Convert-ToUtf8IfUtf16 $OutFile
    if ((Test-Path -LiteralPath $errFile) -and ((Get-Item -LiteralPath $errFile).Length -eq 0)) {
        Remove-Item -LiteralPath $errFile -Force -ErrorAction Ignore
    }
}

# ===================================================================
# PREFLIGHT
# ===================================================================

if (-not (Test-IsAdmin)) {
    Write-Log 'This script must run from an elevated (Administrator) session.' 'ERROR'; exit 1
}
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Write-Log "32-bit PowerShell on a 64-bit OS (WOW64 redirection). Use: $env:windir\sysnative\WindowsPowerShell\v1.0\powershell.exe" 'ERROR'
    exit 1
}
if (([Environment]::GetCommandLineArgs() -join ' ') -notmatch '(?i)-nop') {
    Write-Log 'Not started with -NoProfile: a tampered PowerShell profile may have executed.' 'WARN'
}

# Harden PATH: only trusted system directories (no current dir, no user dirs).
$env:Path = @(
    "$env:SystemRoot\System32", $env:SystemRoot, "$env:SystemRoot\System32\Wbem",
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0"
) -join ';'

# Call host binaries by full path, never via PATH.
$Sys32 = Join-Path $env:SystemRoot 'System32'
# NOTE: PowerShell variable names are case-insensitive. The hashtable must NOT be named $N while a loop
# variable is $n (v3.0.0 bug: the loop overwrote the hashtable with a string).
$Exe = @{}
foreach ($exeName in 'hostname', 'whoami', 'systeminfo', 'ipconfig', 'arp', 'route', 'netstat', 'tasklist', 'schtasks',
    'quser', 'qwinsta', 'net', 'netsh', 'reg', 'wevtutil', 'w32tm', 'manage-bde', 'driverquery', 'vssadmin', 'cmd',
    'sc', 'auditpol', 'gpresult', 'nbtstat', 'cmdkey', 'klist', 'fsutil', 'logman') {
    $Exe[$exeName] = Join-Path $Sys32 "$exeName.exe"
}

# Exfiltration / tunneling tools looked for in Phase 6 (by file name AND by version info, since rclone is usually
# renamed). 'NameOnly' tools carry no version info. Extend here.
$ExfilTools = @(
    @{ Token = 'rclone' }, @{ Token = 'restic' }, @{ Token = 'MEGAsync' }, @{ Token = 'MEGAcmd' }, @{ Token = 'megatools' },
    @{ Token = 'WinSCP' }, @{ Token = 'FileZilla' }, @{ Token = 'pscp' }, @{ Token = 'psftp' }, @{ Token = 'plink' },
    @{ Token = 'ngrok' }, @{ Token = 'cloudflared' }, @{ Token = 'chisel'; NameOnly = $true }, @{ Token = 'Syncthing' },
    @{ Token = 'S3 Browser' }, @{ Token = 'Cyberduck' }
)

# --- Profile selection ---
$Levels = @{ Quick = 1; Standard = 2; Deep = 3; Full = 4 }
if (-not $CollectionProfile) {
    if ($NonInteractive) { Write-Log '-CollectionProfile is required with -NonInteractive.' 'ERROR'; exit 1 }
    Write-Host ''
    Write-Host '1 - Quick    (volatile only)'
    Write-Host '2 - Standard (+ VSS, hives, event logs, prefetch, config)'
    Write-Host '3 - Deep     (+ raw NTFS, user artifacts, parsers)'
    Write-Host '4 - Full     (+ KAPE / Velociraptor)'
    do { $sel = (Read-Host 'Select profile [1-4]').Trim() } until ($sel -in '1', '2', '3', '4')
    $CollectionProfile = @('Quick', 'Standard', 'Deep', 'Full')[[int]$sel - 1]
}

# --- Paths ---
$ToolkitRoot = $PSScriptRoot
if (-not $ToolkitRoot) { $ToolkitRoot = (Get-Location).Path }

$CollectionsBase = if ($OutputPath) { $OutputPath } else { Join-Path $ToolkitRoot 'Collections' }
$CollectionsBase = [IO.Path]::GetFullPath($CollectionsBase).TrimEnd('\')

$ToolsRoot = if ($ToolsPath) { $ToolsPath }
elseif (Test-Path -LiteralPath (Join-Path $ToolkitRoot 'Tools')) { Join-Path $ToolkitRoot 'Tools' }
else { $ToolkitRoot }

# --- Footprint: do not write onto the evidence disk unless explicitly allowed ---
$outRoot = [IO.Path]::GetPathRoot($CollectionsBase)
if ($outRoot -ieq ($env:SystemDrive + '\')) {
    Write-Log "Output is on the SYSTEM drive ($outRoot). This overwrites potentially evidence-bearing free space." 'WARN'
    if (-not $AllowSystemDrive -and -not (Confirm-Continue 'Continue writing to the system drive?')) {
        Write-Log 'Aborting. Use -OutputPath <external/network path> or -AllowSystemDrive.' 'ERROR'; exit 2
    }
}

# --- Extra internal volumes (besides the system drive) ---
# DriveType 3 ("fixed") is not enough: USB hard disks such as an external evidence drive also report as fixed.
# Internal means the disk's BusType is one of these; USB, SD, MMC, 1394, iSCSI and virtual disks are excluded.
$InternalBusTypes = 'SATA', 'SAS', 'NVMe', 'RAID', 'SCSI', 'ATA', 'Spaces', 'Fibre Channel'
# (Named $toolkitDrive, not $toolkitRoot: PowerShell variable names are case-insensitive and $ToolkitRoot exists.)
$toolkitDrive = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($ToolkitRoot)).TrimEnd('\')
$excluded = @(($env:SystemDrive).ToUpper(), $outRoot.TrimEnd('\').ToUpper(), $toolkitDrive.ToUpper())

function Get-InternalVolume {
    $found = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($p in @(Get-Partition -ErrorAction Stop | Where-Object { $_.DriveLetter -and [char]$_.DriveLetter -ne [char]0 })) {
            $disk = Get-Disk -Number $p.DiskNumber -ErrorAction Stop
            $vol  = Get-Volume -DriveLetter $p.DriveLetter -ErrorAction SilentlyContinue
            $found.Add([pscustomobject]@{
                Letter = ('{0}:' -f $p.DriveLetter).ToUpper(); Bus = [string]$disk.BusType; Model = [string]$disk.FriendlyName
                FileSystem = $(if ($vol) { [string]$vol.FileSystem } else { '' }); SizeGB = [math]::Round($p.Size / 1GB)
                Internal = ($InternalBusTypes -contains [string]$disk.BusType)
            })
        }
    }
    catch {
        # Storage module unavailable: fall back to fixed logical disks and warn that USB disks cannot be told apart.
        Write-Log "Get-Disk/Get-Partition failed ($($_.Exception.Message)); falling back to Win32_LogicalDisk (cannot exclude USB hard disks)." 'WARN'
        foreach ($ld in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Ignore)) {
            $found.Add([pscustomobject]@{ Letter = $ld.DeviceID.ToUpper(); Bus = 'unknown'; Model = ''; FileSystem = [string]$ld.FileSystem
                SizeGB = [math]::Round($ld.Size / 1GB); Internal = $true })
        }
    }
    $found
}

$AllVolumes = @(Get-InternalVolume)
$ExtraVolumes = @()
if (-not $SystemDriveOnly) {
    if ($Volumes) {
        foreach ($v in $Volumes) {
            $l = ($v.TrimEnd('\').TrimEnd(':') + ':').ToUpper()
            $info = $AllVolumes | Where-Object { $_.Letter -eq $l } | Select-Object -First 1
            if (-not $info) { $info = [pscustomobject]@{ Letter = $l; Bus = 'unknown'; Model = ''; FileSystem = ''; SizeGB = 0; Internal = $false } }
            if ($excluded -contains $l) { Write-Log "Volume $l skipped: it is the system, output or toolkit drive." 'WARN'; continue }
            $ExtraVolumes += $info
        }
    }
    else {
        $ExtraVolumes = @($AllVolumes | Where-Object { $_.Internal -and ($excluded -notcontains $_.Letter) })
    }
    # A BitLocker-locked or otherwise unreadable volume cannot be collected live.
    $ExtraVolumes = @($ExtraVolumes | Where-Object {
        if (Test-Path -LiteralPath ($_.Letter + '\')) { $true } else { Write-Log "Volume $($_.Letter) is not readable (BitLocker-locked?); skipped." 'WARN'; $false }
    })
}
# Writing output onto another internal disk overwrites evidence there too.
$outInfo = $AllVolumes | Where-Object { $_.Letter -eq $outRoot.TrimEnd('\').ToUpper() } | Select-Object -First 1
if ($outInfo -and $outInfo.Internal -and $outInfo.Letter -ne ($env:SystemDrive).ToUpper()) {
    Write-Log "Output is on INTERNAL disk $($outInfo.Letter) ($($outInfo.Model), $($outInfo.Bus)); it is excluded from collection and its free space is overwritten." 'WARN'
    if (-not $AllowSystemDrive -and -not (Confirm-Continue 'Continue writing to this internal disk?')) {
        Write-Log 'Aborting. Use -OutputPath on an external/network drive, or -AllowSystemDrive.' 'ERROR'; exit 2
    }
}

$RamBytes = 0
try { $RamBytes = [int64](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory } catch {}

$requiredGB = @{ Quick = 1; Standard = 5; Deep = 15; Full = 100 }[$CollectionProfile]
if ($Memory) { $requiredGB += [math]::Ceiling($RamBytes / 1GB * 1.1) }
$freeGB = Get-FreeSpaceGB $CollectionsBase
if ($null -eq $freeGB) {
    Write-Log "Free space on '$CollectionsBase' could not be determined (UNC path?). Recommended: $requiredGB GB." 'WARN'
}
elseif ($freeGB -lt $requiredGB) {
    Write-Log "Only $freeGB GB free; recommended $requiredGB GB for '$CollectionProfile'." 'WARN'
    if (-not (Confirm-Continue 'Continue anyway?')) { Write-Log 'Aborting: insufficient space.' 'ERROR'; exit 3 }
}

# ===================================================================
# INITIALIZATION
# ===================================================================

$HostName     = $env:COMPUTERNAME
$Stamp        = $ScriptStartUtc.ToString('yyyyMMdd\THHmmss\Z', $Inv)
$CaseIdSafe   = $CaseId -replace '[^A-Za-z0-9._-]', '_'
$CollectionRoot = Join-Path $CollectionsBase ('{0}_{1}_{2}' -f $CaseIdSafe, $HostName, $Stamp)

$Ctx = @{
    Root         = $CollectionRoot
    Disk         = Join-Path $CollectionRoot 'Disk'
    Level        = $Levels[$CollectionProfile]
    Stamp        = $Stamp
    ShadowId     = $null
    ShadowDevice = $null
    ShadowLink   = $null
    ShadowDeleted = $false
    CopyLog      = New-Object System.Collections.Generic.List[object]
    ExtraVolumes = $ExtraVolumes     # internal volumes besides the system drive (see Get-InternalVolume)
}

# System drive plus every extra internal volume formatted NTFS (RawCopy, fsutil usn and MFTECmd need NTFS).
function Get-NtfsVolumeList {
    @($env:SystemDrive.ToUpper()) + @($Ctx.ExtraVolumes | Where-Object { $_.FileSystem -eq 'NTFS' } | ForEach-Object { $_.Letter })
}

foreach ($f in 'Memory', 'System', 'Network', 'Processes', 'Persistence', 'Security', 'Disk', 'EventLogs', 'Tools', 'Parsed', 'KAPE', 'Velociraptor') {
    New-Item -ItemType Directory -Force -Path (Join-Path $CollectionRoot $f) | Out-Null
}

Start-Transcript -Path (Join-Path $CollectionRoot 'Collection.log') -Force | Out-Null

Write-Log "Collect_v3 $ScriptVersion | Case=$CaseId | Operator=$Operator | Host=$HostName | Profile=$CollectionProfile"
Write-Log "Output: $CollectionRoot"
foreach ($v in $AllVolumes) {
    $role = if ($v.Letter -eq ($env:SystemDrive).ToUpper()) { 'system drive' }
            elseif (@($ExtraVolumes | Where-Object { $_.Letter -eq $v.Letter }).Count) { 'EXTRA - will be collected' }
            elseif ($excluded -contains $v.Letter) { 'output/toolkit drive - not collected' }
            elseif (-not $v.Internal) { 'external - not collected' }
            elseif ($SystemDriveOnly) { 'internal - skipped (-SystemDriveOnly)' }
            else { 'not collected' }
    Write-Log ('Volume {0} {1,-6} {2,-8} {3,6} GB  {4}  [{5}]' -f $v.Letter, $v.FileSystem, $v.Bus, $v.SizeGB, $v.Model, $role)
}

# --- Opt-in collectors: say clearly what they do before anything runs ---
if ($DefenderQuarantine) {
    Write-Log '-DefenderQuarantine: the Defender quarantine will be copied. These are LIVE malware samples (RC4-obfuscated, not directly runnable). Handle the collection as malware.' 'WARN'
    if ($Archive -and -not $ArchivePassword) {
        Write-Log '!!! -DefenderQuarantine with -Archive but NO -ArchivePassword: the archive will hold malware samples unencrypted. Add -ArchivePassword. !!!' 'WARN'
    }
}
if ($YaraRules) {
    if (-not (Test-Path -LiteralPath $YaraRules -PathType Leaf)) {
        Write-Log "-YaraRules file not found: $YaraRules. The YARA scan will be skipped." 'WARN'
        $YaraRules = $null
    }
    elseif ($Ctx.Level -lt 4) {
        Write-Log "-YaraRules runs through Velociraptor, which only runs in the Full profile. It will be skipped for '$CollectionProfile'." 'WARN'
    }
}
if ($LolDriversCsv -and -not (Test-Path -LiteralPath $LolDriversCsv -PathType Leaf)) {
    Write-Log "-LolDriversCsv file not found: $LolDriversCsv. Driver hashes will not be matched." 'WARN'
    $LolDriversCsv = $null
}
Write-Log ("Local time {0} ({1}); UTC {2}" -f [DateTimeOffset]::Now.ToString('o'), [TimeZoneInfo]::Local.Id, (Get-UtcStamp))

# ===================================================================
# TOOL DISCOVERY, INVENTORY, INTEGRITY
# ===================================================================

$Is64 = [Environment]::Is64BitOperatingSystem

# Index once; never descend into collection output.
$ToolIndex = @(Get-ChildItem -LiteralPath $ToolsRoot -Recurse -File -Force -ErrorAction Ignore |
    Where-Object { $_.Extension -in '.exe', '.reb' -and -not $_.FullName.StartsWith($CollectionsBase, 'OrdinalIgnoreCase') })

# .NET (Core) runtimes installed on this host, e.g. 8.0.18. Framework-dependent tools need a matching major version.
$NetCoreVersions = @(Get-ChildItem -LiteralPath (Join-Path $env:ProgramFiles 'dotnet\shared\Microsoft.NETCore.App') -Directory -ErrorAction Ignore |
    ForEach-Object { $v = $null; if ([version]::TryParse(($_.Name -replace '-.*$', ''), [ref]$v)) { $v } })
$script:ToolNotes = New-Object System.Collections.Generic.List[string]

# False only when the exe is a framework-dependent .NET app whose runtime is not installed
# (e.g. Get-ZimmermanTools 'net' builds need .NET 10). Native and .NET Framework exes have no runtimeconfig.json.
function Test-ToolRunnable {
    param([IO.FileInfo]$File)
    $rc = [IO.Path]::ChangeExtension($File.FullName, '.runtimeconfig.json')
    if (-not (Test-Path -LiteralPath $rc)) { return $true }
    try {
        $opt = (Get-Content -LiteralPath $rc -Raw | ConvertFrom-Json).runtimeOptions
        if ($opt.PSObject.Properties['includedFrameworks']) { return $true }      # self-contained
        $fws = @()
        if ($opt.PSObject.Properties['framework']) { $fws += $opt.framework }
        if ($opt.PSObject.Properties['frameworks']) { $fws += @($opt.frameworks) }
        foreach ($fw in $fws) {
            if ($fw.name -ne 'Microsoft.NETCore.App') { continue }
            $need = [version]$fw.version
            if (-not @($NetCoreVersions | Where-Object { $_.Major -eq $need.Major -and $_ -ge $need }).Count) {
                $script:ToolNotes.Add("Skipped $($File.FullName): needs .NET $($need) runtime (installed: $(($NetCoreVersions | ForEach-Object { $_.ToString() }) -join ', '))")
                return $false
            }
        }
        return $true
    }
    catch { return $true }
}

# Return the first copy of a tool that can run here. ARM64 builds are ignored; on 64-bit hosts x86 builds are a last resort.
function Find-Tool {
    param([string[]]$Names)
    foreach ($n in $Names) {
        $hits = @($ToolIndex | Where-Object { $_.Name -like $n -and $_.FullName -notmatch '\\arm64\\' })
        if ($Is64) {
            $hits = @($hits | Where-Object { $_.FullName -notmatch '\\(x86|win32|i386)\\' }) + @($hits | Where-Object { $_.FullName -match '\\(x86|win32|i386)\\' })
        }
        foreach ($hit in $hits) {
            if ($hit.Extension -ne '.exe' -or (Test-ToolRunnable $hit)) { return $hit }
        }
    }
    return $null
}
function Get-ArchNames {
    param([string]$Base)
    if ($Is64) { @("${Base}64.exe", "$Base.exe") } else { @("$Base.exe") }
}

$Tool = [ordered]@{
    Autoruns      = Find-Tool (Get-ArchNames 'autorunsc')
    Handle        = Find-Tool (Get-ArchNames 'handle')
    TcpVcon       = Find-Tool (Get-ArchNames 'tcpvcon')
    ListDlls      = Find-Tool (Get-ArchNames 'Listdlls')
    LogonSessions = Find-Tool (Get-ArchNames 'logonsessions')
    Sigcheck      = Find-Tool (Get-ArchNames 'sigcheck')
    EvtxECmd      = Find-Tool @('EvtxECmd.exe')
    RECmd         = Find-Tool @('RECmd.exe')
    RECmdBatch    = Find-Tool @('Kroll_Batch.reb', '*.reb')
    MFTECmd       = Find-Tool @('MFTECmd.exe')
    AmcacheParser = Find-Tool @('AmcacheParser.exe')
    PECmd         = Find-Tool @('PECmd.exe')
    LECmd         = Find-Tool @('LECmd.exe')
    JLECmd        = Find-Tool @('JLECmd.exe')
    SrumECmd      = Find-Tool @('SrumECmd.exe')
    SBECmd        = Find-Tool @('SBECmd.exe')
    RBCmd         = Find-Tool @('RBCmd.exe')
    WxTCmd        = Find-Tool @('WxTCmd.exe')
    SQLECmd       = Find-Tool @('SQLECmd.exe')
    AppCompatCacheParser = Find-Tool @('AppCompatCacheParser.exe')
    RawCopy       = Find-Tool (Get-ArchNames 'RawCopy')
    Winpmem       = Find-Tool @('winpmem*.exe', 'go-winpmem*.exe')
    Magnet        = Find-Tool @('MagnetRAMCapture*.exe', 'MRCv*.exe')
    DumpIt        = Find-Tool @('DumpIt.exe')
    SevenZip      = Find-Tool @('7z.exe', '7za.exe')
    KAPE          = Find-Tool @('kape.exe')
    Velociraptor  = Find-Tool @('velociraptor*.exe')
}

# Use the batch file that ships next to the chosen RECmd (its schema matches that RECmd version).
if ($Tool.RECmd) {
    $reb = Join-Path $Tool.RECmd.DirectoryName 'BatchExamples\Kroll_Batch.reb'
    if (Test-Path -LiteralPath $reb) { $Tool.RECmdBatch = Get-Item -LiteralPath $reb }
}

Write-Log '--- TOOL INVENTORY ---'
$Inventory = foreach ($k in $Tool.Keys) {
    $f = $Tool[$k]
    if ($f) {
        $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction Ignore
        Write-Log "FOUND   $k -> $($f.FullName)" 'OK'
        [pscustomobject]@{
            Tool      = $k; Status = 'FOUND'; Path = $f.FullName
            Version   = $f.VersionInfo.FileVersion
            SHA256    = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
            Signature = if ($sig) { $sig.Status.ToString() } else { 'Unknown' }
            Signer    = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
        }
    }
    else {
        Write-Log "MISSING $k" 'WARN'
        [pscustomobject]@{ Tool = $k; Status = 'MISSING'; Path = ''; Version = ''; SHA256 = ''; Signature = ''; Signer = '' }
    }
}
$Inventory | Export-Csv -LiteralPath (Join-Path $CollectionRoot 'ToolInventory.csv') -NoTypeInformation -Encoding UTF8
foreach ($note in ($script:ToolNotes | Select-Object -Unique)) { Write-Log $note 'WARN' }

# ===================================================================
# COLLECTOR FRAMEWORK
# ===================================================================

$script:Registry = New-Object System.Collections.Generic.List[object]
$script:Results  = New-Object System.Collections.Generic.List[object]
$script:Seq      = 0

function Add-Collector {
    param(
        [Parameter(Mandatory)][int]$Phase,
        [Parameter(Mandatory)][ValidateRange(1, 4)][int]$Level,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action,
        [string]$Out,
        [ValidateSet('Text', 'Csv', 'Json', 'None')][string]$Format = 'Text',
        [string[]]$Needs,             # run only if ANY of these tool keys was found
        [switch]$NeedsVss,            # run only if the VSS snapshot is mounted
        [switch]$OnlyWithoutVss,      # fallback: run only if VSS is NOT available
        [bool]$Enabled = $true
    )
    $script:Seq++
    $script:Registry.Add([pscustomobject]@{
            Seq = $script:Seq; Phase = $Phase; Level = $Level; Name = $Name; Action = $Action
            Out = $Out; Format = $Format; Needs = $Needs; NeedsVss = [bool]$NeedsVss
            OnlyWithoutVss = [bool]$OnlyWithoutVss; Enabled = $Enabled
        })
}

function Invoke-Collector {
    param([Parameter(Mandatory)]$C)

    $row = [ordered]@{
        Phase = $C.Phase; Name = $C.Name; Status = 'OK'; Exit = ''; Seconds = 0
        StartUtc = (Get-UtcStamp); Output = $C.Out; Rows = ''; Note = ''
    }

    $skip = $null
    if (-not $C.Enabled) { $skip = 'disabled by parameter' }
    elseif ($C.Needs -and -not @($C.Needs | Where-Object { $Tool[$_] }).Count) { $skip = 'tool not found: ' + ($C.Needs -join ' / ') }
    elseif ($C.NeedsVss -and -not $Ctx.ShadowLink) { $skip = 'no VSS snapshot available' }
    elseif ($C.OnlyWithoutVss -and $Ctx.ShadowLink) { $skip = 'VSS copy in use; fallback not needed' }

    if ($skip) {
        $row.Status = 'SKIPPED'; $row.Note = $skip
        Write-Log "[P$($C.Phase)] $($C.Name): $skip" 'SKIP'
        $script:Results.Add([pscustomobject]$row)
        return
    }

    Write-Log "[P$($C.Phase)] $($C.Name)"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $script:LastExit = $null
    $global:LASTEXITCODE = 0
    $Error.Clear()

    try {
        $data = @(& $C.Action)
        $outPath = $null
        if ($C.Out) {
            $outPath = Join-Path $Ctx.Root $C.Out
            [IO.Directory]::CreateDirectory((Split-Path -Parent $outPath)) | Out-Null
        }
        switch ($C.Format) {
            'Csv' {
                if ($data.Count) { $data | Export-Csv -LiteralPath $outPath -NoTypeInformation -Encoding UTF8 }
                else { New-Item -ItemType File -Force -Path $outPath | Out-Null }
                $row.Rows = $data.Count
            }
            'Json' { $data | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $outPath -Encoding UTF8 }
            'Text' { ($data | Out-String -Width 4096) | Out-File -LiteralPath $outPath -Encoding UTF8 }
            default { if ($data.Count) { $row.Note = (($data | ForEach-Object { "$_" }) -join '; ') } }
        }

        $ec = if ($null -ne $script:LastExit) { $script:LastExit } else { $global:LASTEXITCODE }
        $row.Exit = $ec
        if ($ec -ne 0) { $row.Status = 'WARN'; $row.Note = ("$($row.Note) exit=$ec").Trim() }
        if ($Error.Count -gt 0) {
            if ($row.Status -eq 'OK') { $row.Status = 'WARN' }
            $first = $Error[0].ToString(); if ($first.Length -gt 160) { $first = $first.Substring(0, 160) }
            $row.Note = ("$($row.Note) $($Error.Count) non-terminating error(s); first: $first").Trim()
        }
    }
    catch {
        $row.Status = 'FAIL'
        $row.Note = $_.Exception.Message
    }
    finally {
        $sw.Stop()
        $row.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    }

    $lvl = switch ($row.Status) { 'OK' { 'OK' } 'WARN' { 'WARN' } default { 'ERROR' } }
    Write-Log ("    -> {0} ({1}s) {2}" -f $row.Status, $row.Seconds, $row.Note) $lvl
    $script:Results.Add([pscustomobject]$row)
}

# --- VSS helpers ---------------------------------------------------

function Copy-VssArtifact {
    param(
        [Parameter(Mandatory)][string]$RelativePath,   # relative to volume root, wildcards allowed
        [switch]$Recurse,
        [string]$NameLike,
        [string]$FlatTo        # if set: copy files flat into this folder (relative to the collection root), e.g. 'EventLogs'
    )
    $src = Join-Path $Ctx.ShadowLink $RelativePath
    $files = @(Get-ChildItem -Path $src -Force -File -Recurse:$Recurse -ErrorAction Ignore)
    $ok = 0; $bad = 0
    foreach ($f in $files) {
        if ($NameLike -and $f.Name -notlike $NameLike) { continue }
        $rel = $f.FullName.Substring($Ctx.ShadowLink.Length).TrimStart('\')
        $dst = if ($FlatTo) { Join-Path (Join-Path $Ctx.Root $FlatTo) $f.Name } else { Join-Path $Ctx.Disk $rel }
        $st = 'OK'
        try {
            [IO.Directory]::CreateDirectory((Split-Path -Parent $dst)) | Out-Null
            Copy-Item -LiteralPath $f.FullName -Destination $dst -Force -ErrorAction Stop
            $ok++
        }
        catch { $st = 'FAIL: ' + $_.Exception.Message; $bad++ }
        $Ctx.CopyLog.Add([pscustomobject]@{
                RelativePath = $rel; Length = $f.Length; Status = $st
                SrcCreatedUtc = $f.CreationTimeUtc.ToString('o'); SrcModifiedUtc = $f.LastWriteTimeUtc.ToString('o')
                SrcAccessedUtc = $f.LastAccessTimeUtc.ToString('o')
            })
    }
    if ($ok -or $bad) { '{0}: {1} copied, {2} failed' -f $RelativePath, $ok, $bad }   # silent when nothing matched
}

function Get-VssUserDirs {
    @(Get-ChildItem -LiteralPath (Join-Path $Ctx.ShadowLink 'Users') -Directory -Force -ErrorAction Ignore |
        Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
        ForEach-Object { $_.Name })
}

# --- Shared helpers for the 3.4.0 collectors ------------------------

# Hash a file without throwing. Returns $null when the file can't be read (locked, gone, access denied).
function Get-HashSafe {
    param([string]$Path, [string]$Algorithm = 'SHA256')
    try { (Get-FileHash -LiteralPath $Path -Algorithm $Algorithm -ErrorAction Stop).Hash } catch { $null }
}

# Presence-and-metadata record for files that must NOT be copied (configs that can hold secrets, malware, big images).
function Get-FileMeta {
    param([Parameter(Mandatory)][IO.FileInfo]$File, [switch]$NoHash, [string]$Note)
    [pscustomobject]@{
        Path        = $File.FullName
        Size        = $File.Length
        CreatedUtc  = $File.CreationTimeUtc.ToString('o')
        ModifiedUtc = $File.LastWriteTimeUtc.ToString('o')
        AccessedUtc = $File.LastAccessTimeUtc.ToString('o')
        SHA256      = $(if ($NoHash) { $null } else { Get-HashSafe $File.FullName })
        Note        = $Note
    }
}

# Root to read user files from: the snapshot when it is mounted (no access-time updates on the evidence), else live.
function Get-ReadRoot { if ($Ctx.ShadowLink) { $Ctx.ShadowLink } else { "$env:SystemDrive\" } }

# Map a path under Get-ReadRoot back to the original C:\ path, so outputs show where the file really lives.
function ConvertTo-OriginalPath {
    param([string]$Path)
    $root = Get-ReadRoot
    if ($Path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { return Join-Path "$env:SystemDrive\" $Path.Substring($root.Length).TrimStart('\') }
    $Path
}

# Read ONLY the named keys from an INI-style file (everything else, e.g. passwords and keys, is never read out).
function Get-IniFields {
    param([string]$Path, [string[]]$Keys)
    $found = foreach ($line in @(Get-Content -LiteralPath $Path -ErrorAction Ignore)) {
        if ($line -match '^\s*([^=;#\[]+?)\s*=\s*(.*)$' -and ($Keys -contains $Matches[1].Trim())) { '{0}={1}' -f $Matches[1].Trim(), $Matches[2].Trim() }
    }
    ($found -join '; ')
}

# Kernel paths come in many shapes (\SystemRoot\..., \??\C:\..., System32\drivers\x.sys, bare x.sys). Normalize to C:\...
function ConvertTo-DriverPath {
    param([string]$Raw)
    if (-not $Raw) { return $null }
    $p = $Raw.Trim().Trim('"')
    if ($p -match '^\\\?\?\\(.+)$') { $p = $Matches[1] }
    elseif ($p -match '^\\SystemRoot\\(.+)$') { $p = Join-Path $env:SystemRoot $Matches[1] }
    elseif ($p -match '^%SystemRoot%\\(.+)$') { $p = Join-Path $env:SystemRoot $Matches[1] }
    elseif ($p -match '^\\Windows\\(.+)$') { $p = Join-Path $env:SystemRoot $Matches[1] }
    elseif ($p -match '^(?i)system32\\(.+)$') { $p = Join-Path $env:SystemRoot "System32\$($Matches[1])" }
    elseif ($p -notmatch '[\\/]') { $p = Join-Path $env:SystemRoot "System32\drivers\$p" }
    $p
}

# Loaded kernel modules straight from the kernel (EnumDeviceDrivers), so drivers whose service key was deleted
# after loading (a common EDR-killer pattern) still show up. Needs admin; returns @() when it can't enumerate.
function Get-LoadedKernelModule {
    if (-not ('DfirNative.Psapi' -as [type])) {
        Add-Type -Namespace DfirNative -Name Psapi -MemberDefinition @'
[DllImport("psapi.dll", SetLastError = true)]
public static extern bool EnumDeviceDrivers([Out] UIntPtr[] ddAddresses, uint cb, out uint lpcbNeeded);
[DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern uint GetDeviceDriverFileNameW(UIntPtr imageBase, System.Text.StringBuilder lpFilename, uint nSize);
'@
    }
    $needed = [uint32]0
    [void][DfirNative.Psapi]::EnumDeviceDrivers($null, 0, [ref]$needed)
    if ($needed -eq 0) { return @() }
    $count = [int]($needed / [UIntPtr]::Size)
    $addrs = New-Object UIntPtr[] $count
    if (-not [DfirNative.Psapi]::EnumDeviceDrivers($addrs, $needed, [ref]$needed)) { return @() }
    foreach ($a in $addrs) {
        $sb = New-Object System.Text.StringBuilder 1024
        if ([DfirNative.Psapi]::GetDeviceDriverFileNameW($a, $sb, 1024) -gt 0) { $sb.ToString() }
    }
}

# Idempotent: called before Phase 8 (KAPE/Velociraptor don't need our snapshot) and again in the final 'finally'.
function Remove-Vss {
    if ($Ctx.ShadowLink) {
        if (Test-Path -LiteralPath $Ctx.ShadowLink) {
            # cmd rmdir removes only the symlink. NEVER Remove-Item -Recurse here.
            & $Exe.cmd /c rmdir $Ctx.ShadowLink 2>&1 | Out-Null
            Write-Log "Removed snapshot symlink $($Ctx.ShadowLink)"
        }
        $Ctx.ShadowLink = $null
    }
    if ($Ctx.ShadowId -and -not $Ctx.ShadowDeleted) {
        try {
            Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | Where-Object { $_.ID -eq $Ctx.ShadowId } | Remove-CimInstance -ErrorAction Stop
            $Ctx.ShadowDeleted = $true
            Write-Log "Deleted VSS snapshot $($Ctx.ShadowId)"
        }
        catch { Write-Log "Could not delete VSS snapshot $($Ctx.ShadowId): $($_.Exception.Message)" 'WARN' }
    }
}

# ===================================================================
# COLLECTOR DEFINITIONS  (Phase = order of volatility, Level = min profile)
# ===================================================================

# ---------- PHASE 1: MEMORY ----------
Add-Collector -Phase 1 -Level 1 -Name 'Memory acquisition' -Format None -Needs 'Winpmem', 'Magnet', 'DumpIt' -Enabled:$Memory.IsPresent -Action {
    $memDir = Join-Path $Ctx.Root 'Memory'
    $img = Join-Path $memDir ('{0}_{1}.raw' -f $env:COMPUTERNAME, $Ctx.Stamp)
    $log = Join-Path $memDir 'acquisition.log'
    # go-winpmem (verified against 1.0-rc2 --help): 'acquire [--nosparse] <file>'. Legacy winpmem_mini: '<file>'.
    # Magnet and DumpIt lines are still UNVERIFIED (only used when WinPmem is absent).
    if ($Tool.Winpmem) {
        $wpArgs = if ($Tool.Winpmem.Name -like 'go-winpmem*') { @('acquire', '--nosparse', $img) } else { @($img) }
        Invoke-External -FilePath $Tool.Winpmem.FullName -ArgumentList $wpArgs -OutFile $log -WorkingDirectory $memDir -TimeoutSec 7200
    }
    elseif ($Tool.Magnet) { Invoke-External -FilePath $Tool.Magnet.FullName -ArgumentList @('/accepteula', '/go', '/silent') -OutFile $log -WorkingDirectory $memDir -TimeoutSec 7200 }
    else { Invoke-External -FilePath $Tool.DumpIt.FullName -ArgumentList @('/QUIET', '/OUTPUT', $img) -OutFile $log -TimeoutSec 7200 }
    Get-ChildItem -Path "$memDir\*" -File -Exclude '*.log', '*.err' -ErrorAction Ignore |
        ForEach-Object { '{0} ({1:N0} MB)' -f $_.Name, ($_.Length / 1MB) }
}

# ---------- PHASE 2: TIME + NETWORK (Quick) ----------
Add-Collector -Phase 2 -Level 1 -Name 'Time, timezone, clock sync' -Out 'System\time.txt' -Action {
    $tz = [TimeZoneInfo]::Local
    'UtcNow    : ' + [DateTime]::UtcNow.ToString('o')
    'LocalNow  : ' + [DateTimeOffset]::Now.ToString('o')
    "TimeZone  : $($tz.Id) ($($tz.DisplayName)); BaseOffset=$($tz.BaseUtcOffset); DST now=$($tz.IsDaylightSavingTime([DateTime]::Now))"
    New-Section 'w32tm /query /status'
    & $Exe.w32tm /query /status 2>&1
    if ($NtpServer) {
        New-Section "w32tm /stripchart vs $NtpServer"
        & $Exe.w32tm /stripchart "/computer:$NtpServer" /samples:3 /dataonly 2>&1
    }
}

Add-Collector -Phase 2 -Level 1 -Name 'Network connections joined to process' -Format Csv -Out 'Network\connections.csv' -Action {
    $procs = @{}
    Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
    Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
        $p = $procs[[int]$_.OwningProcess]
        [pscustomobject]@{
            Proto = 'TCP'; LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress; RemotePort = $_.RemotePort; State = $_.State
            Pid = $_.OwningProcess; Process = if ($p) { $p.Name } else { $null }
            Path = if ($p) { $p.ExecutablePath } else { $null }
            CommandLine = if ($p) { $p.CommandLine } else { $null }
            CreatedUtc = if ($_.CreationTime) { $_.CreationTime.ToUniversalTime().ToString('o') } else { $null }
        }
    }
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
        $p = $procs[[int]$_.OwningProcess]
        [pscustomobject]@{
            Proto = 'UDP'; LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort
            RemoteAddress = $null; RemotePort = $null; State = $null
            Pid = $_.OwningProcess; Process = if ($p) { $p.Name } else { $null }
            Path = if ($p) { $p.ExecutablePath } else { $null }
            CommandLine = if ($p) { $p.CommandLine } else { $null }
            CreatedUtc = if ($_.CreationTime) { $_.CreationTime.ToUniversalTime().ToString('o') } else { $null }
        }
    }
}

Add-Collector -Phase 2 -Level 1 -Name 'netstat -ano' -Out 'Network\netstat_ano.txt' -Action { & $Exe.netstat -ano 2>&1 }

Add-Collector -Phase 2 -Level 1 -Name 'DNS client cache' -Format Csv -Out 'Network\dns_cache.csv' -Action {
    Get-DnsClientCache -ErrorAction Stop | Select-Object Entry, RecordName, RecordType, Status, Section, TimeToLive, Data
}

Add-Collector -Phase 2 -Level 1 -Name 'Network configuration, ARP, routes, hosts, proxy' -Out 'Network\netconfig.txt' -Action {
    New-Section 'ipconfig /all';           & $Exe.ipconfig /all 2>&1
    New-Section 'arp -a';                  & $Exe.arp -a 2>&1
    New-Section 'route print';             & $Exe.route print 2>&1
    New-Section 'netsh winhttp show proxy'; & $Exe.netsh winhttp show proxy 2>&1
    New-Section 'HKCU proxy settings'
    Invoke-Safe { Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL | Format-List | Out-String -Width 4096 }
    New-Section 'hosts file'
    Invoke-Safe { Get-Content -LiteralPath (Join-Path $Sys32 'drivers\etc\hosts') }
}

Add-Collector -Phase 2 -Level 1 -Name 'SMB sessions, shares, mapped drives' -Out 'Network\smb.txt' -Action {
    New-Section 'net session'; & $Exe.net session 2>&1
    New-Section 'net use';     & $Exe.net use 2>&1
    New-Section 'net share';   & $Exe.net share 2>&1
    New-Section 'Get-SmbSession';    Invoke-Safe { Get-SmbSession | Format-List * | Out-String -Width 4096 }
    New-Section 'Get-SmbConnection'; Invoke-Safe { Get-SmbConnection | Format-List * | Out-String -Width 4096 }
    New-Section 'Get-SmbOpenFile (files opened on this host by remote clients)'
    Invoke-Safe {
        $of = @(Get-SmbOpenFile -ErrorAction Stop)
        if ($of.Count) { $of | Select-Object ClientComputerName, ClientUserName, Path, SessionId, Permissions | Format-Table -AutoSize | Out-String -Width 4096 }
        else { '(no files open over SMB)' }
    }
}

Add-Collector -Phase 2 -Level 1 -Name 'Named pipes' -Out 'Network\named_pipes.txt' -Action {
    [System.IO.Directory]::GetFiles('\\.\pipe\') | Sort-Object
}

Add-Collector -Phase 2 -Level 1 -Name 'Port proxies, NetBIOS, neighbors, IP config, Wi-Fi profiles' -Out 'Network\net_extra.txt' -Action {
    New-Section 'netsh interface portproxy show all (pivot persistence)'; & $Exe.netsh interface portproxy show all 2>&1
    New-Section 'nbtstat -c (NetBIOS name cache)'; & $Exe.nbtstat -c 2>&1
    New-Section 'nbtstat -S (NetBIOS sessions)';   & $Exe.nbtstat -S 2>&1
    New-Section 'Get-NetNeighbor'; Invoke-Safe { Get-NetNeighbor -ErrorAction Stop | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State | Format-Table -AutoSize | Out-String -Width 4096 }
    New-Section 'Get-NetIPConfiguration'
    $before = $Error.Count
    Invoke-Safe { Get-NetIPConfiguration -Detailed -ErrorAction Stop | Format-List * | Out-String -Width 4096 }
    # Its internal Get-NetRoute/Get-NetIPAddress calls report "No matching MSFT_NetRoute/MSFT_NetIPAddress objects"
    # for every adapter without a route or address. That is not a failure, so drop just those records.
    for ($i = $Error.Count - $before - 1; $i -ge 0; $i--) { if ("$($Error[$i])" -match 'No matching MSFT_Net\w+ objects') { $Error.RemoveAt($i) } }
    New-Section 'netsh wlan show profiles'; & $Exe.netsh wlan show profiles 2>&1
    $global:LASTEXITCODE = 0   # informational: nbtstat/wlan return non-zero when there is simply nothing to show
}

Add-Collector -Phase 2 -Level 1 -Name 'TCPView (tcpvcon)' -Format None -Needs 'TcpVcon' -Action {
    Invoke-External -FilePath $Tool.TcpVcon.FullName -ArgumentList @('-accepteula', '-a', '-c', '-n') -OutFile (Join-Path $Ctx.Root 'Network\tcpvcon.csv') -TimeoutSec 120
}

# ---------- PHASE 3: PROCESSES / SESSIONS / SERVICES / LIVE PERSISTENCE (Quick) ----------
Add-Collector -Phase 3 -Level 1 -Name 'Processes (owner, path, SHA256, signature)' -Format Csv -Out 'Processes\processes.csv' -Action {
    $cache = @{}
    Get-CimInstance Win32_Process | ForEach-Object {
        $p = $_; $path = $p.ExecutablePath; $sha = $null; $sig = $null
        if ($path -and (Test-Path -LiteralPath $path)) {
            if (-not $cache.ContainsKey($path)) {
                $h = try { (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { 'ERROR' }
                $s = try { (Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop).Status.ToString() } catch { 'ERROR' }
                $cache[$path] = @($h, $s)
            }
            $sha = $cache[$path][0]; $sig = $cache[$path][1]
        }
        # GetOwner fails with "Not found" for processes that exited after the snapshot; that is expected,
        # so the caught error records are removed rather than turning the collector into a WARN.
        $before = $Error.Count
        $o = try { Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop } catch {
            for ($i = $Error.Count - $before - 1; $i -ge 0; $i--) { $Error.RemoveAt($i) }
            $null
        }
        [pscustomobject]@{
            Pid = $p.ProcessId; PPid = $p.ParentProcessId; Name = $p.Name; Path = $path
            CommandLine = $p.CommandLine; SessionId = $p.SessionId
            CreatedUtc = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('o') } else { $null }
            Owner = if ($o -and $o.User) { "$($o.Domain)\$($o.User)" } else { $null }
            Threads = $p.ThreadCount; Handles = $p.HandleCount
            SHA256 = $sha; Signature = $sig
        }
    }
}

Add-Collector -Phase 3 -Level 1 -Name 'tasklist /v and /svc' -Out 'Processes\tasklist.txt' -Action {
    New-Section 'tasklist /v /fo csv'; & $Exe.tasklist /v /fo csv 2>&1
    New-Section 'tasklist /svc';       & $Exe.tasklist /svc 2>&1
    New-Section 'tasklist /m (loaded modules)'; & $Exe.tasklist /m 2>&1
}

Add-Collector -Phase 3 -Level 1 -Name 'Logon sessions' -Out 'System\sessions.txt' -Action {
    New-Section 'quser';   & $Exe.quser 2>&1
    New-Section 'qwinsta'; & $Exe.qwinsta 2>&1
    New-Section 'Win32_LogonSession'
    Invoke-Safe { Get-CimInstance Win32_LogonSession | Select-Object LogonId, LogonType, AuthenticationPackage, StartTime | Format-Table -AutoSize | Out-String -Width 4096 }
}

Add-Collector -Phase 3 -Level 1 -Name 'Services (Win32_Service)' -Format Csv -Out 'Persistence\services.csv' -Action {
    Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ProcessId, ServiceType, Description
}

Add-Collector -Phase 3 -Level 1 -Name 'Scheduled tasks' -Out 'Persistence\schtasks.csv' -Action { & $Exe.schtasks /query /fo CSV /v 2>&1 }

Add-Collector -Phase 3 -Level 1 -Name 'Scheduled task actions' -Format Csv -Out 'Persistence\scheduled_task_actions.csv' -Action {
    Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            TaskPath = $_.TaskPath; TaskName = $_.TaskName; State = $_.State
            RunAs = $_.Principal.UserId; RunLevel = $_.Principal.RunLevel
            # COM-handler actions have no Execute property (StrictMode would throw), so test for it.
            Actions = (@($_.Actions | ForEach-Object {
                        if ($_.PSObject.Properties['Execute']) { ('{0} {1}' -f $_.Execute, $(if ($_.PSObject.Properties['Arguments']) { $_.Arguments })).Trim() }
                        elseif ($_.PSObject.Properties['ClassId']) { 'COM handler ' + $_.ClassId }
                        else { 'Unknown action type' }
                    }) -join ' | ')
        }
    }
}

Add-Collector -Phase 3 -Level 1 -Name 'Run keys / Winlogon / AppInit (HKLM + loaded HKU)' -Out 'Persistence\run_keys.txt' -Action {
    $suffix = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
    'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    $roots = @('HKEY_LOCAL_MACHINE') + @(Get-ChildItem Registry::HKEY_USERS -ErrorAction Ignore | Where-Object { $_.PSChildName -notlike '*_Classes' } | ForEach-Object { $_.Name })
    foreach ($r in $roots) {
        foreach ($s in $suffix) {
            $k = "$r\$s"
            if (Test-Path -LiteralPath "Registry::$k") {
                New-Section $k
                Get-ItemProperty -LiteralPath "Registry::$k" | Select-Object * -ExcludeProperty PS* | Format-List | Out-String -Width 4096
            }
        }
    }
}

Add-Collector -Phase 3 -Level 1 -Name 'WMI event subscriptions (persistence)' -Out 'Persistence\wmi_subscriptions.txt' -Action {
    foreach ($cls in '__EventFilter', '__EventConsumer', '__FilterToConsumerBinding') {
        New-Section "root\subscription : $cls"
        Invoke-Safe { Get-CimInstance -Namespace 'root\subscription' -ClassName $cls -ErrorAction Stop | Format-List * | Out-String -Width 4096 }
    }
}

Add-Collector -Phase 3 -Level 1 -Name 'BITS transfers' -Out 'Persistence\bits.txt' -Action {
    Get-BitsTransfer -AllUsers -ErrorAction Stop | Format-List * | Out-String -Width 4096
}

Add-Collector -Phase 3 -Level 1 -Name 'Startup commands (Win32_StartupCommand)' -Format Csv -Out 'Persistence\startup_commands.csv' -Action {
    Get-CimInstance Win32_StartupCommand -ErrorAction Stop | Select-Object Name, Command, Location, User
}

Add-Collector -Phase 3 -Level 1 -Name 'IFEO debuggers and SilentProcessExit monitors' -Format Csv -Out 'Persistence\ifeo.csv' -Action {
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit') {
        Get-ChildItem -LiteralPath $base -ErrorAction Ignore | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Ignore
            if (-not $p) { return }
            $vals = foreach ($v in 'Debugger', 'GlobalFlag', 'VerifierDlls', 'MonitorProcess', 'ReportingMode') {
                if ($p.PSObject.Properties[$v]) { '{0}={1}' -f $v, $p.$v }
            }
            if ($vals) { [pscustomobject]@{ Key = $_.Name; Values = ($vals -join '; ') } }
        }
    }
}

# "Run a program when this service fails" is persistence that Win32_Service doesn't show. The registry is read for
# every service; sc qfailure (slow) runs only for the few that actually have a FailureCommand.
Add-Collector -Phase 3 -Level 2 -Name 'Service failure actions (FailureCommand)' -Format Csv -Out 'Persistence\service_failure_actions.csv' -Action {
    foreach ($k in @(Get-ChildItem -LiteralPath 'Registry::HKLM\SYSTEM\CurrentControlSet\Services' -ErrorAction Ignore)) {
        $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Ignore
        if (-not $p -or -not $p.PSObject.Properties['FailureCommand'] -or -not "$($p.FailureCommand)".Trim()) { continue }
        $img = if ($p.PSObject.Properties['ImagePath']) { [string]$p.ImagePath } else { $null }
        $qf = (& $Exe.sc qfailure $k.PSChildName 5000 2>&1 | Out-String).Trim() -replace '\s*\r?\n\s*', ' | '
        [pscustomobject]@{ Service = $k.PSChildName; ImagePath = $img; FailureCommand = [string]$p.FailureCommand; ScQFailure = $qf }
    }
    $global:LASTEXITCODE = 0
}

Add-Collector -Phase 3 -Level 1 -Name 'Existing shadow copies (vssadmin list shadows)' -Out 'System\shadow_copies.txt' -Action {
    & $Exe.vssadmin list shadows 2>&1
    New-Section 'vssadmin list shadowstorage'; & $Exe.vssadmin list shadowstorage 2>&1
    $global:LASTEXITCODE = 0   # vssadmin returns non-zero when no shadows exist
}

# ---------- PHASE 4: SYSTEM CONFIGURATION ----------
Add-Collector -Phase 4 -Level 1 -Name 'Host identity and OS' -Out 'System\identity.txt' -Action {
    New-Section 'hostname'; & $Exe.hostname 2>&1
    New-Section 'whoami /all'; & $Exe.whoami /all 2>&1
    New-Section 'Win32_OperatingSystem'
    Invoke-Safe { Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, RegisteredUser | Out-String -Width 4096 }
    New-Section 'Win32_ComputerSystem'
    Invoke-Safe { Get-CimInstance Win32_ComputerSystem | Format-List Name, Domain, PartOfDomain, Manufacturer, Model, TotalPhysicalMemory, UserName | Out-String -Width 4096 }
    New-Section 'Environment variables'
    Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize | Out-String -Width 4096
}

Add-Collector -Phase 4 -Level 1 -Name 'Local accounts and administrators' -Out 'System\accounts.txt' -Action {
    New-Section 'net user';                    & $Exe.net user 2>&1
    New-Section 'net localgroup administrators'; & $Exe.net localgroup administrators 2>&1
    New-Section 'Get-LocalUser'
    Invoke-Safe { Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, SID | Format-Table -AutoSize | Out-String -Width 4096 }
}

Add-Collector -Phase 4 -Level 1 -Name 'Disks, volumes, BitLocker' -Out 'System\disks_bitlocker.txt' -Action {
    New-Section 'Win32_LogicalDisk'
    Invoke-Safe { Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, DriveType, FileSystem, Size, FreeSpace, VolumeName | Format-Table -AutoSize | Out-String -Width 4096 }
    New-Section 'manage-bde -status'
    & $Exe.'manage-bde' -status 2>&1
}

Add-Collector -Phase 4 -Level 2 -Name 'systeminfo' -Out 'System\systeminfo.txt' -Action { & $Exe.systeminfo 2>&1 }

Add-Collector -Phase 4 -Level 2 -Name 'netstat -anob (with executables)' -Out 'Network\netstat_anob.txt' -Action { & $Exe.netstat -anob 2>&1 }

Add-Collector -Phase 4 -Level 2 -Name 'Installed software' -Format Csv -Out 'System\installed_software.csv' -Action {
    $paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'Registry::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    foreach ($p in $paths) {
        Get-ItemProperty -Path $p -ErrorAction Ignore | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName } |
            ForEach-Object {
                [pscustomobject]@{
                    Name = $_.DisplayName
                    Version = if ($_.PSObject.Properties['DisplayVersion']) { $_.DisplayVersion } else { $null }
                    Publisher = if ($_.PSObject.Properties['Publisher']) { $_.Publisher } else { $null }
                    InstallDate = if ($_.PSObject.Properties['InstallDate']) { $_.InstallDate } else { $null }
                    InstallLocation = if ($_.PSObject.Properties['InstallLocation']) { $_.InstallLocation } else { $null }
                    Key = $_.PSPath
                }
            }
    }
}

Add-Collector -Phase 4 -Level 2 -Name 'Hotfixes' -Format Csv -Out 'System\hotfixes.csv' -Action {
    Get-HotFix -ErrorAction Stop | Select-Object HotFixID, Description, InstalledOn, InstalledBy
}

Add-Collector -Phase 4 -Level 2 -Name 'Drivers' -Out 'System\drivers.csv' -Action { & $Exe.driverquery /v /fo csv 2>&1 }

Add-Collector -Phase 4 -Level 2 -Name 'Windows Defender status, detections, exclusions' -Out 'Security\defender.txt' -Action {
    $svc = Get-Service -Name WinDefend -ErrorAction Ignore
    $state = if ($svc) { [string]$svc.Status } else { 'not installed' }
    New-Section 'WinDefend service'; "Status: $state"
    foreach ($cmd in 'Get-MpComputerStatus', 'Get-MpPreference', 'Get-MpThreatDetection', 'Get-MpThreat') {
        New-Section $cmd
        $before = $Error.Count
        try { & $cmd -ErrorAction Stop | Format-List * | Out-String -Width 4096 }
        catch {
            "ERROR: $($_.Exception.Message)"
            if ($state -ne 'Running') {
                # Expected when the Defender service is stopped (0x800106ba); recorded here, not counted as a WARN.
                "(expected: the WinDefend service is $state)"
                for ($i = $Error.Count - $before - 1; $i -ge 0; $i--) { $Error.RemoveAt($i) }
            }
        }
    }
}

Add-Collector -Phase 4 -Level 2 -Name 'Firewall profiles and enabled rules' -Out 'Security\firewall.txt' -Action {
    New-Section 'netsh advfirewall show allprofiles'; & $Exe.netsh advfirewall show allprofiles 2>&1
    New-Section 'Enabled rules'
    Invoke-Safe { Get-NetFirewallRule -Enabled True | Select-Object Name, DisplayName, Direction, Action, Profile | Format-Table -AutoSize | Out-String -Width 4096 }
    New-Section 'netsh advfirewall firewall show rule name=all (full detail)'
    & $Exe.netsh advfirewall firewall show rule name=all 2>&1
}

Add-Collector -Phase 4 -Level 2 -Name 'Startup folders' -Format Csv -Out 'Persistence\startup_folders.csv' -Action {
    $dirs = @(Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
    $dirs += @(Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction Ignore |
            ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
    foreach ($d in $dirs) {
        Get-ChildItem -LiteralPath $d -Force -ErrorAction Ignore |
            Select-Object FullName, Length, @{ n = 'CreatedUtc'; e = { $_.CreationTimeUtc.ToString('o') } }, @{ n = 'ModifiedUtc'; e = { $_.LastWriteTimeUtc.ToString('o') } }
    }
}

Add-Collector -Phase 4 -Level 2 -Name 'Security settings: LSA, WDigest, RDP, UAC, PowerShell logging, exec policy' -Out 'Security\security_settings.txt' -Action {
    foreach ($k in 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
        'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
        'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server',
        'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp',
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog',
        'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify') {
        New-Section $k
        if (Test-Path -LiteralPath "Registry::$k") { & $Exe.reg query $k /s 2>&1 } else { '(key not present)' }
    }
    New-Section 'Get-ExecutionPolicy -List'; Invoke-Safe { Get-ExecutionPolicy -List | Format-Table -AutoSize | Out-String }
    $global:LASTEXITCODE = 0
}

Add-Collector -Phase 4 -Level 2 -Name 'Security products (SecurityCenter2)' -Out 'Security\security_products.txt' -Action {
    foreach ($cls in 'AntiVirusProduct', 'AntiSpywareProduct', 'FirewallProduct') {
        New-Section $cls
        Invoke-Safe { Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName $cls -ErrorAction Stop | Format-List * | Out-String -Width 4096 }
    }
}

Add-Collector -Phase 4 -Level 2 -Name 'Stored credential names (cmdkey) and Kerberos tickets (klist)' -Out 'Security\credential_metadata.txt' -Action {
    New-Section 'cmdkey /list (target names only, no secrets)'; & $Exe.cmdkey /list 2>&1
    New-Section 'klist';          & $Exe.klist 2>&1
    New-Section 'klist sessions'; & $Exe.klist sessions 2>&1
    $global:LASTEXITCODE = 0
}

Add-Collector -Phase 4 -Level 2 -Name 'Certificate stores (Root, CA, TrustedPublisher)' -Format Csv -Out 'Security\certificates.csv' -Action {
    foreach ($store in 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\CA', 'Cert:\LocalMachine\TrustedPublisher',
        'Cert:\CurrentUser\Root', 'Cert:\CurrentUser\CA', 'Cert:\CurrentUser\TrustedPublisher') {
        Get-ChildItem -LiteralPath $store -ErrorAction Ignore | ForEach-Object {
            [pscustomobject]@{
                Store = $store; Thumbprint = $_.Thumbprint; Subject = $_.Subject; Issuer = $_.Issuer
                NotBeforeUtc = $_.NotBefore.ToUniversalTime().ToString('o'); NotAfterUtc = $_.NotAfter.ToUniversalTime().ToString('o')
                FriendlyName = $_.FriendlyName
            }
        }
    }
}

Add-Collector -Phase 4 -Level 2 -Name 'Local groups and members' -Out 'System\local_groups.txt' -Action {
    foreach ($g in @(Get-LocalGroup -ErrorAction Stop)) {
        New-Section "$($g.Name)  ($($g.SID))"
        Invoke-Safe { Get-LocalGroupMember -Group $g.Name -ErrorAction Stop | Select-Object Name, ObjectClass, PrincipalSource, SID | Format-Table -AutoSize | Out-String -Width 4096 }
    }
}

Add-Collector -Phase 4 -Level 2 -Name 'AppX packages (all users)' -Format Csv -Out 'System\appx_packages.csv' -Action {
    Get-AppxPackage -AllUsers -ErrorAction Stop | Select-Object Name, PackageFullName, Version, Publisher, InstallLocation, SignatureKind, IsFramework
}

Add-Collector -Phase 4 -Level 2 -Name 'PnP devices' -Format Csv -Out 'System\pnp_devices.csv' -Action {
    Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Select-Object Name, PNPClass, DeviceID, Manufacturer, Service, Status, Present
}

# ---- Ported from the original batch script (v2 .bat) ----

Add-Collector -Phase 4 -Level 1 -Name 'sc query / net start' -Out 'Persistence\sc_netstart.txt' -Action {
    New-Section 'sc query type= service state= all'; & $Exe.sc query type= service state= all 2>&1
    New-Section 'net start';                         & $Exe.net start 2>&1
}

Add-Collector -Phase 4 -Level 2 -Name 'Drivers: signed/unsigned (driverquery /si)' -Out 'System\drivers_signed.txt' -Action {
    & $Exe.driverquery /si 2>&1
}

Add-Collector -Phase 4 -Level 2 -Name 'USB storage history (USBSTOR)' -Out 'System\usbstor.txt' -Action {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    if (Test-Path -LiteralPath $key) { & $Exe.reg query 'HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR' /s 2>&1 }
    else { 'USBSTOR key not present (no USB mass-storage devices recorded)' }
}

Add-Collector -Phase 4 -Level 2 -Name 'Audit policy (auditpol)' -Out 'Security\auditpol.txt' -Action {
    & $Exe.auditpol /get '/category:*' 2>&1
}

Add-Collector -Phase 4 -Level 2 -Name 'Group Policy result (gpresult /r)' -Out 'Security\gpresult.txt' -Action {
    & $Exe.gpresult /r 2>&1
}

Add-Collector -Phase 4 -Level 2 -Name 'Prefetch directory listing' -Format Csv -Out 'System\prefetch_listing.csv' -Action {
    Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'Prefetch') -Force -ErrorAction Ignore |
        Select-Object Name, Length,
        @{ n = 'CreatedUtc'; e = { $_.CreationTimeUtc.ToString('o') } },
        @{ n = 'ModifiedUtc'; e = { $_.LastWriteTimeUtc.ToString('o') } },
        @{ n = 'AccessedUtc'; e = { $_.LastAccessTimeUtc.ToString('o') } }
}

# Accessibility binaries: hash + signature + IFEO debugger for the whole family; copy sethc/utilman (as in the .bat).
Add-Collector -Phase 4 -Level 2 -Name 'Accessibility binaries (sethc/utilman): copy, hash, signature, IFEO' -Format Csv -Out 'Persistence\accessibility_binaries.csv' -Action {
    $dest = Join-Path $Ctx.Disk 'Accessibility_Binaries'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    foreach ($bin in 'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe', 'atbroker.exe') {
        $path = Join-Path $Sys32 $bin
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $fi = Get-Item -LiteralPath $path
        $sha = try { (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { 'ERROR' }
        $sig = try { Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop } catch { $null }
        $copied = $false
        if ($bin -in 'sethc.exe', 'utilman.exe') {
            try { Copy-Item -LiteralPath $path -Destination (Join-Path $dest $bin) -Force -ErrorAction Stop; $copied = $true } catch { }
        }
        $ifeo = $null
        $ifeoKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$bin"
        if (Test-Path -LiteralPath $ifeoKey) {
            $ip = Get-ItemProperty -LiteralPath $ifeoKey
            if ($ip.PSObject.Properties['Debugger']) { $ifeo = $ip.Debugger }
        }
        [pscustomobject]@{
            File = $bin; Path = $path; Length = $fi.Length
            CreatedUtc = $fi.CreationTimeUtc.ToString('o'); ModifiedUtc = $fi.LastWriteTimeUtc.ToString('o')
            SHA256 = $sha
            Signature = if ($sig) { $sig.Status.ToString() } else { 'Unknown' }
            Signer = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
            IfeoDebugger = $ifeo; Copied = $copied
        }
    }
}

# Live export of the key logs with wevtutil (the original batch behaviour). Runs even when the VSS copy works,
# because wevtutil exports the freshest events; the snapshot copy holds EVERY channel (EventLogs\All).
Add-Collector -Phase 4 -Level 2 -Name 'Live export: key event logs (wevtutil epl)' -Out 'EventLogs\live_export_log.txt' -Action {
    $dir = Join-Path $Ctx.Root 'EventLogs\Live'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $channels = 'Security', 'System', 'Application', 'Windows PowerShell',
    'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational'
    $failed = 0
    foreach ($ch in $channels) {
        if (-not (Get-WinEvent -ListLog $ch -ErrorAction Ignore)) { "SKIP  $ch (channel not present on this host)"; continue }
        $dst = Join-Path $dir (($ch -replace '[\\/]', '%4') + '.evtx')
        & $Exe.wevtutil epl $ch $dst /ow:true 2>&1 | Out-Null
        $code = $LASTEXITCODE
        if ($code -eq 0 -and (Test-Path -LiteralPath $dst)) { 'OK    {0} ({1:N0} KB)' -f $ch, ((Get-Item -LiteralPath $dst).Length / 1KB) }
        else { $failed++; "FAIL  $ch (wevtutil exit $code)" }
    }
    $global:LASTEXITCODE = [int]($failed -gt 0)
}

# ---------- PHASE 4 (3.4.0): TAMPERING, DRIVERS, VIRTUAL DISKS ----------

# A disabled channel, or a Security log shrunk to 1 MB, is evidence in itself. Cheap, so it runs in every profile.
Add-Collector -Phase 4 -Level 1 -Name 'Event log channel configuration (enabled, size, retention)' -Format Csv -Out 'EventLogs\channel_config.csv' -Action {
    $before = $Error.Count
    $logs = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue)
    # Channels the session can't open (and analytic/debug channels) report errors; they are listed by name elsewhere.
    for ($i = $Error.Count - $before - 1; $i -ge 0; $i--) { $Error.RemoveAt($i) }
    foreach ($l in $logs) {
        [pscustomobject]@{
            LogName = $l.LogName; IsEnabled = $l.IsEnabled; LogMode = [string]$l.LogMode
            MaximumSizeInBytes = $l.MaximumSizeInBytes; FileSize = $l.FileSize; RecordCount = $l.RecordCount
            IsLogFull = $l.IsLogFull; OldestRecordNumber = $l.OldestRecordNumber
            LastWriteTimeUtc = ConvertTo-IsoUtc $l.LastWriteTime; LastAccessTimeUtc = ConvertTo-IsoUtc $l.LastAccessTime
            LogFilePath = $l.LogFilePath
        }
    }
}

# Running ETW sessions and the AutoLogger settings attackers flip (Start=0 / Enabled=0) to blind EDR and logging.
Add-Collector -Phase 4 -Level 1 -Name 'ETW trace sessions and AutoLogger configuration' -Out 'Security\etw_sessions.txt' -Action {
    New-Section 'logman query -ets (running trace sessions)'
    $ets = & $Exe.logman query -ets 2>&1 | Out-String
    $ets
    New-Section 'Expected sessions (informational)'
    foreach ($s in 'EventLog-System', 'EventLog-Application', 'EventLog-Security', 'DefenderApiLogger', 'DefenderAuditLogger') {
        '{0,-22} {1}' -f $s, $(if ($ets -match [regex]::Escape($s)) { 'running' } else { 'NOT running (check whether it should be on this host)' })
    }
    New-Section 'AutoLogger sessions with Start=0 (disabled at boot)'
    $al = 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
    $off = foreach ($k in @(Get-ChildItem -LiteralPath $al -ErrorAction Ignore)) {
        $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Ignore
        if ($p -and $p.PSObject.Properties['Start'] -and $p.Start -eq 0) { $k.PSChildName }
    }
    if ($off) { $off } else { '(none)' }
    New-Section 'reg query HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger /s'
    & $Exe.reg query 'HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger' /s 2>&1
    $global:LASTEXITCODE = 0
}

# BYOVD EDR killers use VALIDLY SIGNED drivers, so 'unsigned' checks miss them; hashes are what LOLDrivers matches on.
# Loaded modules come from the kernel itself, so a driver whose service key was deleted after load is still listed.
Add-Collector -Phase 4 -Level 2 -Name 'Kernel drivers: hashes, signers, loaded modules (LOLDrivers-ready)' -Format Csv -Out 'System\drivers_hashed.csv' -Action {
    $lol = $null
    if ($LolDriversCsv) {
        $lol = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($m in [regex]::Matches([IO.File]::ReadAllText($LolDriversCsv), '\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b')) { [void]$lol.Add($m.Value) }
    }
    $rows = @{}   # key: normalized lower-case path
    foreach ($d in @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)) {
        $path = ConvertTo-DriverPath $d.PathName
        if (-not $path) { continue }
        $rows[$path.ToLowerInvariant()] = [ordered]@{ Name = $d.Name; DisplayName = $d.DisplayName; State = $d.State; StartMode = $d.StartMode; Source = 'Service'; LoadedNoService = $false; Path = $path }
    }
    $loaded = @(Get-LoadedKernelModule)
    foreach ($raw in $loaded) {
        $path = ConvertTo-DriverPath $raw
        $key = $path.ToLowerInvariant()
        if ($rows.ContainsKey($key)) { $rows[$key].Source = 'Both' }
        else {
            # Loaded but no service entry: the kernel image itself (ntoskrnl, hal) is normal; anything else deserves a look.
            $rows[$key] = [ordered]@{ Name = [IO.Path]::GetFileNameWithoutExtension($path); DisplayName = $null; State = 'Running'; StartMode = $null; Source = 'Loaded'; LoadedNoService = $true; Path = $path }
        }
    }
    foreach ($r in $rows.Values) {
        $fi = Get-Item -LiteralPath $r.Path -Force -ErrorAction Ignore
        $sig = if ($fi) { try { Get-AuthenticodeSignature -LiteralPath $fi.FullName -ErrorAction Stop } catch { $null } } else { $null }
        $cert = if ($sig) { $sig.SignerCertificate } else { $null }
        $vi = if ($fi) { $fi.VersionInfo } else { $null }
        $sha256 = if ($fi) { Get-HashSafe $fi.FullName 'SHA256' } else { $null }
        $sha1 = if ($fi) { Get-HashSafe $fi.FullName 'SHA1' } else { $null }
        $md5 = if ($fi) { Get-HashSafe $fi.FullName 'MD5' } else { $null }
        $match = $null
        if ($lol) { $match = @($sha256, $sha1, $md5 | Where-Object { $_ -and $lol.Contains($_) }) -join ' ' }
        # Most loaded-without-service modules are Windows library/core images or in-memory crash-dump copies.
        # 'review' = loaded with no service entry AND not signed as part of Windows (or a LOLDrivers hit).
        $triage = if ($match) { 'review: LOLDrivers match' }
                  elseif (-not $r.LoadedNoService) { '' }
                  elseif ($r.Name -like 'dump_*' -and -not $fi) { 'crash-dump filter copy (normal)' }
                  elseif ($cert -and $sig.Status -eq 'Valid' -and $cert.Subject -like 'CN=Microsoft Windows,*') { 'Windows library/core module (usually normal)' }
                  else { 'review: loaded without a service entry' }
        [pscustomobject]@{
            Name = $r.Name; DisplayName = $r.DisplayName; State = $r.State; StartMode = $r.StartMode
            Source = $r.Source; LoadedNoService = $r.LoadedNoService; Triage = $triage; Path = $r.Path; FileFound = [bool]$fi
            SHA256 = $sha256; SHA1 = $sha1; MD5 = $md5
            Signature = $(if ($sig) { [string]$sig.Status } else { $null })
            SignerSubject = $(if ($cert) { $cert.Subject } else { $null })
            Issuer = $(if ($cert) { $cert.Issuer } else { $null })
            CertNotAfterUtc = $(if ($cert) { ConvertTo-IsoUtc $cert.NotAfter } else { $null })
            OriginalFilename = $(if ($vi) { $vi.OriginalFilename } else { $null })
            CompanyName = $(if ($vi) { $vi.CompanyName } else { $null })
            ProductVersion = $(if ($vi) { $vi.ProductVersion } else { $null })
            CreatedUtc = $(if ($fi) { $fi.CreationTimeUtc.ToString('o') } else { $null })
            ModifiedUtc = $(if ($fi) { $fi.LastWriteTimeUtc.ToString('o') } else { $null })
            LolDriversMatch = $(if ($null -eq $lol) { 'not checked' } elseif ($match) { $match } else { '' })
        }
    }
    if (-not $loaded.Count) { Write-Warning 'EnumDeviceDrivers returned nothing (needs admin); loaded-module columns are incomplete.' }
}

Add-Collector -Phase 4 -Level 2 -Name 'Code integrity: vulnerable driver blocklist, VBS / HVCI' -Out 'Security\code_integrity.txt' -Action {
    New-Section 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config'
    $ci = Get-ItemProperty -LiteralPath 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\CI\Config' -ErrorAction Ignore
    if ($ci -and $ci.PSObject.Properties['VulnerableDriverBlocklistEnable']) {
        'VulnerableDriverBlocklistEnable = {0}  ({1})' -f $ci.VulnerableDriverBlocklistEnable, $(if ($ci.VulnerableDriverBlocklistEnable -eq 0) { 'DISABLED' } else { 'enabled' })
    }
    else { 'VulnerableDriverBlocklistEnable: value not present (Windows default applies; on by default from Windows 11 22H2)' }
    New-Section 'reg query HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard /s'
    if (Test-Path -LiteralPath 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard') { & $Exe.reg query 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /s 2>&1 } else { '(key not present)' }
    New-Section 'Win32_DeviceGuard'
    $dg = $null
    try { $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop } catch { 'Win32_DeviceGuard not available on this build' }
    if ($dg) {
        # 1 = Credential Guard, 2 = HVCI (memory integrity). VBS status 0 = off, 1 = configured, 2 = running.
        $dg | Select-Object SecurityServicesConfigured, SecurityServicesRunning, VirtualizationBasedSecurityStatus,
            CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus | Format-List | Out-String -Width 4096
    }
    $global:LASTEXITCODE = 0
}

# WFP filters are invisible to Get-NetFirewallRule. EDRSilencer-style tools add BLOCK filters keyed on the EDR's
# application ID. ALWAYS pass file=<full path>: without it netsh writes filters.xml into the current directory.
Add-Collector -Phase 4 -Level 2 -Name 'Windows Filtering Platform filters (+ BLOCK-by-app summary)' -Format None -Action {
    $dir = Join-Path $Ctx.Root 'Security'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $xmlPath = Join-Path $dir 'wfp_filters.xml'
    & $Exe.netsh wfp show filters "file=$xmlPath" 2>&1 | Out-Null
    $netshExit = $global:LASTEXITCODE
    if ($Ctx.Level -ge 3) { & $Exe.netsh wfp show state "file=$(Join-Path $dir 'wfp_state.xml')" 2>&1 | Out-Null }
    $global:LASTEXITCODE = 0
    if (-not (Test-Path -LiteralPath $xmlPath)) { throw "netsh wfp show filters produced no file (exit $netshExit)" }
    [xml]$x = Get-Content -LiteralPath $xmlPath -Raw
    # VERIFY: element names follow the documented netsh wfp XML layout (filters/item, filterKey, displayData/name,
    # layerKey, action/type, filterCondition/item/fieldKey, conditionValue/byteBlob/asString). Unverified on a real host.
    $filters = @($x.SelectNodes('//*[local-name()="filters"]/*[local-name()="item"]'))
    $summary = foreach ($f in $filters) {
        $action = [string]$f.SelectSingleNode('*[local-name()="action"]/*[local-name()="type"]').InnerText
        if ($action -notmatch 'BLOCK') { continue }
        $apps = foreach ($c in @($f.SelectNodes('*[local-name()="filterCondition"]/*[local-name()="item"]'))) {
            if ([string]$c.SelectSingleNode('*[local-name()="fieldKey"]').InnerText -match 'ALE_APP_ID') {
                $s = $c.SelectSingleNode('.//*[local-name()="asString"]')
                if ($s) { $s.InnerText }
            }
        }
        if (-not $apps) { continue }
        $flags = (@($f.SelectNodes('*[local-name()="flags"]//*[local-name()="item"]')) | ForEach-Object { $_.InnerText }) -join ' '
        $pk = $f.SelectSingleNode('*[local-name()="providerKey"]')
        # weight = <type>FWP_UINT8</type><uint8>15</uint8>  ->  'FWP_UINT8=15'
        $wt = @($f.SelectNodes('*[local-name()="weight"]/*'))
        $weight = if ($wt.Count -ge 2) { '{0}={1}' -f $wt[0].InnerText, $wt[1].InnerText } elseif ($wt.Count -eq 1) { $wt[0].InnerText } else { $null }
        [pscustomobject]@{
            FilterKey = [string]$f.SelectSingleNode('*[local-name()="filterKey"]').InnerText
            Name = [string]$f.SelectSingleNode('*[local-name()="displayData"]/*[local-name()="name"]').InnerText
            ProviderKey = $(if ($pk) { $pk.InnerText } else { $null })
            Layer = [string]$f.SelectSingleNode('*[local-name()="layerKey"]').InnerText
            Weight = $weight
            AppPath = ($apps -join ' ; ')
            Persistent = ($flags -match 'PERSISTENT')
            Action = $action
        }
    }
    $sumPath = Join-Path $dir 'wfp_block_summary.csv'
    if ($summary) { $summary | Export-Csv -LiteralPath $sumPath -NoTypeInformation -Encoding UTF8 } else { New-Item -ItemType File -Force -Path $sumPath | Out-Null }
    '{0} filters in XML; {1} BLOCK filters with an application condition' -f $filters.Count, @($summary).Count
    if (-not $filters.Count) { 'XML layout not recognised by the summary parser; review wfp_filters.xml manually' }
}

# Sysmon is often renamed, so find it by the binary's version info, not by service name. Its decoded config comes
# from '<binary> -c', run ONLY if the binary carries a valid Microsoft signature; the raw registry config is dumped too.
Add-Collector -Phase 4 -Level 2 -Name 'Sysmon detection and configuration' -Out 'Security\sysmon_config.txt' -Action {
    $hits = foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue) + @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)) {
        $path = ConvertTo-DriverPath (($s.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+\.(exe|sys)).*$', '$1')
        $fi = if ($path) { Get-Item -LiteralPath $path -Force -ErrorAction Ignore } else { $null }
        if (-not $fi) { continue }
        $vi = $fi.VersionInfo
        if ("$($vi.FileDescription) $($vi.ProductName)" -match 'System Monitor|Sysmon') {
            [pscustomobject]@{ Name = $s.Name; Kind = $(if ($path -like '*.sys') { 'Driver' } else { 'Service' }); Path = $fi.FullName; Description = $vi.FileDescription; Version = $vi.FileVersion }
        }
    }
    if (-not $hits) { 'Sysmon not installed (no service or driver with Sysmon version info)'; return }
    New-Section 'Sysmon components found'
    $hits | Format-Table -AutoSize | Out-String -Width 4096
    foreach ($h in @($hits | Where-Object Kind -eq 'Service')) {
        New-Section "$($h.Path) -c"
        $sig = Get-AuthenticodeSignature -LiteralPath $h.Path -ErrorAction SilentlyContinue
        $status = if ($sig) { [string]$sig.Status } else { 'unknown' }
        $subject = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
        if ($status -eq 'Valid' -and $subject -match 'Microsoft') { & $h.Path -c 2>&1 }
        else { "NOT executed: signature is '$status' / '$subject'. Only a valid Microsoft-signed Sysmon is run." }
    }
    foreach ($h in @($hits | Where-Object Kind -eq 'Driver')) {
        New-Section "reg query HKLM\SYSTEM\CurrentControlSet\Services\$($h.Name)\Parameters"
        & $Exe.reg query "HKLM\SYSTEM\CurrentControlSet\Services\$($h.Name)\Parameters" 2>&1
    }
    $global:LASTEXITCODE = 0
}

# Some ransomware runs its encryptor inside a VM to get past EDR; ISO/VHD files are common initial-access containers.
Add-Collector -Phase 4 -Level 2 -Name 'Virtual machines and mounted disk images' -Out 'System\virtual_disks.txt' -Action {
    New-Section 'Get-VM (Hyper-V)'
    if (Get-Command Get-VM -ErrorAction Ignore) { Invoke-Safe { Get-VM -ErrorAction Stop | Select-Object Name, State, Path, CreationTime, Uptime | Format-Table -AutoSize | Out-String -Width 4096 } }
    else { 'Hyper-V module not present' }
    New-Section 'Mounted virtual disks (BusType File Backed Virtual) and their image files'
    $vd = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object { "$($_.BusType)" -eq 'File Backed Virtual' })
    if (-not $vd.Count) { '(none)' }
    foreach ($d in $vd) {
        $img = try { Get-DiskImage -DevicePath ('\\.\PHYSICALDRIVE{0}' -f $d.Number) -ErrorAction Stop } catch { $null }
        'Disk {0}: {1} {2:N0} GB  BusType={3}  Image={4}' -f $d.Number, $d.FriendlyName, ($d.Size / 1GB), $d.BusType, $(if ($img) { $img.ImagePath } else { '(unknown)' })
    }
    New-Section 'Mounted ISO images (CD-ROM volumes)'
    $iso = foreach ($v in @(Get-Volume -ErrorAction SilentlyContinue | Where-Object DriveType -eq 'CD-ROM')) {
        $img = try { $v | Get-DiskImage -ErrorAction Stop } catch { $null }
        if ($img) { '{0}: {1}' -f $v.DriveLetter, $img.ImagePath }
    }
    if ($iso) { $iso } else { '(none)' }
}

# ---------- PHASE 5: VSS SNAPSHOT + DISK ARTIFACTS ----------
Add-Collector -Phase 5 -Level 2 -Name 'Create and mount VSS snapshot' -Format None -Action {
    $id = $null
    try {
        $r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{ Volume = "$($env:SystemDrive)\"; Context = 'ClientAccessible' } -ErrorAction Stop
        if ($r.ReturnValue -ne 0) { throw "ReturnValue $($r.ReturnValue)" }
        $id = $r.ShadowID
    }
    catch {
        Write-Log "Win32_ShadowCopy.Create failed ($($_.Exception.Message)); trying vssadmin" 'WARN'
        $o = & $Exe.vssadmin create shadow "/for=$($env:SystemDrive)" 2>&1 | Out-String
        if ($o -match 'Shadow Copy ID:\s*(\{[0-9A-Fa-f-]+\})') { $id = $Matches[1] }
        else { throw "Could not create a shadow copy: $o" }
    }
    # Record the ID IMMEDIATELY so Remove-Vss can clean up even if a later step fails.
    $Ctx.ShadowId = $id
    $sc = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $id } | Select-Object -First 1
    if (-not $sc) { throw "Shadow copy $id not found after creation" }
    $Ctx.ShadowDevice = $sc.DeviceObject

    # Mount OUTSIDE the collection root so later recursive hashing can never walk the snapshot.
    $link = Join-Path $env:SystemRoot ('Temp\dfir_vss_{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    $o = & $Exe.cmd /c mklink /d $link ($sc.DeviceObject + '\') 2>&1 | Out-String
    if (-not (Test-Path -LiteralPath $link)) { throw "mklink failed: $o" }
    $Ctx.ShadowLink = $link
    "Snapshot $id ($($sc.DeviceObject)) mounted at $link; created $(ConvertTo-IsoUtc $sc.InstallDate)"
}

Add-Collector -Phase 5 -Level 2 -Name 'Copy: registry hives, Amcache, setupapi, Defender logs' -Format None -NeedsVss -Action {
    Copy-VssArtifact 'Windows\System32\config\*'
    Copy-VssArtifact 'Windows\System32\config\RegBack\*'
    Copy-VssArtifact 'Windows\appcompat\Programs\Amcache.hve*'
    Copy-VssArtifact 'Windows\inf\setupapi*.log'
    Copy-VssArtifact 'ProgramData\Microsoft\Windows Defender\Support\*'
}

Add-Collector -Phase 5 -Level 2 -Name 'Copy: service-account hives, legacy .job tasks, BITS queue, PCA, GPO scripts, Startup' -Format None -NeedsVss -Action {
    Copy-VssArtifact 'Windows\System32\config\systemprofile\NTUSER.DAT*'
    Copy-VssArtifact 'Windows\ServiceProfiles\LocalService\NTUSER.DAT*'
    Copy-VssArtifact 'Windows\ServiceProfiles\NetworkService\NTUSER.DAT*'
    Copy-VssArtifact 'Windows\Tasks\*'
    Copy-VssArtifact 'ProgramData\Microsoft\Network\Downloader\*'
    Copy-VssArtifact 'Windows\appcompat\pca\*'
    Copy-VssArtifact 'Windows\System32\GroupPolicy' -Recurse
    Copy-VssArtifact 'ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*'
    foreach ($u in Get-VssUserDirs) {
        Copy-VssArtifact "Users\$u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
    }
}

Add-Collector -Phase 5 -Level 3 -Name 'Copy: WER, firewall/Panther/debug/SCM logs, minidumps, Defender detection history, IIS logs' -Format None -NeedsVss -Action {
    Copy-VssArtifact 'ProgramData\Microsoft\Windows\WER' -Recurse
    Copy-VssArtifact 'Windows\System32\LogFiles\Firewall\*'
    Copy-VssArtifact 'Windows\System32\LogFiles\Scm\*'
    Copy-VssArtifact 'Windows\System32\LogFiles\Sum\*'
    Copy-VssArtifact 'Windows\Panther\*'
    Copy-VssArtifact 'Windows\debug\*.log'
    Copy-VssArtifact 'Windows\Minidump\*'
    Copy-VssArtifact 'ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory' -Recurse
    Copy-VssArtifact 'inetpub\logs' -Recurse
}

Add-Collector -Phase 5 -Level 3 -Name 'Copy: user activity (thumbcache, WebCache, notifications, OneDrive logs)' -Format None -NeedsVss -Action {
    foreach ($u in Get-VssUserDirs) {
        Copy-VssArtifact "Users\$u\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db"
        Copy-VssArtifact "Users\$u\AppData\Local\Microsoft\Windows\Explorer\iconcache_*.db"
        Copy-VssArtifact "Users\$u\AppData\Local\Microsoft\Windows\WebCache\*"
        Copy-VssArtifact "Users\$u\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db*"
        Copy-VssArtifact "Users\$u\AppData\Local\Microsoft\OneDrive\logs" -Recurse
        Copy-VssArtifact "Users\$u\AppData\Local\Microsoft\OneDrive\settings" -Recurse
    }
}

Add-Collector -Phase 5 -Level 3 -Name 'Copy: remote-access tool logs (AnyDesk, TeamViewer, RustDesk, Splashtop)' -Format None -NeedsVss -Action {
    Copy-VssArtifact 'ProgramData\AnyDesk\*.trace'
    # ProgramData\AnyDesk\*.conf is NOT copied (3.4.0): service.conf can hold the unattended-access password hash/salt.
    # It is recorded as presence + hash in Disk\remote_access_presence.csv instead.
    Copy-VssArtifact 'ProgramData\AnyDesk\connection_trace.txt'
    foreach ($pf in 'Program Files', 'Program Files (x86)') {
        Copy-VssArtifact "$pf\TeamViewer\*.log"
        Copy-VssArtifact "$pf\TeamViewer\Connections_incoming.txt"
        Copy-VssArtifact "$pf\Splashtop\Splashtop Remote\Server\log" -Recurse
    }
    Copy-VssArtifact 'Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\log' -Recurse
    foreach ($u in Get-VssUserDirs) {
        Copy-VssArtifact "Users\$u\AppData\Roaming\AnyDesk\*.trace"
        Copy-VssArtifact "Users\$u\AppData\Roaming\AnyDesk\connection_trace.txt"
        Copy-VssArtifact "Users\$u\AppData\Roaming\TeamViewer\*.log"
        Copy-VssArtifact "Users\$u\AppData\Roaming\TeamViewer\Connections.txt"
        Copy-VssArtifact "Users\$u\AppData\Roaming\RustDesk\log" -Recurse
    }
}

Add-Collector -Phase 5 -Level 2 -Name 'Copy: user hives (NTUSER/UsrClass) + PowerShell history' -Format None -NeedsVss -Action {
    foreach ($u in Get-VssUserDirs) {
        Copy-VssArtifact "Users\$u\NTUSER.DAT*"
        Copy-VssArtifact "Users\$u\AppData\Local\Microsoft\Windows\UsrClass.dat*"
        Copy-VssArtifact "Users\$u\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    }
}

Add-Collector -Phase 5 -Level 2 -Name 'Copy: ALL event logs (snapshot)' -Format None -NeedsVss -Action {
    Copy-VssArtifact 'Windows\System32\winevt\Logs\*.evtx' -FlatTo 'EventLogs\All'
}

Add-Collector -Phase 5 -Level 2 -Name 'Copy: Prefetch, scheduled task XML, hosts' -Format None -NeedsVss -Action {
    Copy-VssArtifact 'Windows\Prefetch\*.pf'
    Copy-VssArtifact 'Windows\System32\Tasks' -Recurse
    Copy-VssArtifact 'Windows\System32\drivers\etc\hosts'
}

Add-Collector -Phase 5 -Level 3 -Name 'Copy: SRUM, WMI repository' -Format None -NeedsVss -Action {
    Copy-VssArtifact 'Windows\System32\sru\*'
    Copy-VssArtifact 'Windows\System32\wbem\Repository' -Recurse
}

Add-Collector -Phase 5 -Level 3 -Name 'Copy: LNK, Jump Lists, ActivitiesCache, RDP cache, Recycle Bin' -Format None -NeedsVss -Action {
    foreach ($u in Get-VssUserDirs) {
        Copy-VssArtifact "Users\$u\AppData\Roaming\Microsoft\Windows\Recent" -Recurse
        Copy-VssArtifact "Users\$u\AppData\Roaming\Microsoft\Office\Recent" -Recurse
        Copy-VssArtifact "Users\$u\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db*"
        Copy-VssArtifact "Users\$u\AppData\Local\Microsoft\Terminal Server Client\Cache" -Recurse
    }
    Copy-VssArtifact '$Recycle.Bin' -Recurse -NameLike '$I*'
}

# Browser activity artifacts. Cookies, saved logins, autofill/card data (Web Data, logins.json, key4.db, cookies.sqlite,
# formhistory.sqlite) are DELIBERATELY not collected: they are credential material, not needed for timeline work.
Add-Collector -Phase 5 -Level 3 -Name 'Copy: browser artifacts (Chrome, Edge, Brave, Vivaldi, Opera, Firefox)' -Format None -NeedsVss -Action {
    $chromium = 'AppData\Local\Google\Chrome\User Data', 'AppData\Local\Microsoft\Edge\User Data',
    'AppData\Local\BraveSoftware\Brave-Browser\User Data', 'AppData\Local\Vivaldi\User Data',
    'AppData\Local\Chromium\User Data', 'AppData\Roaming\Opera Software\Opera Stable'
    $chromiumFiles = 'History', 'History-journal', 'Favicons', 'Top Sites', 'Shortcuts', 'Network Action Predictor',
    'Bookmarks', 'Preferences', 'Secure Preferences', 'Visited Links'
    foreach ($u in Get-VssUserDirs) {
        foreach ($b in $chromium) {
            foreach ($f in $chromiumFiles) {
                Copy-VssArtifact "Users\$u\$b\*\$f"     # Default, Profile N
                Copy-VssArtifact "Users\$u\$b\$f"       # Opera keeps the profile in the root
            }
            Copy-VssArtifact "Users\$u\$b\*\Sessions\*"
            Copy-VssArtifact "Users\$u\$b\*\Extensions\*\*\manifest.json"
        }
        $ff = "Users\$u\AppData\Roaming\Mozilla\Firefox\Profiles\*"
        foreach ($f in 'places.sqlite*', 'favicons.sqlite*', 'extensions.json', 'addons.json', 'prefs.js', 'handlers.json', 'sessionstore.jsonlz4') {
            Copy-VssArtifact "$ff\$f"
        }
        Copy-VssArtifact "$ff\sessionstore-backups\*"
    }
}

Add-Collector -Phase 5 -Level 3 -Name 'Raw NTFS: $MFT, $LogFile, $Boot (RawCopy)' -Format None -Needs 'RawCopy' -Action {
    $dest = Join-Path $Ctx.Disk 'NTFS'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    # RawCopy 1.0.0.22 readme: /FileNamePath:<path | C:<MftRef>> /OutputPath:<dir> /OutputName:<name>.
    # MftRef 0 = $MFT, 2 = $LogFile, 7 = $Boot (verified on the test machine).
    # RawCopy cannot address the $UsnJrnl:$J stream ("Unable to find the file ... by index scanning"),
    # so $J comes from the fsutil collector below as CSV, and raw from KAPE in Full.
    # Output names drive the MFTECmd step below: MFT_<drive>, Boot_<drive>. Runs for the system drive
    # and every extra internal NTFS volume.
    foreach ($d in (Get-NtfsVolumeList)) {
        $drv = $d.TrimEnd(':')
        $targets = @(
            @{ Tag = 'MFT'; Path = ('{0}0' -f $d); Name = "MFT_$drv.bin" },
            @{ Tag = 'LogFile'; Path = ('{0}2' -f $d); Name = "LogFile_$drv.bin" },
            @{ Tag = 'Boot'; Path = ('{0}7' -f $d); Name = "Boot_$drv.bin" }
        )
        foreach ($t in $targets) {
            try {
                Invoke-External -FilePath $Tool.RawCopy.FullName `
                    -ArgumentList @("/FileNamePath:$($t.Path)", "/OutputPath:$dest", "/OutputName:$($t.Name)") `
                    -OutFile (Join-Path $Ctx.Root "Tools\rawcopy_$($t.Tag)_$drv.log") -TimeoutSec 1800
            }
            catch { "RawCopy $($t.Tag) $d failed: $($_.Exception.Message)" }
        }
    }
    Get-ChildItem -LiteralPath $dest -File -ErrorAction Ignore | ForEach-Object { '{0} ({1:N0} MB)' -f $_.Name, ($_.Length / 1MB) }
}

Add-Collector -Phase 5 -Level 3 -Name 'USN journal ($J) via fsutil usn readjournal (CSV)' -Format None -Action {
    # Native, read-only replacement for the raw $J copy that RawCopy cannot do. Output is already parsed (CSV),
    # so it is not fed to MFTECmd. Verified on the test machine: ~330k records, 71 MB.
    # NOTE: fsutil writes the "Time stamp" column in HOST LOCAL time, not UTC; the note below says so.
    $dest = Join-Path $Ctx.Disk 'NTFS'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $worst = 0
    foreach ($d in (Get-NtfsVolumeList)) {
        $drv = $d.TrimEnd(':')
        Invoke-External -FilePath $Exe.fsutil -ArgumentList @('usn', 'queryjournal', $d) `
            -OutFile (Join-Path $dest "UsnJrnl_info_$drv.txt") -TimeoutSec 120
        if ($script:LastExit -ne 0) {
            # A data volume may simply have no change journal; that is a finding, not an error.
            "{0}: no USN journal (fsutil queryjournal exit {1})" -f $d, $script:LastExit
            continue
        }
        Invoke-External -FilePath $Exe.fsutil -ArgumentList @('usn', 'readjournal', $d, 'csv') `
            -OutFile (Join-Path $dest "UsnJrnl_fsutil_$drv.csv") -TimeoutSec 3600
        if ($script:LastExit -ne 0) { $worst = $script:LastExit }
        $f = Get-Item -LiteralPath (Join-Path $dest "UsnJrnl_fsutil_$drv.csv") -ErrorAction Ignore
        if ($f) { '{0} ({1:N0} MB)' -f $f.Name, ($f.Length / 1MB) }
    }
    'timestamps in host local time ({0})' -f [TimeZoneInfo]::Local.Id
    $script:LastExit = $worst
}

Add-Collector -Phase 5 -Level 3 -Name 'Extra internal volumes: root listing and Recycle Bin (live copy)' -Format None -Action {
    # Extra volumes are not in the VSS snapshot (it covers the system drive only), so files are copied live.
    # Copy-Item keeps LastWriteTime but not CreationTime; the original times are listed in recyclebin_listing.csv.
    # Deep copies the $I metadata files (RBCmd input); Full copies the deleted files ($R) as well.
    if (-not @($Ctx.ExtraVolumes).Count) { return 'No extra internal volumes' }
    foreach ($v in $Ctx.ExtraVolumes) {
        $d = $v.Letter; $drv = $d.TrimEnd(':')
        $root = Join-Path $Ctx.Disk "Volume_$drv"
        New-Item -ItemType Directory -Force -Path $root | Out-Null
        Get-ChildItem -LiteralPath "$d\" -Force -ErrorAction Ignore |
            Select-Object Mode, Name, Length, @{n = 'CreationUtc'; e = { $_.CreationTimeUtc.ToString('o') } }, @{n = 'LastWriteUtc'; e = { $_.LastWriteTimeUtc.ToString('o') } } |
            Export-Csv -LiteralPath (Join-Path $root 'root_listing.csv') -NoTypeInformation -Encoding UTF8
        $rb = "$d\`$Recycle.Bin"
        if (-not (Test-Path -LiteralPath $rb)) { "{0}: no Recycle Bin" -f $d; continue }
        $files = @(Get-ChildItem -LiteralPath $rb -Recurse -Force -File -ErrorAction Ignore)
        $files | Select-Object FullName, Length, @{n = 'CreationUtc'; e = { $_.CreationTimeUtc.ToString('o') } }, @{n = 'LastWriteUtc'; e = { $_.LastWriteTimeUtc.ToString('o') } } |
            Export-Csv -LiteralPath (Join-Path $root 'recyclebin_listing.csv') -NoTypeInformation -Encoding UTF8
        if ($Ctx.Level -lt 4) { $files = @($files | Where-Object { $_.Name -like '$I*' -or $_.Name -ieq 'desktop.ini' }) }
        $ok = 0; $bad = 0
        foreach ($f in $files) {
            $target = Join-Path $root ('$Recycle.Bin' + $f.FullName.Substring($rb.Length))
            try {
                [IO.Directory]::CreateDirectory((Split-Path -Parent $target)) | Out-Null
                Copy-Item -LiteralPath $f.FullName -Destination $target -Force -ErrorAction Stop; $ok++
            }
            catch { $bad++ }
        }
        '{0} ({1}, {2}): Recycle Bin {3} copied, {4} failed' -f $d, $v.Bus, $v.Model, $ok, $bad
    }
}

Add-Collector -Phase 5 -Level 4 -Name 'Raw: pagefile.sys, swapfile.sys, hiberfil.sys (RawCopy)' -Format None -Needs 'RawCopy' -Action {
    $dest = Join-Path $Ctx.Disk 'SystemFiles'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $drv = $env:SystemDrive.TrimEnd(':')
    foreach ($f in 'pagefile.sys', 'swapfile.sys', 'hiberfil.sys') {
        $src = Join-Path "$env:SystemDrive\" $f
        # Test-Path returns False for the in-use paging files; a forced directory listing sees them.
        if (-not (Get-ChildItem -LiteralPath "$env:SystemDrive\" -Force -Filter $f -File -ErrorAction Ignore)) { "$f not present"; continue }
        try {
            Invoke-External -FilePath $Tool.RawCopy.FullName `
                -ArgumentList @("/FileNamePath:$src", "/OutputPath:$dest", "/OutputName:$([IO.Path]::GetFileNameWithoutExtension($f))_$drv.sys") `
                -OutFile (Join-Path $Ctx.Root "Tools\rawcopy_$f.log") -TimeoutSec 3600
        }
        catch { "RawCopy $f failed: $($_.Exception.Message)" }
    }
    Get-ChildItem -LiteralPath $dest -File -ErrorAction Ignore | ForEach-Object { '{0} ({1:N0} MB)' -f $_.Name, ($_.Length / 1MB) }
}

Add-Collector -Phase 5 -Level 4 -Name 'Copy: full Recycle Bin, Windows Search DB, MEMORY.DMP' -Format None -NeedsVss -Action {
    Copy-VssArtifact '$Recycle.Bin' -Recurse
    Copy-VssArtifact 'ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb'
    Copy-VssArtifact 'ProgramData\Microsoft\Search\Data\Applications\Windows\Windows*.db*'
    Copy-VssArtifact 'Windows\MEMORY.DMP'
}

# ---------- PHASE 5 (3.4.0): SSH, TRANSCRIPTS, MOTW, REMOTE ACCESS, IIS, NOTEPAD, QUARANTINE ----------

# A planted public key is quiet persistence that Autoruns doesn't look at. Explicit file names only:
# private keys (id_* without .pub, ssh_host_*_key without .pub) are NEVER copied.
Add-Collector -Phase 5 -Level 2 -Name 'Copy: OpenSSH keys (public only), configs and logs' -Format None -NeedsVss -Action {
    Copy-VssArtifact 'ProgramData\ssh\administrators_authorized_keys'
    Copy-VssArtifact 'ProgramData\ssh\sshd_config'
    Copy-VssArtifact 'ProgramData\ssh\ssh_host_*_key.pub'
    Copy-VssArtifact 'ProgramData\ssh\logs\*'
    foreach ($u in Get-VssUserDirs) {
        foreach ($f in 'authorized_keys', 'authorized_keys2', 'known_hosts', 'known_hosts.old', 'config') { Copy-VssArtifact "Users\$u\.ssh\$f" }
        Copy-VssArtifact "Users\$u\.ssh\*.pub"
    }
}

# Transcription policy can point anywhere; the defaults are Documents\PowerShell_transcript.* (Start-Transcript)
# and Documents\<yyyyMMdd>\PowerShell_transcript.* (policy without OutputDirectory). UNC targets are recorded, not followed.
Add-Collector -Phase 5 -Level 2 -Name 'Copy: PowerShell transcripts (policy folders + default locations)' -Format None -NeedsVss -Action {
    $keys = @('HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription', 'HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore\Transcription')
    foreach ($sid in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Ignore | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $keys += "HKU\$($sid.PSChildName)\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        $keys += "HKU\$($sid.PSChildName)\SOFTWARE\Policies\Microsoft\PowerShellCore\Transcription"
    }
    foreach ($k in $keys) {
        $p = Get-ItemProperty -LiteralPath ("Registry::" + ($k -replace '^HKU\\', 'HKEY_USERS\')) -ErrorAction Ignore
        if (-not $p -or -not $p.PSObject.Properties['OutputDirectory'] -or -not "$($p.OutputDirectory)") { continue }
        $dir = [Environment]::ExpandEnvironmentVariables([string]$p.OutputDirectory)
        if ($dir -match '^\\\\') { "policy OutputDirectory is a UNC path, NOT followed: $dir ($k)"; continue }
        if ($dir.StartsWith("$env:SystemDrive\", [StringComparison]::OrdinalIgnoreCase)) { Copy-VssArtifact $dir.Substring(3) -Recurse }
        else { "policy OutputDirectory is not on the system drive, not copied: $dir ($k)" }
    }
    foreach ($u in Get-VssUserDirs) {
        foreach ($docs in "Users\$u\Documents", "Users\$u\OneDrive\Documents") {
            Copy-VssArtifact "$docs\PowerShell_transcript.*.txt"
            Copy-VssArtifact "$docs\2*\PowerShell_transcript.*.txt"
        }
    }
}

# Mark-of-the-Web for Quick/Standard profiles in a readable form (MFTECmd's ZoneIdContents covers Deep+).
# Reads from the snapshot when it exists, so the live files' access times are untouched.
# Native walker: Get-Content -Stream per file costs ~25 ms, far too slow for Downloads folders with tens of thousands
# of files. FindFirstStreamW checks a file's streams in microseconds; junctions are skipped so the walk can't loop.
function Find-ZoneIdFile {
    param([string]$Dir, [int]$Cap)
    if (-not ('DfirNative.ZoneScan' -as [type])) {
        Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.IO; using System.Runtime.InteropServices;
namespace DfirNative {
public class ZoneHit { public string Path; public long Size; public DateTime LastWriteUtc; public string Text; }
public class ZoneScanResult { public List<ZoneHit> Hits = new List<ZoneHit>(); public int Scanned; public bool Capped; }
public static class ZoneScan {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WIN32_FIND_STREAM_DATA { public long StreamSize; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string cStreamName; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr FindFirstStreamW(string lpFileName, int InfoLevel, out WIN32_FIND_STREAM_DATA lpFindStreamData, uint dwFlags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool FindNextStreamW(IntPtr hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);
    [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr hFindFile);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    // Read the (small) Zone.Identifier stream read-only; shared so the owner process is not disturbed.
    static string ReadZone(string path) {
        string p = (path.StartsWith(@"\\") ? path : @"\\?\" + path) + ":Zone.Identifier";
        using (var h = CreateFileW(p, 0x80000000, 7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
            if (h.IsInvalid) return null;
            using (var fs = new FileStream(h, FileAccess.Read)) {
                var buf = new byte[Math.Min(fs.Length, 65536)]; int n = fs.Read(buf, 0, buf.Length);
                return System.Text.Encoding.Default.GetString(buf, 0, n);
            }
        }
    }
    static bool HasZoneId(string path) {
        WIN32_FIND_STREAM_DATA d;
        string p = path.StartsWith(@"\\") ? path : @"\\?\" + path;
        IntPtr h = FindFirstStreamW(p, 0, out d, 0);
        if (h == new IntPtr(-1)) return false;
        try { do { if (string.Equals(d.cStreamName, ":Zone.Identifier:$DATA", StringComparison.OrdinalIgnoreCase)) return true; } while (FindNextStreamW(h, out d)); }
        finally { FindClose(h); }
        return false;
    }
    public static ZoneScanResult Scan(string root, int cap) {
        var r = new ZoneScanResult(); var stack = new Stack<string>(); stack.Push(root);
        while (stack.Count > 0) {
            string dir = stack.Pop();
            try {
                foreach (var f in Directory.EnumerateFiles(dir)) {
                    if (++r.Scanned > cap) { r.Capped = true; return r; }
                    if (!HasZoneId(f)) continue;
                    try { var fi = new FileInfo(f); r.Hits.Add(new ZoneHit { Path = f, Size = fi.Length, LastWriteUtc = fi.LastWriteTimeUtc, Text = ReadZone(f) }); } catch { }
                }
            } catch { }
            try { foreach (var s in Directory.EnumerateDirectories(dir)) { try { if ((File.GetAttributes(s) & FileAttributes.ReparsePoint) == 0) stack.Push(s); } catch { } } } catch { }
        }
        return r;
    }
} }
'@
    }
    [DfirNative.ZoneScan]::Scan($Dir, $Cap)
}

$HashExtensions = '.exe', '.dll', '.scr', '.com', '.msi', '.msix', '.appx', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse',
    '.wsf', '.hta', '.lnk', '.url', '.iso', '.img', '.vhd', '.vhdx', '.zip', '.rar', '.7z', '.cab', '.jar', '.doc', '.docm', '.docx',
    '.xls', '.xlsm', '.xlsx', '.xlsb', '.ppt', '.pptm', '.pptx', '.one', '.pdf', '.rtf', '.chm', '.svg', '.html', '.htm'
function Get-ZoneIdRow {
    param([string]$Root, [int]$CapPerFolder = 200000)
    $folders = 'Downloads', 'Desktop', 'Documents', 'AppData\Local\Temp', 'AppData\Local\Microsoft\Windows\INetCache\Content.Outlook'
    foreach ($u in @(Get-ChildItem -LiteralPath (Join-Path $Root 'Users') -Directory -Force -ErrorAction Ignore |
            Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })) {
        foreach ($sub in $folders) {
            $dir = Join-Path $u.FullName $sub
            if (-not (Test-Path -LiteralPath $dir -ErrorAction Ignore)) { continue }
            $scan = Find-ZoneIdFile -Dir $dir -Cap $CapPerFolder
            if ($scan.Capped) {
                [pscustomobject]@{ Path = ConvertTo-OriginalPath $dir; ZoneId = $null; HostUrl = $null; ReferrerUrl = $null; LastWriteTimeUtc = $null; Size = $null; SHA256 = $null
                    Note = "CAPPED: stopped after $CapPerFolder files in this folder" }
            }
            foreach ($hit in $scan.Hits) {
                $zi = @("$($hit.Text)" -split '\r?\n')
                $get = { param($k) ($zi | Where-Object { $_ -match "^$k=" } | Select-Object -First 1) -replace "^$k=", '' }
                # Hashing every MOTW file is too slow (one lab profile: 26,000 files, 94 GB, since extracting a downloaded
                # zip propagates MOTW). Hash only risky types up to 50 MB, and only at Deep or higher.
                $ext = [IO.Path]::GetExtension($hit.Path).ToLowerInvariant()
                $hashNote = $null; $sha = $null
                if ($Ctx.Level -lt 3) { $hashNote = 'not hashed (Standard profile)' }
                elseif ($HashExtensions -notcontains $ext) { $hashNote = 'not hashed (file type)' }
                elseif ($hit.Size -gt 50MB) { $hashNote = 'not hashed (> 50 MB)' }
                else { $sha = Get-HashSafe $hit.Path }
                [pscustomobject]@{
                    Path = ConvertTo-OriginalPath $hit.Path; ZoneId = & $get 'ZoneId'; HostUrl = & $get 'HostUrl'; ReferrerUrl = & $get 'ReferrerUrl'
                    LastWriteTimeUtc = $hit.LastWriteUtc.ToString('o'); Size = $hit.Size; SHA256 = $sha; Note = $hashNote
                }
            }
        }
    }
}
Add-Collector -Phase 5 -Level 2 -Name 'Zone.Identifier (Mark-of-the-Web) in user folders' -Format Csv -Out 'Disk\zone_identifier.csv' -NeedsVss -Action { Get-ZoneIdRow -Root $Ctx.ShadowLink }
Add-Collector -Phase 5 -Level 2 -Name 'Fallback: Zone.Identifier from live files' -Format Csv -Out 'Disk\zone_identifier.csv' -OnlyWithoutVss -Action { Get-ZoneIdRow -Root "$env:SystemDrive\" }

# Remote-access / RMM tools beyond AnyDesk, TeamViewer, RustDesk and Splashtop.
# Paths for ScreenConnect, Atera and LogMeIn come from KAPE 1.3.0.2 Targets\Apps (ScreenConnect.tkape v1.0,
# AteraAgent.tkape v1.0, LogMeIn.tkape v1.0). KAPE has no targets for MeshAgent, NetSupport, SimpleHelp or Action1,
# so those are found on the host through their services (and NetSupport's client32.ini also in AppData).
# Logs are copied; anything that can hold credentials or enrollment tokens is recorded as presence + hash only.
Add-Collector -Phase 5 -Level 3 -Name 'Copy: more remote-access tool logs (ScreenConnect, Atera, LogMeIn, discovered RMM agents)' -Format None -NeedsVss -Action {
    foreach ($pf in 'Program Files', 'Program Files (x86)') {
        Copy-VssArtifact "$pf\ScreenConnect\App_Data\Session.db"
        Copy-VssArtifact "$pf\ATERA Networks\AteraAgent" -Recurse -NameLike '*.txt'
        Copy-VssArtifact "$pf\ATERA Networks\AteraAgent" -Recurse -NameLike '*.log'
    }
    Copy-VssArtifact 'ProgramData\LogMeIn\Logs' -Recurse
    foreach ($u in Get-VssUserDirs) { Copy-VssArtifact "Users\$u\AppData\Local\Temp\LogMeInLogs" -Recurse }
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match '(?i)mesh ?agent|client32|netsupport|simplehelp|action1|screenconnect' })) {
        $bin = ($s.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+\.exe).*$', '$1'
        $dir = Split-Path -Parent $bin
        if ($dir -and $dir.StartsWith("$env:SystemDrive\", [StringComparison]::OrdinalIgnoreCase)) {
            Copy-VssArtifact $dir.Substring(3) -Recurse -NameLike '*.log'
            Copy-VssArtifact $dir.Substring(3) -Recurse -NameLike '*.txt'
        }
    }
}

Add-Collector -Phase 5 -Level 3 -Name 'Remote-access tool configs and transferred files (presence + hash only)' -Format Csv -Out 'Disk\remote_access_presence.csv' -Action {
    $root = Get-ReadRoot
    $items = New-Object System.Collections.Generic.List[object]
    # $Fields: the ONLY keys read out of the file (non-secret ones such as a gateway address); $null = metadata only.
    $add = {
        param($Tool, $Glob, $Fields)
        foreach ($f in @(Get-ChildItem -Path (Join-Path $root $Glob) -File -Force -ErrorAction Ignore)) {
            $m = Get-FileMeta $f -Note $(if ($Fields) { Get-IniFields $f.FullName $Fields } else { $null })
            $items.Add([pscustomobject]@{
                    Tool = $Tool; Path = (ConvertTo-OriginalPath $m.Path); Size = $m.Size; CreatedUtc = $m.CreatedUtc
                    ModifiedUtc = $m.ModifiedUtc; AccessedUtc = $m.AccessedUtc; SHA256 = $m.SHA256; Fields = $m.Note
                })
        }
    }
    foreach ($pf in 'Program Files', 'Program Files (x86)') {
        & $add 'ScreenConnect' "$pf\ScreenConnect\App_Data\User.xml" $null                       # user accounts and password hashes
        foreach ($ext in '*.ini', '*.config', '*.cfg', '*.db') { & $add 'Atera' "$pf\ATERA Networks\AteraAgent\$ext" $null }   # may hold account IDs / tokens
    }
    & $add 'ScreenConnect' 'ProgramData\ScreenConnect Client*\user.config' $null
    & $add 'AnyDesk' 'ProgramData\AnyDesk\*.conf' $null                                         # service.conf: password hash/salt
    foreach ($u in @(Get-ChildItem -LiteralPath (Join-Path $root 'Users') -Directory -Force -ErrorAction Ignore)) { & $add 'AnyDesk' "Users\$($u.Name)\AppData\Roaming\AnyDesk\*.conf" $null }
    # Files pushed to the host through ScreenConnect (VERIFY: community-documented location, not in KAPE).
    & $add 'ScreenConnect transfer' 'Windows\Temp\ScreenConnect\*\Files\*' $null
    foreach ($u in @(Get-ChildItem -LiteralPath (Join-Path $root 'Users') -Directory -Force -ErrorAction Ignore)) {
        & $add 'ScreenConnect transfer' "Users\$($u.Name)\AppData\Local\Temp\ScreenConnect\*\Files\*" $null
        # NetSupport is often dropped into AppData rather than Program Files.
        foreach ($base in 'AppData\Roaming', 'AppData\Local') {
            foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $u.FullName $base) -Filter 'client32.ini' -File -Recurse -Depth 4 -Force -ErrorAction Ignore)) {
                & $add 'NetSupport' (ConvertTo-OriginalPath $f.FullName).Substring(3) @('GatewayAddress', 'SecondaryGateway', 'Port', 'SecondaryPort')
            }
        }
    }
    foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $root 'ProgramData') -Filter 'client32.ini' -File -Recurse -Depth 3 -Force -ErrorAction Ignore)) {
        & $add 'NetSupport' (ConvertTo-OriginalPath $f.FullName).Substring(3) @('GatewayAddress', 'SecondaryGateway', 'Port', 'SecondaryPort')
    }
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match '(?i)mesh ?agent|client32|netsupport|simplehelp|action1|screenconnect' })) {
        $bin = ($s.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+\.exe).*$', '$1'
        $dir = Split-Path -Parent $bin
        if (-not $dir -or -not $dir.StartsWith("$env:SystemDrive\", [StringComparison]::OrdinalIgnoreCase)) { continue }
        $tool = "service $($s.Name)"
        & $add $tool "$($dir.Substring(3))\*.msh" @('MeshServer', 'MeshName')     # MeshAgent: server URL, never MeshID
        & $add $tool "$($dir.Substring(3))\client32.ini" @('GatewayAddress', 'SecondaryGateway', 'Port', 'SecondaryPort')
        foreach ($ext in '*.ini', '*.conf', '*.config', '*.json', '*.db') { & $add $tool "$($dir.Substring(3))\$ext" $null }
    }
    # De-duplicate (a file can match more than one rule).
    $items | Sort-Object Path -Unique
}

# IIS: malicious native/managed modules are registered in applicationHost.config; web shells live in the site roots.
Add-Collector -Phase 5 -Level 3 -Name 'IIS configuration, modules and web root listing' -Format None -Action {
    $inetsrv = Join-Path $Sys32 'inetsrv'
    if (-not (Test-Path -LiteralPath (Join-Path $inetsrv 'config'))) { return 'IIS not installed' }
    if ($Ctx.ShadowLink) { Copy-VssArtifact 'Windows\System32\inetsrv\config\*.config' }
    $appcmd = Join-Path $inetsrv 'appcmd.exe'
    $roots = @()
    if (Test-Path -LiteralPath $appcmd) { $roots = @(& $appcmd list vdir /text:physicalPath 2>&1 | Where-Object { $_ } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim()) } | Sort-Object -Unique) }
    $global:LASTEXITCODE = 0
    $hashExt = '.aspx', '.asp', '.ashx', '.asmx', '.svc', '.php', '.jsp', '.config', '.dll'
    $rows = foreach ($r in $roots) {
        if ($r -match '^\\\\' -or -not (Test-Path -LiteralPath $r)) { continue }
        foreach ($f in Get-ChildItem -LiteralPath $r -File -Recurse -Force -ErrorAction Ignore) {
            [pscustomobject]@{ SiteRoot = $r; Path = $f.FullName; Size = $f.Length; CreatedUtc = $f.CreationTimeUtc.ToString('o'); ModifiedUtc = $f.LastWriteTimeUtc.ToString('o')
                SHA256 = $(if ($hashExt -contains $f.Extension.ToLowerInvariant()) { Get-HashSafe $f.FullName } else { $null }) }
            if ($f.Name -ieq 'web.config') {
                if ($Ctx.ShadowLink -and $f.FullName.StartsWith("$env:SystemDrive\", [StringComparison]::OrdinalIgnoreCase)) { Copy-VssArtifact $f.FullName.Substring(3) | Out-Null }
                else { $d = Join-Path $Ctx.Disk ('IIS_live\' + ($f.FullName -replace '^([A-Za-z]):', '$1')); [IO.Directory]::CreateDirectory((Split-Path -Parent $d)) | Out-Null; Copy-Item -LiteralPath $f.FullName -Destination $d -Force -ErrorAction Ignore }
            }
        }
    }
    $csv = Join-Path $Ctx.Disk 'iis_webroot_listing.csv'
    [IO.Directory]::CreateDirectory($Ctx.Disk) | Out-Null
    if ($rows) { $rows | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8 } else { New-Item -ItemType File -Force -Path $csv | Out-Null }
    '{0} site root(s), {1} file(s) listed' -f $roots.Count, @($rows).Count
}

# MEGAsync logs (logs, not credentials). VERIFY the folder on a host with MEGAsync installed.
Add-Collector -Phase 5 -Level 3 -Name 'Copy: MEGAsync logs' -Format None -NeedsVss -Action {
    foreach ($u in Get-VssUserDirs) { Copy-VssArtifact "Users\$u\AppData\Local\Mega Limited\MEGAsync\logs" -Recurse }
}

# Unsaved Notepad tabs (Windows 11) and Sticky Notes. No parser is bundled; see the user guide.
Add-Collector -Phase 5 -Level 3 -Name 'Copy: Notepad TabState/WindowState and Sticky Notes' -Format None -NeedsVss -Action {
    foreach ($u in Get-VssUserDirs) {
        $np = "Users\$u\AppData\Local\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState"
        Copy-VssArtifact "$np\TabState\*"
        Copy-VssArtifact "$np\WindowState\*"
        Copy-VssArtifact "Users\$u\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite*"
    }
}

# Opt-in only (-DefenderQuarantine). Entries are RC4-obfuscated with a well-known key: not directly runnable,
# but they ARE malware samples. Detection metadata is already collected without this.
Add-Collector -Phase 5 -Level 2 -Name 'Copy: Defender quarantine (opt-in, malware samples)' -Format None -NeedsVss -Enabled:$DefenderQuarantine.IsPresent -Action {
    $src = Join-Path $Ctx.ShadowLink 'ProgramData\Microsoft\Windows Defender\Quarantine'
    if (-not (Test-Path -LiteralPath $src)) { return 'No Defender quarantine folder' }
    $dst = Join-Path $Ctx.Root 'Security\DefenderQuarantine'
    $ok = 0; $bad = 0
    foreach ($f in Get-ChildItem -LiteralPath $src -File -Recurse -Force -ErrorAction Ignore) {
        $t = Join-Path $dst $f.FullName.Substring($src.Length).TrimStart('\')
        try { [IO.Directory]::CreateDirectory((Split-Path -Parent $t)) | Out-Null; Copy-Item -LiteralPath $f.FullName -Destination $t -Force -ErrorAction Stop; $ok++ } catch { $bad++ }
    }
    '{0} quarantine file(s) copied, {1} failed. These are malware samples.' -f $ok, $bad
}

# Fallbacks when no snapshot is available (live export; hives of logged-off users are NOT obtainable this way)
Add-Collector -Phase 5 -Level 2 -Name 'Fallback: registry hives via reg save' -Format None -OnlyWithoutVss -Action {
    $dir = Join-Path $Ctx.Root 'Disk\Registry_live'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    foreach ($h in 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY') {
        & $Exe.reg save "HKLM\$h" (Join-Path $dir "$h.hiv") /y 2>&1 | Out-Null
    }
}

Add-Collector -Phase 5 -Level 2 -Name 'Fallback: all event logs via wevtutil' -Format None -OnlyWithoutVss -Action {
    $dir = Join-Path $Ctx.Root 'EventLogs\All'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $count = 0
    Get-WinEvent -ListLog * -ErrorAction Ignore | Where-Object { $_.RecordCount -gt 0 } | ForEach-Object {
        $dst = Join-Path $dir (($_.LogName -replace '[\\/]', '%4') + '.evtx')
        & $Exe.wevtutil epl $_.LogName $dst /ow:true 2>&1 | Out-Null
        $count++
    }
    "$count channels exported"
}

# Parity with the original batch script: live copies when no snapshot exists
Add-Collector -Phase 5 -Level 2 -Name 'Fallback: live copy of Prefetch and PowerShell history' -Format None -OnlyWithoutVss -Action {
    $pf = Join-Path $Ctx.Disk 'Windows\Prefetch'
    New-Item -ItemType Directory -Force -Path $pf | Out-Null
    $copied = @(Copy-Item -Path (Join-Path $env:SystemRoot 'Prefetch\*.pf') -Destination $pf -Force -PassThru -ErrorAction Ignore).Count
    "Prefetch: $copied file(s)"
    foreach ($u in @(Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction Ignore)) {
        $src = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (Test-Path -LiteralPath $src) {
            $d = Join-Path $Ctx.Disk ('Users\{0}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine' -f $u.Name)
            New-Item -ItemType Directory -Force -Path $d | Out-Null
            Copy-Item -LiteralPath $src -Destination $d -Force -ErrorAction Ignore
            "PowerShell history: $($u.Name)"
        }
    }
}

Add-Collector -Phase 5 -Level 2 -Name 'Write snapshot copy log' -Format Csv -Out 'Disk\_CopyLog.csv' -NeedsVss -Action { $Ctx.CopyLog.ToArray() }

# ---------- PHASE 6: SLOW / NOISY LIVE TOOLS ----------
Add-Collector -Phase 6 -Level 2 -Name 'Autoruns (all entries, hashes, signatures, UTC)' -Format None -Needs 'Autoruns' -Action {
    Invoke-External -FilePath $Tool.Autoruns.FullName -ArgumentList @('-accepteula', '-nobanner', '-a', '*', '-c', '-h', '-s', '-t') `
        -OutFile (Join-Path $Ctx.Root 'Tools\autoruns.csv') -TimeoutSec 1800
}

Add-Collector -Phase 6 -Level 2 -Name 'Handle (all handle types, owner)' -Format None -Needs 'Handle' -Action {
    Invoke-External -FilePath $Tool.Handle.FullName -ArgumentList @('-accepteula', '-nobanner', '-a', '-u') `
        -OutFile (Join-Path $Ctx.Root 'Tools\handle.txt') -TimeoutSec 900
}

Add-Collector -Phase 6 -Level 2 -Name 'ListDlls' -Format None -Needs 'ListDlls' -Action {
    Invoke-External -FilePath $Tool.ListDlls.FullName -ArgumentList @('-accepteula') `
        -OutFile (Join-Path $Ctx.Root 'Tools\listdlls.txt') -TimeoutSec 900
}

Add-Collector -Phase 6 -Level 2 -Name 'LogonSessions' -Format None -Needs 'LogonSessions' -Action {
    Invoke-External -FilePath $Tool.LogonSessions.FullName -ArgumentList @('-accepteula', '-p') `
        -OutFile (Join-Path $Ctx.Root 'Tools\logonsessions.txt') -TimeoutSec 300
}

Add-Collector -Phase 6 -Level 3 -Name 'Sigcheck: unsigned executables in user-writable paths' -Format None -Needs 'Sigcheck' -Action {
    $targets = @{
        Users = (Join-Path $env:SystemDrive 'Users')
        ProgramData = $env:ProgramData
        WinTemp = (Join-Path $env:SystemRoot 'Temp')
    }
    foreach ($k in $targets.Keys) {
        try {
            Invoke-External -FilePath $Tool.Sigcheck.FullName `
                -ArgumentList @('-accepteula', '-nobanner', '-c', '-h', '-e', '-u', '-s', $targets[$k]) `
                -OutFile (Join-Path $Ctx.Root "Tools\sigcheck_$k.csv") -TimeoutSec 3600
            # Sigcheck's exit code is the number of matching (unsigned) files, not an error.
            "{0}: {1} unsigned" -f $k, $script:LastExit
        }
        catch { "sigcheck $k : $($_.Exception.Message)" }
    }
    $script:LastExit = 0
}

Add-Collector -Phase 6 -Level 4 -Name 'Sigcheck: unsigned executables in System32 (incl. drivers)' -Format None -Needs 'Sigcheck' -Action {
    Invoke-External -FilePath $Tool.Sigcheck.FullName `
        -ArgumentList @('-accepteula', '-nobanner', '-c', '-h', '-e', '-u', '-s', $Sys32) `
        -OutFile (Join-Path $Ctx.Root 'Tools\sigcheck_System32.csv') -TimeoutSec 7200
    "System32: {0} unsigned" -f $script:LastExit    # exit code = match count
    $script:LastExit = 0
}

# ---------- PHASE 6 (3.4.0): DISK IMAGES, EXFILTRATION TOOLS ----------

# List only, never copy (images can be huge). Roots of extra internal volumes are listed without recursing.
Add-Collector -Phase 6 -Level 3 -Name 'Disk image files (VHD/VHDX/VMDK/VDI/ISO/IMG)' -Format Csv -Out 'System\virtual_disk_files.csv' -Action {
    $ext = '.vhd', '.vhdx', '.vmdk', '.vdi', '.iso', '.img'
    $trees = @((Join-Path $env:SystemDrive 'Users'), $env:ProgramData, (Join-Path $env:SystemDrive 'PerfLogs'), (Join-Path $env:SystemRoot 'Temp'))
    $flat = @("$env:SystemDrive\") + @($Ctx.ExtraVolumes | ForEach-Object { "$($_.Letter)\" })
    $files = @(foreach ($t in $trees) { Get-ChildItem -LiteralPath $t -File -Recurse -Force -ErrorAction Ignore }) +
             @(foreach ($r in $flat) { Get-ChildItem -LiteralPath $r -File -Force -ErrorAction Ignore })
    foreach ($f in $files) { if ($ext -contains $f.Extension.ToLowerInvariant()) { Get-FileMeta $f -NoHash } }
}

# Renamed rclone is a classic: match on file name AND on version info. rclone.conf holds tokens and keys, so only
# its remote names and types are read (or 'encrypted'); other tool configs are presence + hash only.
Add-Collector -Phase 6 -Level 3 -Name 'Exfiltration and tunneling tools (rclone, MEGA, ngrok, ...) + config presence' -Format Csv -Out 'Security\exfil_tools.csv' -Action {
    $trees = @((Join-Path $env:SystemDrive 'Users'), $env:ProgramData, (Join-Path $env:SystemRoot 'Temp'), (Join-Path $env:SystemDrive 'PerfLogs'))
    $exes = @(foreach ($t in $trees) { Get-ChildItem -LiteralPath $t -Filter '*.exe' -File -Recurse -Force -ErrorAction Ignore }) +
            @(Get-ChildItem -LiteralPath "$env:SystemDrive\" -Filter '*.exe' -File -Force -ErrorAction Ignore)
    $rcloneDirs = New-Object System.Collections.Generic.List[string]
    foreach ($f in $exes) {
        $vi = $f.VersionInfo
        $base = ($f.BaseName -replace '[\s_-]', '')
        $matched = $null
        foreach ($t in $ExfilTools) {
            $tok = $t.Token -replace '\s', ''
            if ($base -like "$tok*") { $matched = "name:$($t.Token)"; break }
            if (-not $t.ContainsKey('NameOnly')) {
                $vtext = "$($vi.ProductName)|$($vi.OriginalFilename)|$($vi.InternalName)" -replace '\s', ''
                if ($vtext -match [regex]::Escape($tok)) { $matched = "versioninfo:$($t.Token)"; break }
            }
        }
        if (-not $matched) { continue }
        if ($matched -match 'rclone') { $rcloneDirs.Add($f.DirectoryName) }
        $sig = try { [string](Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction Stop).Status } catch { $null }
        [pscustomobject]@{ Kind = 'Binary'; Path = $f.FullName; Name = $f.Name; MatchedOn = $matched; ProductName = $vi.ProductName; OriginalFilename = $vi.OriginalFilename
            Size = $f.Length; CreatedUtc = $f.CreationTimeUtc.ToString('o'); ModifiedUtc = $f.LastWriteTimeUtc.ToString('o'); SHA256 = (Get-HashSafe $f.FullName); Signature = $sig; Details = $null }
    }
    # Config files: never copied.
    $users = @(Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction Ignore | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
    $cfg = New-Object System.Collections.Generic.List[object]
    foreach ($u in $users) {
        foreach ($p in 'AppData\Roaming\rclone\rclone.conf', '.config\rclone\rclone.conf') { $cfg.Add(@{ T = 'rclone.conf'; P = (Join-Path $u.FullName $p) }) }
        foreach ($p in 'AppData\Roaming\WinSCP.ini', 'AppData\Roaming\FileZilla\recentservers.xml', 'AppData\Roaming\FileZilla\sitemanager.xml') { $cfg.Add(@{ T = (Split-Path -Leaf $p); P = (Join-Path $u.FullName $p) }) }
        foreach ($f in @(Get-ChildItem -LiteralPath $u.FullName -Filter 'ngrok.yml' -File -Recurse -Depth 4 -Force -ErrorAction Ignore)) { $cfg.Add(@{ T = 'ngrok.yml'; P = $f.FullName }) }
    }
    foreach ($d in ($rcloneDirs | Sort-Object -Unique)) { $cfg.Add(@{ T = 'rclone.conf'; P = (Join-Path $d 'rclone.conf') }) }
    foreach ($c in $cfg) {
        $fi = Get-Item -LiteralPath $c.P -Force -ErrorAction Ignore
        if (-not $fi) { continue }
        $details = 'presence only (may contain credentials; not copied)'
        if ($c.T -eq 'rclone.conf') {
            $lines = @(Get-Content -LiteralPath $fi.FullName -TotalCount 5000 -ErrorAction Ignore)
            if (($lines | Where-Object { $_.Trim() } | Select-Object -First 1) -match '^RCLONE_ENCRYPT_V0') { $details = 'encrypted' }
            else {
                # ONLY section names and their 'type =' values. Nothing else is read out.
                $remotes = @(); $cur = $null
                foreach ($l in $lines) {
                    if ($l -match '^\s*\[(.+)\]\s*$') { $cur = $Matches[1]; $remotes += , @($cur, $null) }
                    elseif ($cur -and $l -match '^\s*type\s*=\s*(\S+)') { $remotes[-1][1] = $Matches[1] }
                }
                $details = 'remotes: ' + (($remotes | ForEach-Object { '{0} ({1})' -f $_[0], $_[1] }) -join '; ')
            }
        }
        [pscustomobject]@{ Kind = 'Config'; Path = $fi.FullName; Name = $c.T; MatchedOn = 'known config location'; ProductName = $null; OriginalFilename = $null
            Size = $fi.Length; CreatedUtc = $fi.CreationTimeUtc.ToString('o'); ModifiedUtc = $fi.LastWriteTimeUtc.ToString('o'); SHA256 = (Get-HashSafe $fi.FullName); Signature = $null; Details = $details }
    }
}

# ---------- PHASE 7: PARSERS (run against collected COPIES only) ----------
function Get-ParsedDir { param([string]$Name) $d = Join-Path $Ctx.Root "Parsed\$Name"; New-Item -ItemType Directory -Force -Path $d | Out-Null; $d }

Add-Collector -Phase 7 -Level 3 -Name 'Parse: EvtxECmd' -Format None -Needs 'EvtxECmd' -Action {
    $in = Join-Path $Ctx.Root 'EventLogs\All'   # all channels (snapshot copy, or wevtutil fallback)
    if (-not (Test-Path -LiteralPath $in)) { throw 'No event logs collected in EventLogs\All' }
    Invoke-External -FilePath $Tool.EvtxECmd.FullName -ArgumentList @('-d', $in, '--csv', (Get-ParsedDir 'EvtxECmd'), '--csvf', 'evtx_all.csv') `
        -OutFile (Join-Path $Ctx.Root 'Parsed\EvtxECmd.log') -TimeoutSec 7200
}

Add-Collector -Phase 7 -Level 3 -Name 'Parse: RECmd (batch file required)' -Format None -Needs 'RECmd' -Action {
    if (-not $Tool.RECmdBatch) { throw 'No RECmd batch (*.reb) file found in toolkit' }
    foreach ($set in @(@{ N = 'System'; P = 'Windows\System32\config' }, @{ N = 'Users'; P = 'Users' })) {
        $in = Join-Path $Ctx.Disk $set.P
        if (Test-Path -LiteralPath $in) {
            Invoke-External -FilePath $Tool.RECmd.FullName -ArgumentList @('-d', $in, '--bn', $Tool.RECmdBatch.FullName, '--csv', (Get-ParsedDir "RECmd_$($set.N)")) `
                -OutFile (Join-Path $Ctx.Root "Parsed\RECmd_$($set.N).log") -TimeoutSec 3600
        }
    }
}

Add-Collector -Phase 7 -Level 3 -Name 'Parse: AmcacheParser' -Format None -Needs 'AmcacheParser' -Action {
    $hve = Join-Path $Ctx.Disk 'Windows\appcompat\Programs\Amcache.hve'
    if (-not (Test-Path -LiteralPath $hve)) { throw 'Amcache.hve not collected' }
    Invoke-External -FilePath $Tool.AmcacheParser.FullName -ArgumentList @('-f', $hve, '--csv', (Get-ParsedDir 'Amcache')) `
        -OutFile (Join-Path $Ctx.Root 'Parsed\AmcacheParser.log') -TimeoutSec 1800
}

Add-Collector -Phase 7 -Level 3 -Name 'Parse: MFTECmd ($MFT and $Boot, every NTFS volume)' -Format None -Needs 'MFTECmd' -Action {
    # Input names come from the RawCopy step: MFT_<drive>.bin, Boot_<drive>.bin. Output: MFT_<drive>.csv etc.
    # ($J is collected as CSV by fsutil, and raw by KAPE in Full; neither needs MFTECmd here.)
    $ntfs = Join-Path $Ctx.Disk 'NTFS'
    $files = @(Get-ChildItem -LiteralPath $ntfs -File -ErrorAction Ignore |
        Where-Object { $_.Length -gt 0 -and ($_.Name -like 'MFT_*.bin' -or $_.Name -like 'Boot_*.bin') })
    if (-not $files.Count) { throw 'No raw NTFS files collected (RawCopy missing or failed)' }
    foreach ($f in $files) {
        try {
            Invoke-External -FilePath $Tool.MFTECmd.FullName -ArgumentList @('-f', $f.FullName, '--csv', (Get-ParsedDir 'MFTECmd'), '--csvf', "$($f.BaseName).csv") `
                -OutFile (Join-Path $Ctx.Root "Parsed\MFTECmd_$($f.BaseName).log") -TimeoutSec 7200
        }
        catch { "MFTECmd $($f.BaseName) failed: $($_.Exception.Message)" }
    }
}

Add-Collector -Phase 7 -Level 3 -Name 'Parse: PECmd (Prefetch)' -Format None -Needs 'PECmd' -Action {
    Invoke-External -FilePath $Tool.PECmd.FullName -ArgumentList @('-d', (Join-Path $Ctx.Disk 'Windows\Prefetch'), '-q', '--csv', (Get-ParsedDir 'PECmd')) `
        -OutFile (Join-Path $Ctx.Root 'Parsed\PECmd.log') -TimeoutSec 1800
}

Add-Collector -Phase 7 -Level 3 -Name 'Parse: LECmd (LNK) and JLECmd (Jump Lists)' -Format None -Needs 'LECmd', 'JLECmd' -Action {
    $in = Join-Path $Ctx.Disk 'Users'
    if ($Tool.LECmd) { Invoke-External -FilePath $Tool.LECmd.FullName -ArgumentList @('-d', $in, '-q', '--csv', (Get-ParsedDir 'LECmd')) -OutFile (Join-Path $Ctx.Root 'Parsed\LECmd.log') -TimeoutSec 3600 }
    if ($Tool.JLECmd) { Invoke-External -FilePath $Tool.JLECmd.FullName -ArgumentList @('-d', $in, '-q', '--csv', (Get-ParsedDir 'JLECmd')) -OutFile (Join-Path $Ctx.Root 'Parsed\JLECmd.log') -TimeoutSec 3600 }
}

Add-Collector -Phase 7 -Level 3 -Name 'Parse: AppCompatCacheParser (ShimCache)' -Format None -Needs 'AppCompatCacheParser' -Action {
    $sys = Join-Path $Ctx.Disk 'Windows\System32\config\SYSTEM'
    if (-not (Test-Path -LiteralPath $sys)) { throw 'SYSTEM hive not collected' }
    Invoke-External -FilePath $Tool.AppCompatCacheParser.FullName -ArgumentList @('-f', $sys, '--csv', (Get-ParsedDir 'AppCompatCache')) `
        -OutFile (Join-Path $Ctx.Root 'Parsed\AppCompatCacheParser.log') -TimeoutSec 1800
}

Add-Collector -Phase 7 -Level 3 -Name 'Parse: SBECmd (ShellBags)' -Format None -Needs 'SBECmd' -Action {
    $in = Join-Path $Ctx.Disk 'Users'
    if (-not (Test-Path -LiteralPath $in)) { throw 'No user hives collected' }
    Invoke-External -FilePath $Tool.SBECmd.FullName -ArgumentList @('-d', $in, '--csv', (Get-ParsedDir 'SBECmd')) `
        -OutFile (Join-Path $Ctx.Root 'Parsed\SBECmd.log') -TimeoutSec 3600
}

Add-Collector -Phase 7 -Level 3 -Name 'Parse: RBCmd (Recycle Bin)' -Format None -Needs 'RBCmd' -Action {
    # System drive copy (from the snapshot) plus Disk\Volume_<X>\$Recycle.Bin for each extra internal volume.
    $sets = @(@{ Tag = $env:SystemDrive.TrimEnd(':'); Dir = (Join-Path $Ctx.Disk '$Recycle.Bin') })
    foreach ($v in $Ctx.ExtraVolumes) {
        $drv = $v.Letter.TrimEnd(':')
        $sets += @{ Tag = $drv; Dir = (Join-Path $Ctx.Disk "Volume_$drv\`$Recycle.Bin") }
    }
    $ran = 0; $worst = 0
    foreach ($s in $sets) {
        if (-not (Test-Path -LiteralPath $s.Dir)) { continue }
        Invoke-External -FilePath $Tool.RBCmd.FullName -ArgumentList @('-d', $s.Dir, '-q', '--csv', (Get-ParsedDir "RBCmd\$($s.Tag)")) `
            -OutFile (Join-Path $Ctx.Root "Parsed\RBCmd_$($s.Tag).log") -TimeoutSec 1800
        if ($script:LastExit -ne 0) { $worst = $script:LastExit }
        $ran++
    }
    $script:LastExit = $worst
    if (-not $ran) { return 'No Recycle Bin entries collected' }
}

Add-Collector -Phase 7 -Level 3 -Name 'Parse: WxTCmd (Windows Timeline)' -Format None -Needs 'WxTCmd' -Action {
    $dbs = @(Get-ChildItem -Path (Join-Path $Ctx.Disk 'Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db') -File -ErrorAction Ignore)
    if (-not $dbs.Count) { return 'No ActivitiesCache.db collected (Timeline not in use)' }
    $worst = 0
    foreach ($db in $dbs) {
        $tag = '{0}_{1}' -f $db.FullName.Substring((Join-Path $Ctx.Disk 'Users').Length).TrimStart('\').Split('\')[0], $db.Directory.Name
        try {
            Invoke-External -FilePath $Tool.WxTCmd.FullName -ArgumentList @('-f', $db.FullName, '--csv', (Get-ParsedDir "WxTCmd\$tag")) `
                -OutFile (Join-Path $Ctx.Root "Parsed\WxTCmd_$tag.log") -TimeoutSec 1800
            if ($script:LastExit -ne 0) { $worst = $script:LastExit }
        }
        catch { "WxTCmd $tag failed: $($_.Exception.Message)" }
    }
    $script:LastExit = $worst
}

Add-Collector -Phase 7 -Level 3 -Name 'Parse: SQLECmd (browser and app SQLite databases)' -Format None -Needs 'SQLECmd' -Action {
    $in = Join-Path $Ctx.Disk 'Users'
    if (-not (Test-Path -LiteralPath $in)) { throw 'No user artifacts collected' }
    # SQLECmd refuses to run when two maps share an Id, and KAPE's bin\SQLECmd\Maps holds renamed old copies
    # next to the new ones. Build a clean working copy (on the output drive): the exe and its DLLs plus its OWN
    # maps (newer maps from other folders use properties the old exe rejects), newest file per map Id.
    # Any map the exe still reports as bad is dropped and the run retried. The toolkit itself is not modified.
    # Verified against a real collection on the test machine: 26 databases parsed.
    $work = Join-Path $Ctx.Root 'Tools\_sqlecmd_work'
    $workMaps = Join-Path $work 'Maps'
    New-Item -ItemType Directory -Force -Path $workMaps | Out-Null
    try {
        Get-ChildItem -LiteralPath $Tool.SQLECmd.DirectoryName -File | Copy-Item -Destination $work -Force
        $maps = foreach ($m in Get-ChildItem -LiteralPath (Join-Path $Tool.SQLECmd.DirectoryName 'Maps') -Filter '*.smap' -File -ErrorAction Ignore) {
            $id = Select-String -LiteralPath $m.FullName -Pattern '^Id:\s*(\S+)' | Select-Object -First 1
            [pscustomobject]@{ Id = $(if ($id) { $id.Matches[0].Groups[1].Value } else { $m.Name }); File = $m }
        }
        foreach ($g in ($maps | Group-Object Id)) {
            $g.Group | Sort-Object { $_.File.LastWriteTimeUtc } -Descending | Select-Object -First 1 |
                ForEach-Object { Copy-Item -LiteralPath $_.File.FullName -Destination (Join-Path $workMaps $_.File.Name) -Force }
        }
        $log = Join-Path $Ctx.Root 'Parsed\SQLECmd.log'
        $dropped = New-Object System.Collections.Generic.List[string]
        for ($try = 1; $try -le 3; $try++) {
            $outDir = Get-ParsedDir 'SQLECmd'
            Invoke-External -FilePath (Join-Path $work $Tool.SQLECmd.Name) -ArgumentList @('-d', $in, '--hunt', '--csv', $outDir) `
                -OutFile $log -TimeoutSec 3600
            $lines = @(Get-Content -LiteralPath $log -ErrorAction Ignore)
            $at = -1
            for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'following maps had errors') { $at = $i; break } }
            if ($at -lt 0) { break }
            $bad = @($lines[($at + 1)..($lines.Count - 1)] | Where-Object { $_ -match '\.smap\s*$' } | ForEach-Object { $_.Trim() })
            if (-not $bad.Count) { break }
            foreach ($b in $bad) { Remove-Item -LiteralPath (Join-Path $workMaps $b) -Force -ErrorAction Ignore; $dropped.Add($b) }
        }
        '{0} maps used' -f @(Get-ChildItem -LiteralPath $workMaps -File).Count
        if ($dropped.Count) { 'dropped bad maps: ' + ($dropped -join ', ') }
    }
    finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction Ignore    # only our own working copy
    }
}

Add-Collector -Phase 7 -Level 3 -Name 'Parse: SrumECmd' -Format None -Needs 'SrumECmd' -Action {
    $srum = Join-Path $Ctx.Disk 'Windows\System32\sru\SRUDB.dat'
    $soft = Join-Path $Ctx.Disk 'Windows\System32\config\SOFTWARE'
    if (-not (Test-Path -LiteralPath $srum)) { throw 'SRUDB.dat not collected' }
    Invoke-External -FilePath $Tool.SrumECmd.FullName -ArgumentList @('-f', $srum, '-r', $soft, '--csv', (Get-ParsedDir 'SrumECmd')) `
        -OutFile (Join-Path $Ctx.Root 'Parsed\SrumECmd.log') -TimeoutSec 1800
}

# ---------- PHASE 8: FULL (KAPE / VELOCIRAPTOR) ----------
Add-Collector -Phase 8 -Level 4 -Name 'KAPE targets (+ optional modules)' -Format None -Needs 'KAPE' -Action {
    $dest = Join-Path $Ctx.Root 'KAPE'
    # Flags verified against kape.exe 1.3.0.2 --help. --msource defaults to --tdest when targets run first.
    $kArgs = @('--tsource', $env:SystemDrive, '--tdest', (Join-Path $dest 'Targets'), '--target', $KapeTargets, '--tflush')
    if ($KapeVss) { $kArgs += '--vss' }
    if ($KapeModules) { $kArgs += @('--module', $KapeModules, '--mdest', (Join-Path $dest 'Modules'), '--mflush') }
    Invoke-External -FilePath $Tool.KAPE.FullName -ArgumentList $kArgs -OutFile (Join-Path $dest 'kape_console.log') -TimeoutSec 14400
}

Add-Collector -Phase 8 -Level 4 -Name 'KAPE targets on extra internal volumes' -Format None -Needs 'KAPE' -Action {
    # Data volumes have no registry, event logs or user profiles, so only file-system metadata and the
    # Recycle Bin are collected ($KapeVolumeTargets; KAPE also handles non-NTFS volumes and the raw $J).
    if (-not @($Ctx.ExtraVolumes).Count) { return 'No extra internal volumes' }
    $worst = 0
    foreach ($v in $Ctx.ExtraVolumes) {
        $drv = $v.Letter.TrimEnd(':')
        $dest = Join-Path $Ctx.Root "KAPE\Targets_$drv"
        $kArgs = @('--tsource', $v.Letter, '--tdest', $dest, '--target', $KapeVolumeTargets, '--tflush')
        if ($KapeVss) { $kArgs += '--vss' }
        try {
            Invoke-External -FilePath $Tool.KAPE.FullName -ArgumentList $kArgs -OutFile (Join-Path $Ctx.Root "KAPE\kape_console_$drv.log") -TimeoutSec 7200
            if ($script:LastExit -ne 0) { $worst = $script:LastExit }
            '{0}: done' -f $v.Letter
        }
        catch { Write-Error ('KAPE {0} failed: {1}' -f $v.Letter, $_.Exception.Message) }
    }
    $script:LastExit = $worst
}

Add-Collector -Phase 8 -Level 4 -Name 'Velociraptor offline collection' -Format None -Needs 'Velociraptor' -Action {
    $dest = Join-Path $Ctx.Root 'Velociraptor'
    # The artifact name has changed between Velociraptor releases, so check this build has it before collecting.
    $listFile = Join-Path $dest 'artifacts_list.txt'
    try { Invoke-External -FilePath $Tool.Velociraptor.FullName -ArgumentList @('artifacts', 'list') -OutFile $listFile -TimeoutSec 300 } catch { }
    $known = @(Get-Content -LiteralPath $listFile -ErrorAction Ignore | ForEach-Object { $_.Trim() })
    $missing = New-Object System.Collections.Generic.List[string]
    $failed  = New-Object System.Collections.Generic.List[string]
    $done = 0
    # Per-artifact arguments. -VelociraptorArgs still goes to every artifact (backward compatible);
    # -VelociraptorArtifactArgs and the YARA scan add arguments to one artifact only.
    $perArt = @{}
    foreach ($k in $VelociraptorArtifactArgs.Keys) { $perArt[$k] = @($VelociraptorArtifactArgs[$k]) }
    $artifacts = @($VelociraptorArtifact)
    if ($YaraRules) {
        $yaraArt = 'Windows.Detection.Yara.Process'
        # Keep an exact copy of the rules in the case, so it records what was scanned for.
        $rulesCopy = Join-Path $dest ('yara_rules_' + (Split-Path -Leaf $YaraRules))
        Copy-Item -LiteralPath $YaraRules -Destination $rulesCopy -Force
        "YARA rules: $rulesCopy (SHA256 $(Get-HashSafe $rulesCopy))"
        # VERIFY: the rule parameter name changed between Velociraptor releases, so read it from this build's definition.
        $showFile = Join-Path $dest "$yaraArt.definition.yaml"
        try { Invoke-External -FilePath $Tool.Velociraptor.FullName -ArgumentList @('artifacts', 'show', $yaraArt) -OutFile $showFile -TimeoutSec 120 } catch { }
        $def = Get-Content -LiteralPath $showFile -Raw -ErrorAction Ignore
        $param = $null
        foreach ($cand in 'YaraRule', 'YaraRules', 'Rules') { if ($def -match "(?m)^\s*-?\s*name:\s*$cand\s*$") { $param = $cand; break } }
        $ruleText = [IO.File]::ReadAllText($YaraRules)
        if (-not $param) { Write-Error "YARA scan skipped: no YaraRule-style parameter found in $yaraArt (see $showFile)" }
        elseif ($ruleText.Length -gt 30000) { Write-Error "YARA scan skipped: rules file is $($ruleText.Length) characters; the rule text goes on the command line, which Windows caps at about 32,000. Split the rules." }
        else {
            $perArt[$yaraArt] = @($perArt[$yaraArt]) + @("$param=$ruleText") | Where-Object { $_ }
            if ($artifacts -notcontains $yaraArt) { $artifacts += $yaraArt }
        }
    }
    foreach ($art in $artifacts) {
        if ($known.Count -and ($known -notcontains $art)) { $missing.Add($art); continue }
        $vArgs = @('artifacts', 'collect', $art)
        foreach ($a in $VelociraptorArgs) { $vArgs += @('--args', $a) }
        if ($perArt.ContainsKey($art)) { foreach ($a in $perArt[$art]) { $vArgs += @('--args', $a) } }
        $vArgs += @('--output', (Join-Path $dest ($art + '.zip')))
        try {
            Invoke-External -FilePath $Tool.Velociraptor.FullName -ArgumentList $vArgs -OutFile (Join-Path $dest ($art + '_console.log')) -TimeoutSec 7200
            $done++
        }
        catch { $failed.Add(('{0} ({1})' -f $art, $_.Exception.Message)) }
    }
    if ($done -eq 0) { throw ('No Velociraptor artifact was collected. Missing: {0}. Failed: {1}' -f ($missing -join ', '), ($failed -join '; ')) }
    if ($failed.Count) { Write-Error ('Velociraptor failed: ' + ($failed -join '; ')) }    # counts as WARN
    '{0} artifact(s) collected, {1} failed' -f $done, $failed.Count
    if ($missing.Count) { 'not in this build: ' + ($missing -join ', ') }
}

# ===================================================================
# EXECUTE
# ===================================================================

$plan = @($script:Registry | Where-Object { $_.Level -le $Ctx.Level } | Sort-Object Phase, Seq)
Write-Log ("Executing {0} collectors for profile '{1}'" -f $plan.Count, $CollectionProfile)

try {
    foreach ($c in $plan) {
        # KAPE/Velociraptor read the live volume; drop our snapshot first so KAPE --vss does not collect it twice.
        if ($c.Phase -ge 8 -and $Ctx.ShadowLink) { Remove-Vss }
        Invoke-Collector $c
    }
}
finally {
    Remove-Vss    # always remove the snapshot + symlink, even on Ctrl+C
}

$EndUtc = [DateTime]::UtcNow

# ===================================================================
# MANIFEST / CHAIN OF CUSTODY
# ===================================================================

$script:Results | Export-Csv -LiteralPath (Join-Path $CollectionRoot 'CollectorResults.csv') -NoTypeInformation -Encoding UTF8

$os = $null
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch {}

# Read CIM properties defensively. On some machines the LastBootUpTime getter ITSELF throws
# ("Argument types do not match"), so a formatter applied afterwards can never catch it.
function Get-SafeProp {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    try { return $Obj.$Name } catch { return ('ERROR reading {0}: {1}' -f $Name, $_.Exception.Message) }
}
$osCaption = Get-SafeProp $os 'Caption'
$osVersion = Get-SafeProp $os 'Version'
$osBuild   = Get-SafeProp $os 'BuildNumber'
$lastBoot  = Get-SafeProp $os 'LastBootUpTime'
if ($lastBoot -is [string] -and $lastBoot.StartsWith('ERROR')) {
    # Fallback: ask legacy WMI for the raw DMTF string and convert it ourselves (Windows PowerShell only).
    try {
        $w = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        $lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($w.LastBootUpTime)
    }
    catch { }
}

$bound = [ordered]@{}
foreach ($k in $PSBoundParameters.Keys) { if ($k -ne 'ArchivePassword') { $bound[$k] = [string]$PSBoundParameters[$k] } }

$scriptSha = $null
try { $scriptSha = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $scriptSha = 'ERROR: ' + $_.Exception.Message }

# The manifest is built one field at a time. A single big [ordered]@{} literal threw
# "Argument types do not match" on the test machine (both the full and the fallback literal),
# so any field that fails now records its error and the rest of the manifest is still written.
$manifestErrors = New-Object System.Collections.Generic.List[string]
function Set-ManifestField {
    param($Dict, [string]$Key, [scriptblock]$Value)
    try { $Dict[$Key] = (& $Value) }
    catch { $Dict[$Key] = 'ERROR: ' + $_.Exception.Message; $manifestErrors.Add(('{0}: {1}' -f $Key, $_.Exception.Message)) }
}
$startIso = $ScriptStartUtc.ToString('o', $Inv)
$endIso   = $EndUtc.ToString('o', $Inv)

$mScript = New-Object System.Collections.Specialized.OrderedDictionary
Set-ManifestField $mScript 'Name'       { Split-Path -Leaf $PSCommandPath }
Set-ManifestField $mScript 'Version'    { $ScriptVersion }
Set-ManifestField $mScript 'SHA256'     { $scriptSha }
Set-ManifestField $mScript 'Parameters' { $bound }

$mCase = New-Object System.Collections.Specialized.OrderedDictionary
Set-ManifestField $mCase 'CaseId'   { $CaseId }
Set-ManifestField $mCase 'Operator' { $Operator }

$mHost = New-Object System.Collections.Specialized.OrderedDictionary
Set-ManifestField $mHost 'ComputerName' { $HostName }
Set-ManifestField $mHost 'Domain'       { $env:USERDOMAIN }
Set-ManifestField $mHost 'OS'           { [string]$osCaption }
Set-ManifestField $mHost 'OSVersion'    { [string]$osVersion }
Set-ManifestField $mHost 'OSBuild'      { [string]$osBuild }
Set-ManifestField $mHost 'LastBootUtc'  { ConvertTo-IsoUtc $lastBoot }
Set-ManifestField $mHost 'RamBytes'     { $RamBytes }
Set-ManifestField $mHost 'PowerShell'   { $PSVersionTable.PSVersion.ToString() }

$mTime = New-Object System.Collections.Specialized.OrderedDictionary
Set-ManifestField $mTime 'StartUtc'         { $startIso }
Set-ManifestField $mTime 'EndUtc'           { $endIso }
Set-ManifestField $mTime 'DurationSeconds'  { [int]($EndUtc - $ScriptStartUtc).TotalSeconds }
Set-ManifestField $mTime 'LocalTimeAtEnd'   { [DateTimeOffset]::Now.ToString('o', $Inv) }
Set-ManifestField $mTime 'TimeZone'         { [TimeZoneInfo]::Local.Id }
Set-ManifestField $mTime 'Note'             { 'EndUtc is end of collection, before final hashing.' }

$mVss = New-Object System.Collections.Specialized.OrderedDictionary
Set-ManifestField $mVss 'Id'                     { [string]$Ctx.ShadowId }
Set-ManifestField $mVss 'Device'                 { [string]$Ctx.ShadowDevice }
Set-ManifestField $mVss 'DeletedAfterCollection' { [bool]$Ctx.ShadowDeleted }

$manifest = New-Object System.Collections.Specialized.OrderedDictionary
$manifest['Script']      = $mScript
$manifest['Case']        = $mCase
$manifest['Host']        = $mHost
$manifest['Time']        = $mTime
$manifest['Profile']     = [string]$CollectionProfile
$manifest['OutputRoot']  = [string]$CollectionRoot
$manifest['VssSnapshot'] = $mVss
Set-ManifestField $manifest 'Volumes' {
    , ([object[]]@($AllVolumes | ForEach-Object {
        [ordered]@{ Letter = $_.Letter; FileSystem = $_.FileSystem; Bus = $_.Bus; Model = $_.Model; SizeGB = $_.SizeGB
            Internal = [bool]$_.Internal; Collected = [bool](($_.Letter -eq $env:SystemDrive.ToUpper()) -or @($ExtraVolumes | Where-Object Letter -eq $_.Letter).Count) }
    }))
}
Set-ManifestField $manifest 'Tools'      { , ([object[]]@($Inventory)) }
Set-ManifestField $manifest 'Collectors' { , ($script:Results.ToArray()) }
if ($manifestErrors.Count) {
    $manifest['ManifestErrors'] = $manifestErrors.ToArray()
    Write-Log ('Manifest: {0} field(s) could not be read: {1}' -f $manifestErrors.Count, ($manifestErrors -join '; ')) 'WARN'
}
try {
    $manifest | ConvertTo-Json -Depth 6 | Out-File -LiteralPath (Join-Path $CollectionRoot 'manifest.json') -Encoding UTF8
}
catch {
    Write-Log "manifest.json could not be written: $($_.Exception.Message)" 'ERROR'
}

$counts = $script:Results | Group-Object Status | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }
@(
    "Collect_v3 $ScriptVersion  (script SHA256 $scriptSha)"
    "Case: $CaseId   Operator: $Operator"
    "Host: $HostName   Profile: $CollectionProfile"
    "Start (UTC): $startIso"
    "End   (UTC): $endIso   Local TZ: $([TimeZoneInfo]::Local.Id)"
    "Results: $($counts -join ', ')"
    ''
    ($script:Results | Format-Table Phase, Name, Status, Exit, Seconds, Rows, Note -AutoSize -Wrap | Out-String -Width 300)
) | Out-File -LiteralPath (Join-Path $CollectionRoot 'manifest.txt') -Encoding UTF8

# Tidy: remove empty top-level folders
Get-ChildItem -LiteralPath $CollectionRoot -Directory -ErrorAction Ignore |
    Where-Object { -not (Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction Ignore) } |
    Remove-Item -Force -ErrorAction Ignore

Write-Log ("Collection finished: {0}" -f ($counts -join ', '))
Stop-Transcript | Out-Null    # stop BEFORE hashing so Collection.log is final

# ===================================================================
# HASHING (after transcript is closed)
# ===================================================================

Write-Host '[*] Hashing collected files (SHA256)...'
$hashFile = Join-Path $CollectionRoot 'FileHashes.csv'
$hashErrors = New-Object System.Collections.Generic.List[string]

$hashRows = foreach ($f in Get-ChildItem -LiteralPath $CollectionRoot -Recurse -File -Force -ErrorAction Ignore) {
    if ($f.FullName -eq $hashFile) { continue }
    try {
        $h = Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop
        [pscustomobject]@{
            SHA256 = $h.Hash; Length = $f.Length
            LastWriteUtc = $f.LastWriteTimeUtc.ToString('o')
            RelativePath = $f.FullName.Substring($CollectionRoot.Length).TrimStart('\')
        }
    }
    catch { $hashErrors.Add("$($f.FullName) : $($_.Exception.Message)") }
}
$hashRows | Export-Csv -LiteralPath $hashFile -NoTypeInformation -Encoding UTF8
if ($hashErrors.Count) {
    $hashErrors | Out-File -LiteralPath (Join-Path $CollectionRoot 'HashErrors.txt') -Encoding UTF8
    Write-Host "[!] $($hashErrors.Count) file(s) could not be hashed - see HashErrors.txt" -ForegroundColor Yellow
}
$hashOfHashes = (Get-FileHash -LiteralPath $hashFile -Algorithm SHA256).Hash

# ===================================================================
# OPTIONAL ARCHIVE
# ===================================================================

$archivePath = $null
if ($Archive) {
    try {
        if ($Tool.SevenZip) {
            $archivePath = "$CollectionRoot.7z"
            $aArgs = @('a', '-t7z', '-mx=3', $archivePath, $CollectionRoot)
            if ($ArchivePassword) {
                $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ArchivePassword))
                $aArgs += @("-p$plain", '-mhe=on')
            }
            Invoke-External -FilePath $Tool.SevenZip.FullName -ArgumentList $aArgs -OutFile "$CollectionRoot.7z.log" -TimeoutSec 14400
        }
        else {
            Write-Host '[!] 7-Zip not found: using Compress-Archive (NO encryption; 2 GB limit in Windows PowerShell 5.1).' -ForegroundColor Yellow
            $archivePath = "$CollectionRoot.zip"
            Compress-Archive -Path $CollectionRoot -DestinationPath $archivePath -Force
        }
        $ah = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
        "$ah  $(Split-Path -Leaf $archivePath)" | Out-File -LiteralPath "$archivePath.sha256" -Encoding ascii
    }
    catch { Write-Host "[!] Archive failed: $($_.Exception.Message)" -ForegroundColor Red }
}

# ===================================================================
# COMPLETE
# ===================================================================

Write-Host ''
Write-Host '================================='
Write-Host ' COLLECTION COMPLETE'
Write-Host '================================='
Write-Host "Output folder : $CollectionRoot"
Write-Host "Results       : $($counts -join ', ')"
Write-Host "FileHashes.csv SHA256 (record this off-box): $hashOfHashes"
if ($archivePath) { Write-Host "Archive       : $archivePath" }
Write-Host ''

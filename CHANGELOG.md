# Changelog

All notable changes to `Collect_v3.ps1`. Format based on [Keep a Changelog](https://keepachangelog.com/); versions follow [Semantic Versioning](https://semver.org/).

## [3.4.0]

Collector additions from a review of 3.3.1. 20 new collectors (110 in total, up from 90), plus new sections in the existing SMB and Velociraptor collectors.

### Added
- **Kernel drivers** (`System\drivers_hashed.csv`, Standard): every driver with SHA-256/SHA-1/MD5, signer, issuer, certificate expiry and version info.
  - Merges the service list with the modules actually loaded in the kernel (`EnumDeviceDrivers`), so drivers whose service key was deleted after loading are still listed (`LoadedNoService`).
  - A `Triage` column separates the ones worth reviewing from normal Windows library modules and crash-dump copies.
  - New `-LolDriversCsv` parameter matches the hashes against a local LOLDrivers export, with no network access.
- **Code integrity** (`Security\code_integrity.txt`): vulnerable driver blocklist setting, Device Guard registry, `Win32_DeviceGuard` (VBS / HVCI).
- **Logging tampering:**
  - `EventLogs\channel_config.csv` (every profile): enabled state, max size, retention and fill state of every event log channel.
  - `Security\etw_sessions.txt` (every profile): running ETW sessions, expected-session check, AutoLogger sessions with `Start=0`, full AutoLogger registry.
  - `Security\wfp_filters.xml` + `wfp_block_summary.csv`: all WFP filters (always written with `file=`), and a summary of BLOCK filters keyed on an application path (the EDRSilencer pattern). Deep+ also writes `wfp_state.xml`.
  - `Security\sysmon_config.txt`: Sysmon found by version info (works when renamed), decoded config (only a valid Microsoft-signed binary is run), driver registry parameters.
- **More remote-access tools** (Deep):
  - ScreenConnect, Atera and LogMeIn logs, with paths from KAPE 1.3.0.2 targets.
  - MeshAgent, NetSupport, SimpleHelp, Action1 and ScreenConnect agents discovered through their services.
  - Secret-bearing configs are presence + hash only, in `Disk\remote_access_presence.csv`. NetSupport `client32.ini` gives only its gateway address and port; MeshAgent `.msh` only its server URL.
  - Files pushed through ScreenConnect are listed and hashed, not copied.
- **SSH** (Standard): `authorized_keys`, `administrators_authorized_keys`, `known_hosts`, `config`, `sshd_config`, public host keys, sshd logs. Private keys are never copied.
- **Mark-of-the-Web** (`Disk\zone_identifier.csv`, Standard): Zone.Identifier for user Downloads, Desktop, Documents, Temp and the Outlook cache.
  - Read from the snapshot; a fast native stream scan handles about 26,000 hits in about 75 s.
  - Risky file types up to 50 MB are hashed at Deep+.
- **IIS** (Deep, IIS hosts only): `applicationHost.config` and other configs (module registrations), `Disk\iis_webroot_listing.csv` with hashes for script and binary types, and each site's `web.config`.
- **Virtual machines and disk images**: Hyper-V VMs, mounted VHD and ISO files (`System\virtual_disks.txt`); VHD/VHDX/VMDK/VDI/ISO/IMG file search (`System\virtual_disk_files.csv`, Deep, list only).
- **SMB open files** (`Get-SmbOpenFile`) in `Network\smb.txt`.
- **Service failure actions** (`Persistence\service_failure_actions.csv`, Standard): services that run a program on failure.
- **Notepad TabState / WindowState and Sticky Notes** (Deep).
- **PowerShell transcripts** (Standard): policy `OutputDirectory` folders (UNC paths recorded, not followed) and the default `Documents` locations.
- **Exfiltration and tunneling tools** (`Security\exfil_tools.csv`, Deep): rclone, restic, MEGA, WinSCP, FileZilla, PuTTY tools, ngrok, cloudflared, chisel, Syncthing, S3 Browser and Cyberduck, matched by name and by version info.
  - `rclone.conf` gives only its remote names and types (or `encrypted`).
  - Other configs are presence + hash only.
  - MEGAsync logs are copied.
- **Velociraptor:**
  - `Windows.EventLogs.RDPAuth` added to the defaults (23 artifacts).
  - New `-VelociraptorArtifactArgs` for per-artifact arguments; `-VelociraptorArgs` still applies to all.
  - New opt-in `-YaraRules`: runs `Windows.Detection.Yara.Process`, reads the rule parameter name from the build's artifact definition, and copies and hashes the rules file.
- **New opt-in `-DefenderQuarantine`:** copies Defender's quarantine (malware samples). Never enabled by any profile, with a console warning and a loud warning when archiving without a password.

### Changed
- `ProgramData\AnyDesk\*.conf` is no longer copied. `service.conf` can hold the unattended-access password hash and salt; it is now recorded as presence + hash only.
- `logman` added to the table of system binaries called by full path.

## [3.3.1]

### Added
- Velociraptor browser artifacts in the default Full-profile list: `Windows.Applications.Chrome.History`, `Edge.History`, `Chrome.Extensions`, `Firefox.History` and `Firefox.Downloads` (22 artifacts in total). They give a second, independently parsed source of browser history with **UTC** timestamps. `Chrome.Cookies` is deliberately left out.
- User guide section 7.13 **Browser artifacts**: where parsed and raw browser data lands (SQLECmd CSVs, raw profile files, KAPE copies including shadow-copy versions, Velociraptor zips), what each file holds, how to view it, and what is deliberately not collected.

### Fixed
- **Documentation said every timestamp in `Parsed\` is UTC.** The SQLECmd browser CSVs (`ChromiumBrowser_*`, columns ending in `(Local)`) are in the local time of the machine that ran SQLECmd, which is the suspect machine. Sections 7.10, 7.13 and 9.3 now say so, so analysts convert before correlating with UTC artifacts.

## [3.3.0]

### Added
- **Extra internal drives:** automatic discovery of internal disks besides the system drive (bus type SATA, NVMe, SAS, RAID, SCSI, ATA, Storage Spaces or Fibre Channel; USB, SD/MMC, iSCSI and virtual disks excluded; output and toolkit drives excluded; BitLocker-locked volumes skipped).
  - Deep: raw `$MFT`, `$LogFile` and `$Boot`, USN journal, root listing, Recycle Bin `$I` files.
  - Full: deleted-file content (`$R`) and KAPE (`-KapeVolumeTargets`, default `FileSystem,RecycleBin`).
- Parameters `-Volumes`, `-SystemDriveOnly`, `-KapeVolumeTargets`.
- A drive table at the start of the log, and a `Volumes` section in `manifest.json`.
- A warning and prompt when the output folder is on another internal disk.

### Changed
- MFTECmd output now includes the drive letter (`MFT_C.csv`, `Boot_C.csv`).
- RBCmd output is split per drive (`Parsed\RBCmd\<drive>\`).

## [3.2.2]

### Added
- USN journal via `fsutil usn readjournal <drive> csv` (Deep). Timestamps in that CSV are in host local time.

### Fixed
- **SQLECmd parsed nothing:** KAPE's `Maps` folder held old maps with duplicate IDs. It now runs from a de-duplicated working copy and retries without any map it rejects.
- **pagefile, hiberfil and swapfile reported "not present":** `Test-Path` returns False for in-use paging files.
- **Sigcheck CSVs unreadable:** UTF-16 without a byte-order mark is now converted to UTF-8.
- **Sigcheck WARN:** its exit code is the count of matches, not an error.
- **Network collector WARN:** "No matching MSFT_Net…" records from `Get-NetIPConfiguration` are no longer counted as errors.
- **Processes WARN:** `GetOwner` "Not found" for processes that exit mid-collection is no longer counted.
- **Defender WARN:** when the WinDefend service is stopped (0x800106ba), this is recorded as expected.

### Removed
- The RawCopy `$J` target. RawCopy cannot address the `$UsnJrnl:$J` stream.

## [3.2.1]

### Fixed
- **Manifest build failed** ("Argument types do not match"). The manifest is now built field by field, and any field that fails records its own error.
- **Velociraptor failed:** `Windows.KapeFiles.Targets` is no longer built in. It now collects 17 built-in artifacts, one zip each.

## [3.2.0]

### Added
- **About 40 new artifacts:**
  - network extras: port proxies, NetBIOS, neighbors, Wi-Fi profiles
  - IFEO and SilentProcessExit, startup commands, shadow-copy list
  - security settings, certificate stores, stored credential names, Kerberos tickets, local groups, AppX packages, PnP devices
  - WER, Panther, minidumps, Defender detection history, IIS logs, thumbcache, WebCache, notifications, OneDrive logs
  - remote-access tool logs, browser artifacts (no cookies, passwords or autofill)
  - pagefile, hiberfil and swapfile, full Recycle Bin, Windows Search database, MEMORY.DMP, Sigcheck of System32
- **New parsers:** AppCompatCacheParser, SBECmd, RBCmd, WxTCmd, SQLECmd.
- **KAPE:** `!EZParser` modules by default; new `-KapeVss` switch.
- **Tool discovery:** detects .NET builds that can't run and falls back to KAPE's bundled copies; ignores ARM64 builds and prefers x64 over x86.

### Fixed
- **WinPmem command line:** corrected for go-winpmem (`acquire --nosparse`).
- **Shadow copy:** removed before KAPE runs, so it isn't collected twice.
- **Copy notes:** no longer fill up with "0 copied" lines.

## [3.1.0] and earlier

- **3.1.0:**
  - shadow-copy event logs go to `EventLogs\All`, plus a live `wevtutil` export
  - ported the remaining items from the original batch collector
- **3.0.2:** defensive reading of CIM properties, and a try/catch around the manifest build.
- **3.0.1:**
  - the shadow-copy ID is recorded right after creation, so a failed mount no longer leaks a snapshot
  - scheduled-task COM-handler actions are guarded
- **3.0.0:** complete rewrite of v2 as a collector framework.
  - fixed a variable-name collision: PowerShell names are case-insensitive, and `$N` / `$n` clashed

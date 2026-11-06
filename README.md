# Collect_v3: Windows DFIR Live-Response Collector

A single PowerShell script that collects forensic evidence from a live Windows machine, in order of volatility. It drives the standard free DFIR toolset (Sysinternals, Eric Zimmerman's tools, KAPE, Velociraptor, WinPmem / Magnet RAM Capture / DumpIt, RawCopy) and writes a hashed, self-documenting collection: a manifest, per-step results, and SHA-256 hashes of every file.

![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-blue) ![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-informational) ![Version](https://img.shields.io/badge/version-3.4.0-green) ![License: MIT](https://img.shields.io/badge/license-MIT-yellow)

> 🛡️ **A blue-team tool** for incident responders, forensic analysts and researchers. Use it only on systems you own or are authorized to examine. See [Purpose and responsible use](#purpose-and-responsible-use).

---

## Quick start

1. Set up the toolkit drive as described in [Tools/README.md](Tools/README.md).
2. On the target machine, open **PowerShell as Administrator**, go to the toolkit folder, and run:

```powershell
cd X:\Toolkit
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Collect_v3.ps1 -CollectionProfile Full -Memory -CaseId IR-001 -NonInteractive
```

Results go to `X:\Toolkit\Collections\<CaseId>_<COMPUTER>_<UTC time>\`. Use `-OutputPath` to send them elsewhere. **Never write output to the suspect machine's internal disks.**

| Profile | Collects | Typical time |
|---|---|---|
| `Quick` | Volatile state: processes, network, sessions, services, persistence, event-log channel and ETW tampering checks | 2–3 min |
| `Standard` | + shadow copy, registry hives, all event logs, Prefetch, system and security config, Autoruns, driver hashes and loaded kernel modules, WFP filters, Sysmon config, SSH keys, PowerShell transcripts, Mark-of-the-Web | ~10 min |
| `Deep` | + `$MFT`, USN journal, SRUM, LNK / Jump Lists, browser artifacts, all Zimmerman parsers, extra internal drives, RMM tools, IIS, exfiltration-tool search | 30–40 min |
| `Full` | + KAPE, Velociraptor, pagefile / hiberfil, full Recycle Bin, Sigcheck of System32 | 60–100 min |
| `-Memory` | RAM image first (any profile) | ~5 min for 32 GB |

Opt-in extras: `-YaraRules <file.yar>` (process-memory YARA scan, Full), `-LolDriversCsv <file>` (match driver hashes against a local LOLDrivers export) and `-DefenderQuarantine` (copies quarantined **malware samples**; see below).

📖 **The full instructions** (every parameter, what every output folder contains and how to analyze it, and a Timeline Explorer refresher) are in **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)**.

---

## Features

- **Order of volatility:** memory → network → processes → configuration → disk artifacts → parsers.
- **Forensically careful:** refuses to write to the system drive or other internal disks unless explicitly allowed; calls Windows binaries by full path; timestamps in UTC; removes the shadow copy and temporary link it creates, even on Ctrl+C.
- **Chain of custody:** `manifest.json` (script hash, parameters, host, timing, tool inventory, per-step results) and `FileHashes.csv` (SHA-256 of every collected file).
- **Resilient:** each step is isolated and recorded as OK / WARN / FAIL / SKIPPED, so a missing tool or failed step never stops the run.
- **Drive-letter independent:** finds its tools relative to its own location, collects whatever drive Windows is on, and auto-detects extra **internal** disks (USB and virtual disks are excluded).
- **Tamper and BYOVD awareness:** records whether logging was interfered with (disabled or shrunk event-log channels, stopped ETW/AutoLogger sessions, WFP filters blocking security tools) and hashes every driver, including ones loaded with no service entry, ready for LOLDrivers matching.
- **No credentials:** configs that can hold secrets (rclone, ngrok, WinSCP, FileZilla, RMM agents, AnyDesk) are recorded as presence and hash only; SSH private keys, cookies, saved passwords and autofill are never collected.
- **Smart tool handling:** finds tools by file name anywhere under `Tools\`; picks the runnable build (skips .NET builds whose runtime is missing and falls back to KAPE's bundled copies; prefers x64 over x86 and ARM64).

## Requirements

- Windows 10 / 11 / Server 2016+, **Windows PowerShell 5.1**, Administrator rights.
- An external drive with enough free space (Full + Memory on a 32 GB RAM laptop is about 72 GB).
- The third-party tools, which you download yourself (they are **not** included in this repository because their licenses don't allow redistribution). See [Tools/README.md](Tools/README.md).

## Repository layout

```text
.
├── Collect_v3.ps1        # the collector (must stay next to the Tools folder)
├── README.md
├── CHANGELOG.md
├── LICENSE               # MIT
├── docs/
│   ├── USER_GUIDE.md     # full operator guide and output reference
│   └── DEVELOPMENT.md    # architecture, coding rules, testing, known issues
└── Tools/
    └── README.md         # what to download and where to put it (binaries are git-ignored)
```

`Tools/*` (except its README) and `Collections/` are excluded by `.gitignore`, so tool binaries and evidence are never committed.

## Analysis tools

The collection is designed to be opened with **Timeline Explorer** and the other Zimmerman GUI tools, **Volatility 3** / **MemProcFS** for memory, and a **Velociraptor** server for the Velociraptor zips. See section 7 of the [user guide](docs/USER_GUIDE.md).

## Purpose and responsible use

Collect_v3 is built **for defenders**: incident responders, forensic examiners, SOC analysts, students and researchers who need a fast, repeatable and well-documented way to preserve evidence from a Windows machine before it changes or disappears.

**Nothing in it is new offensive capability.** Every technique it uses (memory acquisition, shadow copies, copying locked files such as the registry hives, `$MFT` and event logs) is long-established, publicly documented forensic practice. It is taught in DFIR courses and performed by the freely available tools credited below. The script's contribution is **orchestration and rigor**: running those tools in order of volatility, keeping its footprint on the evidence small, and recording a manifest, hashes and per-step results so the collection holds up to review.

Collecting credential-bearing artifacts such as the SAM and SECURITY hives is a normal and necessary part of an investigation: it's how analysts find rogue accounts, password-change times and evidence of credential theft. Attackers already have far simpler and stealthier ways to get the same data. Withholding these capabilities from defenders protects no one.

**Please use it responsibly:**

- **Authorization:** run it only on systems you own or have written authorization to examine (for example an incident-response engagement, internal investigation, lab or training environment).
- **Coordination:** shadow-copy creation, memory-driver loading and hive copying look like attacker activity to EDR and antivirus products. Tell your SOC before collecting, so the alerts don't trigger a second incident.
- **Handling:** a collection can contain password hashes, personal data, browsing history and full memory contents. Store, transfer and destroy it according to your organization's evidence-handling and privacy policies, and the law in your jurisdiction.
- **`-DefenderQuarantine`:** this opt-in switch copies Defender's quarantine, which means **real malware samples** (RC4-obfuscated with a well-known key, so not directly runnable, but trivially restored). It is never enabled by any profile. Use it only when you need the samples, archive the collection with `-Archive -ArchivePassword`, and store it as malware. The detection metadata is collected without it.
- **`-YaraRules`:** scanning process memory is slow and can trigger EDR alerts. Coordinate with the SOC first.
- **Testing:** test changes on a lab VM before using them on a real case.

## Credits

This project stands on the shoulders of the people who build and maintain the free DFIR tools it orchestrates. **None of these tools are included in this repository.** Download each from its official source and follow its license. If they help you, star their repositories, cite them in your reports and support their work.

| Tool | Created and maintained by | What Collect_v3 uses it for | Official source |
|---|---|---|---|
| **EZ Tools** (EvtxECmd, RECmd, MFTECmd, PECmd, AmcacheParser, AppCompatCacheParser, LECmd, JLECmd, SBECmd, RBCmd, SrumECmd, WxTCmd, SQLECmd, Timeline Explorer) | **Eric Zimmerman** | Parsing every collected artifact into analysis-ready CSV, and viewing it | https://ericzimmerman.github.io |
| **KAPE** (Kroll Artifact Parser and Extractor) | **Eric Zimmerman / Kroll**, with community-maintained Targets and Modules ([KapeFiles](https://github.com/EricZimmerman/KapeFiles)) | Full-profile triage collection and `!EZParser` processing | https://www.kroll.com/kape |
| **Sysinternals Suite** (Autoruns, Handle, ListDlls, LogonSessions, Sigcheck, TCPView) | **Mark Russinovich** and **Bryce Cogswell** (Sysinternals founders), now **Microsoft** | Persistence, open handles, loaded DLLs, logon sessions, signature checks, network connections | https://learn.microsoft.com/sysinternals |
| **Velociraptor** | **Mike Cohen** and the **Velocidex** team (now part of **Rapid7**), with the open-source community | Built-in forensic artifacts collected offline | https://github.com/Velocidex/velociraptor |
| **WinPmem** | **Velocidex** (originally from the Rekall / Google memory-forensics projects) | Memory acquisition (1st choice) | https://github.com/Velocidex/WinPmem |
| **Magnet RAM Capture** | **Magnet Forensics** | Memory acquisition (2nd choice) | https://www.magnetforensics.com/resources/magnet-ram-capture/ |
| **DumpIt** (Comae Toolkit) | **Matt Suiche** (MoonSols, then **Comae Technologies**, founded 2016 and acquired by **Magnet Forensics** in 2022) | Memory acquisition (3rd choice); Hibr2Bin for hibernation files | Magnet Forensics |
| **RawCopy** | **Joakim Schicht** | Copying locked NTFS files (`$MFT`, `$LogFile`, pagefile, hiberfil) | https://github.com/jschicht/RawCopy |
| **7-Zip** | **Igor Pavlov** | Optional encrypted archive of the collection | https://www.7-zip.org |

The user guide also recommends these analysis tools, credited to their authors: **Volatility 3** (The Volatility Foundation), **MemProcFS** (Ulf Frisk), **Hayabusa** (Yamato Security), **Chainsaw** (WithSecure), and **DB Browser for SQLite** (the sqlitebrowser project). Thanks also to **AboutDFIR** (aboutdfir.com) for its Timeline Explorer guide, which section 9 of the user guide draws on.

All product names and trademarks belong to their respective owners. Their mention here doesn't imply endorsement of this project.

## License

Released under the [MIT License](LICENSE). You're free to use, modify and share it, including commercially, as long as the copyright notice is kept. The license covers only this repository's own files, not the third-party tools above, which keep their own licenses.

## Disclaimer

Provided as-is, without warranty of any kind. The authors are not responsible for misuse or for any damage or data loss arising from its use. You are responsible for having legal authority to collect data from any system you run it on.

# Development notes

For anyone (human or AI assistant) changing `Collect_v3.ps1`.

## Architecture

- **Collectors.** Every artifact is registered with `Add-Collector`:
  - `-Phase`: 1–8, order of volatility
  - `-Level`: Quick=1, Standard=2, Deep=3, Full=4
  - `-Name`
  - `-Out` (relative output path) and `-Format`: `Text`, `Csv`, `Json` or `None`
  - optional `-Needs <tool keys>`, `-NeedsVss`, `-OnlyWithoutVss`
- **`Invoke-Collector`** runs each one with timing and error capture, and records OK / WARN / FAIL / SKIPPED:
  - **FAIL** when the action throws.
  - **WARN** for a non-zero exit code or anything left in `$Error`.
  - Expected, harmless errors should be removed from `$Error` inside the collector (see the Processes and Defender collectors) rather than hidden globally.
- **Phases:**

  | Phase | Contents |
  |---|---|
  | 1 | Memory |
  | 2 | Time and network |
  | 3 | Processes, sessions, services, persistence |
  | 4 | System configuration |
  | 5 | Shadow copy and disk copies (plus live fallbacks) |
  | 6 | Slow live tools |
  | 7 | Parsers (run only against collected **copies**) |
  | 8 | KAPE and Velociraptor (the shadow copy is removed first) |

- **External tools** run through `Invoke-External`, which captures stdout/stderr, enforces a hard timeout, converts UTF-16 output to UTF-8 and stores the exit code in `$script:LastExit`.
- **Windows binaries** are called by full path through the `$Exe` table (System32). `PATH` is reset to system directories at start.
- **Tool discovery:** `Find-Tool` searches `Tools\` recursively by file name. It:
  - skips `\arm64\` paths
  - ranks x86 paths last on 64-bit systems
  - uses `Test-ToolRunnable` to skip framework-dependent .NET apps whose runtime major version isn't installed
- **Shadow copy:** created in phase 5 and mounted through a directory symlink under `%SystemRoot%\Temp`, so hashing never walks it. `Copy-VssArtifact` copies from it. `Remove-Vss` is idempotent and runs before phase 8 and in a `finally` block.
- **Extra volumes:** `Get-InternalVolume` uses `Get-Partition` / `Get-Disk` (BusType allowlist), with a `Win32_LogicalDisk` fallback. `$Ctx.ExtraVolumes` holds the drives selected. `Get-NtfsVolumeList` returns the system drive plus the extra NTFS drives.
- **After collection:**
  1. `CollectorResults.csv`
  2. `manifest.json` (built field by field with `Set-ManifestField`) and `manifest.txt`
  3. `Stop-Transcript`
  4. SHA-256 of every file into `FileHashes.csv`
  5. optional archive

## Rules

1. **Forensic soundness first:**
   - never write to the system drive or another internal disk unless `-AllowSystemDrive` is given
   - call host binaries by full path
   - keep all timestamps UTC (or label them clearly, as with the fsutil USN CSV)
   - hash after the transcript closes
   - remove only what the script itself created
2. **Windows PowerShell 5.1 compatibility:**
   - no ternary, `??`, `?.` or `&&`
   - `-Encoding UTF8` writes a BOM
   - `Start-Process` needs `$null = $p.Handle` before `ExitCode` can be read
3. **`Set-StrictMode -Version Latest` is on.** Reading a missing property throws; guard with `PSObject.Properties`.
4. **Variable names are case-insensitive.** `$ToolkitRoot` and `$toolkitRoot` are the same variable. Check for clashes with every new variable. This has caused two bugs.
5. **Large `[ordered]@{}` literals** with many computed values have thrown "Argument types do not match" on PS 5.1. Build dictionaries one statement at a time.
6. **Keep the collector pattern.** Add new artifacts with `Add-Collector`, not as loose top-level code.
7. **Privacy:** don't collect cookies, saved passwords or autofill data.

## Testing

Only on a lab VM or a dedicated test machine. Snapshot the VM first.

1. Parse check:
   ```powershell
   [void][System.Management.Automation.Language.Parser]::ParseFile('.\Collect_v3.ps1',[ref]$null,[ref]$e); $e
   ```
2. Run `Quick`, then `Standard`, `Deep`, and `Full -Memory`.
3. After each run, read `CollectorResults.csv` (filter Status ≠ OK), then `manifest.json`, and spot-check the output files themselves: a step marked OK can still produce empty output.
4. Check that the shadow copy was removed: `vssadmin list shadows`.

## Verification status of third-party command lines

| Tool | Status |
|---|---|
| KAPE 1.3.0.2 (`--tsource --tdest --target --tflush --vss --module --mdest --mflush`) | Verified (full run) |
| Velociraptor 0.77.3 (`artifacts list`, `artifacts collect <name> --output <zip>`) | Verified (17 artifacts; the 5 browser artifacts added in 3.3.1 are in the build list but not yet run) |
| go-winpmem (`acquire --nosparse <file>`) | Verified (33.5 GB image) |
| RawCopy 1.0.0.22 (`/FileNamePath:C:0`, `C:2`, `C:7`, file paths for paging files) | Verified. `$UsnJrnl:$J` is **not** supported. |
| `fsutil usn queryjournal` / `readjournal <drive> csv` | Verified |
| EZ tools (KAPE-bundled .NET Framework builds) | Verified, including the SQLECmd map de-duplication |
| Magnet RAM Capture, DumpIt command lines | **Unverified** (WinPmem is used first) |
| Extra-internal-volume collection | **Unverified**: no test machine with a second internal disk yet |
| `-Archive` / 7-Zip, `-NtpServer` | **Unverified** |

## Known benign output

- `<tool>.err` files containing only a Sysinternals copyright banner.
- `Skipped ...: needs .NET 10.0.0 runtime` during tool discovery, when a KAPE-bundled fallback is found.

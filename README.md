# FoFo Care Sweep (`fcsweep`)

Standalone, zero-dependency, deterministic malware, adware, and browser hijack cleanup CLI for **Windows 10/11** (full scan, fix, verify, undo, harden, and Defender control) and **macOS** (read-only scan).

Free and standalone — every command (`scan`, `triage`, `fix`, `verify`, `undo`, `harden`, `defender`, `sessions`) runs locally with no account, licence check, sign-in, telemetry, or feature gating.

## Core Design Principles

1. **Read-only by default** — `scan` changes nothing on the machine outside its session folder (unless Defender quarantines a confirmed signature threat).
2. **Every change is reversible** — nothing is deleted directly. Files move to an Administrators-only session `quarantine/` folder; registry keys, scheduled tasks, services, WMI subscriptions, policies, hosts entries, exclusions, and certificates are exported to `backups/` and written + flushed (`fsync`) to `manifest.json` *before* each action runs.
3. **Fail closed** — if a backup or manifest write fails, the paired change never executes.
4. **Deterministic first** — fixed weights in [`data/rules.json`](data/rules.json) score every finding 0–100. Optional AI triage is out-of-band and strictly constrained by code rules.
5. **Hostile input isolation** — measured `facts` and attacker-controlled `untrusted` machine strings are kept separate everywhere.
6. **Microsoft engines only** — drives Microsoft Defender in place (`Update-MpSignature`, `Start-MpScan`, `Start-MpWDOScan`) with Authenticode-verified Microsoft Safety Scanner (`msert.exe`) detect-only fallback.

## Commands

| Command | Description | Modifies Machine |
| --- | --- | --- |
| `fcsweep scan` | Preflight, collectors, Defender scan (`--defender quick\|full\|none`), scoring, `report.md` | No |
| `fcsweep triage export` | Exports `review` + `suspicious` findings with sanitized `untrusted` strings to `triage-request.json` | No |
| `fcsweep triage import <file>` | Strictly validates model verdicts, applies fixed tier rules, regenerates `plan.json` & `report.md` | No |
| `fcsweep fix` | Applies approved actions (`--interactive`, `--approve <id,id>`, or `--dry-run`; no `--yes`) | Yes (elevated) |
| `fcsweep verify` | Re-runs collectors and flags any removed items that resurrected | No |
| `fcsweep undo` | Replays `manifest.json` inverses newest-first (whole session or `--item <id>`) | Yes (elevated) |
| `fcsweep harden` | Enables built-in Windows protections (Defender, PUA, Cloud, 4 ASR rules, SmartScreen, Windows Update, `HideFileExt=0`); `--revert` restores prior values | Yes (elevated) |
| `fcsweep defender` | Direct Defender control (`--status`, `--update`, `--quick`, `--full`, `--offline`) | Scan only |
| `fcsweep sessions` | Lists session folders; `--purge` deletes sessions older than 30 days | Purge only |

### Global Flags

`--session <id>` · `--session-root <path>` · `--json` (NDJSON on stdout, human text on stderr) · `--only <c1,c2>` · `--since <days>` (default 30) · `--rules <path>` · `--quiet`

### Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Completed, nothing needs attention |
| `1` | Tool error |
| `2` | Completed, findings need review |
| `3` | Elevation required |
| `4` | Completed, reboot required to finish |
| `5` | Partial: some actions failed |
| `6` | Stop condition hit (ransomware, 2x resurrection, unrecoverable Defender, or malicious boot driver) |

## Quick Start (Manual Cleanup Runbook)

```powershell
# 1. Run an elevated scan
.\fcsweep.exe scan --defender quick

# 2. Review report.md in the printed session folder, then fix interactively
.\fcsweep.exe fix --interactive

# 3. Reboot and verify nothing resurrected
.\fcsweep.exe verify

# 4. Harden Windows built-in protections
.\fcsweep.exe harden

# 5. Undo a specific item (or the entire session) if anything legitimate broke
.\fcsweep.exe undo --item f-0042
```

## Development & Building

```bash
npm install
npm run typecheck
npm test
npm run build        # produces dist/bundle.cjs
npm run build:sea    # produces standalone Node 22 SEA binary (dist/fcsweep or dist/fcsweep.exe)
```

## Release Signing Setup (Sweet Papa Technologies)

CI and signed releases are configured via `.github/workflows/ci.yml` and `.github/workflows/release.yml`:
- **macOS (arm64 & x64):** Apple Developer ID Application + hardened runtime + `notarytool` notarization
- **Windows (x64):** Azure Trusted Signing via GitHub OIDC (`metadata.json` + `scripts/sign-windows.ps1`)

Configure repository secrets/variables/OIDC trust with:

```bash
./scripts/setup-ci.sh --apple --env /path/to/.env
./scripts/setup-ci.sh --azure
./scripts/setup-ci.sh --show
```

Cut a draft signed release by pushing a semver tag on `main`:

```bash
git tag -a v0.1.0 -m "fcsweep v0.1.0"
git push origin v0.1.0
```

# Sysmon Event ID 1 Native Parity Runbook

Status: Tooling Implemented / Bounded Native Live Validation Observed

## 1. Purpose And Boundary

This runbook describes a bounded, manual validation of the implemented Sysmon
Event ID 1 source and parsed-event contracts against a native Windows Event Log
record. Repository tooling is implemented, and a bounded manual live validation
has been observed.

```text
windows-victim01
  Get-WinEvent / ToXml()
  -> local outbox provider-like JSON
  -> manual SCP
soc-analyzer
  local Git-ignored incoming directory
  -> source fixture schema
  -> source parser
  -> parsed-event schema
```

The collector does not sanitize, transfer, parse, execute command text, decode
data, detect activity, or create canonical events. Live JSON, raw XML, EVTX,
runtime identifiers, and runtime values must remain outside Git.

## 2. Prerequisites

- `windows-victim01` has Sysmon running and the
  `Microsoft-Windows-Sysmon/Operational` channel is readable.
- The operator can run PowerShell 5.1 or PowerShell 7.
- The collector script is available on Windows:
  `scripts/windows/sysmon_event1/export_sysmon_event1_provider_json.ps1`.
- The operator has an approved manual file-transfer path to `soc-analyzer`.
- The repository Python development environment is available through `uv`.

If the repository is not present on Windows, manually copy only
`export_sysmon_event1_provider_json.ps1` to a temporary code directory. Do not
copy live output into a repository checkout or fixture directory.

## 3. Generate Controlled Benign Observations

Open PowerShell on Windows and record the start time before generating two
bounded benign process observations:

```powershell
$StartTime = Get-Date

notepad.exe
powershell.exe -NoProfile -Command "Write-Output live-parity-ok"

Start-Sleep -Seconds 2
```

Do not substitute encoded payloads, downloads, network access, malicious
commands, or credential-bearing text.

## 4. Run The Native Collector

Create a local outbox and run the collector:

```powershell
New-Item -ItemType Directory -Force -Path C:\Lab\sysmon-parity\outbox

.\scripts\windows\sysmon_event1\export_sysmon_event1_provider_json.ps1 `
  -OutputDirectory C:\Lab\sysmon-parity\outbox `
  -StartTime $StartTime `
  -MaxEvents 10 `
  -FixtureSlug live-capture `
  -Force
```

Parameters:

- `OutputDirectory` is mandatory and local.
- `StartTime` defaults to ten minutes before invocation.
- `MaxEvents` accepts 1 through 999 and defaults to 20.
- `FixtureSlug` is a lowercase hyphenated slug and defaults to `live-capture`.
- `AllowUnknownEventData` reports unknown field names as warnings but does not
  include their values or add them to output.
- `Force` permits replacement of same-named output files.

Without `AllowUnknownEventData`, an unknown EventData name fails closed.
Duplicate names, unnamed nodes, missing required names, a route mismatch, zero
matching events, and an existing output without `Force` also fail closed.

The collector obtains Event ID 1 with `Get-WinEvent`, sorts by record ID, calls
`ToXml()`, and uses namespace-aware XPath plus each EventData `Name` attribute.
It writes only contracted fields as stable provider-like JSON with UTF-8 and no
BOM. It does not use positional `Event.Properties` indexes.

## 5. Inspect File Names And Counts Only

Do not dump the JSON bodies to the terminal. Inspect only file metadata:

```powershell
Get-ChildItem C:\Lab\sysmon-parity\outbox -Filter *.json |
  Select-Object Name, Length
```

## 6. Prepare A Local-Only Incoming Directory

On `soc-analyzer`:

```bash
cd ~/code/intelligent-soc-lab
mkdir -p data/local/windows/sysmon_event1/native/incoming
chmod 700 data/local/windows/sysmon_event1/native/incoming
```

This repository has no tracked ignore rule dedicated to this workflow. Use the
checkout-local exclude file instead of changing `.gitignore`:

```bash
printf '\n/data/local/windows/sysmon_event1/native/\n' >> .git/info/exclude
git check-ignore -v data/local/windows/sysmon_event1/native/incoming
```

## 7. Transfer Manually

From Windows, transfer only the generated provider-like JSON to the excluded
incoming directory:

```powershell
scp `
  C:\Lab\sysmon-parity\outbox\*.json `
  <SOC_USER>@<SOC_ANALYZER_HOST>:~/code/intelligent-soc-lab/data/local/windows/sysmon_event1/native/incoming/
```

Use operator-approved authentication. Do not place a password, private-key
content, credential, or host-specific key path in this repository. SCP remains
a manual runbook action and is intentionally absent from the collector.

## 8. Verify Git Exclusion Before Validation

After transfer:

```bash
git check-ignore -v data/local/windows/sysmon_event1/native/incoming/*
git status --short --untracked-files=all
```

Stop before validation if any live JSON appears in Git status. Fix the local
exclude configuration first. Never move the files into `tests/fixtures/`,
`docs/`, or another tracked path.

## 9. Validate Source, Parser, And Parsed Shape

Run:

```bash
uv run python scripts/windows/sysmon_event1/validate_sysmon_event1_native_parity.py \
  --input data/local/windows/sysmon_event1/native/incoming
```

The validator processes direct-child `*.json` files in filename order:

```text
JSON parse
  -> source fixture schema
  -> Sysmon Event ID 1 source parser
  -> parsed-event schema
```

Expected safe summary shape:

```text
native-parity-ok: sysmon-event1-live-capture-001.json
  source_schema=ok parser=ok parsed_schema=ok provider_event_id=1 timestamps_equal=false
native-parity-count: 2
```

`timestamps_equal` is informational only. Windows Event Log `system_time` and
Sysmon EventData `utc_time` are validated and preserved independently; exact
equality is not required. Either `timestamps_equal=true` or
`timestamps_equal=false` can be a successful result.

The summary does not print host, user, command line, image, GUID, PID,
EventRecordID, timestamp values, hashes, raw source, or parsed objects.

Passing synthetic repository fixtures through this command verifies tooling
only. It is not evidence of native live parity:

```bash
uv run python scripts/windows/sysmon_event1/validate_sysmon_event1_native_parity.py \
  --input tests/fixtures/windows/sysmon_event1/source
```

## 10. Failure Triage

- `Failed to query Sysmon Event ID 1`: confirm the channel exists, the operator
  has read permission, and Sysmon is running.
- `No Sysmon Event ID 1 records`: confirm the start time, controlled
  observation, and requested time window.
- `Unknown EventData field`: record the field name only and inspect native XML
  locally. Do not paste values into an issue or immediately relax the schema.
- `Missing EventData field`: confirm the field name against the installed
  Sysmon version and local XML.
- `source_schema failed`: review the safe field path and compare the local
  source shape with the contract.
- `parser failed`: review the safe field path; do not dump the source value.
- `parsed_schema failed`: treat it as parser/schema contract drift.
- SCP permission failure: correct the operator account or destination directory
  permissions without storing credentials in the repository.
- Live file visible to Git: stop, correct `.git/info/exclude`, rerun
  `git check-ignore`, and confirm `git status`.

Unknown or missing fields require field-name-level review. They do not
automatically justify schema expansion.

## 11. Cleanup

After recording a value-free result, delete the local runtime files.

On Windows:

```powershell
Remove-Item -LiteralPath C:\Lab\sysmon-parity\outbox -Recurse -Force
```

On `soc-analyzer`:

```bash
find data/local/windows/sysmon_event1/native/incoming \
  -maxdepth 1 -type f -name '*.json' -delete
```

Keep the local exclusion entry if this workflow will be repeated. Do not commit
the exclusion or generated files.

## 12. Evidence Recording

```text
Observed manually on 2026-07-26:
- collector returned 2 Sysmon Event ID 1 records
- unknown EventData warnings: none observed
- source schema: pass for 2/2
- source parser: pass for 2/2
- parsed-event schema: pass for 2/2
- system_time and utc_time were independently valid and were not equal in 2/2
- raw/live artifacts committed: no
```

Do not add hostnames, users, GUIDs, PIDs, EventRecordIDs, timestamps, hashes,
command lines, raw XML, EVTX, or live provider JSON to that summary.

# Windows Slice 2 Correlation Contract

## Scope

Windows Slice 2 validates one distinct multi-event Correlation shape through the
existing common defender correlation boundary. The bounded fixture represents a
PowerShell parent process followed by a PowerShell child process that carries an
encoded-command flag observation.

The slice reuses:

- the existing `endpoint_events.v1` schema;
- the existing PowerShell process and encoded-command observation rules;
- the canonical detection, dedupe, correlation, and exact-ID Incident-selection
  boundaries.

It does not introduce a Windows-specific Incident, Triage, or Investigation
contract.

## Deterministic join

The policy emits `windows_powershell_parent_child_encoded_command` only when all
of the following are true:

1. `powershell_process_observed` and `encoded_command_observed` refer to the
   exact same non-empty child `event_id`, `pid`, `ppid`, host, user, and
   timestamp.
2. A distinct `powershell_process_observed` parent has `pid == child.ppid`.
3. Parent and child have the same host and user.
4. The parent timestamp is not after the child timestamp and the elapsed time is
   at most 60 seconds, inclusively.
5. All referenced timestamps and process identities are present and valid.

The correlation carries both parent and child process detections plus the child
encoded-command detection. This preserves exact supporting-detection IDs for
the existing Incident selection and suppression behavior.

Process-event dedupe uses `event_id` when it is present. Detections without an
event ID retain the previous dedupe key and behavior; PID alone does not create
a new identity contract.

## Fixture and evidence boundary

The curated fixture is
`tests/fixtures/windows/sysmon_event1/slice2/powershell_parent_child_encoded_command.json`.
It is a synthetic normalized defender-side artifact. `SAFE_PLACEHOLDER` is inert
text, not a functional encoded payload.

This fixture supports only deterministic contract and pipeline validation. It
does not establish:

- Sysmon source-fixture or mapper parity for this two-event sequence;
- live Windows, Wazuh, or collector execution;
- malicious intent, successful execution, compromise, or impact;
- persistent identity across runs;
- Windows downstream analytical quality;
- apply, deployment, runtime update, or promotion authorization.

## Done Criteria

This bounded slice is done when:

- canonical detections preserve `event_id`, `pid`, and `ppid`;
- parent and child process observations remain distinct after dedupe;
- the positive fixture produces exactly one deterministic correlation with all
  three supporting detection IDs;
- reversed input is deterministic;
- host, user, PID/PPID, event identity, ordering, missing-data, and time-window
  mismatches do not correlate;
- the inclusive 60-second boundary is tested;
- existing Linux and Windows Slice 1 behavior remains unchanged in the full
  repository regression suite.

The final item is a shared-boundary regression requirement, not a claim of live
or runtime validation.

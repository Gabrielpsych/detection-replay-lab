# detection-replay-lab

Detection content that is not allowed to ship without a replay.

**Altitude:** LAB-NOW. Synthetic telemetry only. Not production coverage. Not an EDR.
**Author:** Gabriel Pokiano

A detection without a true-positive fixture and a benign near-miss is a rumor. This lab stores both next to the rule and fails the suite if either drifts.

## Rule contract

Each rule is declarative YAML: field predicates, MITRE ATT&CK id, severity, and the fixture ids it must hit and must not hit. The matcher supports `equals`, `contains`, `contains_any`, `regex`. No network. No live hunt.

## Detections in this pack

| ID | Behavior | ATT&CK |
| --- | --- | --- |
| DET-001 | Encoded PowerShell download cradle | T1059.001 |
| DET-002 | Cloud metadata SSRF from a workload | T1552.005 |
| DET-003 | Unexpected LSASS access by a non-system process | T1003.001 |
| DET-004 | Scheduled task created with a remote payload | T1053.005 |
| DET-005 | Defender exclusion added then archive dropped | T1562.001 |

## Run

```bash
pip install -r requirements.txt pytest
python -m replay.cli run --rules rules --events fixtures/events.ndjson
pytest -q
```

A green suite means the fixtures match the rules. It does not mean the rules survive a real tenant.

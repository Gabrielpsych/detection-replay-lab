from pathlib import Path
from replay.runner import contract_gaps, load_events, load_rules, run

def test_contracts_hold():
    rules = load_rules(Path("rules"))
    events = load_events(Path("fixtures/events.ndjson"))
    assert contract_gaps(rules, events) == []
    report = run(rules, events)
    assert report["hit_count"] == 5

def test_benign_powershell_does_not_hit_cradle():
    rules = load_rules(Path("rules"))
    events = load_events(Path("fixtures/events.ndjson"))
    hits = run(rules, events)["hits"]
    assert not any(h["rule_id"] == "DET-001" and h["event_id"] == "evt-ps-benign" for h in hits)

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .matcher import match_rule


def load_rules(path: Path) -> list[dict[str, Any]]:
    rules = []
    for file in sorted(path.glob("*.yaml")):
        rules.append(yaml.safe_load(file.read_text(encoding="utf-8")))
    return rules


def load_events(path: Path) -> list[dict[str, Any]]:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def run(rules: list[dict[str, Any]], events: list[dict[str, Any]]) -> dict[str, Any]:
    hits = []
    for rule in rules:
        for event in events:
            if match_rule(rule, event):
                hits.append({"rule_id": rule["id"], "event_id": event.get("id"), "mitre": rule.get("mitre")})
    return {"hit_count": len(hits), "hits": hits}


def contract_gaps(rules: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[str]:
    by_id = {e["id"]: e for e in events}
    gaps = []
    for rule in rules:
        for fid in rule.get("must_hit", []):
            event = by_id.get(fid)
            if event is None or not match_rule(rule, event):
                gaps.append(f"{rule['id']} missed required fixture {fid}")
        for fid in rule.get("must_miss", []):
            event = by_id.get(fid)
            if event is not None and match_rule(rule, event):
                gaps.append(f"{rule['id']} falsely hit fixture {fid}")
    return gaps

"""Small declarative matcher. Not a SIEM."""
from __future__ import annotations

import re
from typing import Any


def match_rule(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    pred = rule.get("match") or {}
    if "all" in pred:
        return all(_one(p, event) for p in pred["all"])
    if "any" in pred:
        return any(_one(p, event) for p in pred["any"])
    return False


def _one(pred: dict[str, Any], event: dict[str, Any]) -> bool:
    value = _get(event, pred["field"])
    if value is None:
        return False
    text = str(value)
    if "equals" in pred:
        return text == str(pred["equals"])
    if "contains" in pred:
        return str(pred["contains"]).lower() in text.lower()
    if "contains_any" in pred:
        low = text.lower()
        return any(str(item).lower() in low for item in pred["contains_any"])
    if "regex" in pred:
        return re.search(pred["regex"], text) is not None
    return False


def _get(event: dict[str, Any], path: str) -> Any:
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur

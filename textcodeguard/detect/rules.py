from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

RULES_PATH = Path(__file__).resolve().parents[1] / "data" / "rules.yaml"


def _line_number_for_match(text: str, match: re.Match[str]) -> int:
    return text.count("\n", 0, match.start()) + 1


def load_rules() -> list[dict[str, Any]]:
    if not RULES_PATH.exists():
        return []
    with RULES_PATH.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    return payload.get("rules", [])


def evaluate_rules(code: str, language: str) -> list[tuple[int, str, float, str]]:
    findings: list[tuple[int, str, float, str]] = []
    for rule in load_rules():
        rule_language = str(rule.get("language", "")).lower()
        if rule_language and rule_language != language:
            continue
        pattern = rule.get("pattern")
        if not pattern:
            continue
        regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        for match in regex.finditer(code):
            findings.append((_line_number_for_match(code, match), str(rule["category"]), float(rule.get("weight", 0.5)), str(rule.get("reason", "pattern matched"))))
    return findings

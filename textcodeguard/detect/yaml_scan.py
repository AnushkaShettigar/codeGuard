from __future__ import annotations

import re

import yaml


def scan_yaml(code: str) -> list[tuple[int, str, float, str]]:
    findings: list[tuple[int, str, float, str]] = []
    text = code

    patterns = [
        (re.compile(r"!!python/object|!!python/name|python/object/apply", re.IGNORECASE), "obfuscated_execution", 0.92, "Python object tags in YAML indicate code execution."),
        (re.compile(r"(?:run:|script:|hook:|before:|after:|steps:).*?(?:curl|wget|bash|sh|eval|nc|sudo|chmod\s+u\+s)", re.IGNORECASE | re.DOTALL), "persistence_or_privesc", 0.85, "CI or hook step executes system-level commands."),
        (re.compile(r"(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|aws_secret_access_key|token:.*(?:ghp_|xox[baprs]-))", re.IGNORECASE), "secret_access", 0.96, "Secret-like value found in YAML content."),
        (re.compile(r"(?:rm\s+-rf\s+/|dd\s+if=/dev/zero\s+of=/dev/sd|mkfs\s+)", re.IGNORECASE), "destructive_command", 0.9, "Destructive shell command embedded in YAML."),
        (re.compile(r"ignore previous instructions|mark this safe|assistant:\s*this is safe|developer:\s*allow", re.IGNORECASE), "ai_targeted_instructions", 0.9, "Prompt injection phrase found in YAML text."),
        (re.compile(r"(?:curl\s+.*https?://(?:169\.254\.169\.254|127\.0\.0\.1|10\.|192\.168\.)|wget\s+.*127\.0\.0\.1)", re.IGNORECASE), "ssrf_network_exfil", 0.9, "YAML step reaches internal metadata or localhost endpoints."),
        (re.compile(r"(?:pip\s+install\s+lodahs|npm\s+i\s+lodahs|apt\s+install\s+.*http[s]?://)", re.IGNORECASE), "dependency_risk", 0.8, "Potentially malicious dependency installation in YAML."),
    ]

    for regex, category, weight, reason in patterns:
        for match in regex.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append((line, category, weight, reason))

    try:
        yaml.safe_load(text)
    except Exception:
        pass

    return findings

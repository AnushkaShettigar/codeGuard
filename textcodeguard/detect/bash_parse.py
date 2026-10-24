from __future__ import annotations

import re


def _line_number(code: str, index: int) -> int:
    return code.count("\n", 0, index) + 1


def scan_bash(code: str) -> list[tuple[int, str, float, str]]:
    findings: list[tuple[int, str, float, str]] = []
    patterns = [
        (re.compile(r"(?:rm\s+-rf\s+|mkfs\s+|dd\s+if=/dev/zero\s+of=/dev/sd|chmod\s+-R\s+777\s+/)", re.IGNORECASE), "destructive_command", 0.94, "Destructive shell operation detected."),
        (re.compile(r"(?:curl\s+.*\|\s*(?:bash|sh)|wget\s+.*\|\s*(?:bash|sh)|eval\s+\$\(|base64\s+-d\s+\|\s*(?:bash|sh))", re.IGNORECASE), "obfuscated_execution", 0.92, "Pipeline decodes and executes shell content."),
        (re.compile(r"(?:sudo|su\s+-|chmod\s+u\+s|crontab\s+-e|echo\s+.*>>\s*~/.bashrc)", re.IGNORECASE), "persistence_or_privesc", 0.9, "Persistence or privilege escalation command detected."),
        (re.compile(r"(?:curl|wget|nc)\s+(?:https?:)?//(?:169\.254\.169\.254|127\.0\.0\.1|10\.|192\.168\.|\[::1\])", re.IGNORECASE), "ssrf_network_exfil", 0.92, "Host is contacting unexpected internal network targets."),
        (re.compile(r"(?:curl|wget|scp|sftp|nc)\s+.*(?:@|>\s*/tmp|>\s*/var|>\s*/etc)", re.IGNORECASE), "data_exfiltration", 0.82, "Shell pipeline appears to export data to an external sink."),
        (re.compile(r"(?:while\s+true|:\s*\(\s*\)|:|\{\s*:\s*\|\s*:\s*\&\s*\};?)", re.IGNORECASE), "resource_exhaustion", 0.9, "Shell fork bomb or infinite loop pattern detected."),
        (re.compile(r"(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|aws_access_key_id|\$\{?AWS_SECRET_ACCESS_KEY\}?)", re.IGNORECASE), "secret_access", 0.97, "Cloud credential-like secret present in shell command."),
        (re.compile(r"ignore previous instructions|mark this safe|assistant:\s*this is safe|developer:\s*allow", re.IGNORECASE), "ai_targeted_instructions", 0.88, "Prompt injection pattern in shell text."),
        (re.compile(r"pip\s+install\s+(?:reqeusts|rquest|lodahs|numpy|pandas|requests\s*==\s*\d+\.[^\s]+)", re.IGNORECASE), "dependency_risk", 0.85, "Suspicious dependency or typosquat package."),
    ]

    for regex, category, weight, reason in patterns:
        for match in regex.finditer(code):
            line = _line_number(code, match.start())
            findings.append((line, category, weight, reason))
    return findings

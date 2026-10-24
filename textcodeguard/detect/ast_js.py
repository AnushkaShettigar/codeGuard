from __future__ import annotations

import re


def _line_number(code: str, index: int) -> int:
    return code.count("\n", 0, index) + 1


def scan_js(code: str) -> list[tuple[int, str, float, str]]:
    findings: list[tuple[int, str, float, str]] = []
    patterns = [
        (
            re.compile(r"process\.env\.(?:AWS_|GCP_|AZURE_|SECRET|TOKEN|KEY)|process\.env\[\s*['\"](?:AWS_|GCP_|AZURE_|SECRET|TOKEN|KEY)", re.IGNORECASE),
            "secret_access",
            0.96,
            "Reference to secret-bearing environment variables.",
        ),
        (
            re.compile(r"fetch\s*\(\s*['\"](?:https?:)?//(?:169\.254\.169\.254|127\.0\.0\.1|10\.|192\.168\.|\[::1\])", re.IGNORECASE),
            "ssrf_network_exfil",
            0.92,
            "Fetch targets an internal or metadata endpoint.",
        ),
        (
            re.compile(r"eval\s*\(|new\s+Function\s*\(|atob\s*\(|setTimeout\s*\(\s*['\"][^'\"]*['\"]\s*,\s*0\)", re.IGNORECASE),
            "obfuscated_execution",
            0.9,
            "Dynamic code evaluation or decode-and-run pattern.",
        ),
        (
            re.compile(r"(?:rm\s+-rf|mkfs|dd\s+if=/dev/zero|chmod\s+-R\s+777\s+/)", re.IGNORECASE),
            "destructive_command",
            0.9,
            "Destructive command pattern found.",
        ),
        (
            re.compile(r"(?:curl|wget|fetch)\s+.*(?:\|\s*(?:bash|sh)|base64\s+-d|FormData|sendBeacon)", re.IGNORECASE),
            "data_exfiltration",
            0.82,
            "Script appears to send local data to a remote sink.",
        ),
        (
            re.compile(r"ignore previous instructions|mark this safe|assistant:\s*this is safe|developer:\s*allow", re.IGNORECASE),
            "ai_targeted_instructions",
            0.9,
            "Prompt injection text detected.",
        ),
        (
            re.compile(r"(?:npm\s+i\s+|yarn\s+add\s+|pnpm\s+add\s+)(?:lodahs|reqeusts|rquest)", re.IGNORECASE),
            "dependency_risk",
            0.8,
            "Suspicious dependency or typosquat install detected.",
        ),
        (
            re.compile(r"while\s*\(\s*true\s*\)|setInterval\s*\(|for\s*\(\s*;;\s*\)", re.IGNORECASE),
            "resource_exhaustion",
            0.9,
            "Busy loop or scheduler storm detected.",
        ),
    ]

    for regex, category, weight, reason in patterns:
        for match in regex.finditer(code):
            line = _line_number(code, match.start())
            findings.append((line, category, weight, reason))
    return findings

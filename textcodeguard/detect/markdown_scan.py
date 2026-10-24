from __future__ import annotations

import re


def _line_number(code: str, index: int) -> int:
    return code.count("\n", 0, index) + 1


def scan_markdown(code: str) -> list[tuple[int, str, float, str]]:
    findings: list[tuple[int, str, float, str]] = []
    snippets = [code]
    for match in re.finditer(r"```(?:\w+)?\n(.*?)```", code, re.DOTALL):
        snippets.append(match.group(1))

    patterns = [
        (re.compile(r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]+)", re.IGNORECASE), "secret_access", 0.96, "Credential-like token appears in markdown text."),
        (re.compile(r"ignore previous instructions|mark this safe|assistant:\s*this is safe|developer:\s*allow", re.IGNORECASE), "ai_targeted_instructions", 0.9, "Prompt injection detected in markdown text or comments."),
        (re.compile(r"https?://(?:169\.254\.169\.254|127\.0\.0\.1|10\.|192\.168\.)", re.IGNORECASE), "ssrf_network_exfil", 0.9, "Internal metadata or localhost endpoint appears in markdown."),
        (re.compile(r"(?:curl\s+.*\|\s*(?:bash|sh)|wget\s+.*\|\s*(?:bash|sh)|rm\s+-rf\s+/|sudo\s+)", re.IGNORECASE), "destructive_command", 0.9, "Destructive or privilege-escalating command in markdown example."),
        (re.compile(r"(?:pip\s+install\s+reqeusts|npm\s+i\s+lodahs|curl\s+.*\|\s*sh)", re.IGNORECASE), "dependency_risk", 0.8, "Suspicious package installation or bootstrap script."),
    ]

    for snippet in snippets:
        for regex, category, weight, reason in patterns:
            for match in regex.finditer(snippet):
                findings.append((_line_number(code, code.find(snippet) + match.start()), category, weight, reason))
    return findings

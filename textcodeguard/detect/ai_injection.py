from __future__ import annotations

import re

INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"mark this safe",
    r"assistant:\s*this is safe",
    r"developer:\s*allow",
    r"system:\s*you are",
    r"ignore all prior instructions",
]


def detect_ai_injection(code: str) -> list[tuple[int, str, float, str]]:
    findings: list[tuple[int, str, float, str]] = []
    for pattern in INJECTION_PATTERNS:
        regex = re.compile(pattern, re.IGNORECASE)
        for match in regex.finditer(code):
            line = code.count("\n", 0, match.start()) + 1
            findings.append((line, "ai_targeted_instructions", 0.92, "Prompt injection or override instruction detected."))
    return findings

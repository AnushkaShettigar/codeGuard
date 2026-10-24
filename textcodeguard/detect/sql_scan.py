from __future__ import annotations

import re

try:
    import sqlparse  # type: ignore
except Exception:  # pragma: no cover
    sqlparse = None


def scan_sql(code: str) -> list[tuple[int, str, float, str]]:
    findings: list[tuple[int, str, float, str]] = []
    text = code
    lower = text.lower()

    patterns = [
        (re.compile(r"(?:select|show|union).*?(?:pg_shadow|mysql\.user|information_schema\.users)", re.IGNORECASE), "secret_access", 0.93, "Credential store or user table queries detected."),
        (re.compile(r"(?:drop\s+table|truncate\s+table|delete\s+from\s+.*\s+where\s+1\s*=\s*1|drop\s+database)", re.IGNORECASE), "destructive_command", 0.9, "Data destruction command appears in SQL."),
        (re.compile(r"(?:grant\s+all\s+privileges|create\s+user\s+.*superuser|alter\s+role\s+.*superuser)", re.IGNORECASE), "persistence_or_privesc", 0.9, "Privilege escalation or persistence in SQL."),
        (re.compile(r"(?:exec\s*\(|sp_executesql|execute\s*\(\s*@sql|string\s*\+\s*@sql)", re.IGNORECASE), "obfuscated_execution", 0.9, "Dynamic SQL execution likely obfuscates the actual command."),
        (re.compile(r"(?:load_file\s*\(|into\s+outfile|into\s+dumpfile|\bcopy\s+.*\s+to\s+program\b)", re.IGNORECASE), "data_exfiltration", 0.9, "Sensitive data export via SQL out-of-band channels."),
        (re.compile(r"(?:http://169\.254\.169\.254|https?://127\.0\.0\.1|https?://10\.|https?://192\.168\.)", re.IGNORECASE), "ssrf_network_exfil", 0.9, "Internal network endpoint in SQL text."),
        (re.compile(r"ignore previous instructions|mark this safe|assistant:\s*this is safe|developer:\s*allow", re.IGNORECASE), "ai_targeted_instructions", 0.9, "Prompt injection phrase found in SQL comment or string."),
        (re.compile(r"(?:with\s+recursive|union\s+all\s+select\s+.*\s+from\s+.*)\s*", re.IGNORECASE), "resource_exhaustion", 0.75, "Potentially unbounded recursive or large join query detected."),
    ]

    for regex, category, weight, reason in patterns:
        for match in regex.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append((line, category, weight, reason))

    if sqlparse is not None:
        try:
            parsed = sqlparse.parse(text)
            for statement in parsed:
                normalized = statement.normalized
                if re.search(r"\b(xp_cmdshell|sp_executesql)\b", normalized, re.IGNORECASE):
                    findings.append((1, "obfuscated_execution", 0.9, "Command shell execution via SQL stored procedure."))
        except Exception:
            pass

    return findings

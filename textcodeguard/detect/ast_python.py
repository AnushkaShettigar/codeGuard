from __future__ import annotations

import ast
import difflib
import re

PROMPT_RE = re.compile(r"ignore previous instructions|mark this safe|system:\s*you are|developer:\s*allow|assistant:\s*this is safe", re.IGNORECASE)
SECRET_ENV_RE = re.compile(r"(?:AWS|GCP|AZURE|SECRET|TOKEN|KEY|PASSWORD|ACCESS|PRIVATE|SESSION)[A-Z0-9_]*", re.IGNORECASE)


def _add(findings: list[tuple[int, str, float, str]], lineno: int, category: str, weight: float, reason: str) -> None:
    findings.append((lineno, category, weight, reason))


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _matches_file_path(value: str) -> bool:
    return bool(re.search(r"(\.env|id_rsa|\.aws|credentials|\.npmrc|authorized_keys|\.ssh|cron|\.bashrc|\.profile|\.ssh/authorized_keys)", value, re.IGNORECASE))


def _contains_break(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Break):
            return True
    return False


def scan_python_ast(code: str) -> list[tuple[int, str, float, str]]:
    findings: list[tuple[int, str, float, str]] = []

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in {"eval", "exec", "compile"}:
                _add(findings, getattr(node, "lineno", 1), "obfuscated_execution", 0.92, f"Dynamic execution via {name}() detected.")
            if name == "__import__":
                _add(findings, getattr(node, "lineno", 1), "obfuscated_execution", 0.88, "Dynamic import detected.")
            if name in {"os.system", "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "Popen", "run"}:
                if node.args and any(isinstance(arg, ast.Constant) and isinstance(arg.value, str) and re.search(r"(rm\s+-rf|curl\s+.*\|\s*sh|base64\s+-d|nc\s+|sudo|chmod\s+u\+s)", arg.value, re.I) for arg in node.args):
                    _add(findings, getattr(node, "lineno", 1), "destructive_command", 0.9, f"Dangerous command execution via {name}.")
                if name in {"subprocess.run", "Popen", "run"} and any(isinstance(k, ast.keyword) and k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                    _add(findings, getattr(node, "lineno", 1), "destructive_command", 0.82, "Shell execution enabled with subprocess.")
            if name in {"open", "pathlib.Path.open"}:
                first_arg = node.args[0] if node.args else None
                mode = node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) else None
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str) and _matches_file_path(first_arg.value):
                    category = "secret_access" if any(token in first_arg.value.lower() for token in (".env", ".aws", "credentials", "id_rsa", ".npmrc", ".ssh")) else "persistence_or_privesc"
                    _add(findings, getattr(node, "lineno", 1), category, 0.93, "Sensitive or persistence-related file path opened.")
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str) and re.search(r"(/etc/cron|/var/spool/cron|\.bashrc|\.profile|authorized_keys|/etc/sudoers)", first_arg.value, re.IGNORECASE):
                    _add(findings, getattr(node, "lineno", 1), "persistence_or_privesc", 0.94, "Persistence file path is being written.")
            if name in {"requests.post", "requests.get", "urllib.request.urlopen", "httpx.get", "httpx.post"}:
                if any(isinstance(arg, ast.Constant) and isinstance(arg.value, str) and re.search(r"169\.254\.169\.254|127\.0\.0\.1|10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.|\[::1\]", arg.value) for arg in node.args):
                    _add(findings, getattr(node, "lineno", 1), "ssrf_network_exfil", 0.92, "Internal network target used in HTTP call.")
            if name in {"subprocess.run", "subprocess.Popen", "subprocess.call", "Popen", "run"}:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and re.search(r"(rm\s+-rf\s+/|shutdown|reboot|mkfs\s+|dd\s+if=/dev/zero\s+of=/dev/sd)", arg.value, re.I):
                        _add(findings, getattr(node, "lineno", 1), "destructive_command", 0.92, "Dangerous system command executed.")

        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
                if isinstance(node.value.value, ast.Name) and node.value.value.id == "os":
                    if isinstance(node.ctx, ast.Subscript):
                        pass
            if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
                pass

        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name) and node.value.value.id == "os" and node.value.attr == "environ":
                key = None
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    key = node.slice.value
                elif isinstance(node.slice, ast.Index):
                    index = node.slice.value
                    if isinstance(index, ast.Constant) and isinstance(index.value, str):
                        key = index.value
                if key and SECRET_ENV_RE.search(key):
                    _add(findings, getattr(node, "lineno", 1), "secret_access", 0.95, "Access to a secret-bearing environment variable.")

        if isinstance(node, ast.While):
            if isinstance(node.test, ast.Constant) and node.test.value is True and not _contains_break(node):
                _add(findings, getattr(node, "lineno", 1), "resource_exhaustion", 0.9, "Infinite loop without a break condition detected.")

        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                known = {"os", "subprocess", "requests", "urllib", "yaml", "pathlib", "shutil"}
                if name not in known and len(name) > 4:
                    for safe_name in known:
                        if difflib.SequenceMatcher(None, name, safe_name).ratio() >= 0.82:
                            _add(findings, getattr(node, "lineno", 1), "dependency_risk", 0.7, f"Typosquat import {name!r} resembles {safe_name!r}.")

        if isinstance(node, (ast.Constant, ast.JoinedStr)):
            value = None
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
            elif isinstance(node, ast.JoinedStr):
                parts = []
                for v in node.values:
                    if isinstance(v, ast.Constant) and isinstance(v.value, str):
                        parts.append(v.value)
                value = "".join(parts)
            if value:
                if PROMPT_RE.search(value):
                    _add(findings, getattr(node, "lineno", 1), "ai_targeted_instructions", 0.9, "Prompt injection text is embedded in a literal string.")
                if re.search(r"os\.system\s*\(|subprocess\.(?:run|Popen|call)\s*\(|rm\s+-rf\s+/|curl\s+.*\|\s*(?:bash|sh)|base64\s+-d", value, re.IGNORECASE):
                    _add(findings, getattr(node, "lineno", 1), "destructive_command", 0.92, "Dangerous command string embedded in a literal value.")

    for node in ast.walk(tree):
        if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript, ast.Constant)):
            continue

    return findings

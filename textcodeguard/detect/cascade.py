from __future__ import annotations

from typing import Any

from ..schema import CheckResponse
from .ai_injection import detect_ai_injection
from .ast_js import scan_js
from .ast_python import scan_python_ast
from .bash_parse import scan_bash
from .language import detect_language
from .markdown_scan import scan_markdown
from .ml_classifier import ml_ambiguous_score
from .rules import evaluate_rules
from .sql_scan import scan_sql
from .yaml_scan import scan_yaml


def _combine_score(weights: list[float]) -> float:
    if not weights:
        return 0.0
    score = 1.0
    for weight in weights:
        score *= 1.0 - weight
    return 1.0 - score


def _severity_reason(findings: list[tuple[int, str, float, str]]) -> str:
    categories: list[str] = []
    for _, category, _, reason in findings:
        if category not in categories:
            categories.append(category)
    if not categories:
        return "No suspicious patterns detected."
    return "; ".join(f"{category}: {reason}" for _, category, _, reason in findings[:3])


def cascade_scan(code: str) -> CheckResponse:
    language = detect_language(code)
    findings: list[tuple[int, str, float, str]] = []
    findings.extend(evaluate_rules(code, language))

    if language == "python":
        findings.extend(scan_python_ast(code))
    elif language == "javascript":
        findings.extend(scan_js(code))
    elif language == "bash":
        findings.extend(scan_bash(code))
    elif language == "markdown":
        findings.extend(scan_markdown(code))
    elif language == "yaml":
        findings.extend(scan_yaml(code))
    elif language == "sql":
        findings.extend(scan_sql(code))

    findings.extend(detect_ai_injection(code))

    if 0.3 < _combine_score([weight for _, _, weight, _ in findings]) < 0.7:
        ml_score, ml_categories = ml_ambiguous_score(code, language)
        if ml_score > 0.4:
            findings.append((1, ml_categories[0] if ml_categories else "ai_targeted_instructions", min(0.95, ml_score), "Local ML model flagged ambiguous content."))

    distinct = sorted({(line, category, weight, reason) for line, category, weight, reason in findings}, key=lambda item: (item[0], item[1]))
    categories = sorted({category for _, category, _, _ in distinct})
    weights = [weight for _, _, weight, _ in distinct]
    risk_score = min(1.0, _combine_score(weights))
    verdict = "block" if any(weight >= 0.8 for _, _, weight, _ in distinct) or risk_score >= 0.6 else "allow"
    lines = sorted({line for line, _, _, _ in distinct})
    reason = _severity_reason(distinct) if distinct else "No suspicious patterns detected."
    return CheckResponse(
        verdict=verdict,
        risk_score=round(risk_score, 3),
        categories=categories,
        code_language=language,
        reason=reason,
        vulnerable_lines=lines,
    )

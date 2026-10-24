# CodeGuard

CodeGuard is a lightweight, local safety layer that intercepts code before execution. It runs a rule-based cascade (regex + AST + language-aware checks) and can optionally use a local ML model when present, but it never calls an external LLM or networked model at inference time.

## Architecture

```text
User code / API request
        |
        v
+----------------------------+
| FastAPI /check + /batch    |
| Request schema validation  |
+-------------+--------------+
              |
              v
+----------------------------+
| guard()                    |
|  - detect language         |
|  - regex rules            |
|  - Python AST / Bash / JS |
|  - markdown / YAML / SQL  |
|  - optional local ML      |
+-------------+--------------+
              |
              v
+----------------------------+
| verdict                    |
| verdict / risk_score       |
| categories / reason        |
| vulnerable_lines           |
+----------------------------+
```

## Components and licenses

- Python standard library: Python Software Foundation License
- FastAPI: MIT License
- Pydantic: MIT License
- PyYAML: MIT License
- SQLParse: BSD-3-Clause
- uvicorn: BSD-3-Clause
- gradio: Apache-2.0
- tree-sitter (optional future parser): MIT
- scikit-learn (optional local model): BSD-3-Clause
- esprima (optional JS frontend parser): BSD-2-Clause

## Detection categories

CodeGuard enforces the nine required categories:

1. secret_access
2. data_exfiltration
3. destructive_command
4. persistence_or_privesc
5. obfuscated_execution
6. dependency_risk
7. resource_exhaustion
8. ssrf_network_exfil
9. ai_targeted_instructions

## Recommended deployment model

- CPU-only, no inference-time network calls.
- Rule-first pipeline for sub-150 ms fast path.
- Local model only when a model exists in `models/` and the score is ambiguous.
- Safe defaults: if the model is absent, code still runs through regex + AST + language scanners without failure.

## Latency expectations

| Path | Typical cost | Notes |
|---|---:|---|
| Regex + YAML rules | 5-15 ms | Cached rules loaded once |
| AST + language-specific scanners | 10-35 ms | Dominant on Python/JS |
| Optional ML (quiet path) | 0 ms | No model = skipped |
| End-to-end p95 | <150 ms | On a modern laptop for short snippets |

## Interception proof

The demo guard wrapper prevents execution by raising `GuardBlocked` before the function body is called. In `demo/intercept_check.py`, the `safe_marker()` function writes a marker file, while `unsafe_marker()` contains a blocked command string but is intentionally never executed. The demonstration asserts:

- `marker_safe.txt` exists
- `marker_unsafe.txt` does not exist
- `GuardBlocked` is raised

This proves the decorator is a real execution interception layer and not a passive log warning.

## Known limitations

- The static analysis is deterministic and deliberately conservative; it may flag some benign shell commands.
- JS and YAML detection rely on regex/heuristic parsing rather than full semantic parsing.
- A local ML model is optional; without a model, the system still operates with a rule-first safety cascade.
- Markdown and YAML scanners are best-effort and should be tightened with richer parsers in a production version.

## Quick start

```bash
python -m pip install -r textcodeguard/requirements.txt
python -m pytest textcodeguard/tests/test_categories.py
```

Use the API:

```bash
uvicorn textcodeguard.api:app --host 0.0.0.0 --port 8000
```

Then call:

```bash
curl -X POST http://localhost:8000/check \
  -H "Content-Type: application/json" \
  -d '{"code": "import os\nprint(os.environ[\"AWS_SECRET_ACCESS_KEY\"])"}'
```

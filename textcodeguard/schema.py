from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CodeLanguage = Literal["python", "bash", "javascript", "markdown", "yaml", "sql", "unknown"]
Verdict = Literal["allow", "block"]


class CheckRequest(BaseModel):
    code: str

    model_config = ConfigDict(extra="forbid")


class CheckResponse(BaseModel):
    verdict: Verdict
    risk_score: float = Field(..., ge=0.0, le=1.0)
    categories: list[str]
    code_language: CodeLanguage
    reason: str
    vulnerable_lines: list[int] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class BatchItem(BaseModel):
    code: str

    model_config = ConfigDict(extra="forbid")

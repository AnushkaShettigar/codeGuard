from __future__ import annotations

import inspect
from functools import wraps
from typing import Any, Callable, TypeVar

from .detect.cascade import cascade_scan

F = TypeVar("F", bound=Callable[..., Any])


class GuardBlocked(RuntimeError):
    """Raised when a guarded function is considered unsafe."""


def guard(code: str) -> dict[str, Any]:
    """Return the schema-compliant result for a code snippet."""
    return cascade_scan(code).model_dump()


def guarded(fn: F) -> F:
    """Decorator that blocks execution when the source is rejected by CodeGuard."""

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            source = inspect.getsource(fn)
        except (OSError, TypeError):
            source = fn.__name__
        verdict = guard(source)
        if verdict["verdict"] == "block":
            raise GuardBlocked(verdict["reason"])
        return fn(*args, **kwargs)

    return wrapper  # type: ignore[return-value]

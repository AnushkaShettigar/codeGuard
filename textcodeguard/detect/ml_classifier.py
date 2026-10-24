from __future__ import annotations

from pathlib import Path
from typing import Any


class LazyLocalClassifier:
    def __init__(self) -> None:
        self._model: Any | None = None
        self._loaded = False

    def _load(self) -> Any | None:
        if self._loaded:
            return self._model
        model_dir = Path(__file__).resolve().parents[1] / "models"
        if not model_dir.exists():
            self._loaded = True
            self._model = None
            return None

        candidates = []
        for pattern in ("*.pkl", "*.joblib", "*.onnx"):
            candidates.extend(model_dir.glob(pattern))
        if not candidates:
            self._loaded = True
            self._model = None
            return None

        try:
            import joblib  # type: ignore

            self._model = joblib.load(str(candidates[0]))
        except Exception:
            self._model = None
        self._loaded = True
        return self._model

    def score(self, code: str, language: str) -> tuple[float, list[str]]:
        model = self._load()
        if model is None:
            return 0.0, []
        try:
            if hasattr(model, "predict_proba"):
                prediction = model.predict_proba([[len(code), len(language)]])[0]
                if hasattr(prediction, "tolist"):
                    prediction = prediction.tolist()
                score = float(max(prediction)) if prediction else 0.0
                return score, []
        except Exception:
            pass
        return 0.0, []


_lazy_classifier = LazyLocalClassifier()


def ml_ambiguous_score(code: str, language: str) -> tuple[float, list[str]]:
    return _lazy_classifier.score(code, language)

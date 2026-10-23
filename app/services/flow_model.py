"""Optional live CNN-LSTM scoring for complete CICIDS2017 flow vectors."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class LiveFlowModel:
    """Lazy model adapter that preserves shadow-mode safety."""

    def __init__(self, mode: str = "shadow") -> None:
        if mode not in {"shadow", "advisory"}:
            raise ValueError("flow model mode must be shadow or advisory")
        self.mode = mode
        self._predictor: Any = None

    def __call__(self, request: Any) -> dict[str, Any] | None:
        features = request.metadata.get("flow_features", [])
        if not isinstance(features, (list, tuple)) or len(features) != 52:
            return None
        if self._predictor is None:
            from ml.cnn_lstm.predict import IntrusionPredictor

            self._predictor = IntrusionPredictor()
        result = self._predictor.predict_sample(list(features))
        result["mode"] = self.mode
        logger.info(
            "Live flow model result: prediction=%s confidence=%s mode=%s",
            result.get("prediction"),
            result.get("confidence_pct"),
            self.mode,
        )
        return result

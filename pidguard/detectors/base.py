"""Detector interface. Every detector is a pure function of (text, report)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from ..types import Detection, NormalizationReport


class Detector(ABC):
    """Base class for all detection strategies.

    Contract: `scan` must be side-effect free and must never raise -- a
    crashing detector must degrade the ensemble, not the agent. `Ensemble`
    enforces this, but detectors should still fail closed on their own.
    """

    name: str = "detector"
    #: relative contribution of this detector to the fused risk score
    fusion_weight: float = 1.0

    @abstractmethod
    def scan(self, text: str, report: NormalizationReport | None = None) -> List[Detection]:
        ...

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<{type(self).__name__} w={self.fusion_weight}>"

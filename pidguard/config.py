"""Runtime configuration, loaded from the calibration produced by training.

Every threshold in this system is a tunable, and every tunable was fitted on a
validation split -- never on the test split and never by eye. `calibration.json`
is the artefact that records the chosen operating point, so a deployment can be
reproduced and a reviewer can see exactly what was tuned.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict

CALIBRATION_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "models", "calibration.json")

#: Used when no calibration file is present (fresh checkout, before training).
DEFAULTS: Dict[str, Any] = {
    "statistical_threshold": 0.60,
    "semantic_threshold": 0.55,
    "window_chars": 320,
    "concentration_bonus": 0.18,
    "window_penalty": 0.06,
    "solo_penalty": 0.55,
    "sanitize_threshold": 0.35,
    "block_threshold": 0.62,
    "lr_epochs": 40,
    "lr_l2": 1e-4,
    "lr_rate": 0.5,
}

_cache: Dict[str, Any] | None = None


def load(path: str = CALIBRATION_PATH) -> Dict[str, Any]:
    """Return the calibrated settings, falling back to DEFAULTS per key."""
    global _cache
    if _cache is not None:
        return _cache
    settings = dict(DEFAULTS)
    try:
        with open(path, encoding="utf-8") as fh:
            settings.update(json.load(fh).get("settings", {}))
    except (OSError, ValueError):
        pass                      # uncalibrated is a valid, documented state
    _cache = settings
    return settings


def get(key: str) -> Any:
    return load()[key]


def save(path: str, settings: Dict[str, Any], report: Dict[str, Any]) -> None:
    """Write the calibration artefact (settings + the evidence behind them)."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"settings": settings, "validation_report": report}, fh, indent=2)
    global _cache
    _cache = None


def reset_cache() -> None:
    global _cache
    _cache = None

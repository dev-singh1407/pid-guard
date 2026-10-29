"""Append-only audit trail.

A security control that cannot explain itself will be switched off the first
time it inconveniences someone. Every decision -- including ALLOW -- is
recorded with the evidence that produced it, so an incident can be
reconstructed and a false positive can be argued about with data.
"""

from __future__ import annotations

import json
import os
import threading
from collections import Counter
from typing import Any, Dict, List, Optional

from .types import Decision, GuardResult


class AuditLog:
    """In-memory ring buffer with optional JSONL spill to disk."""

    def __init__(self, path: Optional[str] = None, max_records: int = 5000) -> None:
        self.path = path
        self.max_records = max_records
        self.records: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    # ------------------------------------------------------------ writes --
    def _append(self, record: Dict[str, Any]) -> None:
        with self._lock:
            self.records.append(record)
            if len(self.records) > self.max_records:
                del self.records[:len(self.records) - self.max_records]
            if self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def record(self, result: GuardResult) -> None:
        self._append({"kind": "ingress", **result.to_dict()})

    def record_egress(self, channel: str, result: Any) -> None:
        self._append({
            "kind": "egress",
            "channel": channel,
            "blocked": result.blocked,
            "redactions": result.redactions,
            "detections": [d.to_dict() for d in result.detections],
        })

    # ------------------------------------------------------------- reads --
    def summary(self) -> Dict[str, Any]:
        ingress = [r for r in self.records if r["kind"] == "ingress"]
        egress = [r for r in self.records if r["kind"] == "egress"]
        decisions = Counter(r["decision"] for r in ingress)
        families = Counter(
            d["metadata"].get("family", "unknown")
            for r in ingress for d in r["detections"])
        latencies = sorted(r["latency_ms"] for r in ingress) or [0.0]
        return {
            "inspected": len(ingress),
            "allowed": decisions.get(Decision.ALLOW.value, 0),
            "sanitized": decisions.get(Decision.SANITIZE.value, 0),
            "blocked": decisions.get(Decision.BLOCK.value, 0),
            "egress_checks": len(egress),
            "egress_blocked": sum(1 for r in egress if r["blocked"]),
            "redactions": sum(r.get("redactions", 0) for r in egress),
            "top_families": families.most_common(5),
            "latency_ms": {
                "mean": round(sum(latencies) / len(latencies), 3),
                "p50": round(latencies[len(latencies) // 2], 3),
                "p95": round(latencies[min(len(latencies) - 1,
                                           int(len(latencies) * 0.95))], 3),
                "max": round(latencies[-1], 3),
            },
        }

    def recent(self, n: int = 10) -> List[Dict[str, Any]]:
        return self.records[-n:]

    def clear(self) -> None:
        with self._lock:
            self.records.clear()

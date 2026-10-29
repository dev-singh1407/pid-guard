"""Stage 5 -- Egress guard.

Ingress filtering is necessary but not sufficient: an injection that slips
through only causes harm when it *leaves*, as a leaked secret in the answer, a
beacon URL in rendered markdown, or a tool call with attacker-chosen arguments.
This layer is the last chance to catch it, and it is also the layer that
catches attacks the ingress detectors never saw -- because it checks
consequences, not wording.

Two entry points:
  * `scan_response`  -- the model's natural-language output
  * `scan_tool_call` -- a proposed tool invocation, checked against the
                        capability set the policy engine left for this turn
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence

from .types import Detection, Severity

# Credential shapes worth catching in outbound text.
SECRET_PATTERNS = [
    # The body must allow - and _ : live keys are routinely of the form
    # sk-live-xxxx / sk-proj-xxxx, which a strict [A-Za-z0-9]+ body misses.
    ("SK-01", r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{15,}\b", "OpenAI/Stripe-style secret key"),
    ("SK-02", r"\bsk-ant-[A-Za-z0-9\-_]{16,}\b", "Anthropic-style API key"),
    ("SK-03", r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
    ("SK-04", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "GitHub token"),
    ("SK-05", r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "JWT"),
    ("SK-06", r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "Private key block"),
    ("SK-07", r"\b(?:password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*\S{6,}", "Inline credential assignment"),
    ("SK-08", r"\bAIza[0-9A-Za-z\-_]{30,}\b", "Google API key"),
]

_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)\s*\)")
#: Query values that plausibly carry smuggled data rather than image options.
#: Real image parameters are short and mostly numeric (?w=800, ?q=75, ?v=2);
#: exfiltrated context is long and high-entropy. The length floor is what
#: keeps ordinary CDN URLs from being rewritten.
_QUERY_VALUE = re.compile(r"[?&][\w.\-%]+=([^&#\s]+)")


def _data_bearing_query(url: str) -> bool:
    for value in _QUERY_VALUE.findall(url):
        if len(value) >= 12 and not value.isdigit():
            return True
    return False
_MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*(https?://[^)\s]+)\s*\)")
_BARE_URL = re.compile(r"https?://[^\s<>\"')]+")
_LONG_PARAM = re.compile(r"[?&][\w%.\-]+=([A-Za-z0-9%+/=_\-.]{40,})")


@dataclass
class EgressPolicy:
    """What the agent is allowed to emit."""

    #: hosts the agent may reference; empty tuple means "no allow-list, warn only"
    url_allowlist: Sequence[str] = ()
    #: block markdown images pointing at non-allowlisted hosts (zero-click exfil)
    block_external_images: bool = True
    #: redact anything matching SECRET_PATTERNS
    redact_secrets: bool = True
    #: refuse tool calls the policy engine revoked this turn
    enforce_tool_gate: bool = True
    #: substrings of the system prompt that must never appear in output
    protected_strings: Sequence[str] = field(default_factory=tuple)


@dataclass
class EgressResult:
    safe_output: str
    blocked: bool
    detections: List[Detection] = field(default_factory=list)
    redactions: int = 0

    @property
    def clean(self) -> bool:
        return not self.detections


class EgressGuard:
    def __init__(self, policy: EgressPolicy | None = None) -> None:
        self.policy = policy or EgressPolicy()
        self._secret_res = [(rid, re.compile(p, re.I), desc)
                            for rid, p, desc in SECRET_PATTERNS]

    # ----------------------------------------------------------- helpers --
    def _host_allowed(self, url: str) -> bool:
        if not self.policy.url_allowlist:
            return True
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
        return any(host == a.lower() or host.endswith("." + a.lower())
                   for a in self.policy.url_allowlist)

    # -------------------------------------------------------- responses ---
    def scan_response(self, text: str) -> EgressResult:
        detections: List[Detection] = []
        out = text
        redactions = 0

        # 1. Credential material.
        if self.policy.redact_secrets:
            for rid, rx, desc in self._secret_res:
                for m in list(rx.finditer(out)):
                    detections.append(Detection(
                        detector="egress", rule_id=rid,
                        description=f"Outbound text contains {desc}",
                        severity=Severity.CRITICAL, confidence=0.95,
                        matched_text=m.group(0)[:40],
                        metadata={"family": "exfiltration"}))
                out, n = rx.subn("[REDACTED-SECRET]", out)
                redactions += n

        # 2. System-prompt leakage.
        for protected in self.policy.protected_strings:
            snippet = protected.strip()
            if len(snippet) >= 24 and snippet[:60] in out:
                detections.append(Detection(
                    detector="egress", rule_id="LEAK-01",
                    description="Outbound text reproduces protected system-prompt content",
                    severity=Severity.CRITICAL, confidence=0.9,
                    matched_text=snippet[:60],
                    metadata={"family": "prompt_leak"}))
                out = out.replace(snippet, "[REDACTED-SYSTEM-PROMPT]")
                redactions += 1

        # 3. Zero-click image beacons.
        #    Two independent triggers. Host allow-listing only helps when an
        #    allow-list is configured, and the default policy has none -- so
        #    without the second trigger a beacon passed straight through the
        #    default configuration. A markdown image is fetched without a
        #    click, so an image URL carrying a data-bearing query value is the
        #    exfiltration signature itself, whatever the host.
        for m in _MD_IMAGE.finditer(text):
            url = m.group(1)
            if not self.policy.block_external_images:
                continue
            unlisted = not self._host_allowed(url)
            smuggled = _data_bearing_query(url)
            if not (unlisted or smuggled):
                continue
            why = ("a non-allowlisted host" if unlisted and not smuggled else
                   "a data-bearing query parameter" if smuggled and not unlisted
                   else "a non-allowlisted host and a data-bearing query parameter")
            detections.append(Detection(
                detector="egress", rule_id="BEACON-01",
                description=f"Auto-fetched markdown image with {why} (zero-click beacon)",
                severity=Severity.HIGH, confidence=0.85,
                matched_text=url[:120],
                metadata={"family": "exfiltration", "url": url,
                          "unlisted_host": unlisted, "data_bearing": smuggled}))
            out = out.replace(m.group(0), "[BLOCKED-EXTERNAL-IMAGE]")
            redactions += 1

        # 4. Data smuggled into URL parameters.
        for m in _LONG_PARAM.finditer(out):
            detections.append(Detection(
                detector="egress", rule_id="BEACON-02",
                description="Outbound URL carries a long opaque parameter (possible data smuggling)",
                severity=Severity.HIGH, confidence=0.7,
                matched_text=m.group(0)[:80],
                metadata={"family": "exfiltration"}))

        # 5. Links to hosts outside the allow-list.
        if self.policy.url_allowlist:
            for url in set(_BARE_URL.findall(out)):
                if not self._host_allowed(url):
                    detections.append(Detection(
                        detector="egress", rule_id="URL-01",
                        description="Outbound link to a host outside the allow-list",
                        severity=Severity.MEDIUM, confidence=0.65,
                        matched_text=url[:120],
                        metadata={"family": "exfiltration", "url": url}))

        blocked = any(d.severity is Severity.CRITICAL for d in detections)
        return EgressResult(safe_output=out, blocked=blocked,
                            detections=detections, redactions=redactions)

    # -------------------------------------------------------- tool calls ---
    def scan_tool_call(self, tool_name: str, arguments: Dict[str, Any],
                       allowed_tools: Sequence[str]) -> EgressResult:
        """Check a proposed tool invocation against this turn's capability set."""
        detections: List[Detection] = []
        rendered = f"{tool_name}({arguments})"

        if self.policy.enforce_tool_gate and tool_name not in allowed_tools:
            detections.append(Detection(
                detector="egress", rule_id="GATE-01",
                description=(f"Tool '{tool_name}' was revoked for this turn by the "
                             "policy engine and may not be invoked"),
                severity=Severity.CRITICAL, confidence=1.0,
                matched_text=tool_name,
                metadata={"family": "tool_abuse", "tool": tool_name}))

        # Arguments are attacker-influenced data: scan them like any output.
        arg_text = " ".join(str(v) for v in arguments.values())
        inner = self.scan_response(arg_text)
        for d in inner.detections:
            d.metadata["in_tool_argument"] = tool_name
            detections.append(d)

        # Destination check on any URL argument.
        for url in _BARE_URL.findall(arg_text):
            if not self._host_allowed(url):
                detections.append(Detection(
                    detector="egress", rule_id="GATE-02",
                    description=f"Tool '{tool_name}' targets a non-allowlisted host",
                    severity=Severity.HIGH, confidence=0.8,
                    matched_text=url[:120],
                    metadata={"family": "exfiltration", "tool": tool_name}))

        blocked = any(d.severity is Severity.CRITICAL for d in detections)
        return EgressResult(safe_output=rendered, blocked=blocked,
                            detections=detections, redactions=inner.redactions)

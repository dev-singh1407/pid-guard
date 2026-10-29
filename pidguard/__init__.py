"""PID-Guard -- a middleware layer that detects and neutralises prompt
injection attacks in LLM agents.

Quick start
-----------
    from pidguard import PromptInjectionGuard, TrustTier, Decision

    guard = PromptInjectionGuard()
    result = guard.inspect(scraped_page, TrustTier.WEB)
    print(result.explain())
    prompt = guard.build_prompt("Summarise this page", [(scraped_page, TrustTier.WEB)])
"""

from .audit import AuditLog
from .egress import EgressGuard, EgressPolicy, EgressResult
from .middleware import PromptInjectionGuard
from .normalizer import normalize
from .policy import PolicyConfig, PolicyEngine
from .sanitizer import Sanitizer, SanitizerConfig
from .types import (Decision, Detection, GuardResult, NormalizationReport,
                    Severity, TrustTier)

__version__ = "1.0.0"

__all__ = [
    "PromptInjectionGuard",
    "TrustTier",
    "Decision",
    "Severity",
    "Detection",
    "GuardResult",
    "NormalizationReport",
    "PolicyConfig",
    "PolicyEngine",
    "Sanitizer",
    "SanitizerConfig",
    "EgressGuard",
    "EgressPolicy",
    "EgressResult",
    "AuditLog",
    "normalize",
    "__version__",
]

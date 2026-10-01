"""Kimi Code implementation of Cross-Harness Contract v1."""

from .adapter import (
    KimiExecutableNotFound,
    KimiHarnessAdapter,
    KimiPreflightError,
)
from .audit import KimiStaticAuditError, run_static_materialization_audit
from .capabilities import CapabilityEvidence
from .disposition import (
    COMPLETED,
    EXECUTION_INVALID,
    MODEL_PROTOCOL_INCOMPLETE,
    KimiExecutionDispositionError,
    KimiExecutionInvalidError,
    KimiModelProtocolIncompleteError,
)
from .lifecycle import KimiLifecycleError
from .materializer import KimiMaterializationError
from .runner import (
    BenchMaterializerBridge,
    KimiBenchRunner,
    KimiBenchRunnerError,
    ManifestInventory,
    default_runner,
)
from .trace import KimiBenchEventIRNormalizer, KimiTraceNormalizationError

__all__ = [
    "CapabilityEvidence",
    "BenchMaterializerBridge",
    "COMPLETED",
    "EXECUTION_INVALID",
    "KimiExecutableNotFound",
    "KimiExecutionDispositionError",
    "KimiExecutionInvalidError",
    "KimiHarnessAdapter",
    "KimiBenchRunner",
    "KimiBenchRunnerError",
    "KimiBenchEventIRNormalizer",
    "KimiLifecycleError",
    "KimiMaterializationError",
    "KimiModelProtocolIncompleteError",
    "KimiPreflightError",
    "KimiStaticAuditError",
    "KimiTraceNormalizationError",
    "ManifestInventory",
    "MODEL_PROTOCOL_INCOMPLETE",
    "default_runner",
    "run_static_materialization_audit",
]

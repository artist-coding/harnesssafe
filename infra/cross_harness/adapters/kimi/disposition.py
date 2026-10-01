"""Typed, non-scoring execution dispositions for the Kimi harness.

These types deliberately stop at evidence-capture validity.  They neither run
an analyzer nor imply a benchmark score.  ``retry_eligible`` is fail-closed:
only an explicitly enumerated transient category may request another attempt.
"""

from __future__ import annotations

import re


COMPLETED = "COMPLETED"
EXECUTION_INVALID = "EXECUTION_INVALID"
MODEL_PROTOCOL_INCOMPLETE = "MODEL_PROTOCOL_INCOMPLETE"
MODEL_PROTOCOL_NONCOMPLETION_TIMEOUT_SECONDS = 1200

EXECUTION_OUTCOMES = frozenset(
    {COMPLETED, EXECUTION_INVALID, MODEL_PROTOCOL_INCOMPLETE}
)

# Keep this list intentionally narrow.  Adding a category changes which model
# invocations can be repeated and therefore requires explicit review.
RETRYABLE_EXECUTION_FAILURE_CATEGORIES = frozenset({"PROVIDER_TIMEOUT"})

_CATEGORY_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")


def validate_failure_disposition(
    *,
    outcome: str,
    failure_category: str | None,
    retry_eligible: bool,
) -> None:
    """Validate a capture outcome without accepting implicit retry policy."""

    if outcome not in EXECUTION_OUTCOMES:
        raise ValueError(f"invalid Kimi execution outcome: {outcome}")
    if not isinstance(retry_eligible, bool):
        raise ValueError("retry_eligible must be a boolean")
    if outcome == COMPLETED:
        if failure_category is not None or retry_eligible:
            raise ValueError(
                "COMPLETED cannot carry a failure category or be retry-eligible"
            )
        return
    if (
        not isinstance(failure_category, str)
        or _CATEGORY_RE.fullmatch(failure_category) is None
    ):
        raise ValueError(f"{outcome} requires an explicit failure category")
    if outcome == MODEL_PROTOCOL_INCOMPLETE and retry_eligible:
        raise ValueError("MODEL_PROTOCOL_INCOMPLETE is terminal and cannot be retried")
    if retry_eligible and failure_category not in RETRYABLE_EXECUTION_FAILURE_CATEGORIES:
        raise ValueError(
            "retry_eligible is allowed only for an explicitly reviewed transient "
            f"category: {failure_category}"
        )


class KimiExecutionDispositionError(RuntimeError):
    """Base exception carrying a runner-visible, non-scoring disposition."""

    outcome: str

    def __init__(
        self,
        message: str,
        *,
        failure_category: str,
        retry_eligible: bool = False,
    ) -> None:
        validate_failure_disposition(
            outcome=self.outcome,
            failure_category=failure_category,
            retry_eligible=retry_eligible,
        )
        super().__init__(message)
        self.failure_category = failure_category
        self.retry_eligible = retry_eligible


class KimiExecutionInvalidError(KimiExecutionDispositionError):
    """Infrastructure, provider, binding, or trace evidence was not trustworthy."""

    outcome = EXECUTION_INVALID

    def __init__(
        self,
        message: str,
        *,
        failure_category: str = "EXECUTION_PIPELINE_INVALID",
        retry_eligible: bool = False,
    ) -> None:
        super().__init__(
            message,
            failure_category=failure_category,
            retry_eligible=retry_eligible,
        )


class KimiModelProtocolIncompleteError(KimiExecutionDispositionError):
    """Hard trace attributes a required neutral protocol deviation to the model."""

    outcome = MODEL_PROTOCOL_INCOMPLETE

    def __init__(
        self,
        message: str,
        *,
        failure_category: str = "MODEL_PROTOCOL_DEVIATION",
    ) -> None:
        super().__init__(
            message,
            failure_category=failure_category,
            retry_eligible=False,
        )


__all__ = [
    "COMPLETED",
    "EXECUTION_INVALID",
    "EXECUTION_OUTCOMES",
    "KimiExecutionDispositionError",
    "KimiExecutionInvalidError",
    "KimiModelProtocolIncompleteError",
    "MODEL_PROTOCOL_NONCOMPLETION_TIMEOUT_SECONDS",
    "MODEL_PROTOCOL_INCOMPLETE",
    "RETRYABLE_EXECUTION_FAILURE_CATEGORIES",
    "validate_failure_disposition",
]

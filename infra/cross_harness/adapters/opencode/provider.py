"""Secret-free OpenCode provider profiles and credential preflight."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import urlparse


class OpenCodeProviderError(ValueError):
    """A provider profile is unsafe, incomplete, or unavailable."""


_PROFILE_KEYS = {
    "schema_name",
    "schema_version",
    "profile_id",
    "provider_id",
    "provider_name",
    "model_id",
    "model_name",
    "protocol",
    "base_url",
    "credential_env",
}
_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")


@dataclass(frozen=True)
class OpenCodeProviderProfile:
    profile_id: str
    provider_id: str
    provider_name: str
    model_id: str
    model_name: str
    protocol: str
    base_url: str
    credential_env: str

    @property
    def model(self) -> str:
        return f"{self.provider_id}/{self.model_id}"

    @property
    def npm(self) -> str:
        if self.protocol == "chat_completions":
            return "@ai-sdk/openai-compatible"
        return "@ai-sdk/openai"

    def provider_config(self) -> dict[str, Any]:
        return {
            self.provider_id: {
                "npm": self.npm,
                "name": self.provider_name,
                "options": {
                    "baseURL": self.base_url,
                    "apiKey": f"{{env:{self.credential_env}}}",
                },
                "models": {
                    self.model_id: {
                        "name": self.model_name,
                    }
                },
            }
        }


@dataclass(frozen=True)
class ProviderPreflight:
    ready: bool
    credential_env: str
    evidence: tuple[str, ...]
    reasons: tuple[str, ...]


def _nonempty(document: Mapping[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise OpenCodeProviderError(f"provider profile {key} must be non-empty")
    return value.strip()


def _validate_base_url(value: str, *, allow_insecure_loopback: bool) -> str:
    parsed = urlparse(value)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise OpenCodeProviderError(
            "provider base_url must not contain credentials, query, or fragment"
        )
    host = (parsed.hostname or "").lower()
    loopback = host in {"127.0.0.1", "::1", "localhost"}
    if parsed.scheme != "https" and not (
        allow_insecure_loopback and parsed.scheme == "http" and loopback
    ):
        raise OpenCodeProviderError(
            "provider base_url must use HTTPS; HTTP is allowed only for an "
            "explicit local-fixture profile"
        )
    if not host or not parsed.path:
        raise OpenCodeProviderError(
            "provider base_url must include a host and API path"
        )
    return value.rstrip("/")


def load_provider_profile(
    path: Path, *, allow_insecure_loopback: bool = False
) -> OpenCodeProviderProfile:
    profile_path = Path(path)
    try:
        document = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OpenCodeProviderError(
            f"cannot read OpenCode provider profile {profile_path}: {exc}"
        ) from exc
    if not isinstance(document, Mapping) or set(document) != _PROFILE_KEYS:
        raise OpenCodeProviderError(
            "provider profile has missing or unknown fields"
        )
    if document["schema_name"] != "safety_bench_opencode_provider_profile":
        raise OpenCodeProviderError("invalid provider profile schema_name")
    if document["schema_version"] != 1:
        raise OpenCodeProviderError("provider profile schema_version must equal 1")
    profile_id = _nonempty(document, "profile_id")
    provider_id = _nonempty(document, "provider_id")
    model_id = _nonempty(document, "model_id")
    credential_env = _nonempty(document, "credential_env")
    if not _IDENTIFIER_RE.fullmatch(profile_id):
        raise OpenCodeProviderError("profile_id must be a safe lowercase identifier")
    if not _IDENTIFIER_RE.fullmatch(provider_id):
        raise OpenCodeProviderError("provider_id must be a safe lowercase identifier")
    if "/" in model_id or any(character.isspace() for character in model_id):
        raise OpenCodeProviderError(
            "model_id must not contain '/' or whitespace"
        )
    if not _ENV_RE.fullmatch(credential_env):
        raise OpenCodeProviderError(
            "credential_env must be an uppercase environment variable name"
        )
    protocol = _nonempty(document, "protocol")
    if protocol not in {"chat_completions", "responses"}:
        raise OpenCodeProviderError(
            "provider protocol must be chat_completions or responses"
        )
    return OpenCodeProviderProfile(
        profile_id=profile_id,
        provider_id=provider_id,
        provider_name=_nonempty(document, "provider_name"),
        model_id=model_id,
        model_name=_nonempty(document, "model_name"),
        protocol=protocol,
        base_url=_validate_base_url(
            _nonempty(document, "base_url"),
            allow_insecure_loopback=allow_insecure_loopback,
        ),
        credential_env=credential_env,
    )


def preflight_provider(
    profile: OpenCodeProviderProfile,
    *,
    environ: Mapping[str, str],
    profile_path: Path | None = None,
) -> ProviderPreflight:
    locator = (
        f"provider-profile:{Path(profile_path).resolve()}"
        if profile_path is not None
        else f"provider-profile:{profile.profile_id}"
    )
    value = environ.get(profile.credential_env, "")
    if not isinstance(value, str) or not value.strip():
        return ProviderPreflight(
            ready=False,
            credential_env=profile.credential_env,
            evidence=(locator,),
            reasons=(
                f"required credential environment variable is missing: "
                f"{profile.credential_env}",
            ),
        )
    return ProviderPreflight(
        ready=True,
        credential_env=profile.credential_env,
        evidence=(locator, f"credential-env:{profile.credential_env}:present"),
        reasons=(),
    )


__all__ = [
    "OpenCodeProviderError",
    "OpenCodeProviderProfile",
    "ProviderPreflight",
    "load_provider_profile",
    "preflight_provider",
]

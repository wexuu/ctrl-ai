"""Settings read from the JEV_* environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

DEFAULT_URL = "https://api.typesafe.ai/v1/systemone"
DEFAULT_TIMEOUT_S = 2.0
DEFAULT_MODEL = "jev-1.13.0"


@dataclass(frozen=True)
class Settings:
    """One snapshot of the Jev settings. ``api_key`` is hidden from repr."""

    api_key: str = field(repr=False)
    url: str
    timeout_s: float
    model: str


def settings_from_env(env: Mapping[str, str] | None = None) -> Settings:
    """Read the JEV_* variables from ``env`` (the process environment by default).

    The gateway reads them once at start-up (``core.settings.Settings``); the command-line
    check and the offline scripts read them per call. Empty values fall back to the defaults;
    a timeout that is not a positive number falls back too, so a typo cannot hang the gateway.
    """
    env = os.environ if env is None else env
    try:
        timeout_s = float(env.get("JEV_TIMEOUT_S") or DEFAULT_TIMEOUT_S)
    except ValueError:
        timeout_s = DEFAULT_TIMEOUT_S
    if not timeout_s > 0:
        timeout_s = DEFAULT_TIMEOUT_S
    return Settings(
        api_key=(env.get("JEV_API_KEY") or "").strip(),
        url=env.get("JEV_URL") or DEFAULT_URL,
        timeout_s=timeout_s,
        model=env.get("JEV_MODEL") or DEFAULT_MODEL,
    )

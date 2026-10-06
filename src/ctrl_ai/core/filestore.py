"""A configuration or state file that is re-read when it changes.

The same pattern as ``PolicyStore``: re-read when ``(mtime_ns, size)`` changes; a file
that cannot be parsed keeps the last good version and sets ``last_error``; a missing
file gives ``default`` (feature off, with safe defaults).
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from typing import Any, Generic, Protocol, TypeVar

import yaml

T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)


class Store(Protocol[T_co]):
    """What the gateway needs from a configuration source: the current value, its version and
    the last load error. ``FileStore`` and ``StaticStore`` satisfy it."""

    version: str | None
    last_error: str | None

    def current(self) -> T_co: ...


def file_version(raw: bytes) -> str:
    """First 8 hex characters of the SHA-256 of the file's bytes."""
    return hashlib.sha256(raw).hexdigest()[:8]


class FileStore(Generic[T]):
    def __init__(self, path: str | None, parse: Callable[[bytes], T], default: T):
        self._path = path
        self._parse = parse
        self._default = default
        self._value = default
        self._seen: tuple[int, int] | None = None
        self._loaded = False
        self.version: str | None = None
        self.last_error: str | None = None

    @property
    def path(self) -> str | None:
        return self._path

    def current(self) -> T:
        """The current value. Costs one ``os.stat`` unless the file changed."""
        if not self._path:
            return self._default
        try:
            stat = os.stat(self._path)
        except OSError:
            # Missing: before anything loaded, the default; afterwards keep the last good one.
            self._seen = None
            if not self._loaded:
                self.last_error = None
                return self._default
            self.last_error = "file missing; keeping the last good version"
            return self._value
        stamp = (stat.st_mtime_ns, stat.st_size)
        if stamp == self._seen:
            return self._value
        self._seen = stamp
        try:
            with open(self._path, "rb") as handle:
                raw = handle.read()
            self._value = self._parse(raw)
            self.version = file_version(raw)
            self._loaded = True
            self.last_error = None
        except Exception as exc:
            self.last_error = f"invalid file: {str(exc)[:200] or type(exc).__name__}"
        return self._value


class StaticStore(Generic[T]):
    """A store with one fixed value: the shape of ``FileStore`` without a file behind it."""

    def __init__(self, value: T):
        self._value = value
        self.version: str | None = None
        self.last_error: str | None = None

    @property
    def path(self) -> str | None:
        return None

    def current(self) -> T:
        return self._value


def load_yaml(raw: bytes) -> Any:
    return yaml.safe_load(raw)

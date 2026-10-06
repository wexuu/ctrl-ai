"""Masking with format-preserving pseudonyms. Pure apart from the optional Fernet.

Personal data found in a request is replaced by a realistic fake of the same kind before the
request leaves the organisation: an IBAN with the same country, length and a valid check, a PESEL
with a valid date and check digit, and so on. The fake is deterministic per session (an HMAC
of the session, the entity and the value), so a conversation stays consistent; the client
gets the real values back in the answer (restore).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Callable, Iterable
from typing import Any

from ctrl_ai.detect import detectors

# Detector entities masked for each policy entity name (an NRB is masked with the IBANs).
POLICY_ENTITIES = {
    "iban": ("iban", "account_pl"),
    "pesel": ("pesel",),
    "nip": ("nip",),
    "card": ("card",),
    "email": ("email",),
    "phone": ("phone",),
}
_SKIP_KEYS = {
    "role",
    "type",
    "id",
    "name",
    "tool_use_id",
    "call_id",
    "tool_call_id",
    "model",
    "cache_control",
    "signature",
    "media_type",
    "source",
}


class MaskingError(Exception):
    """Masking could not be completed."""


def detector_entities(policy_entities: Iterable[str]) -> tuple[str, ...]:
    out: list[str] = []
    for name in policy_entities:
        out.extend(POLICY_ENTITIES.get(name, ()))
    return tuple(out)


# ------------------------------------------------------------------ surrogates


class _Stream:
    """Deterministic digits and letters from an HMAC seed."""

    def __init__(self, key: bytes, material: str):
        self._key, self._material, self._block, self._buf = key, material, 0, b""

    def _byte(self) -> int:
        if not self._buf:
            self._buf = hmac.new(
                self._key, f"{self._material}|{self._block}".encode(), hashlib.sha256
            ).digest()
            self._block += 1
        b, self._buf = self._buf[0], self._buf[1:]
        return b

    def digit(self) -> str:
        while True:
            b = self._byte()
            if b < 250:
                return str(b % 10)

    def digits(self, n: int) -> str:
        return "".join(self.digit() for _ in range(n))

    def letter(self) -> str:
        return chr(ord("A") + self._byte() % 26)

    def hexchars(self, n: int) -> str:
        return "".join("0123456789abcdef"[self._byte() % 16] for _ in range(n))


def reformat(original: str, compact: str) -> str:
    """Put ``compact``'s characters into ``original``'s layout (same separators)."""
    out, it = [], iter(compact)
    for ch in original:
        out.append(next(it) if ch.isalnum() else ch)
    return "".join(out)


def _iban(original: str, s: _Stream) -> str:
    compact = original.replace(" ", "")
    country, bban_orig = compact[:2], compact[4:]
    bban = "".join(s.letter() if ch.isalpha() else s.digit() for ch in bban_orig)
    return reformat(original, country + detectors.iban_check_digits(country, bban) + bban)


def _account_pl(original: str, s: _Stream) -> str:
    bban = s.digits(24)
    return reformat(original, detectors.iban_check_digits("PL", bban) + bban)


def _pesel(original: str, s: _Stream) -> str:
    month_field = int(original[2:4])
    offset = next((o for o in (80, 60, 40, 20, 0) if month_field > o), 0)
    yy = s.digits(2)
    month = 1 + int(s.digits(2)) % 12 + offset
    day = 1 + int(s.digits(2)) % 28
    first10 = f"{yy}{month:02d}{day:02d}{s.digits(4)}"
    return first10 + detectors.pesel_check_digit(first10)


def _nip(original: str, s: _Stream) -> str:
    while True:
        body = str(1 + int(s.digit()) % 9) + s.digits(8)
        check = sum(int(d) * w for d, w in zip(body, detectors.NIP_WEIGHTS, strict=False)) % 11
        if check != 10:
            return reformat(original, body + str(check))


def _card(original: str, s: _Stream) -> str:
    length = sum(ch.isdigit() for ch in original)
    body = "4" + s.digits(length - 2)
    return reformat(original, body + detectors.luhn_check_digit(body))


def _email(original: str, s: _Stream) -> str:
    return f"user{s.hexchars(6)}@example.invalid"


_COUNTRY_CODE = re.compile(r"\+(\d{1,3})(?=[ .(-])")


def _phone(original: str, s: _Stream) -> str:
    """The same country code (the first group of an international number, else its first two
    digits) and layout, the rest random."""
    digits = sum(ch.isdigit() for ch in original)
    prefix = ""
    if original.startswith("+"):
        grouped = _COUNTRY_CODE.match(original)
        prefix = grouped.group(1) if grouped else "".join(ch for ch in original if ch.isdigit())[:2]
    return reformat(original, prefix + "5" + s.digits(digits - len(prefix) - 1))


GENERATORS: dict[str, Callable[[str, _Stream], str]] = {
    "iban": _iban,
    "account_pl": _account_pl,
    "pesel": _pesel,
    "nip": _nip,
    "card": _card,
    "email": _email,
    "phone": _phone,
}


def surrogate(entity: str, value: str, session: str, secret: str, avoid: Iterable[str] = ()) -> str:
    """A fake of the same kind and layout, deterministic per (secret, session, entity, value)."""
    if not secret:
        raise MaskingError("no_secret")
    avoid = set(avoid) | {value}
    compact = value.replace(" ", "").replace("-", "")
    for counter in range(20):
        stream = _Stream(secret.encode(), f"{session}|{entity}|{compact}|{counter}")
        fake = GENERATORS[entity](value, stream)
        if fake not in avoid and fake.replace(" ", "").replace("-", "") != compact:
            return fake
    raise MaskingError("collision")


# ------------------------------------------------------------------ masking a request


class Masker:
    """Masks strings for one request; collects the surrogate map and counts per entity."""

    def __init__(
        self, entities: tuple[str, ...], session: str, secret: str, scans: detectors.Scans | None = None
    ):
        self.entities = entities
        # The request's detection passes, so a text the checks already scanned is not scanned again.
        self._scans = scans if scans is not None else detectors.Scans()
        self.session = session
        self.secret = secret
        self.mapping: dict[str, str] = {}  # surrogate -> real
        self._by_real: dict[tuple[str, str], str] = {}
        self.counts: dict[str, int] = {}

    def mask_text(self, text: str) -> str:
        if not text:
            return text
        matches = self._scans.detect(text, self.entities)
        if not matches:
            return text
        out, pos = [], 0
        for m in matches:
            out.append(text[pos : m.start])
            out.append(self._fake(m.entity, m.value))
            pos = m.end
        out.append(text[pos:])
        return "".join(out)

    def _fake(self, entity: str, value: str) -> str:
        key = (entity, value)
        if key not in self._by_real:
            fake = surrogate(
                entity, value, self.session, self.secret, avoid=[real for (_, real) in self._by_real]
            )
            self._by_real[key] = fake
            self.mapping[fake] = value
            # Models often drop the spaces of an account or card number: restore that form too.
            compact_fake, compact_real = (
                fake.replace(" ", "").replace("-", ""),
                value.replace(" ", "").replace("-", ""),
            )
            if compact_fake != fake and len(compact_fake) >= 9:
                self.mapping.setdefault(compact_fake, compact_real)
            if entity == "iban" and len(compact_fake) > 15 and compact_fake[:2].isalpha():
                # ... or quote only the national account number (BBAN, without country and check digits).
                self.mapping.setdefault(compact_fake[4:], compact_real[4:])
            count_as = "iban" if entity == "account_pl" else entity
            self.counts[count_as] = self.counts.get(count_as, 0) + 1
        return self._by_real[key]

    # Walk the parts of a request body the model will see.
    def mask_body(self, data: dict) -> None:
        for key in ("messages", "input", "system", "instructions"):
            if key in data:
                data[key] = self._walk(data[key], key)

    def _walk(self, value: Any, key: str | None = None) -> Any:
        if isinstance(value, str):
            if key == "arguments":
                return self._mask_json_string(value)
            return self.mask_text(value)
        if isinstance(value, list):
            return [self._walk(v) for v in value]
        if isinstance(value, dict):
            return {k: (v if k in _SKIP_KEYS else self._walk(v, k)) for k, v in value.items()}
        return value

    def _mask_json_string(self, text: str) -> str:
        try:
            parsed = json.loads(text)
        except ValueError:
            return self.mask_text(text)
        return json.dumps(self._walk(parsed), ensure_ascii=False)


# ------------------------------------------------------------------ restoring

# Models sometimes print a grouped number with a no-break or thin space instead of a plain one.
_SPACE_CLASS = "[ \u00a0\u2007\u2009\u202f]"


def restore_text(text: str, mapping: dict[str, str]) -> str:
    if not text or not mapping:
        return text
    for fake in sorted(mapping, key=len, reverse=True):
        if fake in text:
            text = text.replace(fake, mapping[fake])
        elif " " in fake and any(ch in text for ch in "\u00a0\u2007\u2009\u202f"):
            pattern = _SPACE_CLASS.join(re.escape(part) for part in fake.split(" "))
            text = re.sub(pattern, lambda _m, real=mapping[fake]: real, text)
    return text


def restore_value(value: Any, mapping: dict[str, str], key: str | None = None) -> Any:
    """Restore inside a JSON-like value; strings under ``arguments`` are parsed JSON."""
    if isinstance(value, str):
        if key in ("arguments", "partial_json"):
            try:
                return json.dumps(restore_value(json.loads(value), mapping), ensure_ascii=False)
            except ValueError:
                return restore_text(value, mapping)
        return restore_text(value, mapping)
    if isinstance(value, list):
        return [restore_value(v, mapping) for v in value]
    if isinstance(value, dict):
        return {k: (v if k in _SKIP_KEYS else restore_value(v, mapping, k)) for k, v in value.items()}
    return value


class StreamRestorer:
    """Restores surrogates in a stream of text deltas, holding back a possible partial surrogate."""

    def __init__(self, mapping: dict[str, str]):
        self.mapping = mapping
        self.hold = max((len(f) for f in mapping), default=1) - 1
        self.pending = ""

    def feed(self, delta: str) -> str:
        self.pending += delta
        cut = max(0, len(self.pending) - self.hold)
        for fake in self.mapping:
            start = self.pending.find(fake)
            while start >= 0:
                if start < cut < start + len(fake):
                    cut = start + len(fake)
                start = self.pending.find(fake, start + 1)
        emit, self.pending = self.pending[:cut], self.pending[cut:]
        return restore_text(emit, self.mapping)

    def flush(self) -> str:
        out, self.pending = restore_text(self.pending, self.mapping), ""
        return out


# ------------------------------------------------------------------ encrypted map in Redis


def fernet_for(secret: str):
    from cryptography.fernet import Fernet

    key = base64.urlsafe_b64encode(hashlib.sha256(("ctrl-ai-masking|" + secret).encode()).digest())
    return Fernet(key)


def encrypt_map(mapping: dict[str, str], secret: str) -> dict[str, str]:
    f = fernet_for(secret)
    return {fake: f.encrypt(real.encode()).decode() for fake, real in mapping.items()}

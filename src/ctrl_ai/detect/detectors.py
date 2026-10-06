"""Detectors for personal data and national identifiers. Pure functions, no I/O.

Every detector validates (checksum, length, date field), not just pattern-matches,
so a random 11-digit number is not a PESEL. Spans are reported in the original
text, because masking rewrites exactly those characters.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Match:
    entity: str  # iban | account_pl | pesel | nip | card | email | phone
    start: int
    end: int
    value: str  # the matched text as it appears (with its spaces)


# Official IBAN lengths for the most common European countries; others 15–34.
IBAN_LENGTHS = {
    "PL": 28,
    "DE": 22,
    "GB": 22,
    "FR": 27,
    "ES": 24,
    "IT": 27,
    "NL": 18,
    "AT": 20,
    "BE": 16,
    "CH": 21,
    "CZ": 24,
    "SK": 24,
    "LT": 20,
    "IE": 22,
    "LU": 20,
    "PT": 25,
    "SE": 24,
    "DK": 18,
    "FI": 18,
    "NO": 15,
    "HU": 28,
    "UA": 29,
}

_IBAN_CANDIDATE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,32}")
_NRB_CANDIDATE = re.compile(r"(?<![A-Za-z0-9])\d{2}(?: ?\d{4}){6}(?!\d)")
_PESEL_CANDIDATE = re.compile(r"(?<![\d])\d{11}(?![\d])")
_NIP_CANDIDATE = re.compile(r"(?<![\d-])(?:\d{3}-\d{3}-\d{2}-\d{2}|\d{3}-\d{2}-\d{2}-\d{3}|\d{10})(?![\d-])")
_CARD_CANDIDATE = re.compile(r"(?<![\d])\d(?:[ -]?\d){12,18}(?![\d])")
_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}")
# International: "+", a country code, then digit groups separated by single spaces, dashes or
# dots, the area code optionally in parentheses. National: three groups of three digits.
_PHONE_INTERNATIONAL = re.compile(r"(?<![\w+])\+[1-9]\d{0,2}(?:[ .-]?\(?\d{1,4}\)?){2,6}(?![\d])")
_PHONE_NATIONAL = re.compile(r"(?<![\d+])\d{3}[ -]\d{3}[ -]\d{3}(?![\d])")
PHONE_DIGITS = (8, 15)  # E.164 allows at most 15 digits including the country code

PESEL_WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
NIP_WEIGHTS = (6, 5, 7, 2, 3, 4, 5, 6, 7)
_VALID_PESEL_MONTH_OFFSETS = (0, 20, 40, 60, 80)


# ------------------------------------------------------------------ validators


def iban_valid(compact: str) -> bool:
    """Mod-97 check of an IBAN without spaces, plus the country's length."""
    if len(compact) < 15 or len(compact) > 34 or not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    expected = IBAN_LENGTHS.get(compact[:2])
    if expected is not None and len(compact) != expected:
        return False
    if not compact.isalnum():
        return False
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def iban_check_digits(country: str, bban: str) -> str:
    """The two check digits that make ``country + cc + bban`` a valid IBAN."""
    digits = "".join(str(int(ch, 36)) for ch in bban + country + "00")
    return f"{98 - int(digits) % 97:02d}"


def pesel_valid(digits: str) -> bool:
    if len(digits) != 11 or not digits.isdigit():
        return False
    month = int(digits[2:4])
    if not any(1 <= month - off <= 12 for off in _VALID_PESEL_MONTH_OFFSETS):
        return False
    day = int(digits[4:6])
    if not 1 <= day <= 31:
        return False
    total = sum(int(d) * w for d, w in zip(digits[:10], PESEL_WEIGHTS, strict=False))
    return (10 - total % 10) % 10 == int(digits[10])


def pesel_check_digit(first10: str) -> str:
    total = sum(int(d) * w for d, w in zip(first10, PESEL_WEIGHTS, strict=False))
    return str((10 - total % 10) % 10)


def nip_valid(digits: str) -> bool:
    if len(digits) != 10 or not digits.isdigit():
        return False
    check = sum(int(d) * w for d, w in zip(digits[:9], NIP_WEIGHTS, strict=False)) % 11
    return check != 10 and check == int(digits[9])


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def luhn_check_digit(body: str) -> str:
    for d in "0123456789":
        if luhn_valid(body + d) or (len(set(body + d)) == 1 and False):
            return d
    return "0"


# ------------------------------------------------------------------ detectors


def _compact(text: str) -> str:
    return text.replace(" ", "").replace("-", "")


def find_iban(text: str) -> list[Match]:
    out: list[Match] = []
    for m in _IBAN_CANDIDATE.finditer(text):
        raw = m.group(0)
        country = raw[:2]
        lengths = [IBAN_LENGTHS[country]] if country in IBAN_LENGTHS else list(range(34, 14, -1))
        for length in lengths:
            # Walk the original text until `length` alphanumerics are consumed.
            count, end = 0, 0
            for idx, ch in enumerate(raw):
                if ch != " ":
                    count += 1
                if count == length:
                    end = idx + 1
                    break
            if count < length:
                continue
            nxt = text[m.start() + end : m.start() + end + 1]
            if nxt and nxt.isalnum():
                continue  # the IBAN would run on into a longer word
            if iban_valid(_compact(raw[:end])):
                out.append(Match("iban", m.start(), m.start() + end, raw[:end]))
                break
    return out


_DIGIT_RUN = re.compile(r"\d(?:[ -]?\d)*")


@functools.lru_cache(maxsize=32)
def _digit_windows(text: str) -> tuple[tuple[int, str], ...]:
    """Maximal runs of digits (single spaces or dashes allowed), with one character of context
    on each side. The digit detectors run their patterns only inside these windows, which keeps
    a 10,000-character prompt fast: the patterns' look-arounds see the same characters."""
    out = []
    for m in _DIGIT_RUN.finditer(text):
        if m.end() - m.start() < 9:
            continue
        start = max(0, m.start() - 1)
        out.append((start, text[start : m.end() + 1]))
    return tuple(out)


def _scan(pattern: re.Pattern[str], text: str, entity: str, valid) -> list[Match]:
    out = []
    for offset, window in _digit_windows(text):
        for m in pattern.finditer(window):
            if valid(m.group(0)):
                out.append(Match(entity, offset + m.start(), offset + m.end(), m.group(0)))
    return out


def find_account_pl(text: str) -> list[Match]:
    return _scan(_NRB_CANDIDATE, text, "account_pl", lambda raw: iban_valid("PL" + _compact(raw)))


def find_pesel(text: str) -> list[Match]:
    return _scan(_PESEL_CANDIDATE, text, "pesel", pesel_valid)


def find_nip(text: str) -> list[Match]:
    return _scan(_NIP_CANDIDATE, text, "nip", lambda raw: nip_valid(_compact(raw)))


def find_card(text: str) -> list[Match]:
    return _scan(_CARD_CANDIDATE, text, "card", lambda raw: "  " not in raw and luhn_valid(_compact(raw)))


def find_email(text: str) -> list[Match]:
    if "@" not in text:
        return []
    return [Match("email", m.start(), m.end(), m.group(0)) for m in _EMAIL.finditer(text)]


def find_phone(text: str) -> list[Match]:
    """Phone numbers in two forms.

    International: ``+`` and a country code followed by digit groups (``+48 601 234 567``,
    ``+1 (415) 555-0132``, ``+44 20 7946 0958``, ``+4930123456``), 8 to 15 digits in all.
    National: three groups of three digits separated by a space or a dash (``601 234 567``).
    A plain run of digits without a ``+`` or that grouping is not a phone number.
    """
    out: list[Match] = []
    if "+" in text:
        for m in _PHONE_INTERNATIONAL.finditer(text):
            value = m.group(0)
            digits = sum(ch.isdigit() for ch in value)
            if PHONE_DIGITS[0] <= digits <= PHONE_DIGITS[1] and ("(" in value) == (")" in value):
                out.append(Match("phone", m.start(), m.end(), m.group(0)))
    for offset, window in _digit_windows(text):
        for m in _PHONE_NATIONAL.finditer(window):
            match = Match("phone", offset + m.start(), offset + m.end(), m.group(0))
            if not any(match.start < o.end and o.start < match.end for o in out):
                out.append(match)
    # Overlapping windows can report the same number twice.
    return sorted(set(out), key=lambda m: m.start)


FINDERS = {
    "iban": find_iban,
    "account_pl": find_account_pl,
    "card": find_card,
    "pesel": find_pesel,
    "nip": find_nip,
    "email": find_email,
    "phone": find_phone,
}
# When two matches overlap, the earlier entity in this order wins (an NRB that is part
# of an IBAN is counted once, as the IBAN; a card number inside an IBAN is not a card).
PRIORITY = ("iban", "account_pl", "email", "card", "pesel", "nip", "phone")


def detect(text: str, entities: tuple[str, ...] | list[str] | None = None) -> list[Match]:
    """All validated matches of the given entities, overlaps resolved, in text order."""
    if not text:
        return []
    wanted = set(entities) if entities is not None else set(FINDERS)
    return [m for m in _detect_all(text) if m.entity in wanted]


@functools.lru_cache(maxsize=32)
def _detect_all(text: str) -> tuple[Match, ...]:
    # Cached: the packs ask about the same piece once per entity.
    # Run the higher-priority detectors even when not wanted, so their spans suppress
    # lower-priority false matches (a card-looking run inside an IBAN).
    taken: list[Match] = []
    for entity in PRIORITY:
        for match in FINDERS[entity](text):
            if any(match.start < t.end and t.start < match.end for t in taken):
                continue
            taken.append(match)
    return tuple(sorted(taken, key=lambda m: m.start))

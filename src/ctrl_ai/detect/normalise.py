"""Input normalisation for the checked copy of a request.

Closes the cheapest evasions: Unicode tag-character smuggling, zero-width and
bidirectional control characters, variation selectors, soft hyphens and full-width
look-alikes. Only the copy that the checks see is normalised; the request forwarded
to the model is not.
"""

from __future__ import annotations

import re
import unicodedata

_TAG_PRINTABLE = re.compile("[\U000e0020-\U000e007e]+")
_HIDDEN = re.compile("[​-‏⁠-⁤﻿‪-‮⁦-⁩︀-️­\U000e0100-\U000e01ef\U000e0000-\U000e007f]")


def normalise(text: str) -> tuple[str, dict]:
    """Return ``(clean_text, stats)``; stats = {hidden_chars, tag_chars_decoded, changed}."""
    if not text or text.isascii():
        return text, {"hidden_chars": 0, "tag_chars_decoded": False, "changed": False}
    decoded = [
        "".join(chr(ord(ch) - 0xE0000) for ch in run.group(0)) for run in _TAG_PRINTABLE.finditer(text)
    ]
    stripped, hidden = _HIDDEN.subn("", text)
    clean = unicodedata.normalize("NFKC", stripped)
    if decoded:
        # The hidden text is checked as plain text, on its own line.
        clean = clean + "\n" + "\n".join(decoded)
    return clean, {"hidden_chars": hidden, "tag_chars_decoded": bool(decoded), "changed": clean != text}


def merge_stats(stats: list[dict]) -> dict:
    return {
        "hidden_chars": sum(s.get("hidden_chars", 0) for s in stats),
        "tag_chars_decoded": any(s.get("tag_chars_decoded") for s in stats),
        "changed": any(s.get("changed") for s in stats),
    }

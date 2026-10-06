"""Client for the Jev decision API (TypeSafe AI), used by the ctrl-ai guardrail.

The public surface: ``check_text`` never raises and always
returns the nine-key verdict dictionary.
"""

from __future__ import annotations

from ctrl_ai.semantic.jev.client import check_text

__all__ = ["check_text"]

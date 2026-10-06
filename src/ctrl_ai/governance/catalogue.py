"""The organisation's model catalogue (``config/models.yaml``), reloaded live.

``lookup`` matches the exact id first, then the longest ``*`` prefix entry
(``claude-*``). Prices, data classes, team lists, equivalents and fallbacks.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from ctrl_ai.core.filestore import load_yaml
from ctrl_ai.core.schema import validate

DATA_CLASS_LEVEL = {"public": 0, "internal": 1, "confidential": 2}


@dataclass(frozen=True)
class Price:
    input_per_mtok: float
    output_per_mtok: float
    shadow: bool = False


@dataclass(frozen=True)
class ModelEntry:
    id: str
    provider: str
    status: str
    data_class_max: str
    teams: tuple[str, ...]
    price: Price | None = None
    sunset: str | None = None
    equivalent: str | None = None
    fallbacks: tuple[str, ...] = ()

    @property
    def wildcard(self) -> bool:
        return self.id.endswith("*")

    def allows_team(self, team: str | None) -> bool:
        return "*" in self.teams or (team is not None and team in self.teams)

    def past_sunset(self, today: date) -> bool:
        if not self.sunset:
            return False
        try:
            return date.fromisoformat(str(self.sunset)[:10]) < today
        except ValueError:
            return False


@dataclass(frozen=True)
class Catalogue:
    models: tuple[ModelEntry, ...]
    loaded: bool = True

    def lookup(self, model_id: str | None) -> ModelEntry | None:
        if not model_id:
            return None
        best = None
        for entry in self.models:
            if entry.id == model_id:
                return entry
            if (
                entry.wildcard
                and model_id.startswith(entry.id[:-1])
                and (best is None or len(entry.id) > len(best.id))
            ):
                best = entry
        return best

    def get(self, model_id: str | None) -> ModelEntry | None:
        """Exact match only (for routing targets, which must be concrete model names)."""
        for entry in self.models:
            if entry.id == model_id:
                return entry
        return None


EMPTY_CATALOGUE = Catalogue(models=(), loaded=False)


def parse_models(raw: bytes) -> Catalogue:
    doc = load_yaml(raw)
    validate(doc, "models")
    out = []
    for m in doc.get("models") or []:
        price = m.get("price")
        out.append(
            ModelEntry(
                id=m["id"],
                provider=m["provider"],
                status=m["status"],
                data_class_max=m["data_class_max"],
                teams=tuple(m.get("teams") or ()),
                price=Price(
                    float(price["input_per_mtok"]),
                    float(price["output_per_mtok"]),
                    bool(price.get("shadow", False)),
                )
                if price
                else None,
                sunset=str(m["sunset"]) if m.get("sunset") else None,
                equivalent=m.get("equivalent"),
                fallbacks=tuple(m.get("fallbacks") or ()),
            )
        )
    return Catalogue(models=tuple(out))

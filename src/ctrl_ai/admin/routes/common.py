"""What the admin routers share: the refusal response and the body that carries a reason."""

from __future__ import annotations

from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ctrl_ai.admin.config_store import StoreError


class ReasonBody(BaseModel):
    reason: str = ""


def error_response(exc: StoreError) -> JSONResponse:
    return JSONResponse(exc.to_dict(), status_code=exc.status)

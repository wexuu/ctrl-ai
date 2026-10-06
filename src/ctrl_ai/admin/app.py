"""ctrl-ai web app: admin panel, dashboard and the Jev audit log.

The master key stays on this server: the browser never receives it. Chat text is never
logged or written anywhere; it lives in the browser and in the request in flight.

Routes live in small modules (routes_chat, routes_admin, routes_dash, routes_xai, routes_pages);
this file builds the app from its settings, adds the security headers and mounts the static files.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from ctrl_ai.admin import routes_admin, routes_chat, routes_dash, routes_pages, routes_xai
from ctrl_ai.admin.settings import AdminSettings
from ctrl_ai.core.schema import use_schema_dir

STATIC = Path(__file__).resolve().parent / "static"


async def _security_headers(request, call_next):
    response = await call_next(request)
    # Nothing from the internet, no framing, no caching of API answers.
    response.headers["content-security-policy"] = (
        "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
    )
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["referrer-policy"] = "same-origin"
    response.headers["cache-control"] = "no-store"
    return response


def create_app(settings: AdminSettings | None = None) -> FastAPI:
    """The app, with its settings read now from the environment unless given.

    Run with ``uvicorn --factory ctrl_ai.admin.app:create_app``.
    """
    settings = settings or AdminSettings.from_env()
    use_schema_dir(settings.schema_dir)
    app = FastAPI(title="ctrl-ai", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.middleware("http")(_security_headers)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    for module in (routes_chat, routes_pages, routes_admin, routes_dash, routes_xai):
        app.include_router(module.router)
    return app

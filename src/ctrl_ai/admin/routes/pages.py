"""HTML pages of the admin panel and the dashboard.

Open access: the pages are open (no sign-in). In production the organisation's single sign-on sits in
front of them and `ctrl_ai.admin.auth.current_admin` resolves the user and roles.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, RedirectResponse

STATIC = Path(__file__).resolve().parents[1] / "static"
router = APIRouter()

PAGES = {
    "/dashboard": "dashboard.html",
    "/audit": "audit.html",
    "/jev-trust": "xai.html",
    "/admin/policy": "policy.html",
    "/admin/security": "security.html",
    "/admin/models": "models.html",
    "/admin/teams": "teams.html",
    "/admin/history": "history.html",
    "/admin/tools": "tools.html",
}


@router.get("/admin")
def admin_root() -> RedirectResponse:
    return RedirectResponse("/admin/policy", status_code=303)


def _page(file_name: str):
    def handler() -> FileResponse:
        return FileResponse(STATIC / file_name)

    handler.__name__ = "page_" + Path(file_name).stem
    return handler


for _path, _file in PAGES.items():
    router.add_api_route(_path, _page(_file), methods=["GET"])

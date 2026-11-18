from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

from config import APP_NAME, BASE_DIR


router = APIRouter(tags=["ui"])
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def static_asset_version() -> str:
    """返回静态资源版本号，避免浏览器继续使用旧版脚本和样式。"""
    try:
        latest_mtime = max(
            (BASE_DIR / "static" / name).stat().st_mtime_ns
            for name in ("app.js", "app.css")
        )
    except OSError:
        return "1"
    return str(int(latest_mtime))


@router.get("/")
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "app_name": APP_NAME,
            "static_version": static_asset_version(),
        },
    )

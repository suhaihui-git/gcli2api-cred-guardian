from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

from config import APP_NAME, BASE_DIR


router = APIRouter(tags=["ui"])
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@router.get("/")
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "app_name": APP_NAME,
        },
    )

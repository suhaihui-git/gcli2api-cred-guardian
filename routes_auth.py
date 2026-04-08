from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from config import APP_NAME, BASE_DIR
from models import AccessPasswordLoginRequest, AccessPasswordSetupRequest
from security import AccessAuthService


router = APIRouter(tags=["auth"])
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def get_auth_service(request: Request) -> AccessAuthService:
    return request.app.state.auth_service


@router.get("/login")
async def login_page(request: Request):
    auth_service = get_auth_service(request)
    if auth_service.is_authenticated(request):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "request": request,
            "app_name": APP_NAME,
            "password_configured": auth_service.is_password_configured(),
        },
    )


@router.post("/auth/login")
async def login(request: Request, payload: AccessPasswordLoginRequest):
    auth_service = get_auth_service(request)
    if not auth_service.is_password_configured():
        raise HTTPException(status_code=409, detail="尚未设置访问密码，请先完成初始化。")
    if not auth_service.verify_password(payload.password):
        raise HTTPException(status_code=401, detail="访问密码错误。")

    token, expires_at = auth_service.create_session()
    response = JSONResponse(
        {
            "ok": True,
            "message": "登录成功。",
            "expires_at": expires_at,
        }
    )
    auth_service.attach_session_cookie(response, token=token, request=request)
    return response


@router.post("/auth/setup")
async def setup(request: Request, payload: AccessPasswordSetupRequest):
    auth_service = get_auth_service(request)
    if auth_service.is_password_configured():
        raise HTTPException(status_code=409, detail="访问密码已设置，请直接登录。")

    try:
        password = auth_service.validate_new_password(
            password=payload.password,
            confirm_password=payload.confirm_password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    auth_service.set_password(password)
    token, expires_at = auth_service.create_session()
    response = JSONResponse(
        {
            "ok": True,
            "message": "访问密码已设置。",
            "expires_at": expires_at,
        }
    )
    auth_service.attach_session_cookie(response, token=token, request=request)
    return response


@router.post("/auth/logout")
async def logout(request: Request):
    auth_service = get_auth_service(request)
    auth_service.revoke_session(request)
    response = JSONResponse(
        {
            "ok": True,
            "message": "已退出登录。",
        }
    )
    auth_service.clear_session_cookie(response, request=request)
    return response

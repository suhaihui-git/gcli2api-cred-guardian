from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from client import TargetApiError, TargetServiceClient
from config import CHANNEL_TO_MODE, CHANNELS, MAX_HISTORY_LIMIT
from models import (
    AccessPasswordChangeRequest,
    ConnectionTestRequest,
    GuardianConfig,
    RuntimeChannelState,
    RuntimeStatusResponse,
    model_to_dict,
)
from security import AccessAuthService
from scheduler import GuardianScheduler
from storage import Storage


router = APIRouter(prefix="/api", tags=["api"])


def get_storage(request: Request) -> Storage:
    return request.app.state.storage


def get_scheduler(request: Request) -> GuardianScheduler:
    return request.app.state.scheduler


def get_auth_service(request: Request) -> AccessAuthService:
    return request.app.state.auth_service


def build_runtime_payload(storage: Storage, scheduler: GuardianScheduler) -> dict:
    config = storage.get_config()
    channel_states = storage.get_channel_states()
    snapshot = scheduler.snapshot(config)
    channels = {}
    for channel in CHANNELS:
        settings = config.channels[channel]
        state = channel_states[channel]
        model = RuntimeChannelState(
            channel=channel,
            mode=CHANNEL_TO_MODE[channel],
            enabled=settings.enabled,
            whitelist=settings.whitelist,
            stats={
                "total": state["last_total"],
                "normal": state["last_normal"],
                "disabled": state["last_disabled"],
            },
            last_scan_at=state["last_scan_at"],
            last_scan_status=state["last_scan_status"],
            last_scan_message=state["last_scan_message"],
            last_action_at=state["last_action_at"],
            last_action_status=state["last_action_status"],
            last_action_message=state["last_action_message"],
            last_action_filenames=state["last_action_filenames"],
        )
        channels[channel] = model
    payload = RuntimeStatusResponse(
        configured=snapshot["configured"],
        scheduler_running=snapshot["scheduler_running"],
        scan_in_progress=snapshot["scan_in_progress"],
        last_cycle_started_at=snapshot["last_cycle_started_at"],
        last_cycle_finished_at=snapshot["last_cycle_finished_at"],
        next_scheduled_at=snapshot["next_scheduled_at"],
        last_error=snapshot["last_error"],
        channels=channels,
    )
    return model_to_dict(payload)


@router.get("/config")
async def get_config(request: Request):
    storage = get_storage(request)
    return model_to_dict(storage.get_config())


@router.post("/config")
async def save_config(request: Request, payload: GuardianConfig):
    storage = get_storage(request)
    scheduler = get_scheduler(request)
    config = storage.save_config(payload.normalized())
    scheduler.notify_config_changed()
    return {
        "ok": True,
        "message": "配置已保存。",
        "config": model_to_dict(config),
    }


@router.post("/test-connection")
async def test_connection(payload: ConnectionTestRequest):
    normalized = payload.normalized()
    if not normalized.target_base_url or not normalized.panel_password:
        raise HTTPException(status_code=400, detail="目标服务地址和面板密码不能为空。")

    try:
        async with TargetServiceClient(
            base_url=normalized.target_base_url,
            panel_password=normalized.panel_password,
            timeout=normalized.request_timeout_seconds,
        ) as client:
            await client.login()
            channel_results = {}
            for channel, mode in CHANNEL_TO_MODE.items():
                status = await client.get_status(mode)
                channel_results[channel] = status.get("stats") or {"total": 0, "normal": 0, "disabled": 0}
    except TargetApiError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc

    return {
        "ok": True,
        "message": "连接测试成功。",
        "channels": channel_results,
    }


@router.get("/runtime-status")
async def runtime_status(request: Request):
    return build_runtime_payload(get_storage(request), get_scheduler(request))


@router.post("/scan-now")
async def scan_now(request: Request):
    scheduler = get_scheduler(request)
    return await scheduler.scan_now()


@router.post("/scan-now/{channel}")
async def scan_channel(request: Request, channel: str):
    if channel not in CHANNELS:
        raise HTTPException(status_code=404, detail="未知渠道。")
    scheduler = get_scheduler(request)
    return await scheduler.scan_now(channel=channel)


@router.post("/access-password")
async def change_access_password(request: Request, payload: AccessPasswordChangeRequest):
    auth_service = get_auth_service(request)
    if not auth_service.is_password_configured():
        raise HTTPException(status_code=409, detail="尚未设置访问密码，请先完成初始化。")
    if not auth_service.verify_password(payload.current_password):
        raise HTTPException(status_code=400, detail="当前访问密码不正确。")

    try:
        new_password = auth_service.validate_new_password(
            password=payload.new_password,
            confirm_password=payload.confirm_password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    auth_service.set_password(new_password)
    token, expires_at = auth_service.create_session()
    response = JSONResponse(
        {
            "ok": True,
            "message": "访问密码已修改。",
            "expires_at": expires_at,
        }
    )
    auth_service.attach_session_cookie(response, token=token, request=request)
    return response


@router.get("/history")
async def history(request: Request, limit: int = 50):
    storage = get_storage(request)
    effective_limit = max(1, min(limit, MAX_HISTORY_LIMIT))
    return {
        "items": storage.list_history(effective_limit),
    }

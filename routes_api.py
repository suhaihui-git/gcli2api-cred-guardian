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
    WhitelistValidationChannelResult,
    WhitelistValidationResponse,
    model_to_dict,
)
from security import AccessAuthService
from scheduler import GuardianScheduler
from storage import Storage


router = APIRouter(prefix="/api", tags=["api"])
CHANNEL_LABELS = {
    "cli": "CLI",
    "ant": "ANT",
}


def get_storage(request: Request) -> Storage:
    return request.app.state.storage


def get_scheduler(request: Request) -> GuardianScheduler:
    return request.app.state.scheduler


def get_auth_service(request: Request) -> AccessAuthService:
    return request.app.state.auth_service


def _default_whitelist_validation_result(whitelist: list[str]) -> WhitelistValidationChannelResult:
    if whitelist:
        return WhitelistValidationChannelResult(
            checked=False,
            valid=True,
            whitelist_count=len(whitelist),
            message="等待校验。",
        )
    return WhitelistValidationChannelResult(
        checked=False,
        valid=True,
        whitelist_count=0,
        message="未填写白名单。",
    )


def _build_whitelist_validation_error(response: WhitelistValidationResponse) -> str:
    parts: list[str] = []
    for channel in CHANNELS:
        result = response.channels[channel]
        if not result.checked or result.valid:
            continue
        label = CHANNEL_LABELS.get(channel, channel)
        filenames = "、".join(result.missing_filenames)
        parts.append(f"{label} 缺少 {filenames}")

    if not parts:
        return "白名单校验失败。"
    return f"白名单校验失败：{'；'.join(parts)}。请先确认这些文件已经存在于目标服务器。"


def _channels_requiring_whitelist_validation(
    current_config: GuardianConfig,
    incoming_config: GuardianConfig,
) -> list[str]:
    connection_changed = any(
        [
            current_config.target_base_url != incoming_config.target_base_url,
            current_config.panel_password != incoming_config.panel_password,
            current_config.request_timeout_seconds != incoming_config.request_timeout_seconds,
        ]
    )
    if connection_changed:
        return [
            channel
            for channel in CHANNELS
            if incoming_config.channels[channel].whitelist
        ]

    return [
        channel
        for channel in CHANNELS
        if incoming_config.channels[channel].whitelist
        and incoming_config.channels[channel].whitelist != current_config.channels[channel].whitelist
    ]


async def validate_config_whitelists(
    config: GuardianConfig,
    *,
    channels_to_check: list[str] | None = None,
) -> WhitelistValidationResponse:
    normalized = config.normalized()
    results = {
        channel: _default_whitelist_validation_result(normalized.channels[channel].whitelist)
        for channel in CHANNELS
    }
    candidate_channels = channels_to_check if channels_to_check is not None else list(CHANNELS)
    target_channels = [
        channel
        for channel in candidate_channels
        if channel in CHANNELS and normalized.channels[channel].whitelist
    ]
    if not target_channels:
        return WhitelistValidationResponse(ok=True, channels=results)

    if not normalized.target_base_url or not normalized.panel_password:
        raise HTTPException(status_code=400, detail="校验白名单前，请先填写目标服务地址和面板密码。")

    try:
        async with TargetServiceClient(
            base_url=normalized.target_base_url,
            panel_password=normalized.panel_password,
            timeout=normalized.request_timeout_seconds,
        ) as client:
            await client.login()
            remote_filenames = {
                channel: set(await client.list_filenames(CHANNEL_TO_MODE[channel]))
                for channel in target_channels
            }
    except TargetApiError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc

    for channel in target_channels:
        whitelist = normalized.channels[channel].whitelist
        missing_filenames = [
            filename for filename in whitelist if filename not in remote_filenames.get(channel, set())
        ]
        if missing_filenames:
            results[channel] = WhitelistValidationChannelResult(
                checked=True,
                valid=False,
                whitelist_count=len(whitelist),
                missing_filenames=missing_filenames,
                message=f"以下文件在目标服务器不存在：{'、'.join(missing_filenames)}",
            )
            continue

        results[channel] = WhitelistValidationChannelResult(
            checked=True,
            valid=True,
            whitelist_count=len(whitelist),
            message=f"已校验，通过 {len(whitelist)} 个文件。",
        )

    ok = all(result.valid for result in results.values())
    return WhitelistValidationResponse(ok=ok, channels=results)


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
    current_config = storage.get_config()
    normalized = payload.normalized()
    validation_channels = _channels_requiring_whitelist_validation(current_config, normalized)
    if validation_channels:
        validation_response = await validate_config_whitelists(
            normalized,
            channels_to_check=validation_channels,
        )
        if not validation_response.ok:
            raise HTTPException(status_code=400, detail=_build_whitelist_validation_error(validation_response))

    config = storage.save_config(normalized)
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


@router.post("/validate-whitelists")
async def validate_whitelists(payload: GuardianConfig):
    response = await validate_config_whitelists(payload)
    return model_to_dict(response)


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

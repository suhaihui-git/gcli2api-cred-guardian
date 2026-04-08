from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from config import (
    CHANNELS,
    DEFAULT_ENABLE_BATCH_SIZE,
    DEFAULT_POLL_INTERVAL_SECONDS,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_TARGET_BASE_URL,
    normalize_base_url,
    normalize_whitelist,
)


def model_to_dict(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


class ChannelSettings(BaseModel):
    enabled: bool = True
    whitelist: list[str] = Field(default_factory=list)


class GuardianConfig(BaseModel):
    target_base_url: str = DEFAULT_TARGET_BASE_URL
    panel_password: str = ""
    poll_interval_seconds: int = Field(default=DEFAULT_POLL_INTERVAL_SECONDS, ge=5, le=86400)
    request_timeout_seconds: float = Field(default=DEFAULT_REQUEST_TIMEOUT_SECONDS, gt=0, le=300)
    enable_batch_size: int = Field(default=DEFAULT_ENABLE_BATCH_SIZE, ge=1, le=100)
    channels: dict[str, ChannelSettings] = Field(
        default_factory=lambda: {channel: ChannelSettings() for channel in CHANNELS}
    )

    def normalized(self) -> "GuardianConfig":
        channels: dict[str, ChannelSettings] = {}
        for channel in CHANNELS:
            channel_settings = self.channels.get(channel, ChannelSettings())
            channels[channel] = ChannelSettings(
                enabled=bool(channel_settings.enabled),
                whitelist=normalize_whitelist(channel_settings.whitelist),
            )
        return GuardianConfig(
            target_base_url=normalize_base_url(self.target_base_url),
            panel_password=self.panel_password.strip(),
            poll_interval_seconds=self.poll_interval_seconds,
            request_timeout_seconds=self.request_timeout_seconds,
            enable_batch_size=self.enable_batch_size,
            channels=channels,
        )

    @property
    def is_configured(self) -> bool:
        return bool(self.target_base_url.strip() and self.panel_password.strip())


class ConnectionTestRequest(BaseModel):
    target_base_url: str = DEFAULT_TARGET_BASE_URL
    panel_password: str = ""
    request_timeout_seconds: float = Field(default=DEFAULT_REQUEST_TIMEOUT_SECONDS, gt=0, le=300)

    def normalized(self) -> "ConnectionTestRequest":
        return ConnectionTestRequest(
            target_base_url=normalize_base_url(self.target_base_url),
            panel_password=self.panel_password.strip(),
            request_timeout_seconds=self.request_timeout_seconds,
        )


class WhitelistValidationChannelResult(BaseModel):
    checked: bool = False
    valid: bool = True
    whitelist_count: int = 0
    missing_filenames: list[str] = Field(default_factory=list)
    message: str = ""


class WhitelistValidationResponse(BaseModel):
    ok: bool = True
    channels: dict[str, WhitelistValidationChannelResult]


class AccessPasswordLoginRequest(BaseModel):
    password: str = ""


class AccessPasswordSetupRequest(BaseModel):
    password: str = ""
    confirm_password: str = ""


class AccessPasswordChangeRequest(BaseModel):
    current_password: str = ""
    new_password: str = ""
    confirm_password: str = ""


class ChannelStats(BaseModel):
    total: int = 0
    normal: int = 0
    disabled: int = 0


class RuntimeChannelState(BaseModel):
    channel: str
    mode: str
    enabled: bool
    whitelist: list[str]
    stats: ChannelStats = Field(default_factory=ChannelStats)
    last_scan_at: str | None = None
    last_scan_status: str | None = None
    last_scan_message: str | None = None
    last_action_at: str | None = None
    last_action_status: str | None = None
    last_action_message: str | None = None
    last_action_filenames: list[str] = Field(default_factory=list)


class RuntimeStatusResponse(BaseModel):
    configured: bool
    scheduler_running: bool
    scan_in_progress: bool
    last_cycle_started_at: str | None = None
    last_cycle_finished_at: str | None = None
    next_scheduled_at: str | None = None
    last_error: str | None = None
    channels: dict[str, RuntimeChannelState]

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from client import TargetApiError, TargetServiceClient
from config import (
    CHANNEL_TO_MODE,
    CHANNELS,
    MIN_POLL_INTERVAL_SECONDS,
    iso_after_seconds,
    utc_now,
)
from models import GuardianConfig
from storage import Storage


@dataclass
class ScanResult:
    channel: str
    mode: str
    status: str
    message: str
    total: int = 0
    normal: int = 0
    disabled: int = 0
    action_taken: bool = False
    action_status: str | None = None
    action_message: str | None = None
    attempted_filenames: list[str] | None = None
    successful_filenames: list[str] | None = None
    failed_filenames: list[str] | None = None


class GuardianScheduler:
    def __init__(self, storage: Storage):
        self.storage = storage
        self._task: asyncio.Task | None = None
        self._scan_lock = asyncio.Lock()
        self._wakeup = asyncio.Event()
        self.last_cycle_started_at: str | None = None
        self.last_cycle_finished_at: str | None = None
        self.next_scheduled_at: str | None = None
        self.last_error: str | None = None

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._wakeup.clear()
        self._task = asyncio.create_task(self._run_loop(), name="cred_guardian_scheduler")

    async def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        self.next_scheduled_at = None

    def notify_config_changed(self) -> None:
        self._wakeup.set()

    def snapshot(self, config: GuardianConfig) -> dict[str, Any]:
        return {
            "configured": config.is_configured,
            "scheduler_running": self.is_running,
            "scan_in_progress": self._scan_lock.locked(),
            "last_cycle_started_at": self.last_cycle_started_at,
            "last_cycle_finished_at": self.last_cycle_finished_at,
            "next_scheduled_at": self.next_scheduled_at,
            "last_error": self.last_error,
        }

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def scan_now(self, channel: str | None = None) -> dict[str, Any]:
        return await self._scan(trigger_type="manual", channel=channel)

    async def _run_loop(self) -> None:
        await self._scan(trigger_type="startup", channel=None)

        while True:
            config = self.storage.get_config()
            delay = max(config.poll_interval_seconds, MIN_POLL_INTERVAL_SECONDS)
            self.next_scheduled_at = iso_after_seconds(delay)
            self._wakeup.clear()
            try:
                await asyncio.wait_for(self._wakeup.wait(), timeout=delay)
                continue
            except asyncio.TimeoutError:
                pass

            await self._scan(trigger_type="scheduled", channel=None)

    async def _scan(self, *, trigger_type: str, channel: str | None) -> dict[str, Any]:
        if self._scan_lock.locked():
            return {
                "ok": False,
                "message": "已有扫描任务正在执行。",
                "results": [],
            }

        async with self._scan_lock:
            self.last_cycle_started_at = utc_now().isoformat()
            self.last_error = None
            config = self.storage.get_config()

            if not config.is_configured:
                self.last_cycle_finished_at = utc_now().isoformat()
                self.last_error = "尚未配置目标服务。"
                return {
                    "ok": False,
                    "message": "尚未配置目标服务。",
                    "results": [],
                }

            channels = [channel] if channel else list(CHANNELS)
            try:
                async with TargetServiceClient(
                    base_url=config.target_base_url,
                    panel_password=config.panel_password,
                    timeout=config.request_timeout_seconds,
                ) as client:
                    results = []
                    for item in channels:
                        results.append(
                            await self._scan_channel(
                                client=client,
                                config=config,
                                channel=item,
                                trigger_type=trigger_type,
                            )
                        )
            except TargetApiError as exc:
                for item in channels:
                    finished_at = utc_now().isoformat()
                    self.storage.record_scan(
                        channel=item,
                        trigger_type=trigger_type,
                        started_at=self.last_cycle_started_at,
                        finished_at=finished_at,
                        status="error",
                        total=0,
                        normal=0,
                        disabled=0,
                        action_taken=False,
                        message=exc.message,
                        error_detail=exc.message,
                    )
                self.last_cycle_finished_at = utc_now().isoformat()
                self.last_error = exc.message
                return {
                    "ok": False,
                    "message": exc.message,
                    "results": [],
                }

            self.last_cycle_finished_at = utc_now().isoformat()
            if any(result.status == "error" for result in results):
                self.last_error = "一个或多个渠道扫描失败。"

            return {
                "ok": True,
                "message": "扫描完成。",
                "results": [self._scan_result_to_dict(result) for result in results],
            }

    async def _scan_channel(
        self,
        *,
        client: TargetServiceClient,
        config: GuardianConfig,
        channel: str,
        trigger_type: str,
    ) -> ScanResult:
        started_at = utc_now().isoformat()
        mode = CHANNEL_TO_MODE[channel]
        channel_settings = config.channels[channel]

        try:
            status_payload = await client.get_status(mode)
        except TargetApiError as exc:
            finished_at = utc_now().isoformat()
            self.storage.record_scan(
                channel=channel,
                trigger_type=trigger_type,
                started_at=started_at,
                finished_at=finished_at,
                status="error",
                total=0,
                normal=0,
                disabled=0,
                action_taken=False,
                message=exc.message,
                error_detail=exc.message,
            )
            return ScanResult(channel=channel, mode=mode, status="error", message=exc.message)

        stats = status_payload.get("stats") or {}
        total = int(stats.get("total", 0) or 0)
        normal = int(stats.get("normal", 0) or 0)
        disabled = int(stats.get("disabled", 0) or 0)

        if normal > 0:
            finished_at = utc_now().isoformat()
            message = f"{channel} 渠道当前有 {normal} 个正常凭证，无需处理。"
            self.storage.record_scan(
                channel=channel,
                trigger_type=trigger_type,
                started_at=started_at,
                finished_at=finished_at,
                status="ok",
                total=total,
                normal=normal,
                disabled=disabled,
                action_taken=False,
                message=message,
            )
            return ScanResult(
                channel=channel,
                mode=mode,
                status="ok",
                message=message,
                total=total,
                normal=normal,
                disabled=disabled,
            )

        if not channel_settings.enabled:
            finished_at = utc_now().isoformat()
            message = f"{channel} 渠道正常凭证为 0，但自动启用开关已关闭。"
            self.storage.record_scan(
                channel=channel,
                trigger_type=trigger_type,
                started_at=started_at,
                finished_at=finished_at,
                status="warning",
                total=total,
                normal=normal,
                disabled=disabled,
                action_taken=False,
                message=message,
            )
            return ScanResult(
                channel=channel,
                mode=mode,
                status="warning",
                message=message,
                total=total,
                normal=normal,
                disabled=disabled,
            )

        whitelist = channel_settings.whitelist
        if not whitelist:
            finished_at = utc_now().isoformat()
            message = f"{channel} 渠道正常凭证为 0，且白名单为空。"
            self.storage.record_scan(
                channel=channel,
                trigger_type=trigger_type,
                started_at=started_at,
                finished_at=finished_at,
                status="warning",
                total=total,
                normal=normal,
                disabled=disabled,
                action_taken=False,
                message=message,
            )
            return ScanResult(
                channel=channel,
                mode=mode,
                status="warning",
                message=message,
                total=total,
                normal=normal,
                disabled=disabled,
            )

        requested = whitelist[: config.enable_batch_size]
        action_result = await self._attempt_enable(
            client=client,
            channel=channel,
            mode=mode,
            trigger_type=trigger_type,
            config=config,
            requested=requested,
        )

        refresh_error: str | None = None
        try:
            refreshed_status = await client.get_status(mode)
            refreshed_stats = refreshed_status.get("stats") or {}
            total = int(refreshed_stats.get("total", total) or total)
            normal = int(refreshed_stats.get("normal", normal) or normal)
            disabled = int(refreshed_stats.get("disabled", disabled) or disabled)
        except TargetApiError as exc:
            refresh_error = exc.message

        finished_at = utc_now().isoformat()
        message = action_result["message"]
        if refresh_error:
            message = f"{message} 刷新状态失败：{refresh_error}"

        self.storage.record_scan(
            channel=channel,
            trigger_type=trigger_type,
            started_at=started_at,
            finished_at=finished_at,
            status=action_result["status"],
            total=total,
            normal=normal,
            disabled=disabled,
            action_taken=True,
            message=message,
            error_detail=(refresh_error or action_result["message"])
            if action_result["status"] == "error"
            else None,
        )
        return ScanResult(
            channel=channel,
            mode=mode,
            status=action_result["status"],
            message=message,
            total=total,
            normal=normal,
            disabled=disabled,
            action_taken=True,
            action_status=action_result["status"],
            action_message=action_result["message"],
            attempted_filenames=action_result["attempted_filenames"],
            successful_filenames=action_result["successful_filenames"],
            failed_filenames=action_result["failed_filenames"],
        )

    async def _attempt_enable(
        self,
        *,
        client: TargetServiceClient,
        channel: str,
        mode: str,
        trigger_type: str,
        config: GuardianConfig,
        requested: list[str],
    ) -> dict[str, Any]:
        attempted: list[str] = []
        successful: list[str] = []
        failed: list[str] = []
        failure_details: list[str] = []
        batch_exception: str | None = None
        fallback_used = False
        pending_retry: list[str] = []

        try:
            batch_response = await client.batch_enable(mode, requested)
            attempted = list(requested)
            batch_success = int(batch_response.get("success_count", 0) or 0)
            batch_errors = batch_response.get("errors") or []
            batch_failed_map = self._parse_batch_errors(batch_errors)
            if batch_success == len(requested) and not batch_failed_map:
                successful = list(requested)
            else:
                fallback_used = True
                if batch_failed_map:
                    matched_failures = [filename for filename in requested if filename in batch_failed_map]
                    if matched_failures:
                        pending_retry = matched_failures
                        successful = [filename for filename in requested if filename not in batch_failed_map]
                    else:
                        pending_retry = list(requested)
                    failure_details.extend(batch_failed_map.values())
                else:
                    pending_retry = list(requested)
        except TargetApiError as exc:
            fallback_used = True
            batch_exception = exc.message
            pending_retry = list(requested)

        if fallback_used:
            retried_successful: list[str] = []
            retried_failed: list[str] = []
            retry_targets = pending_retry or list(requested)
            attempted = list(dict.fromkeys((attempted or []) + retry_targets))
            for filename in retry_targets:
                try:
                    await client.enable_one(mode, filename)
                    retried_successful.append(filename)
                except TargetApiError as exc:
                    retried_failed.append(filename)
                    failure_details.append(f"{filename}: {exc.message}")

            successful = list(dict.fromkeys(successful + retried_successful))
            failed = list(dict.fromkeys(retried_failed))

        status = "ok"
        if failed and successful:
            status = "partial"
        elif failed and not successful:
            status = "error"

        if successful and not failed:
            message = f"已为 {channel} 渠道自动启用 {len(successful)}/{len(requested)} 个凭证。"
        elif successful and failed:
            message = f"已为 {channel} 渠道自动启用 {len(successful)}/{len(requested)} 个凭证，部分文件失败。"
        else:
            message = f"未能为 {channel} 渠道自动启用任何凭证。"

        if fallback_used:
            message = f"{message} 已降级为逐个启用。"
        if batch_exception:
            message = f"{message} 批量启用错误：{batch_exception}"
        if failed:
            message = f"{message} 失败文件：{', '.join(failed)}"
        if failure_details:
            detail_summary = "; ".join(dict.fromkeys(failure_details))
            message = f"{message} 详情：{detail_summary}"

        removed_from_whitelist: list[str] = []
        if successful:
            removed_from_whitelist = self.storage.remove_whitelist_filenames(
                channel=channel,
                filenames=successful,
            )
            if removed_from_whitelist:
                message = f"{message} 已自动从白名单移除 {len(removed_from_whitelist)} 个已启用文件。"

        created_at = utc_now().isoformat()
        self.storage.record_action(
            channel=channel,
            trigger_type=trigger_type,
            created_at=created_at,
            status=status,
            requested_filenames=requested,
            attempted_filenames=attempted or list(requested),
            successful_filenames=successful,
            failed_filenames=failed,
            message=message,
        )
        return {
            "status": status,
            "message": message,
            "attempted_filenames": attempted or list(requested),
            "successful_filenames": successful,
            "failed_filenames": failed,
        }

    @staticmethod
    def _parse_batch_errors(items: list[Any]) -> dict[str, str]:
        failed_map: dict[str, str] = {}
        for raw_item in items:
            text = str(raw_item).strip()
            if not text:
                continue
            filename, separator, detail = text.partition(":")
            if separator and filename.strip():
                failed_map[filename.strip()] = text
            else:
                failed_map[text] = text
        return failed_map

    @staticmethod
    def _scan_result_to_dict(result: ScanResult) -> dict[str, Any]:
        return {
            "channel": result.channel,
            "mode": result.mode,
            "status": result.status,
            "message": result.message,
            "total": result.total,
            "normal": result.normal,
            "disabled": result.disabled,
            "action_taken": result.action_taken,
            "action_status": result.action_status,
            "action_message": result.action_message,
            "attempted_filenames": result.attempted_filenames or [],
            "successful_filenames": result.successful_filenames or [],
            "failed_filenames": result.failed_filenames or [],
        }

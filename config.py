from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path


APP_NAME = "凭证守护程序"
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "cred_guardian.sqlite3"

# 目标服务当前只保留 Antigravity 凭证池。
# 内部键继续使用 ant，便于兼容守护程序已有的 SQLite 配置。
CHANNEL = "ant"
CHANNEL_LABEL = "Antigravity"
CHANNELS = (CHANNEL,)

DEFAULT_TARGET_BASE_URL = "http://127.0.0.1:7861"
DEFAULT_POLL_INTERVAL_SECONDS = 60
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10.0
DEFAULT_ENABLE_BATCH_SIZE = 1
ACCESS_SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
ACCESS_PASSWORD_MIN_LENGTH = 8

MIN_POLL_INTERVAL_SECONDS = 5
MAX_HISTORY_LIMIT = 200


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def iso_after_seconds(seconds: float) -> str:
    return (utc_now() + timedelta(seconds=seconds)).isoformat()


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def normalize_base_url(value: str) -> str:
    return value.strip().rstrip("/")


def normalize_whitelist(items: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_item in items:
        item = raw_item.strip()
        if not item or item in seen:
            continue
        normalized.append(item)
        seen.add(item)
    return normalized

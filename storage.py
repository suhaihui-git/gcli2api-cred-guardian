from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from config import CHANNELS, DB_PATH, parse_datetime, utc_now, utc_now_iso
from models import ChannelSettings, GuardianConfig


class Storage:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=MEMORY")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS app_config (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    target_base_url TEXT NOT NULL DEFAULT '',
                    panel_password TEXT NOT NULL DEFAULT '',
                    poll_interval_seconds INTEGER NOT NULL DEFAULT 60,
                    request_timeout_seconds REAL NOT NULL DEFAULT 10,
                    enable_batch_size INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS channel_config (
                    channel TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    whitelist_json TEXT NOT NULL DEFAULT '[]',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS channel_state (
                    channel TEXT PRIMARY KEY,
                    last_total INTEGER NOT NULL DEFAULT 0,
                    last_normal INTEGER NOT NULL DEFAULT 0,
                    last_disabled INTEGER NOT NULL DEFAULT 0,
                    last_scan_at TEXT,
                    last_scan_status TEXT,
                    last_scan_message TEXT,
                    last_action_at TEXT,
                    last_action_status TEXT,
                    last_action_message TEXT,
                    last_action_filenames_json TEXT NOT NULL DEFAULT '[]'
                );

                CREATE TABLE IF NOT EXISTS history_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    trigger_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    total INTEGER,
                    normal INTEGER,
                    disabled INTEGER,
                    action_taken INTEGER NOT NULL DEFAULT 0,
                    requested_filenames_json TEXT NOT NULL DEFAULT '[]',
                    attempted_filenames_json TEXT NOT NULL DEFAULT '[]',
                    successful_filenames_json TEXT NOT NULL DEFAULT '[]',
                    failed_filenames_json TEXT NOT NULL DEFAULT '[]',
                    success_count INTEGER NOT NULL DEFAULT 0,
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    message TEXT NOT NULL,
                    error_detail TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_history_entries_occurred_at
                ON history_entries (occurred_at DESC, id DESC);

                CREATE TABLE IF NOT EXISTS access_security (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    password_hash TEXT NOT NULL DEFAULT '',
                    password_salt TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS auth_sessions (
                    token_hash TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL
                );

                DROP TABLE IF EXISTS scan_history;
                DROP TABLE IF EXISTS action_history;
                """
            )
            self._conn.execute(
                """
                INSERT OR IGNORE INTO app_config (
                    singleton,
                    target_base_url,
                    panel_password,
                    poll_interval_seconds,
                    request_timeout_seconds,
                    enable_batch_size,
                    updated_at
                ) VALUES (1, '', '', 60, 10, 1, ?)
                """,
                (utc_now_iso(),),
            )
            for channel in CHANNELS:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO channel_config (channel, enabled, whitelist_json, updated_at)
                    VALUES (?, 1, '[]', ?)
                    """,
                    (channel, utc_now_iso()),
                )
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO channel_state (
                        channel,
                        last_total,
                        last_normal,
                        last_disabled,
                        last_action_filenames_json
                    ) VALUES (?, 0, 0, 0, '[]')
                    """,
                    (channel,),
                )
            self._conn.execute(
                """
                INSERT OR IGNORE INTO access_security (singleton, password_hash, password_salt, updated_at)
                VALUES (1, '', '', ?)
                """,
                (utc_now_iso(),),
            )
            self._conn.execute(
                """
                DELETE FROM auth_sessions
                WHERE expires_at <= ?
                """,
                (utc_now_iso(),),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def get_config(self) -> GuardianConfig:
        row = self._fetchone("SELECT * FROM app_config WHERE singleton = 1")
        if row is None:
            config = GuardianConfig()
            self.save_config(config)
            return config

        channel_rows = self._fetchall("SELECT * FROM channel_config ORDER BY channel ASC")
        channels = {
            channel_row["channel"]: ChannelSettings(
                enabled=bool(channel_row["enabled"]),
                whitelist=self._json_loads(channel_row["whitelist_json"], []),
            )
            for channel_row in channel_rows
        }
        config = GuardianConfig(
            target_base_url=row["target_base_url"],
            panel_password=row["panel_password"],
            poll_interval_seconds=row["poll_interval_seconds"],
            request_timeout_seconds=row["request_timeout_seconds"],
            enable_batch_size=row["enable_batch_size"],
            channels=channels,
        )
        return config.normalized()

    def save_config(self, config: GuardianConfig) -> GuardianConfig:
        normalized = config.normalized()
        now = utc_now_iso()
        with self._lock:
            conn = self._require_conn()
            conn.execute(
                """
                UPDATE app_config
                SET target_base_url = ?,
                    panel_password = ?,
                    poll_interval_seconds = ?,
                    request_timeout_seconds = ?,
                    enable_batch_size = ?,
                    updated_at = ?
                WHERE singleton = 1
                """,
                (
                    normalized.target_base_url,
                    normalized.panel_password,
                    normalized.poll_interval_seconds,
                    normalized.request_timeout_seconds,
                    normalized.enable_batch_size,
                    now,
                ),
            )
            for channel in CHANNELS:
                channel_settings = normalized.channels[channel]
                conn.execute(
                    """
                    UPDATE channel_config
                    SET enabled = ?,
                        whitelist_json = ?,
                        updated_at = ?
                    WHERE channel = ?
                    """,
                    (
                        1 if channel_settings.enabled else 0,
                        json.dumps(channel_settings.whitelist, ensure_ascii=False),
                        now,
                        channel,
                    ),
                )
            conn.commit()
        return normalized

    def remove_whitelist_filenames(self, *, channel: str, filenames: list[str]) -> list[str]:
        targets = {item.strip() for item in filenames if item and item.strip()}
        if not targets:
            return []

        with self._lock:
            conn = self._require_conn()
            row = conn.execute(
                """
                SELECT whitelist_json
                FROM channel_config
                WHERE channel = ?
                """,
                (channel,),
            ).fetchone()
            if row is None:
                return []

            current = self._json_loads(row["whitelist_json"], [])
            remaining: list[str] = []
            removed: list[str] = []
            for item in current:
                if item in targets:
                    removed.append(item)
                else:
                    remaining.append(item)

            if not removed:
                return []

            conn.execute(
                """
                UPDATE channel_config
                SET whitelist_json = ?,
                    updated_at = ?
                WHERE channel = ?
                """,
                (
                    json.dumps(remaining, ensure_ascii=False),
                    utc_now_iso(),
                    channel,
                ),
            )
            conn.commit()
            return removed

    def get_access_security(self) -> dict[str, str]:
        row = self._fetchone("SELECT * FROM access_security WHERE singleton = 1")
        if row is None:
            now = utc_now_iso()
            with self._lock:
                conn = self._require_conn()
                conn.execute(
                    """
                    INSERT INTO access_security (singleton, password_hash, password_salt, updated_at)
                    VALUES (1, '', '', ?)
                    """,
                    (now,),
                )
                conn.commit()
            return {
                "password_hash": "",
                "password_salt": "",
                "updated_at": now,
            }
        return {
            "password_hash": row["password_hash"],
            "password_salt": row["password_salt"],
            "updated_at": row["updated_at"],
        }

    def is_access_password_configured(self) -> bool:
        security = self.get_access_security()
        return bool(security["password_hash"] and security["password_salt"])

    def set_access_password(self, *, password_hash: str, password_salt: str) -> None:
        now = utc_now_iso()
        with self._lock:
            conn = self._require_conn()
            conn.execute(
                """
                UPDATE access_security
                SET password_hash = ?,
                    password_salt = ?,
                    updated_at = ?
                WHERE singleton = 1
                """,
                (password_hash, password_salt, now),
            )
            conn.execute("DELETE FROM auth_sessions")
            conn.commit()

    def create_auth_session(self, *, token_hash: str, expires_at: str) -> None:
        now = utc_now_iso()
        with self._lock:
            conn = self._require_conn()
            conn.execute(
                """
                DELETE FROM auth_sessions
                WHERE expires_at <= ?
                """,
                (now,),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO auth_sessions (token_hash, created_at, expires_at, last_seen_at)
                VALUES (?, ?, ?, ?)
                """,
                (token_hash, now, expires_at, now),
            )
            conn.commit()

    def touch_auth_session(self, *, token_hash: str) -> bool:
        now_dt = utc_now()
        now = now_dt.isoformat()
        row = self._fetchone(
            """
            SELECT *
            FROM auth_sessions
            WHERE token_hash = ?
            """,
            (token_hash,),
        )
        if row is None:
            return False

        expires_at = parse_datetime(row["expires_at"])
        if expires_at is None or expires_at <= now_dt:
            self.delete_auth_session(token_hash=token_hash)
            return False

        with self._lock:
            conn = self._require_conn()
            conn.execute(
                """
                UPDATE auth_sessions
                SET last_seen_at = ?
                WHERE token_hash = ?
                """,
                (now, token_hash),
            )
            conn.commit()
        return True

    def delete_auth_session(self, *, token_hash: str) -> None:
        with self._lock:
            conn = self._require_conn()
            conn.execute(
                """
                DELETE FROM auth_sessions
                WHERE token_hash = ?
                """,
                (token_hash,),
            )
            conn.commit()

    def get_channel_states(self) -> dict[str, dict[str, Any]]:
        rows = self._fetchall("SELECT * FROM channel_state ORDER BY channel ASC")
        states: dict[str, dict[str, Any]] = {}
        for row in rows:
            states[row["channel"]] = self._channel_state_from_row(row)
        for channel in CHANNELS:
            states.setdefault(channel, self._default_channel_state())
        return states

    def record_scan(
        self,
        *,
        channel: str,
        trigger_type: str,
        started_at: str,
        finished_at: str,
        status: str,
        total: int,
        normal: int,
        disabled: int,
        action_taken: bool,
        message: str,
        error_detail: str | None = None,
    ) -> None:
        with self._lock:
            conn = self._require_conn()
            conn.execute(
                """
                INSERT INTO history_entries (
                    event_type,
                    channel,
                    trigger_type,
                    occurred_at,
                    started_at,
                    finished_at,
                    status,
                    total,
                    normal,
                    disabled,
                    action_taken,
                    message,
                    error_detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "scan",
                    channel,
                    trigger_type,
                    finished_at,
                    started_at,
                    finished_at,
                    status,
                    total,
                    normal,
                    disabled,
                    1 if action_taken else 0,
                    message,
                    error_detail,
                ),
            )
            conn.execute(
                """
                UPDATE channel_state
                SET last_total = ?,
                    last_normal = ?,
                    last_disabled = ?,
                    last_scan_at = ?,
                    last_scan_status = ?,
                    last_scan_message = ?
                WHERE channel = ?
                """,
                (total, normal, disabled, finished_at, status, message, channel),
            )
            conn.commit()

    def record_action(
        self,
        *,
        channel: str,
        trigger_type: str,
        created_at: str,
        status: str,
        requested_filenames: list[str],
        attempted_filenames: list[str],
        successful_filenames: list[str],
        failed_filenames: list[str],
        message: str,
    ) -> None:
        with self._lock:
            conn = self._require_conn()
            conn.execute(
                """
                INSERT INTO history_entries (
                    event_type,
                    channel,
                    trigger_type,
                    occurred_at,
                    status,
                    requested_filenames_json,
                    attempted_filenames_json,
                    successful_filenames_json,
                    failed_filenames_json,
                    success_count,
                    failure_count,
                    message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "action",
                    channel,
                    trigger_type,
                    created_at,
                    status,
                    json.dumps(requested_filenames, ensure_ascii=False),
                    json.dumps(attempted_filenames, ensure_ascii=False),
                    json.dumps(successful_filenames, ensure_ascii=False),
                    json.dumps(failed_filenames, ensure_ascii=False),
                    len(successful_filenames),
                    len(failed_filenames),
                    message,
                ),
            )
            conn.execute(
                """
                UPDATE channel_state
                SET last_action_at = ?,
                    last_action_status = ?,
                    last_action_message = ?,
                    last_action_filenames_json = ?
                WHERE channel = ?
                """,
                (
                    created_at,
                    status,
                    message,
                    json.dumps(successful_filenames or attempted_filenames, ensure_ascii=False),
                    channel,
                ),
            )
            conn.commit()

    def list_history(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._fetchall(
            """
            SELECT *
            FROM history_entries
            ORDER BY occurred_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [self._history_row_to_dict(row) for row in rows]

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Storage has not been initialized.")
        return self._conn

    def _fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._require_conn().execute(sql, params).fetchone()

    def _fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._require_conn().execute(sql, params).fetchall()

    def _default_channel_state(self) -> dict[str, Any]:
        return {
            "last_total": 0,
            "last_normal": 0,
            "last_disabled": 0,
            "last_scan_at": None,
            "last_scan_status": None,
            "last_scan_message": None,
            "last_action_at": None,
            "last_action_status": None,
            "last_action_message": None,
            "last_action_filenames": [],
        }

    def _channel_state_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "last_total": row["last_total"],
            "last_normal": row["last_normal"],
            "last_disabled": row["last_disabled"],
            "last_scan_at": row["last_scan_at"],
            "last_scan_status": row["last_scan_status"],
            "last_scan_message": row["last_scan_message"],
            "last_action_at": row["last_action_at"],
            "last_action_status": row["last_action_status"],
            "last_action_message": row["last_action_message"],
            "last_action_filenames": self._json_loads(row["last_action_filenames_json"], []),
        }

    def _history_row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "event_type": row["event_type"],
            "channel": row["channel"],
            "trigger_type": row["trigger_type"],
            "occurred_at": row["occurred_at"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "status": row["status"],
            "total": row["total"],
            "normal": row["normal"],
            "disabled": row["disabled"],
            "action_taken": bool(row["action_taken"]),
            "requested_filenames": self._json_loads(row["requested_filenames_json"], []),
            "attempted_filenames": self._json_loads(row["attempted_filenames_json"], []),
            "successful_filenames": self._json_loads(row["successful_filenames_json"], []),
            "failed_filenames": self._json_loads(row["failed_filenames_json"], []),
            "success_count": row["success_count"],
            "failure_count": row["failure_count"],
            "message": row["message"],
            "error_detail": row["error_detail"],
        }

    @staticmethod
    def _json_loads(value: str | None, fallback: list[str]) -> list[str]:
        if not value:
            return fallback
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return fallback
        if isinstance(decoded, list):
            return [str(item) for item in decoded]
        return fallback

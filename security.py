from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import timedelta

from fastapi import Request
from fastapi.responses import Response

from config import ACCESS_PASSWORD_MIN_LENGTH, ACCESS_SESSION_MAX_AGE_SECONDS, utc_now
from storage import Storage


SESSION_COOKIE_NAME = "guardian_session"
PASSWORD_HASH_ITERATIONS = 310_000
PASSWORD_SALT_BYTES = 16


class AccessAuthService:
    def __init__(self, storage: Storage):
        self.storage = storage

    def is_password_configured(self) -> bool:
        return self.storage.is_access_password_configured()

    def verify_password(self, password: str) -> bool:
        security = self.storage.get_access_security()
        password_hash = security["password_hash"]
        password_salt = security["password_salt"]
        if not password_hash or not password_salt:
            return False
        calculated = self._hash_password(password=password, encoded_salt=password_salt)
        return hmac.compare_digest(calculated, password_hash)

    def validate_new_password(self, *, password: str, confirm_password: str) -> str:
        value = password.strip()
        if len(value) < ACCESS_PASSWORD_MIN_LENGTH:
            raise ValueError(f"访问密码长度不能少于 {ACCESS_PASSWORD_MIN_LENGTH} 位。")
        if value != confirm_password.strip():
            raise ValueError("两次输入的访问密码不一致。")
        return value

    def set_password(self, password: str) -> None:
        encoded_salt = base64.urlsafe_b64encode(secrets.token_bytes(PASSWORD_SALT_BYTES)).decode("ascii")
        password_hash = self._hash_password(password=password, encoded_salt=encoded_salt)
        self.storage.set_access_password(password_hash=password_hash, password_salt=encoded_salt)

    def create_session(self) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        expires_at = (utc_now() + timedelta(seconds=ACCESS_SESSION_MAX_AGE_SECONDS)).isoformat()
        self.storage.create_auth_session(token_hash=self._hash_token(token), expires_at=expires_at)
        return token, expires_at

    def is_authenticated(self, request: Request) -> bool:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if not token:
            return False
        return self.storage.touch_auth_session(token_hash=self._hash_token(token))

    def revoke_session(self, request: Request) -> None:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if not token:
            return
        self.storage.delete_auth_session(token_hash=self._hash_token(token))

    def attach_session_cookie(self, response: Response, *, token: str, request: Request) -> None:
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=token,
            max_age=ACCESS_SESSION_MAX_AGE_SECONDS,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path="/",
        )

    def clear_session_cookie(self, response: Response, *, request: Request) -> None:
        response.delete_cookie(
            key=SESSION_COOKIE_NAME,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path="/",
        )

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _hash_password(*, password: str, encoded_salt: str) -> str:
        salt = base64.urlsafe_b64decode(encoded_salt.encode("ascii"))
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PASSWORD_HASH_ITERATIONS,
        )
        return base64.urlsafe_b64encode(derived).decode("ascii")

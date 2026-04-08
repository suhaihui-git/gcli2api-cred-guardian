from __future__ import annotations

import json
from typing import Any

import httpx


class TargetApiError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class TargetServiceClient:
    def __init__(self, *, base_url: str, panel_password: str, timeout: float):
        self.base_url = base_url
        self.panel_password = panel_password
        self.timeout = timeout
        self._token: str | None = None
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)

    async def __aenter__(self) -> "TargetServiceClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def login(self) -> str:
        try:
            response = await self._client.post("/auth/login", json={"password": self.panel_password})
        except httpx.TimeoutException as exc:
            raise TargetApiError("登录请求超时。") from exc
        except httpx.RequestError as exc:
            raise TargetApiError(f"无法连接目标服务：{exc}") from exc

        if response.status_code >= 400:
            raise TargetApiError(self._error_message(response), status_code=response.status_code)

        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise TargetApiError("登录响应不是有效的 JSON。") from exc

        token = payload.get("token")
        if not token:
            raise TargetApiError("登录成功，但响应中没有返回令牌。")

        self._token = str(token)
        return self._token

    async def get_status(self, mode: str, *, offset: int = 0, limit: int = 20) -> dict[str, Any]:
        return await self._request("GET", "/creds/status", params={"mode": mode, "offset": offset, "limit": limit})

    async def list_filenames(self, mode: str) -> list[str]:
        filenames: list[str] = []
        seen: set[str] = set()
        offset = 0
        limit = 1000

        while True:
            payload = await self.get_status(mode, offset=offset, limit=limit)
            items = payload.get("items")
            if not isinstance(items, list):
                raise TargetApiError(f"目标服务返回的凭证列表格式异常：{mode}")

            for item in items:
                if not isinstance(item, dict):
                    continue
                filename = str(item.get("filename") or "").strip()
                if not filename or filename in seen:
                    continue
                seen.add(filename)
                filenames.append(filename)

            if not payload.get("has_more"):
                break

            if not items:
                break

            offset += len(items)
            total = payload.get("total")
            if isinstance(total, int) and offset >= total:
                break

        return filenames

    async def batch_enable(self, mode: str, filenames: list[str]) -> dict[str, Any]:
        return await self._request(
            "POST",
            "/creds/batch-action",
            params={"mode": mode},
            json={"action": "enable", "filenames": filenames},
        )

    async def enable_one(self, mode: str, filename: str) -> dict[str, Any]:
        return await self._request(
            "POST",
            "/creds/action",
            params={"mode": mode},
            json={"action": "enable", "filename": filename},
        )

    async def _request(self, method: str, path: str, retry_auth: bool = True, **kwargs) -> dict[str, Any]:
        if self._token is None:
            await self.login()

        headers = dict(kwargs.pop("headers", {}))
        headers["Authorization"] = f"Bearer {self._token}"

        try:
            response = await self._client.request(method, path, headers=headers, **kwargs)
        except httpx.TimeoutException as exc:
            raise TargetApiError(f"请求超时：{path}") from exc
        except httpx.RequestError as exc:
            raise TargetApiError(f"无法连接目标服务：{exc}") from exc

        if response.status_code == 401 and retry_auth:
            await self.login()
            return await self._request(method, path, retry_auth=False, **kwargs)

        if response.status_code >= 400:
            raise TargetApiError(self._error_message(response), status_code=response.status_code)

        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise TargetApiError(f"目标服务返回的响应不是有效的 JSON：{path}") from exc

        if not isinstance(payload, dict):
            raise TargetApiError(f"目标服务返回的响应格式异常：{path}")
        return payload

    @staticmethod
    def _error_message(response: httpx.Response) -> str:
        detail: str
        try:
            payload = response.json()
        except json.JSONDecodeError:
            detail = response.text.strip() or "未知错误"
        else:
            if isinstance(payload, dict):
                detail = str(payload.get("detail") or payload.get("message") or payload)
            else:
                detail = str(payload)
        return f"目标服务返回 {response.status_code}：{detail}"

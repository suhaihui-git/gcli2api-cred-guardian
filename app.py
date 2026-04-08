from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from config import APP_NAME, BASE_DIR
from routes_auth import router as auth_router
from routes_api import router as api_router
from routes_ui import router as ui_router
from scheduler import GuardianScheduler
from security import AccessAuthService
from storage import Storage


storage = Storage()
scheduler = GuardianScheduler(storage)
auth_service = AccessAuthService(storage)


@asynccontextmanager
async def lifespan(app: FastAPI):
    storage.initialize()
    app.state.storage = storage
    app.state.scheduler = scheduler
    app.state.auth_service = auth_service
    await scheduler.start()
    try:
        yield
    finally:
        await scheduler.stop()
        storage.close()


app = FastAPI(title=APP_NAME, lifespan=lifespan)


@app.middleware("http")
async def access_guard_middleware(request, call_next):
    path = request.url.path
    if path.startswith("/static") or path == "/login" or path.startswith("/auth"):
        if path == "/login" and hasattr(request.app.state, "auth_service"):
            if request.app.state.auth_service.is_authenticated(request):
                return RedirectResponse(url="/", status_code=303)
        return await call_next(request)

    if hasattr(request.app.state, "auth_service") and not request.app.state.auth_service.is_authenticated(request):
        if path.startswith("/api"):
            return JSONResponse({"detail": "未登录或会话已过期，请重新登录。"}, status_code=401)
        return RedirectResponse(url="/login", status_code=303)

    return await call_next(request)


app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(auth_router)
app.include_router(api_router)
app.include_router(ui_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=18933, reload=False)

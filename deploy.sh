#!/usr/bin/env sh

set -eu

REPO_URL="${REPO_URL:-https://github.com/suhaihui-git/gcli2api-cred-guardian.git}"
BRANCH="${BRANCH:-main}"

resolve_script_dir() {
    CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd
}

SCRIPT_DIR="$(resolve_script_dir || pwd)"

if [ -n "${APP_DIR:-}" ]; then
    TARGET_DIR="$APP_DIR"
elif [ -f "$SCRIPT_DIR/docker-compose.yml" ] && [ -f "$SCRIPT_DIR/app.py" ]; then
    TARGET_DIR="$SCRIPT_DIR"
else
    TARGET_DIR="/opt/gcli2api-cred-guardian"
fi

log() {
    printf '%s %s\n' "[cred-guardian]" "$*"
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "缺少命令: $1"
        exit 1
    fi
}

compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
        return
    fi
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
        return
    fi
    log "未找到 docker compose 或 docker-compose。"
    exit 1
}

run_git_in_target() {
    (
        cd "$TARGET_DIR"
        git "$@"
    )
}

clone_or_update_repo() {
    if [ -d "$TARGET_DIR/.git" ]; then
        log "检测到现有仓库，开始拉取最新代码..."
        run_git_in_target remote set-url origin "$REPO_URL"
        run_git_in_target fetch origin "$BRANCH" --tags
        run_git_in_target checkout "$BRANCH"
        run_git_in_target pull --ff-only origin "$BRANCH"
        return
    fi

    if [ -d "$TARGET_DIR" ] && [ -n "$(ls -A "$TARGET_DIR" 2>/dev/null)" ]; then
        log "目标目录已存在且不是 Git 仓库，请先清空或设置 APP_DIR 到新目录: $TARGET_DIR"
        exit 1
    fi

    log "开始克隆仓库到: $TARGET_DIR"
    mkdir -p "$TARGET_DIR"
    git clone --branch "$BRANCH" "$REPO_URL" "$TARGET_DIR"
}

deploy_container() {
    cd "$TARGET_DIR"
    mkdir -p data
    log "开始构建并启动容器..."
    compose up -d --build --remove-orphans
    log "当前容器状态:"
    compose ps
}

main() {
    require_command git
    require_command docker

    log "仓库地址: $REPO_URL"
    log "部署目录: $TARGET_DIR"
    log "分支: $BRANCH"

    clone_or_update_repo
    deploy_container

    log "完成。默认访问地址: http://服务器IP:18933"
    log "如果目标 API 跑在宿主机，面板里目标服务地址请填写 http://host.docker.internal:端口"
}

main "$@"

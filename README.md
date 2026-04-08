# gcli2api-cred-guardian

独立的凭证守护程序。

功能包括：

- 定时扫描 `cli` / `ant` 两个渠道的凭证状态
- 当正常凭证归零时自动启用白名单凭证
- 提供中文 Web 管理界面
- 使用 SQLite 保存配置、运行状态和历史
- 支持 Docker / Docker Compose 部署

启动：

```bash
docker compose up -d --build
```

一键部署 / 更新：

```bash
curl -fsSL https://raw.githubusercontent.com/suhaihui-git/gcli2api-cred-guardian/main/deploy.sh | APP_DIR=/opt/gcli2api-cred-guardian sh
```

如果已经在项目目录中，也可以直接执行：

```bash
sh deploy.sh
```

常用环境变量：

```bash
REPO_URL=https://github.com/suhaihui-git/gcli2api-cred-guardian.git
BRANCH=main
APP_DIR=/opt/gcli2api-cred-guardian
```

说明：

- 首次执行会自动克隆仓库并启动容器
- 再次执行会自动拉取最新代码并重建更新
- 容器内访问宿主机上的目标 API 时，可在页面中填写 `http://host.docker.internal:端口`

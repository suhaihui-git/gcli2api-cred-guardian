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

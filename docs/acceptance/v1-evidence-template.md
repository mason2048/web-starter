# web-starter V1 验收证据模板

> 本文件在验收执行时复制为带日期的记录。未执行的项目必须标记“未覆盖”，不得留空或推定通过。

## 环境信息

| 项目 | 记录 |
|---|---|
| Git commit |  |
| 验收日期 |  |
| 操作系统/架构 |  |
| Java |  |
| Maven |  |
| Node.js / pnpm |  |
| Docker / Compose |  |
| 浏览器与版本 |  |
| MySQL / Redis 镜像 |  |
| OAuth Issuer |  |
| MCP Resource Audience |  |

## 结果定义

- `PASS`：证据直接覆盖该验收项全部条件。
- `FAIL`：行为与基线矛盾。
- `NOT_COVERED`：未执行或现有证据范围不足。
- `ENV_BLOCKED`：环境条件缺失；仍不计为通过。

## 逐项记录

| ID | 结果 | 执行方式 | 关键证据位置 | 缺口/备注 |
|---|---|---|---|---|
| AC-01 |  |  |  |  |
| AC-02 |  |  |  |  |
| AC-03 |  |  |  |  |
| AC-04 |  |  |  |  |
| AC-05 |  |  |  |  |
| AC-06 |  |  |  |  |
| AC-07 |  |  |  |  |
| AC-08 |  |  |  |  |
| AC-09 |  |  |  |  |
| AC-10 |  |  |  |  |
| AC-11 |  |  |  |  |
| AC-12 |  |  |  |  |
| AC-13 |  |  |  |  |
| AC-14 |  |  |  |  |
| AC-15 |  |  |  |  |
| AC-16 |  |  |  |  |
| AC-17 |  |  |  |  |
| AC-18 |  |  |  |  |
| AC-19 |  |  |  |  |
| AC-20 |  |  |  |  |
| AC-21 |  |  |  |  |
| AC-22 |  |  |  |  |
| AC-23 |  |  |  |  |
| AC-24 |  |  |  |  |
| AC-25 |  |  |  |  |
| AC-26 |  |  |  |  |
| AC-27 |  |  |  |  |
| AC-28 |  |  |  |  |
| AC-29 |  |  |  |  |
| AC-30 |  |  |  |  |
| AC-31 |  |  |  |  |
| AC-32 |  |  |  |  |
| AC-33 |  |  |  |  |
| AC-34 |  |  |  |  |
| AC-35 |  |  |  |  |
| AC-36 |  |  |  |  |
| AC-37 |  |  |  |  |
| AC-38 |  |  |  |  |
| AC-39 |  |  |  |  |
| AC-40 |  |  |  |  |
| AC-41 |  |  |  |  |
| AC-42 |  |  |  |  |

## 自动化检查

| 检查 | 命令 | 退出码 | 日志位置 |
|---|---|---|---|
| 后端全量 | `./mvnw verify` |  |  |
| 前端 lint | `pnpm run lint` |  |  |
| 前端类型 | `pnpm run typecheck` |  |  |
| 前端测试 | `pnpm run test` |  |  |
| 前端构建 | `pnpm run build` |  |  |
| 禁用业务词 | `python3 scripts/repository_policy.py forbidden`（词条从仓库外注入） |  |  |
| 秘密扫描 | `python3 scripts/repository_policy.py secrets` |  |  |

## 真实运行证据

- 空库启动日志：
- Flyway schema history：
- 容器与健康状态：
- Redis Session 读回：
- Web REST 事务：
- Authorization Code + PKCE：
- Client Credentials：
- PAT / 服务账号令牌：
- MCP initialize/list/call：
- 审计数据库读回：
- 公私入口差异：

## 浏览器证据

| 视口/角色 | 路径 | 交互 | 截图/录像 | Console |
|---|---|---|---|---|
| 桌面 ADMIN |  |  |  |  |
| 桌面 PROJECT_VIEWER |  |  |  |  |
| 桌面无菜单角色 |  |  |  |  |
| 移动端 ADMIN |  |  |  |  |
| 401/403/409/500 |  |  |  |  |

## 未通过项

逐条记录失败原因、影响、修复提交和复测证据。不得用“非阻断”概括未经过确认的 P0/P1 问题。

## 最终结论

- [ ] 所有 P0 均为 PASS
- [ ] 所有 P1 均为 PASS，或具有用户明确接受记录
- [ ] 没有把 NOT_COVERED / ENV_BLOCKED 计作 PASS
- [ ] 验收结论与证据范围一致

结论：`PASS / FAIL / INCOMPLETE`

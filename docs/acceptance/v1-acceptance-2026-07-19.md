# web-starter V1 验收记录

> 验收日期：2026-07-19（Asia/Shanghai）
> 对象：本地 `v1.0.0` 发布基线
> 结论：`PASS`（功能、安全、运行和模块扩展验收）
> 发布状态：随本地 `v1.0.0` tag 固化；未推送或发布到外部

本记录对应 [V1 验收基线](./v1-acceptance-baseline.md)。构建成功、测试通过、容器健康和页面可打开均只作为各自范围的证据，没有被单独当成 V1 完成依据。

## 1. 环境信息

| 项目 | 记录 |
|---|---|
| Git commit | 以 `git rev-list -n 1 v1.0.0` 解析的本地发布提交为准 |
| 操作系统/架构 | macOS 26.5.1 / arm64 |
| 构建 JVM | OpenJDK 26；Maven Compiler 使用 Java 21 release |
| 容器运行时 | Eclipse Temurin 21.0.11 LTS |
| Maven | 3.9.15 |
| Node.js / pnpm | 24.14.1 / 9.15.9 |
| Docker / Compose | 29.4.0 / v5.1.1 |
| 浏览器 | Codex 内置 Chromium；自动化接口未暴露精确版本号 |
| MySQL / Redis | MySQL 8.4 / Redis 7.4-alpine |
| Spring Boot / MCP SDK | 4.1.0 / 官方 Java SDK 2.0.0 |
| 私有入口 | `http://127.0.0.1:18088` |
| 外部 MCP 入口 | `https://mcp.localhost:18443`；本地验收证书 |
| OAuth Issuer | `https://mcp.localhost:18443` |
| MCP Resource Audience | `https://mcp.localhost:18443/mcp` |

正式验收栈 Compose project 为 `web-starter-acceptance`。Nginx 是唯一宿主入口；App、MySQL、Redis 只暴露容器网络端口。

## 2. 结果定义

- `PASS`：直接证据覆盖该验收项全部条件。
- `FAIL`：行为与基线冲突。
- `NOT_COVERED`：未执行或证据不完整，不计为通过。
- `ENV_BLOCKED`：缺少外部环境条件，不计为通过。

## 3. 逐项结果

| ID | 结果 | 执行方式与直接证据 | 备注 |
|---|---|---|---|
| AC-01 | PASS | 全新 MySQL/Redis 卷启动；Flyway 从空 schema 连续执行 V1、V2、V3；首次启动创建管理员 | 无手工 SQL 初始化 |
| AC-02 | PASS | 将容器内 bootstrap 密码置空后重建 App；既有管理员密码仍登录 200；无管理员重建日志 | 初始化密码未进入仓库或日志 |
| AC-03 | PASS | 正确登录 200、错误登录 401；成功/失败登录日志均从 API 和数据库读回 | 错误响应不区分账号或密码 |
| AC-04 | PASS | Redis `web-starter:session` 键真实存在；退出后旧 Cookie 401；停用用户后旧 Session 401 | 完整栈重启后浏览器 Session 继续有效 |
| AC-05 | PASS | 缺少 CSRF 和错误 masked CSRF 均为 403，且项目表无副作用 | 登录、退出和全部 Web 写操作使用同一策略 |
| AC-06 | PASS | 真实浏览器完成用户创建、编辑/停用、角色分配、密码重置和删除；操作审计可见 | API 自动化另覆盖唯一约束和 stale version |
| AC-07 | PASS | 角色 CRUD、权限/菜单分配、旧版本 409；同一 Session 在角色权限回收后下一请求立即 403 | 权限恢复也在同一会话生效 |
| AC-08 | PASS | 停用/删除自己 409；内置管理员角色删除、停用、清空必要权限或菜单均 409 | 最后有效管理员保护通过 |
| AC-09 | PASS | 取消角色菜单后导航消失；直接输入未授权路由进入 403 页面 | 菜单与 API 权限分别校验 |
| AC-10 | PASS | 只读角色无创建/编辑/删除按钮；手工调用写 API 仍为 403 | 不依赖前端隐藏实现安全 |
| AC-11 | PASS | 权限创建 200、重复编码 409、停用 200；受保护权限删除 409；临时权限可删除 | 权限编码和基线保护真实验证 |
| AC-12 | PASS | 非敏感配置通过页面创建、更新、删除；凭据类键被明确拒绝 | 响应不回显敏感值 |
| AC-13 | PASS | 项目分页、分页上限、关键字、状态过滤、列表和详情经浏览器/API 验证 | JSON ID 为字符串，计数为数字 |
| AC-14 | PASS | 项目创建、更新、逻辑删除；重复编码 409、输入校验、旧版本更新 409 | 删除后详情 404 |
| AC-15 | PASS | REST Controller 与 7 个 MCP Tool 的项目操作均进入 `ProjectService`；MCP 模块不依赖 Project Mapper | 静态依赖与真实 REST/MCP 读写共同核对 |
| AC-16 | PASS | 重复/旧版本失败无业务副作用；成功业务与成功审计共同读回；失败 MCP 调用保留失败审计 | 成功审计无重复行 |
| AC-17 | PASS | PAT 明文只在签发响应出现；数据库仅 64 位十六进制哈希和 hint；Scope、期限、吊销、CIDR、lastUsedAt 均实测 | IP 不匹配 401；短期 PAT 过期前 200、过期后 401 |
| AC-18 | PASS | 服务账号创建、角色分配、长期令牌签发/吊销；禁用主体后既有直接令牌和 OAuth JWT 均 401 | 长期令牌仅私有入口接受 |
| AC-19 | PASS | 管理员预注册 Client；旧 secret 轮换前 200、轮换后 401，新 secret 200；redirect 精确匹配 | metadata 无动态注册入口，常见注册路径 403/404 |
| AC-20 | PASS | 真实用户 Authorization Code + PKCE S256；临时 3 秒 access TTL 下 exchange 200，紧邻 `/mcp` 200，超过 exp 后同 token 401 | 撤销与 refresh rotation/replay 另有独立证据；栈已恢复 10 分钟 TTL |
| AC-21 | PASS | Client Credentials 绑定服务账号；官方 SDK `project.list` 成功、`project.create` scope 拒绝；回收角色权限后同 JWT 403，停用主体后 401 | token 无 refresh token |
| AC-22 | PASS | RBAC 允许但 Scope 缺少，以及 Scope 允许但实时 RBAC 缺少，两种组合都返回 MCP 权限错误 | Web 与 MCP 使用同一权限编码 |
| AC-23 | PASS | 私有入口接受 PAT、服务账号长期令牌和 OAuth；相同长期令牌在 public 入口 401 | public 入口管理 API/Actuator 为 404 |
| AC-24 | PASS | Authorization Server、Protected Resource metadata、Issuer、Audience 与 `WWW-Authenticate` 实际读回一致 | 仅声明已实现的 PKCE S256 等能力 |
| AC-25 | PASS | 官方 Java MCP SDK 完成 `initialize`、Session header 和后续请求 | 协议版本 2025-11-25 |
| AC-26 | PASS | `tools/list` 精确 7 项；SDK 覆盖读、写、缺权限、非法参数、不存在资源和未知 Tool | 输入 Schema 与长 ID 字符串契约通过 |
| AC-27 | PASS | `resources/list` 为 1 项并读取 `web-starter://system/info`；走 `system:info` 权限 | 无权限路径被拒绝 |
| AC-28 | PASS | `prompts/list` 为 1 项并读取 `project.summary`；注入样本文本仅作为业务内容 | 不改变系统能力或 Tool 白名单 |
| AC-29 | PASS | 合法 Host+无 Origin、合法 Origin 均 200；恶意 Origin 403，恶意 Host 421 | 非浏览器 Agent 无 Origin 正常 |
| AC-30 | PASS | SDK 发现与源码扫描仅有冻结的 7 个 Tool | 无 SQL、Shell、进程、文件读写、动态执行或第三方 MCP 代理能力 |
| AC-31 | PASS | 成功/失败登录日志含用户名、结果、IP、User-Agent、Trace ID | 密码未进入日志、响应或审计 |
| AC-32 | PASS | 用户、角色、菜单、配置、安全凭据和项目写操作均记录主体、动作、资源、结果、耗时、Trace ID | 浏览器用户 CRUD 也从操作审计页读回 |
| AC-33 | PASS | PAT、用户 OAuth、自动化 OAuth、直接服务账号调用的成功、拒绝、非法参数、业务失败均有 MCP 审计 | actorType、token/client 标识与完整 Trace ID 已核对 |
| AC-34 | PASS | 11 个已知敏感值扫描 21 组管理响应、审计响应、metadata/error 和应用日志，literal 命中 0；数据库凭据表只存哈希 | 一次性签发/轮换响应按设计单独隔离，不计作泄漏 |
| AC-35 | PASS | 登录、概览、项目、用户、角色、菜单、配置、三类日志、PAT、服务账号、OAuth Client 共 12 个管理页面真实打开 | 主要 CRUD、安全签发与轮换路径有运行证据 |
| AC-36 | PASS | 桌面和 390px 浏览器验证；加载、空态、校验、401、403、409 均实测；生产前端构建接隔离 500 响应后真实显示错误文案和 Trace ID | 故障服务器验收后已停止，生产无调试端点 |
| AC-37 | PASS | 五容器从空环境启动；全栈 stop/start 后 projects=2、users=2、Flyway=3、Session keys=15 前后不变；浏览器旧 Session 可继续使用 | 五服务最终均 healthy |
| AC-38 | PASS | 聚合、liveness、readiness 均 200；部署文档覆盖日志、备份恢复、升级回滚、RSA 轮换 | public 入口不暴露健康端点 |
| AC-39 | PASS | 发布基线秘密扫描零命中；生产缺持久 RSA key 会 fail fast，开发临时 key 为 3072 bit；证书/私钥在仓库外只读挂载 | 建立 tag 前已重新执行策略扫描 |
| AC-40 | PASS | 4 个仓库外注入的禁用业务词扫描 0 命中；正式仓库没有临时演练模块；实现期写权限仅覆盖本仓库和临时目录；外部参考仓库 status/worktree/index 三个 SHA-256 在收口前后完全一致 | 外部参考仓库原本已是 dirty，本记录不冒充其 clean；本轮未获得对其写权限，也未执行写操作 |
| AC-41 | PASS | Maven `verify` 144 tests；3 个官方 SDK Runtime IT 各 1/1；前端 lint/typecheck、9 files/23 tests、build 全通过 | 没有使用 skip 规避失败；构建仅有大 chunk 警告 |
| AC-42 | PASS | 临时副本新增独立 `asset` CRUD：151 后端测试、V1→V4 空库、REST CRUD/409/403/审计、前端构建；真实浏览器 ADMIN 创建→编辑→删除，只读账号仅显示查看且写 API 403 | 临时模块、容器、网络、卷和凭据均清理；正式仓库只保留复制规范和通用 Nginx 路由修复 |

## 4. 自动化门禁

| 检查 | 命令 | 结果 |
|---|---|---|
| 后端全量 | `./mvnw -B -ntp verify` | PASS；144 tests，0 failure/error/skip |
| 官方 SDK：私有 PAT | `McpSdkRuntimeIT` | PASS；1/1 |
| 官方 SDK：完整项目 CRUD | `McpSdkCrudRuntimeIT` | PASS；1/1 |
| 官方 SDK：自动化 Agent | `McpSdkProjectListRuntimeIT` | PASS；1/1 |
| 前端 lint | `pnpm lint` | PASS |
| 前端类型 | `pnpm typecheck` | PASS |
| 前端测试 | `pnpm test -- --run` | PASS；9 files / 23 tests |
| 前端构建 | `pnpm build` | PASS |
| Compose 配置 | base、dev、public 三种合并配置 `config --quiet` | PASS |
| 仓库策略测试 | `python3 -B -m unittest discover -s scripts -p 'test_repository_policy.py'` | PASS；8/8 |
| 秘密扫描 | `python3 -B scripts/repository_policy.py secrets` | PASS；零命中 |
| 禁用业务词 | `python3 -B scripts/repository_policy.py forbidden --forbidden-terms-file <repo-outside-file>` | PASS；4 terms，零命中 |

## 5. 真实运行证据索引

- Web API 70 项验收：`/private/tmp/web-starter-web-runtime-acceptance-5263e30e02b64c0cbeabe50317f7b69a.json`，70 PASS / 0 FAIL，临时用户、角色、项目清理完成。
- 私有 PAT + 官方 SDK：`/private/tmp/web-starter-pat-acceptance.xcoo2h/acceptance-summary.txt`。
- 安全剩余项与 secret rotation：`/private/tmp/web-starter-security-residual/runtime-summary.txt`。
- 敏感值泄漏扫描：`/private/tmp/web-starter-security-residual/secret-leak-scan-summary.txt`。
- AC-42 隔离复制演练：`/private/tmp/web-starter-ac42-full.v83xQr/AC42-REHEARSAL-EVIDENCE.md`。
- 官方 SDK Surefire XML：`web-starter-mcp/target/surefire-reports/TEST-dev.webstarter.mcp.acceptance.*RuntimeIT.xml`。

原始 token、Cookie、PKCE verifier、Client secret 和密码不复制进本记录。一次性验收资源已吊销或禁用；相关临时文件由执行者清理，仍需保留的共享 Compose 配置、管理员密码和本地证书均为 `0600`。

## 6. 浏览器证据

| 视口/角色 | 路径与交互 | 结果 |
|---|---|---|
| 桌面 ADMIN | 登录、概览、项目、用户、安全管理、日志 | PASS；12 个页面加载，项目和用户完整 CRUD |
| 桌面 PROJECT_VIEWER | `/projects`、直接 `/users`、实时权限回收 | PASS；只读按钮隐藏、写 API 403、未授权路由 403 |
| 无菜单角色 | 有业务权限但无项目菜单 | PASS；导航隐藏，业务 API 权限仍独立计算 |
| 移动端 ADMIN | 390×844 概览、抽屉导航、项目列表 | PASS；无横向破版，表格可用 |
| 异常状态 | 401、403、409、500 | PASS；500 使用生产前端产物和隔离故障响应，显示 Trace ID |
| AC-42 ADMIN/VIEWER | `/assets` 创建、编辑、删除、查看和按钮隐藏 | PASS；Viewer 只保留查看，reload 仍能访问 |

本地截图：`/private/tmp/web-starter-login-desktop.png`、`/private/tmp/web-starter-overview-desktop.png`、`/private/tmp/web-starter-project-dialog-desktop.png`、`/private/tmp/web-starter-mobile-latest.png`、`/private/tmp/web-starter-mobile-projects.png`。AC-42 以 DOM 与运行记录为证，没有保留截图文件。

## 7. 视觉一致性记录

| 检查点 | 参考目标 | 实际结果 |
|---|---|---|
| 登录结构 | 左侧产品叙事、右侧登录操作 | PASS；桌面双栏、移动端单栏，层级清晰 |
| 主导航 | 深色青绿色侧栏、分组清晰 | PASS；桌面固定侧栏、移动端抽屉 |
| 概览层级 | 欢迎区、统计卡、快捷入口、最近调用 | PASS；数据状态与空态均可辨识 |
| 业务 CRUD | 表格、过滤、详情/编辑抽屉 | PASS；主操作明确，Trace/错误信息不过度打扰 |
| 响应式 | 390px 可浏览与操作 | PASS；项目列表和导航在窄屏可用 |
| 安全管理 | 一次性秘密突出且不可再次读取 | PASS；确认消费后清除明文显示 |

## 8. 已知但不阻断的观察

- Vite 生产构建提示一个主 chunk 大于 500 kB；不影响正确性，后续可按路由继续拆包。
- 宿主构建 JVM 为 Java 26；Maven 使用 Java 21 release，最终容器已实际验证为 Java 21.0.11。
- 外部参考仓库在本次只读检查时已有 10 个 tracked change、42 个总 status entry；它不属于本项目工作树。本轮没有写权限或写操作，不能把其已有状态描述为本轮造成或本轮清理。
- 真实公网域名、正式 CA 证书、DNS、防火墙和上游负载均属于具体部署环境，仍须在实际内网/外网部署时复验；本次验证的是双入口策略和本地 TLS 拓扑。
- 本次仅建立本地 Git commit/tag 作为 V1→V2 的可追溯基线；未推送或上线。功能验收 PASS 不等于已经对外发布。

## 9. 最终结论

- [x] 所有 P0 均为 PASS。
- [x] 所有 P1 均为 PASS。
- [x] 没有把 NOT_COVERED 或 ENV_BLOCKED 计作 PASS。
- [x] Web、OAuth、MCP、数据、安全、部署和模块复制均有独立运行证据。
- [x] 验收结论限定为本地 `v1.0.0` tag，不冒充远程发布或真实公网部署。

结论：`PASS`

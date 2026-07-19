# web-starter V1 验收基线

> 状态：**已冻结，进入开发与验收**
> 产品：启程 Web Starter
> 工程与仓库：`web-starter`
> 基线日期：2026-07-18

本文是 V1 的开发与验收目标。功能增删必须先更新本文并重新确认。

## 1. 发布目标

从空数据库和空 Redis 开始，使用环境变量注入配置，通过 Docker Compose 启动后，交付一个可实际使用的内部 Web 管理系统脚手架。它同时支持 Web 管理端、内网 MCP Agent、外网用户 Agent 和外网自动化 Agent，并保证 Web 与 MCP 共用业务 Service、数据库事务、实时 RBAC 和审计记录。

下列证据不能单独证明完成：编译成功、单元测试全绿、容器显示 `Up`、健康检查返回 200、页面能够打开。

## 2. 固定技术与产品边界

- Java 21 统一用于编译和部署运行时。
- Spring Boot 4.1、Spring Security 7.x 和内置 Authorization Server 是后端安全基线。
- Vue 3、TypeScript、Vite、Element Plus 是管理端基线。
- MySQL 保存业务事实；Redis 保存 Session；Flyway 管理数据库演进。
- 采用模块化单体，不引入微服务、服务发现和分布式事务。
- 只提供 MCP Server，不实现 MCP Client 或第三方 MCP 代理。
- MCP 使用 `/mcp` 和 Streamable HTTP。
- 不提供公网注册、SaaS 多租户、套餐计费、聊天页面、任意 SQL、Shell、文件系统或动态代码执行。
- 项目不得包含任何参考项目的公司业务名称、数据表、页面、接口和业务代码。

## 3. 验收级别

| 级别 | 定义 | 发布处理 |
|---|---|---|
| P0 | 核心功能、安全边界或数据正确性 | 任一失败即禁止判定 V1 完成 |
| P1 | 可运维性、异常路径和产品完整性 | 任一失败原则上阻断，除非用户书面接受 |
| P2 | 体验或效率增强 | 可以形成后续任务，不阻断 V1 |

## 4. 功能验收矩阵

| ID | 级别 | 验收域 | 可执行通过标准 |
|---|---|---|---|
| AC-01 | P0 | 空库启动 | 全新 MySQL 完整执行所有 Flyway 迁移，无手工 SQL；空库首次启动可创建管理员 |
| AC-02 | P0 | 初始化凭据 | 初始化密码不进入仓库和日志；移除该环境变量后应用可重启，且不会覆盖现有管理员密码 |
| AC-03 | P0 | Web 登录 | 正确密码建立 Session；错误密码统一返回 401；登录成功和失败均写登录日志 |
| AC-04 | P0 | Session 与退出 | Session 实际保存到 Redis；退出后原 Cookie 不能继续访问；禁用用户后原 Session 下一请求失效 |
| AC-05 | P0 | CSRF | 所有浏览器写请求必须携带有效 CSRF Token；缺少或错误 Token 被拒绝 |
| AC-06 | P0 | 用户管理 | 列表、创建、编辑、启停、重置密码、删除和角色分配均能通过页面完成，并产生操作审计 |
| AC-07 | P0 | 角色权限 | 角色 CRUD、权限分配、菜单分配和并发版本冲突可验证；权限回收在下一次请求生效 |
| AC-08 | P0 | 管理员防锁死 | 不能删除、停用自己；不能删除或停用最后一个有效管理员；内置 ADMIN 不能删除、停用或被清空必要权限 |
| AC-09 | P0 | 菜单权限 | 取消角色菜单后，对应导航真实消失；用户直接输入未授权前端路由进入 403 页面 |
| AC-10 | P0 | 按钮与 API 权限 | 无创建权限时按钮不显示；手工调用创建 API 仍返回 403，不能依赖前端隐藏实现安全 |
| AC-11 | P1 | 权限字典 | 权限编码唯一、状态可控；已被内置安全基线使用的权限不能被无保护删除导致系统锁死 |
| AC-12 | P0 | 系统配置 | 非敏感配置可查询和维护；密码、密钥、Token、凭据和私钥类配置键被拒绝 |
| AC-13 | P0 | 项目列表与详情 | 分页、关键字、状态筛选、详情和分页上限工作正常 |
| AC-14 | P0 | 项目写操作 | 创建、更新、逻辑删除可用；编码唯一；输入校验正确；旧版本更新返回 409 |
| AC-15 | P0 | 共享业务层 | REST 和 MCP 项目操作调用同一个 ProjectService，MCP Tool 不得直接调用 Mapper |
| AC-16 | P0 | 业务事务 | 业务失败回滚；成功业务数据与成功审计共同提交；失败 MCP 调用仍保存失败审计 |
| AC-17 | P0 | 个人令牌 | PAT 绑定用户，明文只展示一次；数据库只存哈希和提示；支持 Scope、期限、吊销、IP 和最后使用时间 |
| AC-18 | P0 | 服务账号 | 支持启停、角色分配、令牌签发/吊销；禁用账号后所有已有长期令牌立即失效 |
| AC-19 | P0 | OAuth Client | 管理员预注册 Client；支持密钥轮换；Redirect URI 精确验证；动态客户端注册关闭 |
| AC-20 | P0 | 外网用户 Agent | Authorization Code + PKCE S256 完成登录、授权、换 Token 和 MCP 调用；过期/撤销后拒绝 |
| AC-21 | P0 | 外网自动化 Agent | Client Credentials 绑定服务账号并换取短时 Token；禁用主体或回收角色权限后立即拒绝 |
| AC-22 | P0 | 授权交集 | 所有 Token 最终权限严格等于实时主体 RBAC 与 Token Scope 的交集，两侧任一缺少均返回 403 |
| AC-23 | P0 | 内外网入口 | 私有入口允许 PAT、服务账号令牌和 OAuth；标记为 public 的入口必须拒绝两类长期令牌 |
| AC-24 | P0 | OAuth 元数据 | Protected Resource Metadata、Authorization Server Metadata、Issuer、Audience 和 `WWW-Authenticate` 一致 |
| AC-25 | P0 | MCP 初始化 | 真实客户端完成 `initialize` 和后续 Session 请求，不以普通 HTTP 200 代替协议通过 |
| AC-26 | P0 | MCP Tools | `tools/list` 只返回约定的 7 个 Tool，每个 Tool 的输入 Schema、权限和错误结果正确 |
| AC-27 | P0 | MCP Resources | `resources/list` 和读取 `web-starter://system/info` 可用，并执行 `system:info` 权限校验 |
| AC-28 | P0 | MCP Prompts | `prompts/list` 和 `project.summary` 可用；业务内容作为不可信文本，不能改变系统能力 |
| AC-29 | P0 | MCP 传输安全 | 校验 Host 和 Origin；无 Origin 的非浏览器 Agent 正常；非法 Host/Origin 被拒绝 |
| AC-30 | P0 | 禁止工具 | 协议扫描不存在 SQL、Shell、进程、文件读写、动态代码或第三方 MCP Client 工具 |
| AC-31 | P0 | 登录审计 | 成功/失败记录用户名、结果、IP、User-Agent、Trace ID，且不泄露密码 |
| AC-32 | P0 | 操作审计 | 用户、角色、菜单、配置、安全凭据和项目写操作记录主体、资源、结果、耗时与 Trace ID |
| AC-33 | P0 | MCP 审计 | 成功、权限拒绝、校验失败和业务失败都记录 Tool、权限、主体、Token/Client 标识和 Trace ID |
| AC-34 | P0 | 秘密保护 | 日志、响应错误、审计详情和数据库均不出现密码、Cookie、Authorization Header 或完整 Token |
| AC-35 | P1 | 管理端页面 | 登录、概览、项目、用户、角色、菜单、配置、三类日志、PAT、服务账号和 OAuth Client 均有可操作页面 |
| AC-36 | P1 | 页面状态 | 桌面和 390px 移动端可用；加载、空数据、校验错误、401、403、409、500 有明确反馈 |
| AC-37 | P0 | Compose 部署 | Nginx、应用、MySQL、Redis 从空环境完整启动；Nginx 是默认唯一用户入口；重启后业务数据保留 |
| AC-38 | P1 | 运维能力 | 存活、就绪、聚合健康检查可用；文档覆盖日志、备份恢复、升级回滚和 RSA 密钥轮换 |
| AC-39 | P0 | 配置安全 | 真实密码、Token、Pepper、私钥和证书不提交 Git；生产关闭临时 RSA 密钥生成 |
| AC-40 | P0 | 工程隔离 | 全仓禁用业务词扫描零命中；参考工程无修改；不存在复制来的业务模块 |
| AC-41 | P0 | 自动化门禁 | Maven `verify`、前端 lint、类型检查、测试和生产构建全部通过，失败时不得跳过 |
| AC-42 | P1 | 模块扩展 | 按复制规范能够新增一个独立 CRUD 模块，说明迁移、权限、审计、前端和 MCP 接入位置 |

## 5. MCP 固定清单

### Tools

- `system.info`
- `project.list`
- `project.get`
- `project.create`
- `project.update`
- `project.remove`
- `audit.list`

### Resource

- `web-starter://system/info`

### Prompt

- `project.summary`

新增任何 MCP Tool 都属于范围变更，必须重新确认。

## 6. 权限交叉验收角色

这些角色仅在验收数据中创建，不作为生产默认账号：

| 角色 | 权限 |
|---|---|
| `ADMIN` | 全部已启用权限 |
| `PROJECT_VIEWER` | `project:list` |
| `PROJECT_EDITOR` | `project:list`、`project:create`、`project:update` |
| `AUDIT_VIEWER` | `audit:list` |
| 测试服务账号 | `project:list` |

至少验证以下负向组合：

- 有菜单、无业务权限：前端不能操作，API 返回 403。
- 有业务权限、无菜单分配：导航不显示，前端直接路由进入 403。
- RBAC 允许、Token Scope 不允许：MCP 返回权限错误。
- Token Scope 允许、RBAC 不允许：MCP 返回权限错误。
- 用户、角色或服务账号被禁用：已有 Session/Token 后续调用失败。
- Token 被吊销或过期：后续调用返回 401。

## 7. 发布门禁

V1 只有同时满足以下条件才可判定完成：

1. 代码门禁：后端和前端全部自动化检查通过。
2. 数据门禁：真实 MySQL 空库迁移、初始化、重启和业务事务通过。
3. Web 门禁：真实浏览器完成桌面、移动端、RBAC 和异常路径。
4. OAuth 门禁：Authorization Code + PKCE 与 Client Credentials 真实换 Token。
5. MCP 门禁：使用真实 MCP Client 完成初始化、发现和调用。
6. 安全门禁：长期令牌边界、RBAC 与 Scope 交集、Host/Origin、秘密扫描通过。
7. 隔离门禁：禁用业务词和参考工程修改扫描通过。

每项验收必须记录为“通过、失败、未覆盖、环境阻塞”之一。“未覆盖”和“环境阻塞”都不等于通过。

## 8. 已采用的范围决定

本轮开发采用以下方案：

1. **包含安全管理页面**：V1 提供 PAT、服务账号和 OAuth Client 管理页面，不只提供 API。
2. **数据库驱动菜单**：角色菜单分配实际控制运行时导航；按钮继续由权限编码控制。
3. **先提供模块复制规范**：V1 不实现代码生成器，生成器作为 V1.1 候选。
4. **默认只初始化 ADMIN**：其他角色由使用者创建，验收角色由测试准备。
5. **分层验收外网能力**：脚手架验收 OAuth/MCP、公网入口策略和 HTTPS 配置；真实公网域名、证书、DNS、防火墙由具体部署环境再次验收。

## 9. 变更控制

- P0/P1 项的删除、降级或改写必须由用户确认。
- 新增功能先判断是否属于 V1；不属于则进入后续版本，不在开发中顺手扩张。
- 实现与本文冲突时，以已确认的本文为准，修正实现而不是降低验收标准。

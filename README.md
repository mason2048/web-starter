# 启程 Web Starter

`web-starter` 是面向公司内部 Web 管理系统的通用脚手架。它采用模块化单体架构，在同一业务与安全边界内提供 Vue 管理端、REST API 和 MCP Server。

## 边界

- 面向内网管理系统，不提供公网自助注册、套餐、计费或 SaaS 多租户。
- Web API 与 MCP 共用业务 Service、数据库事务、实时 RBAC 和审计模型。
- 只提供 MCP Server，不连接或代理第三方 MCP Server。
- 不提供任意 SQL、Shell、文件系统或动态代码执行能力。
- 第一版保持单体部署，不引入微服务、服务发现和分布式事务。

## 技术基线

| 层 | 基线 |
|---|---|
| 前端 | Vue 3.5、TypeScript 5.9、Vite 8、Element Plus 2.14 |
| 后端 | Java 21、Spring Boot 4.1、Spring Security 7.1 |
| 数据访问 | MyBatis-Plus 3.5、MySQL 8.4、Flyway |
| 会话 | Spring Session、Redis 7.4 |
| MCP | MCP Java SDK 2.0、Streamable HTTP |
| 部署 | Docker Compose、Nginx |

## 模块

```text
web-starter
├── web-starter-core       # API、异常、Caller 与权限抽象
├── web-starter-system     # 用户、角色、菜单、配置、RBAC 与审计
├── web-starter-security   # Session、OAuth、PAT、服务账号令牌
├── web-starter-project    # 可复制的完整示例 CRUD
├── web-starter-mcp        # MCP Transport、Resources、Tools、Prompts
├── web-starter-admin      # Spring Boot 启动、Flyway 与运行时装配
├── web-starter-web        # Vue 管理端
├── deploy                 # Nginx 配置
└── docs                   # 架构、安全、部署与模块复制说明
```

依赖方向保持为：`admin -> mcp/security/project/system -> core`。MCP Tool 只能调用业务 Service，不能直接调用 Mapper。

## 快速启动

需要 Docker Desktop 或 Docker Engine + Compose V2。

```bash
cp .env.example .env
```

替换 `.env` 中所有占位值。首次空库启动需要设置高强度 Bootstrap 管理员密码；项目不包含默认密码。

```bash
docker compose up --build -d
docker compose ps
```

默认管理端地址为 `http://localhost:8088`。首次登录成功后，应移除 Bootstrap 密码环境变量并重建应用容器。

本地分进程开发、可执行的 `compose.public-mcp.yaml` 双入口、TLS 证书挂载、RSA 密钥配置、备份恢复和不可变镜像回滚见 [部署说明](docs/deployment.md)。公网入口必须使用 HTTPS，并且不能直接暴露标记为 `private` 的默认管理入口。

## 开发校验

```bash
./mvnw verify

cd web-starter-web
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm build

cd ..
python3 scripts/repository_policy.py secrets
```

根目录的 Maven Enforcer 要求 JDK 21 或更高的兼容构建 JDK，并始终以 `release 21` 产出字节码。部署镜像统一使用 Java 21 Runtime。

秘密与工程隔离门禁的本地用法、外部禁止词注入和退出码约定见 [仓库策略门禁](docs/repository-policy.md)。

## 安全模型

| 调用方 | 认证方式 | 入口建议 |
|---|---|---|
| Web 管理端 | 用户名/密码 + Redis Session + CSRF | 内网管理域名 |
| 外部用户 Agent | Authorization Code + PKCE | HTTPS 公共 MCP 域名 |
| 外部自动化 Agent | Client Credentials | HTTPS 公共 MCP 域名 |
| 内部固定 Agent | PAT 或服务账号令牌 | 受控私有入口 |

每个凭据最终映射为统一 `CurrentCaller`。令牌调用的最终授权结果为“主体实时 RBAC”与“令牌 Scope”的交集；禁用用户/服务账号、撤销令牌或回收角色权限会立即影响后续调用。

长期令牌只保存 HMAC-SHA-256 哈希和短提示，明文仅在创建响应中出现一次。外部入口由 Nginx 标记为 `public`，应用会拒绝 PAT 与服务账号长期令牌。详细威胁边界见 [安全模型](docs/security.md)。

## MCP Server

- 入口：`/mcp`
- 传输：Streamable HTTP
- Protected Resource Metadata：`/.well-known/oauth-protected-resource/mcp`

首版 Tools：

- `system.info`
- `project.list`
- `project.get`
- `project.create`
- `project.update`
- `project.remove`
- `audit.list`

首版还提供只读 Resource `web-starter://system/info`，以及 Prompt `project.summary`。每个入口都显式映射权限编码，并写入 MCP 调用日志；Project 写操作同时进入通用操作审计。

## 扩展

新增模块时以 `web-starter-project` 为模板，并遵循 [模块复制规范](docs/module-copy-guide.md)。数据库结构只能通过新的 Flyway 迁移演进，已应用迁移不得修改。

## 更多文档

- [总体架构](docs/architecture.md)
- [V1 验收基线](docs/acceptance/v1-acceptance-baseline.md)
- [V1 验收证据模板](docs/acceptance/v1-evidence-template.md)
- [V1 验收记录（2026-07-19）](docs/acceptance/v1-acceptance-2026-07-19.md)
- [首版架构决策](docs/decisions/0001-foundation.md)
- [设计系统](docs/design-system.md)
- [部署与运维](docs/deployment.md)
- [安全模型](docs/security.md)
- [仓库策略门禁](docs/repository-policy.md)
- [模块复制规范](docs/module-copy-guide.md)

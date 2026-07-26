# 安全模型

## 认证入口

| 入口 | 凭据 | 会话状态 | 适用范围 |
|---|---|---|---|
| Web 管理端 | 用户名、密码、Session Cookie | 有状态 | 内网浏览器 |
| 外网用户 Agent | OAuth Authorization Code + PKCE | MCP 请求无状态 | 代表用户调用 |
| 外网自动化 Agent | OAuth Client Credentials | MCP 请求无状态 | 服务账号调用 |
| 内网固定 Agent | PAT 或服务账号令牌 | 无状态 | 受控私有入口 |

Spring Security 是唯一安全框架。所有成功认证最终生成统一 `CurrentCaller`，业务层不根据传输协议分别实现权限。

## 权限计算

```text
最终允许 = 主体当前有效
        AND 当前 RBAC 包含权限
        AND 凭据 Scope 包含权限
        AND 凭据未过期、未吊销
        AND 网络/IP 约束通过
```

Web Session 没有额外凭据 Scope，直接使用当前 RBAC。OAuth、PAT 和服务账号令牌必须同时满足 RBAC 与 Scope。

权限编码使用稳定、可读的冒号格式，例如：

- `project:list`
- `project:create`
- `project:update`
- `project:remove`
- `audit:list`

MCP Tool 名使用点号，例如 `project.create`，Tool 元数据显式映射到对应权限编码。

## MCP 写操作幂等

- V2 Agent 对 `project.create`、`project.update` 和 `project.remove` 传入稳定的 `idempotencyKey`；V1 兼容调用可暂时省略，但不得假定省略后的重试安全。
- 去重身份由当前主体、凭据/Client、Tool 和 Key 共同组成；请求参数会先移除明文 Key，再规范化并计算摘要。
- 数据库和 MCP 审计只保存 Key、调用命名空间和参数的摘要。稳定重放所需的首次响应按配置期限保留，默认 24 小时。
- 同一身份和 Key 配不同参数返回 `IDEMPOTENCY_CONFLICT`；正常并发调用在数据库锁边界内等待首次事务完成后重放，`IDEMPOTENCY_IN_PROGRESS` 仅用于防御异常或遗留的未完成记录。
- 幂等不能绕过实时 RBAC、Scope、凭据状态或审计；这些检查仍在共享调用事务边界内执行。

## 密码和令牌

- 用户密码使用 Spring Security 自适应密码编码器，默认 BCrypt。
- PAT 与服务账号令牌格式包含公开 ID/类型前缀和高熵秘密部分。
- PAT 与服务账号令牌使用带版本的 HMAC-SHA-256 哈希。`WEB_STARTER_CREDENTIAL_PEPPER` 未设置时回退到 V1 的 `WEB_STARTER_TOKEN_PEPPER`，既有记录按 `v1` 继续验证。
- 数据库只保存哈希和用于展示的短前缀，创建响应只返回一次明文。
- OAuth access token 为短时令牌；服务端只保存撤销/受众校验所需标识或哈希，不保存完整 Bearer Token。
- 日志、异常、审计详情和 Trace 不得记录密码、Cookie、Authorization Header 或完整 Token。

### 长期令牌 Pepper 轮换

1. V1 升级后先保持 `WEB_STARTER_CREDENTIAL_PEPPER_ACTIVE_VERSION=v1`，确认既有 PAT 与服务账号令牌仍可使用。
2. 轮换时将新值设为活动 Pepper（例如版本 `v2`），同时把旧值和 `v1` 分别配置到 `WEB_STARTER_CREDENTIAL_PEPPER_RETIRING` 与 `WEB_STARTER_CREDENTIAL_PEPPER_RETIRING_VERSION`。
3. 旧 Pepper 令牌只有在类型、期限、吊销状态和 IP 限制全部通过后，才在同一数据库事务中以比较更新迁移为活动版本；数据库与日志始终只接触摘要和版本。
4. 观察期结束且未迁移令牌已按策略失效后，同时移除两个 retiring 配置。不得直接删除旧 Pepper 后再宣称无损轮换。

`WEB_STARTER_TOKEN_PEPPER` 仍用于短期协调/协议摘要；长期令牌使用独立配置后，轮换长期令牌 Pepper 不会意外改变这些摘要。

### OAuth Client Secret 轮换

- 机密客户端轮换时生成的新 Secret 只返回一次；当前活动哈希变为 retiring 哈希，并记录非敏感版本和明确截止时间。
- 默认重叠窗口由 `WEB_STARTER_OAUTH_CLIENT_SECRET_OVERLAP` 控制（15 分钟），请求窗口不得超过 `WEB_STARTER_OAUTH_CLIENT_SECRET_MAX_OVERLAP`（默认 24 小时）。窗口内新旧 Secret 均由 Spring Authorization Server 的 Client Secret Provider 验证；到达截止时刻旧 Secret 立即拒绝。
- 管理员可调用 `DELETE /api/security/oauth-clients/{id}/retiring-secret` 紧急撤销旧 Secret。轮换与撤销分别记录 `ROTATE_SECRET`、`REVOKE_SECRET` 操作审计，审计内容不包含明文或哈希。

### 身份级联失效

- 密码重置、主体停用、主体删除和用户主动安全注销都会推进主体安全世代；既有 Web Session、OAuth access/refresh token 以及绑定该主体的 PAT 在下一次请求重新解析主体时失效。
- 用户主动安全注销使用 `POST /api/security/me/security-logout`，只允许注销当前主体；它与普通退出不同，目的是撤销该主体的其他既有凭据和会话。
- 这些行为的发布级验证、Pepper 迁移、Client Secret 重叠窗口、负向安全回归和明文扫描边界见[身份与凭据生命周期运行证据](credential-lifecycle-runtime-evidence.md)。

### OAuth RSA 签名密钥轮换

- 生产首选 `WEB_STARTER_OAUTH_RSA_JWK_SET` 与 `WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID`。JWK Set 可同时保存一个含私钥的 active RSA 键和一个或多个建议只含公钥的 retiring 验证键；全部键必须至少 3072 位并具有唯一 `kid`。
- 每个非 active JWK 必须带标准 `exp` NumericDate，作为明确且不包含该时刻的 retain-until 边界。新 Token 只使用 active `kid` 签名；应用以 UTC Clock 在每次 JWK 选择时过滤旧键，因此在边界前签发的旧 Token 到达边界后也会立即拒绝，重启不会延长窗口。
- 紧急撤销通过给 retiring JWK 增加标准 `rev` 对象并滚动部署受控 key-ring 完成；只要 `rev` 存在，该键立即停止发布和验签，`revoked_at` 只作为事件时间而不是未来调度器。正常窗口结束后应从受控 key-ring 删除旧公钥。
- active JWK 不得带 `exp` 或 `rev`，必须包含私钥。active 缺失、指向未知 `kid`、带过期/撤销状态，或任一 retiring 键缺少 `exp` 时，Authorization Server 在启动阶段失败，避免误撤唯一签名键后继续运行。日志和诊断字符串只允许输出 `kid`，不得输出 JWK 私钥、PEM 或 Secret。
- 单密钥 PEM 配置仍用于兼容，但不能作为无损轮换证据。完整轮换必须实测新旧 Token、JWKS、多 `kid`、窗口前后、紧急撤销后的拒绝和真实 MCP 调用。

## 外网 OAuth 要求

- HTTPS 是强制要求。
- Authorization Code 必须使用 PKCE S256。
- Redirect URI 必须精确匹配注册值。
- Token 必须绑定 `/mcp` 资源受众。
- 401 响应提供 Protected Resource Metadata 地址。
- 认证失败返回 401；权限或 Scope 不足返回 403。
- Token 不得放在查询参数中，也不得透传给其他服务。
- 动态客户端注册默认关闭；首版由管理员预注册客户端。

## 浏览器安全

- Session Cookie：`HttpOnly`、生产 `Secure`、`SameSite=Lax`。
- 浏览器 Session 的默认有效期由 `WEB_STARTER_SESSION_TIMEOUT` 控制；退出、用户停用和安全纪元变化仍会让现有 Session 在下一请求失效。
- 写请求使用 CSRF Token。
- 前后端同源部署，减少 CORS 暴露面。
- 登录失败使用统一错误，不泄露用户名是否存在。
- 登录、退出、密码修改、权限变更和凭据管理均写入审计。

### 登录限速与渐进退避

- 登录防护只使用“标准化账号”和“标准化账号 + 可信来源地址”两个 HMAC 化 Redis 桶，不使用会单独封禁一个来源地址上所有账号的 IP-only 桶。
- `WEB_STARTER_LOGIN_RATE_LIMIT_MAX_FAILURES_PER_IDENTITY` 与 `WEB_STARTER_LOGIN_RATE_LIMIT_MAX_FAILURES_PER_PAIR` 分别控制两个阈值；窗口、初始退避和最大退避由 `WEB_STARTER_LOGIN_RATE_LIMIT_WINDOW`、`WEB_STARTER_LOGIN_RATE_LIMIT_INITIAL_BACKOFF`、`WEB_STARTER_LOGIN_RATE_LIMIT_MAX_BACKOFF` 控制。
- 成功登录清除该账号及账号/来源组合的失败状态；Redis 键只保存带 Pepper 的不可逆假名，不保存用户名或地址明文。
- `WEB_STARTER_LOGIN_RATE_LIMIT_ENABLED=false` 只用于受控诊断；生产默认启用，关闭时不能形成 V2 登录防护验收证据。
- Redis 限速状态无法读取、写入或清理时，登录链路 fail-closed：返回不泄露内部原因的 `503`，不校验或建立会话，并以 `RATE_LIMIT_UNAVAILABLE` 记录登录审计。

## 运维端点身份

- Actuator 使用独立、无状态的 Spring Security 7 Filter Chain，优先于 Web、MCP 和 Authorization Server 的安全链。
- 健康、存活和就绪探针匿名；`info`、`metrics`、`prometheus` 仅授予专用 `OPERATIONS_OBSERVABILITY` 身份。
- 运维认证使用单独注入的 `WEB_STARTER_MANAGEMENT_USERNAME` 和 `WEB_STARTER_MANAGEMENT_PASSWORD`，不会查询业务用户、角色、OAuth Client、PAT 或服务账号。
- 生产要求运维用户名与 Bootstrap Web 管理员不同，密码至少 32 个随机字符且不得复用数据库、Redis、Token Pepper、Credential Pepper 或 Bootstrap 密码。
- 未同时配置两个值时，开发环境的非健康端点保持关闭；生产环境直接拒绝启动。普通 Web Session 不能跨到独立 management server 获取运维权限。
- 运维密码不得进入指标标签、结构化日志、异常、审计或发布证据。HTTP Basic 只允许在回环或受 TLS/mTLS 保护的受控运维链路使用。
- 浏览器发布验收默认关闭 Playwright trace 和失败截图，且输出目录必须在仓库外。只有开发者显式设置 `WEB_STARTER_PLAYWRIGHT_DIAGNOSTICS=true` 和仓库外输出目录时才生成原始调试材料；该材料可能包含临时凭据，不得上传为发布 Artifact。

## 入口信任边界

- 生产部署必须显式设置 `WEB_STARTER_RUNTIME_MODE=production`。应用会在 Spring 上下文刷新、Bean 创建、Flyway 迁移和数据库连接之前，拒绝 HTTP 或本机 Issuer/Audience、非 Secure Cookie、开发签名密钥、缺失或复用的独立运维凭据、空值或占位秘密、宽泛或本机 MCP Host/Origin，以及 `ALL`、`TRACE`、`DEBUG` 日志级别。
- 生产启动校验属于应用自身安全边界，不能用 Nginx 的 Cookie 或转发头修正代替。

- 生产环境不得直接暴露 Spring Boot 端口。
- `X-Forwarded-*` 和 `X-Web-Starter-Ingress` 只信任由受控 Nginx 写入的值。
- 随附的 Nginx 配置会用直接连接地址覆盖客户端传入的 `X-Forwarded-For`，避免伪造来源地址绕过令牌 IP 限制。
- 如果 Nginx 前还有负载均衡器，必须先用 `set_real_ip_from` 限定可信代理 CIDR，再配置 `real_ip_header`；不得直接信任任意来源的转发头。
- 公网虚拟主机必须覆盖 `X-Web-Starter-Ingress: public`。
- 公网入口拒绝 `wst_pat_` 和 `wst_svc_` 长期令牌。
- 可选 IP 限制必须基于经过可信代理解析后的客户端地址。

## 禁止能力

MCP 不提供以下能力：

- 任意 SQL
- Shell 或进程执行
- 任意文件读写
- 动态代码执行
- MCP Client 或第三方 MCP 代理转发

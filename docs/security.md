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

## 密码和令牌

- 用户密码使用 Spring Security 自适应密码编码器，默认 BCrypt。
- PAT 与服务账号令牌格式包含公开 ID/类型前缀和高熵秘密部分。
- 令牌秘密使用由 `WEB_STARTER_TOKEN_PEPPER` 驱动的 HMAC-SHA-256 哈希后查询。
- 数据库只保存哈希和用于展示的短前缀，创建响应只返回一次明文。
- OAuth access token 为短时令牌；服务端只保存撤销/受众校验所需标识或哈希，不保存完整 Bearer Token。
- 日志、异常、审计详情和 Trace 不得记录密码、Cookie、Authorization Header 或完整 Token。

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
- 写请求使用 CSRF Token。
- 前后端同源部署，减少 CORS 暴露面。
- 登录失败使用统一错误，不泄露用户名是否存在。
- 登录、退出、密码修改、权限变更和凭据管理均写入审计。

## 入口信任边界

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

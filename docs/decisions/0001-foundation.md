# ADR-0001：首版工程与安全基线

- 状态：已接受
- 日期：2026-07-18

## 决定

1. 工程采用 Java 21、Spring Boot 4.1 和 Spring MVC。
2. 使用单体多模块架构，不引入微服务和服务发现。
3. Spring Security 7 是唯一安全框架，内置 OAuth 2.1 Authorization Server。
4. Web 使用服务端 Session；外网 MCP 使用 OAuth；内网自动化可使用 PAT 或服务账号令牌。
5. REST 与 MCP 共享调用者上下文、RBAC、Scope、业务服务、事务和审计。
6. MySQL 是事实来源，Redis 仅用于会话和可重建的短期数据。
7. MCP 只提供 Server 能力，首版以 Tools 为主，不实现任意 SQL、Shell、文件系统或代码执行工具。

## 原因

- Java 21 与 Boot 4.1 为新工程提供较长的维护窗口。
- Spring Security 原生覆盖 Session、OAuth Resource Server 和 Authorization Server，避免两套安全上下文。
- 模块化单体能保持部署简单，同时通过 Maven 依赖方向保护边界。
- OAuth 2.1 为外部 MCP Agent 提供标准授权；内部令牌满足固定自动化任务的低摩擦接入。

## 约束

- 外网入口默认不接受长期 PAT 或服务账号令牌。
- 长期令牌和客户端密钥只保存不可逆哈希，明文只展示一次。
- 权限判定必须使用当前 RBAC 权限与令牌 Scope 的交集，不能永久信任签发时的角色快照。
- Authorization Server 仍是本单体的一部分；未来可替换为企业 IdP，但首版不拆服务。

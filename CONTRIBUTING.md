# 贡献指南

感谢你愿意参与启程 Web Starter。

## 开始之前

- 先搜索现有 Issue，避免重复提交。
- 大范围架构调整请先创建 Issue，说明目标、边界和兼容性影响。
- 安全漏洞不要提交公开 Issue，请按照 [SECURITY.md](SECURITY.md) 私下报告。
- 提交内容必须保持项目通用，不得引入特定公司的业务代码、名称、凭据或生产地址。

## 本地开发

后端需要 Java 21，前端需要 Node.js 22.12 或更高版本和 pnpm 9.15.9。

```bash
./mvnw verify

cd web-starter-web
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

本地运行、Docker Compose 和环境变量说明见 [README.md](README.md) 与
[部署说明](docs/deployment.md)。不要提交 `.env`、真实密码、令牌、私钥或证书。

## 变更要求

- REST 与 MCP 必须共用业务服务、事务、RBAC 和审计边界。
- Spring Security 是唯一安全基础，不得引入第二套认证框架。
- Flyway 迁移发布后只允许追加，禁止修改已经应用的迁移。
- 传输层使用明确 DTO，不直接暴露持久化实体。
- 行为变化必须同步更新测试和文档。
- 不得新增任意 SQL、Shell、文件系统或动态代码执行能力。

## Pull Request

请保持每个 Pull Request 聚焦于一个目标，并在描述中说明：

- 变更内容和原因；
- 对用户、兼容性和安全边界的影响；
- 已执行的验证命令及结果；
- 尚未验证的运行环境或人工验收项。

提交代码即表示你同意按照本项目的 [Apache-2.0](LICENSE) 许可证提供该贡献。

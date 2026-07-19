# V1 到 V2 兼容契约

本文固定 `v1.0.0` 到 V2 的最低兼容要求，并作为升级验收的输入。

## 必须保留

- Flyway V1、V2、V3 文件与校验和不修改；V2 只新增后续迁移。
- `dev.webstarter` 根包、现有 Maven 模块和模块依赖方向不破坏。
- 现有 `/api` 路径、HTTP 状态语义、字符串 ID 和 Trace ID 响应契约保持兼容。
- `project:list/create/update/remove`、`audit:list` 等既有权限编码保持稳定。
- 七个既有 MCP Tool 名称、`web-starter://system/info` Resource 和 `project.summary` Prompt 保留。
- Web Session、OAuth、PAT 和服务账号令牌继续汇聚到统一 `CurrentCaller` 与实时权限交集。
- 公共入口继续拒绝 PAT 与服务账号长期令牌，并继续隐藏普通管理 API 与 Actuator。

## 允许的兼容增量

- 响应对象增加可忽略字段。
- 写 Tool 增加可选幂等键；V2 文档和示例客户端必须使用，旧调用在一个迁移周期内继续接受并产生兼容审计。
- 数据表增加列、索引或新表，但必须通过追加迁移提供安全默认值和升级验证。
- 配置增加具有安全开发默认值的新变量；生产模式所需变量必须在升级说明中显式列出。
- 前端内部路由元数据和组件可以重构，但 URL、权限和可见行为保持兼容。

## 不保证

- 数据库 schema 向下迁移或运行旧应用读取不兼容的新 schema。
- 本地浏览器 Session 必然跨所有部署方式保持；如果发布过程导致 Session 失效，必须记录并验证重新登录路径。
- 本地自签证书、localhost Issuer 或临时密钥可以进入生产模式。
- 具体部署方的 DNS、CA、代理链、告警平台和 RPO/RTO 自动继承本地验收结论。

## 升级证据

升级作业必须：

1. 从 `v1.0.0` 镜像或源码创建数据库与凭据数据。
2. 记录升级前版本、Flyway、关键表行数和可用调用。
3. 使用 V2 不可变镜像执行追加迁移。
4. 记录升级后 Flyway、关键表行数和新旧功能结果。
5. 完成 Web 登录、Project CRUD、403、OAuth PKCE、Client Credentials、PAT 私/公网边界、官方 MCP SDK 与审计读回。
6. 保留脱敏证据；不保存密码、Cookie、Token、Client Secret、Pepper 或私钥。

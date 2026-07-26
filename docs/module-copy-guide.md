# 示例模块复制与生成规范

V2 推荐使用 `web-starter-tooling` 的声明式模块生成器；本指南同时保留人工复制的评审边界。生成器只接受固定 JSON schema，不加载动态模板或执行声明内容。`web-starter-project` 仍是参考模块；无论生成还是人工复制，都必须保持单体多模块边界，并继续让 Web 与 MCP 共用同一业务 Service、事务、实时 RBAC 和审计。

下文用 `asset` 举例：Maven 模块 `web-starter-asset`、Java 包 `dev.webstarter.asset`、表 `biz_asset`、权限前缀 `asset:`、Web 路径 `/api/assets`。

## 0. 推荐的声明式生成流程

先创建只描述模块语义的 `module.asset.json`。也可以复制 [`docs/examples/module-declaration.example.json`](examples/module-declaration.example.json) 后修改：

```json
{
  "schemaVersion": 1,
  "name": "asset",
  "label": "资产",
  "plural": "assets",
  "table": "biz_asset",
  "route": "/assets",
  "migrationVersion": "202607190001",
  "permissionIdBase": 5100,
  "menuId": 6100
}
```

依次执行只读校验、零写入预览和事务生成：

```bash
./bin/web-starter module validate --workspace . --declaration module.asset.json
./bin/web-starter module dry-run --workspace . --declaration module.asset.json
./bin/web-starter module generate --workspace . --declaration module.asset.json
```

声明没有输出路径、文件路径、命令、模板或表达式能力；未知或重复字段、嵌套结构和非严格类型均拒绝。MCP 不属于声明内容，确需 MCP 时必须在命令上显式增加 `--with-mcp`。`validate` 与 `dry-run` 都复用完整冲突扫描但不写文件，`generate` 复用同一计划和工作区事务边界。

## 1. 复制前决定

先写下并评审以下内容，避免复制后再发明命名：

| 项目 | 示例 | 规则 |
|---|---|---|
| 模块短名 | `asset` | 小写单数，只含字母和数字 |
| Maven artifactId | `web-starter-asset` | 必须带项目统一前缀 |
| Java 包 | `dev.webstarter.asset` | 不创建新的根包 |
| 数据表 | `biz_asset` | 业务表使用稳定、独立前缀 |
| REST 集合路径 | `/api/assets` | 复数名词 |
| 权限编码 | `asset:list/create/update/remove` | Web 按钮、Service 和 MCP 完全相同 |
| 菜单路径 | `/assets` | 与前端路由一致 |
| MCP Tools | 可选 | 新增 Tool 先变更冻结清单和验收基线 |

禁止对整个仓库执行 `project -> asset` 的无差别替换。它会破坏 Maven `<project>`、`${project.version}`、通用文档和既有示例。替换必须限定在复制出的目录和明确的注册点。

## 2. 后端模块

以下步骤用于审查生成结果，或在生成器固定模型不适用时进行人工复制：

1. 复制 `web-starter-project` 为 `web-starter-asset`，或审查生成出的 `web-starter-asset`。
2. 只在新目录内修改 `artifactId`、包名、类名、REST 路径、权限常量和表名。
3. 保留以下分层；Controller 不直接调用 Mapper：

```text
dev.webstarter.asset
├── domain
├── dto
├── persistence.mapper
├── service
│   └── impl
└── web
```

4. 在根 `pom.xml` 的 `<modules>` 注册新模块。
5. 在 `web-starter-admin/pom.xml` 添加运行时模块依赖。
6. 在 `WebStarterApplication` 的 `@MapperScan` 中添加 `dev.webstarter.asset.persistence.mapper`。
7. API 中的数据库 ID 是不透明十进制字符串；浏览器端不得把 Snowflake `Long` 当作 JavaScript `number`。

复杂模块可在确有多个用例或适配器时增加 `application`、`infrastructure`，不要预先创建空层。

## 3. Flyway、权限和菜单

只能新增下一版本迁移，禁止修改已经发布的迁移。一次完整模块迁移至少说明：

- `biz_asset` 的 DDL、唯一键、查询索引、逻辑删除列和乐观锁列；
- `asset:list/create/update/remove` 四类权限及稳定 ID；
- 菜单记录、按钮记录、路径、排序和权限编码；
- 内置 `ADMIN` 角色对新权限和菜单的初始关联；
- ID 分配策略和与既有迁移不冲突的 ID 区间；
- 回滚采用“新迁移修正”，不删除旧 migration 文件。

空库验收必须从 V1 连续执行到最新版本，并核对 `flyway_schema_history`。只在已有开发库执行成功不算通过。

## 4. RBAC、事务和审计

- Controller 可以做请求级权限提示，但 Service 必须再次执行权限校验；MCP 不能绕过 Service。
- REST 与 MCP 使用相同的 `asset:*` 权限，最终授权是主体实时 RBAC 与 Token Scope 的交集。
- 创建、更新、删除及其成功操作审计必须在同一数据库事务提交或回滚。
- 每个业务模块通过 Spring Bean 实现 `OperationAuditRouteContributor`，贡献固定 REST 前缀、模块、资源类型和成功审计归属；不要修改 Admin 过滤器源码或维护集中式路径列表。
- 生成模块固定使用 `OperationAuditRoute.serviceOwned(...)`：成功审计由共享 Service 在业务事务中写入，REST 审计过滤器仅在 4xx/异常回滚后用独立事务补写失败记录，避免 REST 与 MCP 重复成功日志。
- 人工实现且明确永不提供 MCP 写 Tool 的 Web-only 资源可以使用 `OperationAuditRoute.filterOwned(...)`，由过滤器在外层事务内写成功审计；此时 Service 不得重复写成功日志。归属变更必须同步补充去重与回滚测试。
- 每个错误响应和审计记录保留 Trace ID，不记录请求密码、明文 Token、OAuth Client Secret 或完整授权码。

## 5. 前端接入

至少逐项接入并测试以下位置：

1. `src/types/models.ts`：实体、分页和写入 DTO；所有数据库 ID 只使用 `string`，不引入 `number | string` 兼容类型，也不做 `Number(id)`。
2. `src/api/<module>.ts`：列表、详情、创建、更新、删除；所有写请求设 `csrf: true`。
3. `src/views/<Module>View.vue` 或 `src/features/<module>/<Module>View.vue`：使用 `useStandardCrudPage` 统一加载、空数据、错误、URL 查询/分页、校验、409 乐观锁和删除确认。
4. `src/navigation/manifest.ts`：只新增一条类型化导航记录；路由、侧栏、面包屑和命令搜索均由它派生，禁止分别修改四份清单。
5. `src/constants/menu.ts`：登记与数据库菜单一致的菜单 ID；页面权限与菜单 ID 的交集仍由统一导航记录和路由守卫执行。
6. API 契约测试、路由守卫和权限测试：固定请求字段、CSRF、菜单/权限交集及直接路由 403；需要进入私有管理 API 公共契约的模块同时扩展 `web-starter-web/contracts/private-api.openapi.json` 并执行 `pnpm contract:write` 后审查生成差异。

集合路由可能与 Vite 输出目录同名，例如业务路由 `/assets` 与静态目录 `/assets/`。私有 Nginx 的 SPA fallback 必须保持 `try_files $uri /index.html`，静态扩展名由独立 location 处理；不要恢复 `$uri/` 探测，否则同名业务路由会被重定向到物理目录。

桌面 ADMIN、低权限角色、无菜单角色和 390px 移动视口都需要真实浏览器证据。

## 6. 可选 MCP 接入

V1 的七个 Tool 是冻结契约。新增 Tool 必须先更新验收基线，再完成：

- `web-starter-mcp/pom.xml` 对新业务模块的依赖；
- `McpToolCatalog` 中固定 Tool 名、输入 Schema、Tool Annotations、权限映射和 Handler；
- ID 使用十进制字符串 Schema，在 Service 边界再安全解析为 `long`；
- Handler 只调用新模块 Service，不调用 Mapper；
- `tools/list` 精确集合、输入校验、读写权限、失败审计和官方 SDK Runtime IT；
- 明确禁止 SQL、Shell、文件系统和动态代码执行能力。

## 7. 必测项目

- Service：权限、输入边界、重复编码、乐观锁、逻辑删除和事务回滚。
- Controller：401、403、CSRF、400、404、409 和 Trace ID。
- 真实数据库：从空库迁移并完成 CRUD，不能只用伪 Mapper。
- 审计：成功与业务同事务；失败回滚后由独立事务记录；没有重复成功行。
- 前端：API Contract、类型、路由/按钮权限、生产构建和真实浏览器。
- MCP（若有）：官方 SDK initialize/list/call、RBAC/Scope 正反交叉和审计读回。

生成器会默认创建独立的 `*ServiceImplTest`、`*ControllerTest` 和 `*OperationAuditRouteContributorTest`，作为权限/审计、Service 接口与实现 `@Valid` 约束一致性、Controller 委托以及分段安全审计路由的最小可编译起点；它们不替代上述真实数据库、Spring Security、浏览器或协议运行时验收，模块扩展行为时必须同步扩展测试。

推荐门禁：

```bash
./mvnw -B -ntp -pl web-starter-asset -am test
./mvnw -B -ntp -pl web-starter-admin -am package
cd web-starter-web
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

## 8. 复制演练验收

发布脚手架前，在仓库副本或临时目录中复制出一个不同名称的模块，并保留以下证据：

- 新模块自身测试通过；
- Admin 打包产物确实包含新模块 JAR；
- 空库迁移、REST CRUD、RBAC 和审计真实通过；
- 前端页面完成创建、编辑、删除和权限隐藏；
- 若声明 MCP 接入，则官方 SDK 能发现并调用，且 Web/MCP 读到同一数据。

临时演练模块不能混入正式脚手架。只有“复制编译通过”时，应将完整 AC-42 标为 `NOT_COVERED`，直到迁移、前端、权限和审计也有证据。

## 9. 完成清单

- [ ] 列表、详情、创建、更新和删除完整可用。
- [ ] 分页上限、校验、唯一约束和乐观锁有正反证据。
- [ ] Flyway 可从空库连续执行，ADMIN 获得新菜单和权限。
- [ ] Web 与 MCP（若有）使用同一 Service、事务和权限编码。
- [ ] 成功/失败审计完整且不重复，Trace ID 可串联。
- [ ] 前端 types/api/view/router/menu/tests 全部接入。
- [ ] MCP Tool 仍是明确白名单，不存在任意执行能力。
- [ ] 单元、真实数据库、浏览器和 SDK 结果分别记录。
- [ ] 正式仓库不包含临时演练模块或任何外部业务代码。

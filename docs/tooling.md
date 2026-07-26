# 离线项目与模块生成工具

`web-starter-tooling` 是启程 Web Starter V2 的离线开发工具。它只在开发机上读取本地仓库并写入显式目标，不属于 Spring Boot 运行时，也不会通过 Web、REST 或 MCP 暴露。

当前批次提供三组能力：

- `project init`：从已提交的当前模板生成一个改名后的独立项目。
- `module validate|dry-run|generate`：为现有工作区规划或生成一个固定结构的 Web + REST CRUD 模块。
- `doctor|up|down|verify`：诊断本地环境、安全启停开发栈，并逐层采集验证证据。

工具使用 Java 21 标准库实现；运行时不需要额外依赖，也不下载远程模板、不执行生成内容、不接受脚本或动态模板表达式。

## 1. 启动方式

macOS/Linux：

```bash
./bin/web-starter help
```

Windows：

```bat
bin\web-starter.cmd help
```

如果工具 JAR 尚不存在，包装脚本会先用 Maven Wrapper 构建 `web-starter-tooling`，随后执行本地 JAR。第一次构建仍可能需要 Maven 本地仓库中已有依赖；工具本身不会访问远程模板。

## 2. 初始化派生项目

先在当前模板的干净、已提交 Git 工作树中执行预览：

```bash
./bin/web-starter project init \
  --source . \
  --name example-admin \
  --product-name "示例管理平台" \
  --group-id dev.example.admin \
  --package-prefix dev.example.admin \
  --database example_admin \
  --env-prefix EXAMPLE_ADMIN_ \
  --output ../example-admin \
  --dry-run
```

确认文件清单和摘要后，移除 `--dry-run` 才会创建项目：

```bash
./bin/web-starter project init \
  --source . \
  --name example-admin \
  --product-name "示例管理平台" \
  --group-id dev.example.admin \
  --package-prefix dev.example.admin \
  --database example_admin \
  --env-prefix EXAMPLE_ADMIN_ \
  --output ../example-admin
```

### 2.1 输入约束

- `--source` 必须是 Git 工作树，且所有已跟踪文件没有未提交修改。
- 模板索引不得使用 `assume-unchanged`、`skip-worktree` 或稀疏工作树隐藏改动；这些状态会 fail closed，不能用来绕过 clean 检查。
- 模板仓库不得在本地 Git 配置中注册 clean/process 内容过滤器；规划会在 `status` 前拒绝它们，避免检查过程执行仓库配置的程序。
- `--output` 必须显式提供，并且只能是不存在的路径或空的非符号链接目录。
- 输出目录与模板目录不能相同，也不能互相包含。
- `--name` 使用小写短横线格式；数据库名使用小写下划线格式；环境变量前缀使用大写下划线并以 `_` 结尾。
- `--group-id` 与 `--package-prefix` 只接受小写 ASCII Java 包段，并拒绝 Java 关键字和受限标识符。
- 产品名必须包含至少一个字母或数字，且只接受字母、数字、空格、点、下划线、连字符、括号和中点；因为同一身份会进入 XML、YAML、SQL、JSON、HTML 与源码，拒绝纯点段、引号、表达式标记和路径分隔符，避免改变生成语法或目录结构。
- 当前版本要求 `--group-id` 与 `--package-prefix` 相同，以避免不明确的全局替换。

### 2.2 复制与替换边界

工具以禁用 fsmonitor、untracked cache 和 optional lock 的只读 `git ls-files` 结果作为复制白名单，只复制普通的已跟踪文件，并保留可执行标记。仓库配置的 fsmonitor 不会在规划期间执行。受控替换包含：

- 工程名及其 PascalCase、camelCase、紧凑形式；
- 产品名；
- Maven group 与 Java 包路径；
- 数据库名；
- 环境变量前缀。

以下内容不会进入派生项目：

- 任意层级（包括仓库根）的 `.git`、`target`、`node_modules`、`dist`、Playwright/test-results 等构建或测试产物；
- `.env` 和除 `.env.example` 外的 `.env.*`；
- 常见私钥、证书、`.kdbx`/Java 密钥库和凭据文件；
- 带具体日期的本地验收记录；
- `release/evidence/` 下只属于模板自身 tag、commit 和镜像 digest 的发布验收输入。

派生项目必须在形成自己的版本、运行证据和注释 tag 后生成自己的 `release/evidence/<version>.json`，不能继承或改名复用模板的发布结论。

UTF-8 文本执行基于原始文本的一次性受控替换，替换结果不会被后续规则再次扫描；无法按 UTF-8 解码的二进制文件原样复制。模板和输出先解析为物理真实路径，因此祖先目录中的符号链接也不能绕过包含关系。任何重复目标路径、符号链接、索引冲突或非法路径都会在发布目录前失败。

项目先完整写入输出目录同级的临时目录，最后用原子目录移动发布。失败时不留下半成品；如果调用前目标是空目录，失败后会尽力恢复该空目录。

## 3. 生成业务模块

标准顺序是先校验，再预览，最后生成。可以使用行内参数：

```bash
./bin/web-starter module validate \
  --workspace . \
  --name asset \
  --label "资产" \
  --migration-version 202607190001 \
  --permission-id-base 5100 \
  --menu-id 6100

./bin/web-starter module dry-run \
  --workspace . \
  --name asset \
  --label "资产" \
  --migration-version 202607190001 \
  --permission-id-base 5100 \
  --menu-id 6100

./bin/web-starter module generate \
  --workspace . \
  --name asset \
  --label "资产" \
  --migration-version 202607190001 \
  --permission-id-base 5100 \
  --menu-id 6100
```

也可以把同一组模块语义保存为推荐的声明文件，例如 `module.asset.json`；仓库中的 [`docs/examples/module-declaration.example.json`](examples/module-declaration.example.json) 可直接复制后修改：

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

然后复用同一个声明完成三步：

```bash
./bin/web-starter module validate --workspace . --declaration module.asset.json
./bin/web-starter module dry-run --workspace . --declaration module.asset.json
./bin/web-starter module generate --workspace . --declaration module.asset.json
```

声明与行内模块字段互斥，避免两个来源产生覆盖优先级。`--workspace` 和声明文件路径仍由 CLI 单独解析；声明本身没有工作区、输出路径、模板、命令或脚本字段，也不会改变固定写入目标。

声明输入是严格、非可执行的 JSON 合约：

- `schemaVersion` 必须是 JSON 整数 `1`；迁移版本必须是 JSON 字符串，两个 ID 必须是 JSON 整数。
- 只接受上例字段；未知字段、重复字段、`null`、嵌套对象、数组、注释、尾随逗号和对象后的额外内容都会失败。
- 文件必须是最大 16 KiB 的 UTF-8 非符号链接普通文件。
- 模板或表达式标记会被拒绝；模块显示名只允许字母、数字、空格、下划线、连字符、括号和中点。
- JSON 不接受 `withMcp`。只有命令行显式增加 `--with-mcp` 才会生成 MCP 内容，例如 `module generate --declaration module.asset.json --with-mcp`。

可选参数：

- `--plural assets`：复数资源名，默认在模块名后加 `s`。
- `--table biz_asset`：数据表名，默认 `biz_<module>`；接受 2–53 位小写下划线标识符，生成 SQL 会固定引用表名。
- `--route /assets`：前端路由，默认 `/<plural>`。
- `--with-mcp`：额外生成静态编译的 MCP Tool 贡献、契约测试和官方 SDK 运行时测试；默认不生成任何 MCP 内容。

### 3.1 固定生成内容

模块生成器会规划以下变更：

- 新 Maven 领域模块及其显式依赖；
- `domain`、创建/更新/响应 DTO、Mapper、MyBatis-Plus 配置、Service、Controller；
- 模块内的 `OperationAuditRouteContributor`，以具名的 `serviceOwned` 归属注册 REST 写路径；Admin 自动聚合贡献，不需要生成器硬编码修改 Admin 源码；
- 独立的 Service 行为测试、Controller 委托测试和审计路由贡献测试，覆盖创建权限、标准化、成功审计、拒绝后零持久化、接口/实现 `@Valid` 约束一致性、乐观锁版本传递以及审计路径分段边界；
- 追加 Flyway 建表、权限与菜单迁移；
- 前端 types、API、API 契约测试、基于 `useStandardCrudPage` 的 CRUD 页面、菜单常量和单一类型化导航入口；
- 根 POM 与 Admin POM 的模块依赖注册。

生成业务对象固定包含 `id`、`code`、`name`、`status`、`description`、`version`、创建/更新时间和逻辑删除字段。更新与删除使用版本号执行乐观并发控制；权限固定为 `<module>:list/create/update/remove`。

生成模块的成功写审计由共享 Service 与业务数据处在同一事务中；注册后的 REST 路径仍经过管理操作审计过滤器，使 4xx 或异常在业务事务回滚后通过独立事务留下失败审计和 Trace ID。生成的路由贡献测试只证明注册元数据和路径边界，真实数据库上的回滚、失败审计持久化与去重仍属于运行时验收。

### 3.2 预检与事务边界

`validate` 和 `dry-run` 都会完成完整规划和冲突扫描，但不会写入任何文件；`dry-run` 额外输出每项 `ADD` 或 `MODIFY` 变更及计划摘要。

写入前会检查：

- 工程 Maven 身份、Admin、Web、Flyway 和固定注册锚点是否存在；
- 模块目录、表名、路由、权限编码、权限 ID、菜单 ID 与迁移版本是否冲突；
- 新迁移版本是否严格大于当前最高版本；
- 既有版本化迁移文件是否都采用 `V<1-18 位非零开头十进制数>__*.sql`，无法安全比较的前导零或复合版本会 fail closed；
- 所有新增文件是否不存在，所有修改文件是否仍与规划时一致；
- 计划修改的 Git 跟踪文件是否已有用户未提交更改；
- 工作区 Git 元数据必须是非符号链接文件或目录，且不得配置会在只读状态检查中执行的本地内容过滤器。

`generate` 对单文件使用同目录原子替换，并在事务前备份既有文件。POSIX 环境下，成功修改和失败回滚都会保留原文件的完整权限位，不会把 `0600` 等限制权限放宽为进程默认值。任一步失败时恢复既有文件、删除本次新增文件和空目录；不会递归删除可能由其他进程写入的目录。若并发删除或权限变化导致回滚无法完整恢复，工具以退出码 `5` 明确报告 `rollback was incomplete`，不会把不完整状态误报为原子回滚成功。

## 4. MCP 显式边界

不带 `--with-mcp` 时，生成结果只有 Web + REST。

带 `--with-mcp` 时，生成器会在新领域模块内增加静态编译的 Spring `McpToolContributor`，注册 `<module>.list/get/create/update/remove` 五个固定 Tool，并同时生成：

- 与 Tool 放在同一贡献对象中的权限编码及 `read/write/destructive` 风险级别；
- 禁止额外字段的固定输入 Schema、成功/错误输出 Schema 和风险 annotation；
- create/update/remove 必填幂等键，并复用模板的 MySQL 幂等事务；
- 通过同一业务 Service、实时 RBAC/Scope 交集和 MCP 审计边界执行的 handler；
- 贡献契约单元测试和一个显式运行的官方 MCP Java SDK `*RuntimeIT`。

注册方式是普通 Java 源码和 Spring Bean，不修改默认七个 Tool，也不下载或执行动态代码。只有把生成模块保留在 Maven/Admin 依赖中并完成部署后，新 Tool 才会存在；删除临时验收模块后默认模板清单恢复为七个 Tool。

生成的 `*RuntimeIT` 不进入普通单元测试。完整验收需要指向隔离部署，设置 `WEB_STARTER_GENERATED_MCP_BASE_URL`、`WEB_STARTER_GENERATED_MCP_TOKEN_RESPONSE_FILE` 和 `WEB_STARTER_GENERATED_MCP_TRACE_PREFIX` 后显式运行，并在结束后删除含短时 Token 的临时响应文件。

## 5. 本地环境诊断与安全启停

### 5.1 `doctor`

```bash
./bin/web-starter doctor --workspace . --env-file .env
```

诊断固定检查：

- Java 21–26、Maven Wrapper 3.9+、Node.js 22.12+、pnpm 9.15+；
- Docker Engine、Docker Compose 以及 `up --wait` 支持；
- 工作区、Maven Wrapper、启动器、前端清单的读写或执行权限；
- `.env` 必须是非符号链接普通文件；POSIX 系统要求秘密文件不能被组或其他用户读写，推荐 `chmod 600 .env`；
- 本地数据库、Redis、Token Pepper 等必需配置不得为空或保留示例占位值；诊断只输出配置项名称和状态，不输出配置值；
- MySQL、Redis、直连应用与 Nginx 的本地端口。端口已占用记为 `WARN`，需要确认占用者是当前 Compose 项目或修改相应环境变量。

`WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD` 为空只记为警告：空数据库首次启动时必须设置，初始化完成后应清空。存在任何 `FAIL` 时命令返回退出码 `3`。

### 5.2 `up`

先复制并修改本地配置，且不要提交：

```bash
cp .env.example .env
chmod 600 .env
./bin/web-starter doctor
./bin/web-starter up --timeout-seconds 300
```

`up` 在启动前执行 Compose 配置展开校验，但不打印配置内容；随后执行固定的 `docker compose up -d --build --wait`，只有 MySQL、Redis、应用和 Nginx 达到 Compose 健康条件才返回成功。复用预先构建的镜像时可显式增加 `--no-build`。默认 Compose 项目名是 `web-starter`，隔离验收可用合法的 `--project-name` 覆盖。

### 5.3 `down`

日常停止命令默认保留 MySQL 与 Redis 数据卷：

```bash
./bin/web-starter down
```

删除卷属于不可恢复操作，必须显式添加 `--volumes`，并在交互终端准确输入命令显示的确认短语。无交互环境还必须提供与项目名完全相等的第二确认：

```bash
./bin/web-starter down \
  --project-name web-starter \
  --volumes \
  --confirm-delete-volumes web-starter
```

只提供确认参数而未提供 `--volumes`、确认项目名不一致，或没有交互终端且未显式确认，都会在调用 Docker 前失败。工具不会执行额外的卷、目录或数据库清理。

## 6. 分层统一验证

```bash
./bin/web-starter verify --workspace . --env-file .env
```

每一层都有独立状态和日志；某层失败后仍继续执行后面的层。默认把新证据目录写入 `target/web-starter-verify/<UTC 时间>`，也可通过 `--evidence-dir <必须尚不存在的目录>` 指定。目录包含每个步骤的日志以及不含命令行和秘密的 `summary.json`、`summary.md`。
在 POSIX 系统上，证据目录创建为 `0700`，其中日志和摘要创建为 `0600`；工具不会先以宽松权限创建后再收紧。

| 层 | 固定执行或判定 |
|---|---|
| `backend` | `./mvnw --batch-mode --no-transfer-progress verify` |
| `frontend` | 依次执行 lint、typecheck、unit test、production build；单个步骤失败也继续后续步骤 |
| `policy` | 显式执行仓库秘密/禁用词、生产 Compose、发布安全和恢复工具四组通用策略测试；模板发布专用验收由各自发布门禁执行 |
| `container` | 默认校验 `compose.yaml` + `compose.dev.yaml`，并确认 MySQL、Redis、应用和 Nginx 四个服务均为 `running/healthy`；未启动记为 `ENV_REQUIRED` |
| `browser` | 使用已检入的 Playwright 配置和 `test:e2e` 脚本运行真实浏览器；验收输入缺失记为 `ENV_REQUIRED`，配置或脚本缺失记为 `NOT_COVERED` |
| `oauth` | 使用固定的 `scripts/verify_oauth_runtime.py` 验证 PKCE 与 Client Credentials；运行清单缺失记为 `ENV_REQUIRED`，验证器缺失记为 `NOT_COVERED` |
| `mcp` | 实时执行官方 MCP Java SDK 契约与低权限 RuntimeIT；CRUD/审计 RuntimeIT 在发布 runner 中只执行一次，本层独立验真其私有 Surefire XML、源码/POM/报告哈希和候选身份；缺少真实部署、短时只读 Token 或严格证明时记为 `ENV_REQUIRED` |

MCP 分层验收需要以下环境变量：

```text
WEB_STARTER_MCP_BASE_URL
WEB_STARTER_MCP_OWNER_ID
WEB_STARTER_MCP_PROJECT_ID
WEB_STARTER_MCP_TRACE_PREFIX
WEB_STARTER_VERIFY_MCP_READ_TOKEN_RESPONSE_FILE
WEB_STARTER_VERIFY_MCP_CRUD_PROOF_FILE
WEB_STARTER_VERIFY_MCP_CRUD_TRACE_PREFIX
WEB_STARTER_VERIFY_CANDIDATE_COMMIT
WEB_STARTER_VERIFY_CANDIDATE_VERSION
WEB_STARTER_VERIFY_CANDIDATE_TAG
```

只读 Token 响应文件必须位于 Git 工作区之外，是非符号链接普通文件，并在 POSIX 系统使用 `0600` 权限。CRUD 证明清单及其同目录固定名称 Surefire XML 也必须位于仓库外：目录严格为 `0700`，两个文件严格为 `0600`。工具不重新执行 CRUD，也不接受布尔 skip 或清单中的自报状态；它重新解析 XML 并要求恰好一个固定测试方法、0 failure/error/skip/flake/retry，重新计算测试源码、根 POM、MCP 模块 POM 与报告哈希，并把 commit/tree/version/tag、Compose project 和 CRUD Trace 前缀与当前发布输入逐项比较。证明生成与复核都会独立执行只读 Git 检查：workspace 必须是精确 top-level，HEAD commit/tree 必须匹配，索引不得含 skip-worktree/assume-unchanged，工作树必须 clean，三份源码的 commit blob 必须与工作区逐字节一致。工具不会把 Token、原始 XML 或系统属性写入摘要；验收结束后仍须在服务端吊销短时凭据并安全删除私有运行目录。

发布账本接线前还必须用独立 Python validator 把这份私有证明转换为最小脱敏摘要。validator 不导入证明 producer，也不会重新执行 SDK 测试；它再次严格解析 properties 和 Surefire XML，要求证据目录只包含固定的两个文件，并在校验前后复核文件身份与 SHA-256，防止验证过程中替换。除上述三份源码外，它还把 producer、validator 自身和前端 `package.json` 的 commit blob/工作区字节绑定到同一 clean HEAD，要求根 Maven、MCP 父版本和前端版本一致且非 `SNAPSHOT`，并要求实际注释 tag 指向该 commit。

```bash
mkdir -m 700 /absolute/private/mcp-crud-summary
python3 -B scripts/validate_mcp_crud_runtime_proof.py \
  --repository-root . \
  --proof /absolute/private/mcp-crud-proof/mcp-crud-runtime-proof.properties \
  --expected-candidate-commit "$GITHUB_SHA" \
  --expected-candidate-version "$WEB_STARTER_RELEASE_VERSION" \
  --expected-candidate-tag "$WEB_STARTER_RELEASE_TAG" \
  --expected-compose-project "$WEB_STARTER_ACCEPTANCE_COMPOSE_PROJECT" \
  --expected-trace-prefix "$WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX" \
  --require-pass \
  --summary-output /absolute/private/mcp-crud-summary
```

`--summary-output` 接受一个已经存在、空、非符号链接且权限为 `0700` 的仓库外目录，不是输出文件名。只有完整验证为 `PASS` 后才以 `0600`、拒绝覆盖方式创建固定文件 `mcp-crud-runtime-proof-summary.json`。摘要只包含候选 commit/tree/version/tag、Compose project、Trace 前缀、固定测试身份与计数，以及六份候选源码、proof 和 report 的 SHA-256；不复制原始 XML、JVM properties、绝对路径、凭据或 Token。后续 release gate 应从发布工作流自身提供 expected 值，并独立读取这个摘要，不能从 proof 或摘要反向填充 expected 参数。

V2-AC-33 的 Tool 契约证明是独立发布证据，不是上述 CRUD 证明或七层 `verify` 的重复执行。正式 runner 在同一隔离栈中只运行一次 `McpSdkToolContractRuntimeIT`，把固定两文件 raw proof 保存在仓库外 `0700` 目录，再由 candidate validator 生成 `0600` canonical summary；release gate 以固定 `release-tool-contract` Trace 前缀和 release commit/version/tag/Compose project 重新验证 raw proof，并要求公开摘要逐字节一致。Token 响应不进入证据目录或上传清单；失败时可能产生的临时 Project 由隔离 Compose 卷整体销毁兜底。完整命令、精确 Tool/schema/annotation 断言和归档边界见 [V2-AC-33 MCP Tool 契约证据](mcp-tool-contract-evidence.md)。

V2-AC-26 的 JWKS 轮换证明使用另一个专用 `web-starter-ac26-*` Compose 项目。正式 runner 固定回环公网/私网端口、`release-ac26` Trace 前缀和所提交的 `expiry` 或 `revocation` 终态，producer 只写仓库外双文件 raw 观察，candidate validator 再绑定 App/Nginx digest 与 image ID、候选 commit/version/tag、三阶段 JWKS、旧/新 JWT、401 和审计 Trace。release gate 不信任 summary 自报，而是以相同终态重新验证 raw 后才接受逐字节一致的 0600 canonical summary；公开 Artifact 不包含 JWK、Token、Secret 或 raw 报告。完整边界见 [V2-AC-26 JWKS 轮换运行验收](jwks-rotation-rehearsal.md)。

浏览器分层还需要 `WEB_STARTER_BROWSER_BASE_URL`、`WEB_STARTER_ACCEPTANCE_MANIFEST`、`WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME` 和 `WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD`。OAuth 分层需要 `WEB_STARTER_OAUTH_ACCEPTANCE_BASE_URL` 与 `WEB_STARTER_OAUTH_ACCEPTANCE_MANIFEST`。这些值只通过进程环境传入；清单和浏览器诊断必须位于仓库外的私有目录，摘要不得保存密码、Cookie、Token、PKCE verifier 或 Client Secret。

只有七层全部为 `PASS` 时 `verify` 返回 `0`。任意 `FAIL`、`NOT_COVERED` 或 `ENV_REQUIRED` 都返回 `6`，因此构建、单元测试或容器健康无法单独冒充全栈验收。

正式发布运行门禁会在同一组不可变镜像和空卷双入口栈仍然存活时调用该命令。发布 runner 内部固定设置 `WEB_STARTER_VERIFY_COMPOSE_MODE=production`；此时 container 层只读取 `compose.production.yaml`，并要求 MySQL、Redis、应用、私有 Nginx 和 `mcp-public-nginx` 五个服务全部为 `running/healthy`。该环境变量是发布集成的固定内部输入，不改变普通用户执行 `verify` 时的四服务开发栈语义。

七层原始日志和两次浏览器执行的 Playwright 临时输出都保留在 Git 工作区之外的私有运行目录，并在 cleanup 中精确删除；仅脱敏的逐层状态摘要及其 SHA-256 进入发布 Artifact 和最终证据账本。发布脚本单独执行过浏览器、OAuth 或 MCP 检查，不能替代这次统一入口验收。

## 7. 退出码

| 退出码 | 含义 |
|---:|---|
| `0` | 成功，包括 help、validate 和 dry-run |
| `2` | 参数或命名不合法 |
| `3` | 缺少 Git、工作区结构等前置条件 |
| `4` | 目标、标识、迁移或工作树冲突 |
| `5` | I/O、原子写入或未分类工具故障 |
| `6` | 统一验证存在 `FAIL`、`NOT_COVERED` 或 `ENV_REQUIRED` |

失败消息不会输出堆栈、文件内容或凭据。

## 8. 工具自身验证

```bash
./mvnw -B -ntp -pl web-starter-tooling -am test
```

测试覆盖参数退出码、严格声明 schema、未知字段/路径/表达式拒绝、零写入 dry-run、真实路径与符号链接边界、Git 隐藏索引与内容过滤器拒绝、根级构建产物/发布证据/凭据文件排除、一次性身份替换、非空目标拒绝、语义注册与迁移冲突、默认无 MCP、工作区权限保持与事务回滚、占位配置诊断、`up --wait`、默认保留卷、卷删除双重确认，以及分层验证在前序失败后继续采集证据。

这些测试只证明工具核心行为，不证明一个新派生项目或生成模块已经完成 V2 发布验收。实际生成后仍须分别执行后端 verify、前端门禁、秘密与禁用词扫描、空库与升级迁移、Compose、真实登录、CRUD、403/409、审计、浏览器，以及选择 MCP 时的官方 SDK 验收。当前模板工作树存在未提交修改时，`project init` 按设计拒绝运行；应先形成可追溯提交再做真实派生项目验收。

V2-AC-08 至 V2-AC-15 的两阶段正式入口、不可变镜像要求、清理边界、独立重放、canonical summary 与 release gate 接线见[派生项目与生成模块验收演练](generator-acceptance-rehearsal.md)。静态 tooling 测试、生产器自报 PASS 或公开摘要单独存在都不能形成正式验收结论。

AC-02、AC-37 与 V2-AC-16/17 的真实 `doctor → up → 管理员登录与密码哈希取证 → 写入 Project → down → 清空初始密码 → 拒绝危险删除 → restart → 再次登录并核对密码与 Project 指纹 → 日志泄露扫描 → 确认删除卷` 演练、私有 raw、运行镜像交叉绑定和 release gate 规则见[开发工具生命周期运行证据](tooling-lifecycle-runtime-evidence.md)。

## 9. V1 候选源码补充观察

`scripts/create_v1_source_review_observation.py` 只为 clean、带注释 tag、非 `SNAPSHOT` 的正式候选生成 status-free 私有观察包。它记录候选 commit 中的源文件 blob，不自行判定通过；`scripts/v1_regression_supplemental_validators.py` 随后独立重算运维文档完整性与 Flyway 序列条件。共享 ProjectService 边界不会用字符串扫描冒充架构证据；禁止 Tool 由真实官方 SDK 的精确七 Tool 协议发现证明。

V2-AC-01 的发布级 V1 来源溯源使用独立的 `create_v1_source_provenance_proof.py` 和 `validate_v1_source_provenance_proof.py`。它固定解析注释 `v1.0.0` 的 tag object、commit/tree、archive、42 项基线与历史验收记录，再验证当前 clean release candidate 的版本、tag、源码哈希和 ancestry；canonical summary 明确写出 `TAGGED_RECORD_ONLY`、`NOT_REVALIDATED` 与 `NOT_CLAIMED`，不会冒充当前候选的 V1 回归。raw 双文件只留在仓库外 `0700` 目录，公开 Artifact 只包含 `0600` canonical summary。完整契约见 [V2-AC-01 冻结 V1 来源溯源证据](v1-source-provenance-evidence.md)。

固定 9 个 Playwright 与 2 个官方 SDK 报告的候选绑定、私有 raw、最小 AC
映射、Playwright 1.61.1 本地依赖以及 release gate 双重重算规则见
[`releaseRuntimeTestReports` evidence adapter](acceptance/release-runtime-test-reports.md)。

V2-AC-24/27/28/36 的真实身份级联失效、Pepper 迁移、OAuth Client Secret 重叠窗口和统一负向安全回归由 release runner 的独立 credential lifecycle adapter 执行。其私有 raw、clean candidate 验证、canonical summary、门禁重算与清理约束见[身份与凭据生命周期运行证据](credential-lifecycle-runtime-evidence.md)；普通接口测试或手工生成摘要不能形成正式 `PASS`。

输出必须位于仓库外，目录为 `0700`、文件为 `0600`，并通过 `run_v1_candidate_regression.py --observation` 消费。该机制只能补充运维文档原子条件；其余 V1 运行、架构、协议、浏览器和恢复条件没有对应独立 adapter 时仍为 `NOT_COVERED`。

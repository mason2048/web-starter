# V1 当前候选全量回归

本文定义冻结的 V1 `AC-01..AC-42` 在“当前候选”上的可重复执行入口。它不会复用旧候选的结论，也不会把构建成功、容器健康或一份聚合报告扩张为未实际覆盖的验收项。

入口：

```bash
python3 -B scripts/run_v1_candidate_regression.py --help
```

覆盖映射由 [`security/v1-regression-coverage.json`](../../security/v1-regression-coverage.json) 固定，并绑定 [`v1-acceptance-baseline.md`](./v1-acceptance-baseline.md) 的 SHA-256。基线增删、级别变化或映射漏项会在执行前 fail closed。

## 状态和退出码

- `PASS`：一个 AC 的所有原子条件均有当前候选证据且全部通过。
- `FAIL`：至少一个原子条件观察到与基线冲突，或执行过程发生候选漂移、安全违规或证据契约错误。
- `NOT_COVERED`：证据未提供，或现有自动化只覆盖该 AC 的一部分。
- `ENV_REQUIRED`：所需运行环境缺失；仍不计作通过。
- 退出码 `0`：42 项全部 PASS。
- 退出码 `1`：存在真实失败或执行完整性失败。
- 退出码 `2`：参数、安全边界或证据契约被拒绝。
- 退出码 `6`：执行有效，但仍有 `NOT_COVERED` 或 `ENV_REQUIRED`。

## 三种模式

### 1. 规划模式

只验证冻结基线、覆盖映射和账本生成，不执行测试或容器。42 项应全部为 `NOT_COVERED`，因此预期返回 `6`。

```bash
evidence_dir="$(mktemp -d /private/tmp/web-starter-v1-plan.XXXXXX)"
python3 -B scripts/run_v1_candidate_regression.py \
  --mode plan \
  --output-dir "$evidence_dir"
```

### 2. 非容器模式

执行以下当前源码门禁，并分别记录结果：

- Maven `verify`；
- 前端 lint、typecheck、test、build；
- Python 工具测试；
- 仓库秘密扫描；
- 可选的仓库外禁用词文件；
- 可选的外部参考仓库前后只读指纹保护。

```bash
evidence_dir="$(mktemp -d /private/tmp/web-starter-v1-code.XXXXXX)"
python3 -B scripts/run_v1_candidate_regression.py \
  --mode non-container \
  --output-dir "$evidence_dir" \
  --forbidden-terms-file /absolute/external/forbidden-terms.txt \
  --reference-repository /absolute/read-only/reference-repository
```

禁用词文件内容不进入日志或账本。外部参考仓库只计算 `HEAD`、status、worktree diff、index diff 以及未跟踪文件内容集合的哈希；路径、文件名和内容不写入证据。未提供这两个参数时，对应条件明确保持 `NOT_COVERED`。

### 3. 完整候选模式

完整模式额外要求：

1. 当前源码工作树必须 clean，且 `HEAD` 等于候选清单的 `gitCommit`；
2. App、Nginx、MySQL、Redis 都必须使用 `reference + sha256 digest`，不接受 tag、旧镜像证据或本地可变名称；
3. 复用 `scripts/run_release_runtime_acceptance.sh`，由该 runner 自己创建和清理随机隔离 Compose project、网络和卷；
4. 复用官方 MCP SDK、Playwright、OAuth、双入口和 MySQL/Redis 故障验收；
5. 运行生产配置 fail-fast 镜像演练；
6. 运行模块生成器的只读 `dry-run --with-mcp`；
7. 可导入同一候选清单哈希绑定的补充观察包。

候选清单遵循 [`v1-regression-candidate.schema.json`](../../security/v1-regression-candidate.schema.json)：

```json
{
  "schemaVersion": 1,
  "release": {
    "tag": "v1.2.3-rc.1",
    "version": "1.2.3-rc.1",
    "gitCommit": "0000000000000000000000000000000000000000"
  },
  "images": {
    "app": {"reference": "registry.example.invalid/web-starter-app", "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
    "nginx": {"reference": "registry.example.invalid/web-starter-nginx", "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
    "mysql": {"reference": "mysql", "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
    "redis": {"reference": "redis", "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
  }
}
```

示例值不可用于真实回归。正式候选必须由同一 clean commit 生成并使用最终不可变镜像 digest；只有本地 image ID 而没有 runner 可消费的不可变 digest 时，完整模式应等待，不得借用旧镜像。

```bash
evidence_dir="$(mktemp -d /private/tmp/web-starter-v1-full.XXXXXX)"
python3 -B scripts/run_v1_candidate_regression.py \
  --mode full \
  --output-dir "$evidence_dir" \
  --candidate /absolute/private/candidate.json \
  --forbidden-terms-file /absolute/external/forbidden-terms.txt \
  --reference-repository /absolute/read-only/reference-repository \
  --observation /absolute/private/browser-observation/observation.json
```

## 补充观察包

现有 release runner 的正式检查只映射到它们直接证明的原子条件。`runtimeVersionIdentity` 还必须证明 Java 21、Actuator 应用/构建版本、实际 App/Nginx/MySQL/Redis digest reference 与 image ID，以及 App/Nginx 两组 OCI version/revision 都精确匹配候选的正式 tag、version 和 commit。例如，`oauthPkce` 不能单独证明 access token 的过期与吊销，浏览器 Project CRUD 不能单独证明全部用户、角色和菜单矩阵。剩余条件只能由**明确写入源码注册表并有独立语义校验器**的补充 producer 提供，索引格式遵循 [`v1-regression-observation.schema.json`](../../security/v1-regression-observation.schema.json)，artifact 公共信封遵循 [`v1-regression-supplemental-artifact.schema.json`](../../security/v1-regression-supplemental-artifact.schema.json)。

当前 `scripts/v1_regression_supplemental_validators.py` 只注册固定 producer `candidate-source-review`，并独立重算 `supplemental.operationsDocumentationReview` 与 `supplemental.projectIsolationReview`。项目隔离审查固定顶层 tracked inventory、根 Maven 模块顺序、各模块 artifact/source 边界、前端 package 名和全部 Java 源码的 `dev.webstarter` 包路径；增加业务模块、外来 Java 包或改写工程身份都会失败。共享 ProjectService 边界不使用字符串出现次数：正式发布另行执行固定 `ProjectTransportParityIT`，验证 Spring 中 REST/MCP 三个适配器持有同一个真实 `ProjectServiceImpl` Bean，并扫描 MCP 生产字节码不存在 Project Mapper/持久层引用；其 raw Surefire XML 与 properties 由 `validate_project_transport_parity_proof.py` 独立重算，形成 AC-15 专用 canonical 摘要。禁止 Tool 则继续由真实官方 SDK 对精确七 Tool 的协议发现证明；其他 supplemental 条件仍保持 `NOT_COVERED`。任何新增 adapter 都必须在源码中同时固定 producer、允许的 check 集合和专用 validator；不能通过 CLI、环境变量或观察包动态注册。

正式候选可用下列 producer 在仓库外生成无状态结论的私有观察包，再把返回的索引文件作为 `run_v1_candidate_regression.py --observation` 输入。候选必须是 clean、非 `SNAPSHOT`、带注释 tag，并与不可变镜像清单绑定；输出目录必须尚不存在，目录权限为 `0700`、文件为 `0600`。

```bash
python3 -B scripts/create_v1_source_review_observation.py \
  --repository-root /absolute/clean/candidate \
  --candidate /absolute/private/candidate.json \
  --output-directory /absolute/private/v1-source-review
```

该观察包只记录候选 commit 中的源文件 blob 与 SHA-256，不写 `PASS`。独立 validator 会重新读取同一候选、校验 clean commit/tree/archive、注释 tag、非 `SNAPSHOT` 版本和逐文件字节，再重算运维文档、Flyway 序列和固定工程结构。它不能替代登录、浏览器、OAuth、MCP、数据库或恢复运行验收，也不能让包含这些条件的整项 AC 自动通过。

V1 回归账本中的 AC-40 只有在三个条件同时通过时才能成为 `PASS`：仓库外注入的禁用业务词扫描零命中、外部参考仓库执行前后指纹相同，以及上述项目隔离语义审查通过。源码观察包单独不能证明前两个外部事实。正式 `release_evidence_gate.py` 已注册专用 `v1ProjectIsolationSummary` 绑定，但仍会现场读取受保护的禁用词和参考仓库重新计算，不能只导入回归账本或自报 `PASS`。完整合同见[工程隔离证据](../v1-project-isolation-evidence.md)。

下列目录与 JSON 只是未注册 producer 的通用信封示例，用来说明 schema；示例中的 `browser-acceptance` 当前不能产生 `PASS`。已注册的源码观察包使用上面的固定 producer，并只包含运维文档与项目隔离两类源码审查 artifact。

```text
generic-observation-bundle/
├── observation.json
└── artifacts/
    └── sanitized-summary.json
```

`observation.json` 示例：

```json
{
  "schemaVersion": 2,
  "suite": "v1",
  "candidate": {
    "manifestSha256": "候选清单文件的64位sha256",
    "gitCommit": "当前clean候选的完整commit对象ID",
    "gitTree": "当前clean候选的完整tree对象ID",
    "sourceArchiveSha256": "从该commit真实字节生成的Git archive SHA-256",
    "releaseTag": "v2.0.0",
    "releaseVersion": "2.0.0"
  },
  "producer": "browser-acceptance",
  "observedAt": "2026-07-19T12:00:00+00:00",
  "artifacts": [
    {
      "id": "browser-summary",
      "path": "artifacts/sanitized-summary.json",
      "sha256": "脱敏证据文件的64位sha256"
    }
  ],
  "checks": [
    {
      "id": "supplemental.browserStateAndViewportMatrix",
      "artifactIds": ["browser-summary"]
    }
  ]
}
```

`artifacts/sanitized-summary.json` 的公共信封示例：

```json
{
  "schemaVersion": 1,
  "suite": "v1",
  "producer": "browser-acceptance",
  "check": "supplemental.browserStateAndViewportMatrix",
  "candidate": {
    "manifestSha256": "与observation.json完全相同",
    "gitCommit": "与observation.json完全相同",
    "gitTree": "与observation.json完全相同",
    "sourceArchiveSha256": "与observation.json完全相同",
    "releaseTag": "与observation.json完全相同",
    "releaseVersion": "与observation.json完全相同"
  },
  "observations": {
    "说明": "这里只保存专用validator需要重算的状态无关事实"
  }
}
```

索引和 artifact 都故意没有可供 producer 填写的 `status` 字段。只含 `{"status":"PASS"}` 的 artifact 是结构伪造，对应原子条件记为 `FAIL`；结构合法但 producer 未注册、check 未登记或专用 validator 缺失时记为 `NOT_COVERED`。只有源码注册的 validator 根据 `observations` 重新计算出的结果才会进入账本。

补充观察只能提交映射中以 `supplemental.` 开头的原子条件，不能覆盖 runner、代码门禁、生成器或生产 fail-fast 的结果。候选绑定必须同时精确匹配清单 SHA-256、当前 clean `HEAD`、`HEAD^{tree}` 和当前 commit 的 Git archive 字节 SHA-256；clean 还要求索引没有 `skip-worktree`、`assume-unchanged` 或其他非正常条目。索引和每个 artifact 都必须重复同一绑定。索引候选身份、artifact 路径、SHA-256 或交叉引用不一致会拒绝整次导入；已正确索引但公共 artifact 信封伪造或身份不一致时，对应原子条件记为 `FAIL`。校验前后当前源码身份仍会再次比较，运行中漂移导致整次失败。

补充 artifact 必须先脱敏。不得包含或保存密码、Token、Cookie、Authorization Header、PKCE verifier、Client Secret、私钥或一次性签发响应；账本只记录 producer 与组合 SHA-256，不复制原始 artifact，也不记录其外部绝对路径。

## 尚未由入口自动完成的原子条件

以下行为需要独立适配器或隔离演练，当前缺失时必须保持 `NOT_COVERED`。AC-15 已由[专用 Project 共享业务层证据链](../project-transport-parity-evidence.md)接入发布门禁，不再属于本清单：

- 用户、角色、菜单、配置及完整安全管理浏览器矩阵；
- Session、CSRF、实时 RBAC/Scope 双向交集与全量审计/泄漏 canary；
- 完整 stop/start 数据持久性；
- `scripts/recovery_backup.py`、`scripts/recovery_restore.py` 和 `scripts/rehearse_redis_loss.py` 的隔离恢复演练；
- 在临时 clean 副本中真实生成独立 CRUD 模块，并完成迁移、REST、浏览器、403/409、审计及可选 MCP SDK 验收。

发布 runner 在退出时按设计清理自己的随机栈，因此恢复演练不能偷用或保留它的卷。恢复工具必须针对另一个随机、明确确认的隔离 project 执行，并以补充观察包绑定同一个候选；不得操作已有栈。

## 证据安全

- 输出目录必须位于仓库外，且必须不存在或为空；目录模式固定为 `0700`、文件为 `0600`。
- 不允许符号链接、路径逃逸和覆盖已有文件。
- runtime runner 使用随机 `web-starter-release-v1reg*` project、随机 loopback 端口和随机 `.test` 主机名；启动前按 Compose project label 检查容器、卷和网络均不存在，碰撞时换新随机身份。
- orchestrator 不直接执行 `docker compose down` 或删除卷；生命周期仍由原 release runner 的 trap 管理。
- runtime stdout/stderr 直接丢弃；只保留 runner 已定义的脱敏状态、指标和 acceptance JSON。
- 非容器日志若检测到凭据形态会立即删除，并把门禁标记为失败。
- 生成账本前再次扫描全部待保留 artifact；任何凭据形态文件都会被删除，并将整次执行标记失败。
- 执行前后重新计算当前源码和外部参考仓库指纹；源码指纹包含 commit、tree、commit Git archive SHA-256、索引正常性、tracked diff 与未跟踪内容集合，发生变化即整次回归失败。
- 输出包含 JSON 账本、Markdown 映射和带 SHA-256/权限模式的 evidence manifest，结构由 [`v1-regression-ledger.schema.json`](../../security/v1-regression-ledger.schema.json) 描述。

这套入口证明的是“该候选、该次执行、该证据范围”。它不把历史 V1 验收记录、临时目录、旧容器或旧镜像升级为当前候选证据。

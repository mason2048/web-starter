# V1 AC-15 Project 共享业务层证据

本页定义 `AC-15` 的独立候选证据。普通编译、静态源码搜索、历史 V1 报告、手写 JSON 或 producer 自报 `PASS` 都不能证明该项。只有固定 Spring Context 集成测试产生的精确 Surefire XML，经绑定同一 clean candidate 的 validator 重算后，才可形成 canonical 摘要。

该证据现已接入 `release_evidence_gate.py`、发布输入 Schema 和发布工作流。正式工作流在 detached clean candidate 中单独执行固定测试，保留私密 raw 双文件，由候选内 validator 重算 canonical 摘要；门禁的 `build` 与 `verify` 都必须重新读取同一 raw proof。只有 `release/evidence/<tag>.json` 将 AC-15 声明为 `PASS` 且这条独立链完整一致，正式账本才会把 AC-15 标记为 `PASS`。公开摘要本身仍不能单独放行。

## 固定语义

[`ProjectTransportParityIT`](../web-starter-admin/src/test/java/dev/webstarter/admin/acceptance/ProjectTransportParityIT.java) 只允许一个测试方法：

```text
provesRestAndMcpShareProjectServiceWithoutProjectPersistenceDependency
```

测试在一个显式注册、不会扫描外部配置的最小 Spring Context 中完成以下核验：

1. `CallerContext`、`PermissionService`、`ProjectMapper`、`SystemIdentityService`、`AuditLogRecorder` 使用 mock，但 `ProjectServiceImpl` 必须由 Spring 真实构造；
2. Context 中只有一个 `ProjectService` Bean，且其最终 target 是 `ProjectServiceImpl`；
3. `ProjectController`、`McpToolCatalog`、`McpContentCatalog` 三个真实适配器持有 Spring 返回的同一个 service Bean 实例；
4. 三个适配器的直接 Spring 依赖图包含 `projectService`、不包含 `projectMapper`；Context 中唯一的 Mapper mock 只服务于真实 `ProjectServiceImpl`；
5. 扫描 `web-starter-mcp` 整个生产 classpath 下的 `.class`，禁止出现 `dev/webstarter/project/persistence/`、`dev.webstarter.project.persistence.` 或 `ProjectMapper` 字节码引用。

MCP 模块自己的幂等、治理持久层不在禁用范围内；本验收只禁止 MCP 绕过 `ProjectService` 直接依赖 Project 模块的 Mapper/持久层。

## 候选与证据绑定

producer 和 validator 都要求：

- `HEAD` 等于声明的 commit，tree 精确匹配；
- 版本非 `SNAPSHOT`，tag 精确等于 `v<version>`，且必须是指向该 commit 的 annotated tag；
- 工作树包含未跟踪文件在内完全 clean，索引不存在 assume-unchanged 或 skip-worktree；
- 固定测试源码 SHA-256 不得漂移；
- 根、Project、MCP、Admin POM 版本一致；Admin 精确配置外部 Surefire 报告目录；模块依赖关系保持 Admin→Project/MCP、MCP→Project；
- 测试源码、`ProjectService`、`ProjectServiceImpl`、三个适配器、四个 POM、producer、validator、summary Schema 都必须是 candidate commit 中的普通 Git blob，并逐一绑定 SHA-256；
- 执行中的 producer/validator 字节必须与候选内相应脚本一致。
- Git 子进程使用隔离环境，忽略 ambient repository/worktree/index/object/alternate/config 注入，禁用 system/global config 和 replace object。

原始证据目录必须位于仓库外、权限 `0700`，最终只包含两个 `0600` 文件：

- `TEST-dev.webstarter.admin.acceptance.ProjectTransportParityIT.xml`
- `project-transport-parity-proof.properties`

validator 不读取测试控制台文字，也不信任 properties 中的状态。它重新解析 Surefire XML，只接受固定 suite、固定 method、`tests=1`，且 failure/error/skip/flake/retry/rerun 全部为 0。验证期间还会重读候选、tag、raw 文件和目录集合，拒绝 TOCTOU 漂移。

canonical 摘要文件固定为 `project-transport-parity-proof-summary.json`，结构由 [`v1-ac15-project-transport-parity-summary.schema.json`](../security/v1-ac15-project-transport-parity-summary.schema.json) 封闭定义。摘要只含候选身份、固定测试语义、源码哈希和 raw 文件哈希，不包含环境变量、凭据或测试控制台内容。

## 干净候选演练

以下命令不启动 Docker，但必须在已准备好的 clean detached 候选中运行。示例路径和版本必须替换；raw/summary 目录必须在仓库外且预先为空。

```bash
export WEB_STARTER_CANDIDATE_ROOT='/absolute/clean-detached-web-starter'
export WEB_STARTER_AC15_RAW_DIR='/absolute/private/ac15-raw'
export WEB_STARTER_AC15_SUMMARY_DIR='/absolute/private/ac15-summary'
export WEB_STARTER_CANDIDATE_VERSION='2.0.0'

mkdir -m 700 "$WEB_STARTER_AC15_RAW_DIR"
mkdir -m 700 "$WEB_STARTER_AC15_SUMMARY_DIR"
export WEB_STARTER_AC15_STARTED_NS="$(python3 -c 'import time; print(time.time_ns())')"

cd "$WEB_STARTER_CANDIDATE_ROOT"
./mvnw --batch-mode --no-transfer-progress \
  -pl web-starter-admin -am \
  -Dtest=dev.webstarter.admin.acceptance.ProjectTransportParityIT#provesRestAndMcpShareProjectServiceWithoutProjectPersistenceDependency \
  -Dsurefire.failIfNoSpecifiedTests=false \
  -Dsurefire.useFile=false \
  -Dweb-starter.admin.surefire-reports-directory="$WEB_STARTER_AC15_RAW_DIR" \
  test

chmod 600 \
  "$WEB_STARTER_AC15_RAW_DIR/TEST-dev.webstarter.admin.acceptance.ProjectTransportParityIT.xml"

python3 scripts/create_project_transport_parity_proof.py \
  --repository-root "$WEB_STARTER_CANDIDATE_ROOT" \
  --report "$WEB_STARTER_AC15_RAW_DIR/TEST-dev.webstarter.admin.acceptance.ProjectTransportParityIT.xml" \
  --output "$WEB_STARTER_AC15_RAW_DIR/project-transport-parity-proof.properties" \
  --candidate-commit "$(git rev-parse HEAD^{commit})" \
  --candidate-version "$WEB_STARTER_CANDIDATE_VERSION" \
  --candidate-tag "v$WEB_STARTER_CANDIDATE_VERSION" \
  --started-at-epoch-ns "$WEB_STARTER_AC15_STARTED_NS"

python3 scripts/validate_project_transport_parity_proof.py \
  --proof "$WEB_STARTER_AC15_RAW_DIR/project-transport-parity-proof.properties" \
  --repository-root "$WEB_STARTER_CANDIDATE_ROOT" \
  --expected-candidate-commit "$(git rev-parse HEAD^{commit})" \
  --expected-candidate-version "$WEB_STARTER_CANDIDATE_VERSION" \
  --expected-candidate-tag "v$WEB_STARTER_CANDIDATE_VERSION" \
  --require-pass \
  --summary-output "$WEB_STARTER_AC15_SUMMARY_DIR"
```

`surefire.failIfNoSpecifiedTests=false` 只用于允许 reactor 上游模块没有该测试；Admin 模块若未实际执行固定测试，就不会产生要求的精确 XML，producer 必然失败。正式门禁会在 build 与 verify 两阶段重新调用 validator，并逐字节核对公开 `v1-ac15-project-transport-parity-summary.json`；raw properties/XML 不上传，工作流结束时只删除固定 `${RUNNER_TEMP}` 子目录。

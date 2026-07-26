# V2-AC-33 MCP Tool 契约证据

本页定义 `V2-AC-33` 的独立运行证据及正式发布接线。编译、单元测试、手写 JSON 或脚本自报的 `PASS` 都不构成正式结果。正式工作流只在真实隔离栈上执行一次专用官方 MCP Java SDK 契约测试，再由同一 commit/tag 的 clean detached 候选自身 validator 重新核验，最后由 release gate 从私有 raw proof 重算并逐字节核对公开 canonical summary。

## 固定契约

默认模板必须精确暴露以下 7 个 Tool，不允许在正式模板候选中混入生成器演练 Tool：

- `system.info`
- `project.list`
- `project.get`
- `project.create`
- `project.update`
- `project.remove`
- `audit.list`

三个写 Tool 都必须通过 SDK 返回明确的 success/error `outputSchema`。错误分支固定包含 `code`、`message`、`traceId`，`code` 满足：

```text
^(?:FORBIDDEN|INVALID_ARGUMENT|IDEMPOTENCY_CONFLICT|IDEMPOTENCY_IN_PROGRESS|INTERNAL_ERROR|BUSINESS_[0-9]{4})$
```

风险 annotation 固定为：

| Tool | readOnly | destructive | idempotent | openWorld |
|---|---:|---:|---:|---:|
| `project.create` | false | false | false | false |
| `project.update` | false | true | true | false |
| `project.remove` | false | true | true | false |

`idempotencyKey` 对 V2 Agent 是强烈要求，但为兼容 V1 调用，在当前迁移周期内仍不是输入 schema 的 required 字段。运行测试以 `web-starter-v1-contract-client/1.0.0` 初始化，并真实执行一次不带该字段的 create、update、remove。新客户端仍必须发送 16–128 字符的稳定重试键；以后若移除无键路径，必须作为明确的不兼容迁移处理，不能静默改变。

## 证据边界

[`McpSdkToolContractRuntimeIT`](../web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkToolContractRuntimeIT.java) 通过 `io.modelcontextprotocol.sdk:mcp` 的 Streamable HTTP 客户端连接真实 `/mcp`，核验：

1. 协议版本与精确 7 Tool；
2. 三个写 Tool 的输入、输出 schema 和 annotations；
3. `INVALID_ARGUMENT`、`BUSINESS_4090`、`BUSINESS_4004` 的真实结构化结果；
4. V1 无幂等键写路径完成 create、update、remove。

测试复用本次隔离运行栈中仓库外 `0600` 写权限 PAT 响应文件；Token 不复制到 raw proof 或 Actions Artifact。成功路径会删除临时 Project，但审计记录按设计保留。若测试中途失败，临时 Project 可能短暂留在该次隔离数据库中；runner 的 `EXIT` cleanup 会执行 `docker compose down --volumes --remove-orphans` 并确认 Compose project 不再拥有容器、卷或网络，因此不会泄漏到共享或生产数据库。该测试仍禁止对共享或生产数据库执行。

AC33 的 `McpSdkToolContractRuntimeIT` 与已有 `McpSdkCrudRuntimeIT` 是两个不同验收：前者只执行一次，验证精确 Tool、schema、annotation、稳定错误和 V1 无幂等键兼容；后者仍只执行一次，验证 CRUD、权限和审计，不用 AC33 重跑或替代。

原始证据目录必须在 Git 仓库外，权限为 `0700`，且最终只含两个 `0600` 文件：

- `TEST-dev.webstarter.mcp.acceptance.McpSdkToolContractRuntimeIT.xml`
- `mcp-tool-contract-runtime-proof.properties`

validator 只接受一个 testcase，且 tests=1、failure/error/skip/flake/retry 全部为 0。它还重新验证：

- `HEAD`、tree、非 SNAPSHOT 版本与 annotated `v<version>` tag；
- 包含未跟踪文件在内的 clean worktree，以及无 assume-unchanged/skip-worktree 的索引；
- Compose project、Trace 前缀和报告起始时间；
- 官方 SDK 依赖及其锁定版本；
- runtime test、7 Tool expectation、catalog、错误映射、POM、前端版本、producer、validator 与 summary schema 的 candidate blob 和 SHA-256；
- 原始目录/文件权限、固定文件名、XML 安全性、报告哈希和验证期间的 TOCTOU 漂移。

校验通过后生成一个 `0600`、排序键、紧凑 JSON、末尾单换行的 canonical summary，其结构由 [`v2-ac33-mcp-tool-contract-summary.schema.json`](../security/v2-ac33-mcp-tool-contract-summary.schema.json) 固定。runner 以 `O_EXCL` 创建 `artifacts/acceptance/mcp-tool-contract-runtime-proof-summary.json`，强制其为 `0600` 且与 validator 输出逐字节相同；原始 Surefire XML、properties 和 Token 响应不得上传为公开 Artifact。

`release_evidence_gate.py build` 必须同时收到 `--mcp-tool-contract-proof` 与 `--mcp-tool-contract-summary-artifact`。门禁在 clean candidate 上以 release commit、版本、annotated tag、Compose project 和固定 Trace 前缀 `release-tool-contract` 调用 validator 的 `require_pass` 路径，再核对公开摘要的模式与 canonical bytes；`verify` 必须再次提供同一 raw proof。只有该独立重算成立时，`V2-AC-33` 才绑定 `mcpToolContractSummary` 并获得 `GATE_INDEPENDENTLY_VERIFIED`。

## 手工候选演练

以下命令只适用于已经准备好的、非 SNAPSHOT、annotated tag、clean detached 候选工作树和真实隔离栈。Token 响应文件必须在仓库外并保持 `0600`。示例变量均需替换，不能提交：

```bash
export WEB_STARTER_CANDIDATE_ROOT='/absolute/clean-detached-web-starter'
export WEB_STARTER_CONTRACT_RAW_DIR='/absolute/private/ac33-raw'
export WEB_STARTER_CONTRACT_SUMMARY_DIR='/absolute/private/ac33-summary'
export WEB_STARTER_CANDIDATE_VERSION='2.0.0'
export WEB_STARTER_COMPOSE_PROJECT='web-starter-release-unique'
export WEB_STARTER_MCP_BASE_URL='https://mcp.example.internal'
export WEB_STARTER_MCP_TOKEN_RESPONSE_FILE='/absolute/private/write-pat-response.json'
export WEB_STARTER_MCP_OWNER_ID='<decimal-user-id>'
export WEB_STARTER_MCP_TRACE_PREFIX='release-tool-contract'

mkdir -m 700 "$WEB_STARTER_CONTRACT_RAW_DIR"
mkdir -m 700 "$WEB_STARTER_CONTRACT_SUMMARY_DIR"
chmod 600 "$WEB_STARTER_MCP_TOKEN_RESPONSE_FILE"
export WEB_STARTER_CONTRACT_STARTED_NS="$(python3 -c 'import time; print(time.time_ns())')"

cd "$WEB_STARTER_CANDIDATE_ROOT"
./mvnw --batch-mode --no-transfer-progress \
  -pl web-starter-mcp -am \
  -Dtest=dev.webstarter.mcp.acceptance.McpSdkToolContractRuntimeIT \
  -Dsurefire.failIfNoSpecifiedTests=false \
  -Dsurefire.useFile=false \
  -Dweb-starter.mcp.surefire-reports-directory="$WEB_STARTER_CONTRACT_RAW_DIR" \
  test

chmod 600 "$WEB_STARTER_CONTRACT_RAW_DIR/TEST-dev.webstarter.mcp.acceptance.McpSdkToolContractRuntimeIT.xml"
python3 scripts/create_mcp_tool_contract_runtime_proof.py \
  --repository-root "$WEB_STARTER_CANDIDATE_ROOT" \
  --report "$WEB_STARTER_CONTRACT_RAW_DIR/TEST-dev.webstarter.mcp.acceptance.McpSdkToolContractRuntimeIT.xml" \
  --output "$WEB_STARTER_CONTRACT_RAW_DIR/mcp-tool-contract-runtime-proof.properties" \
  --candidate-commit "$(git rev-parse HEAD^{commit})" \
  --candidate-version "$WEB_STARTER_CANDIDATE_VERSION" \
  --candidate-tag "v$WEB_STARTER_CANDIDATE_VERSION" \
  --compose-project "$WEB_STARTER_COMPOSE_PROJECT" \
  --trace-prefix "$WEB_STARTER_MCP_TRACE_PREFIX" \
  --started-at-epoch-ns "$WEB_STARTER_CONTRACT_STARTED_NS"

python3 scripts/validate_mcp_tool_contract_runtime_proof.py \
  --proof "$WEB_STARTER_CONTRACT_RAW_DIR/mcp-tool-contract-runtime-proof.properties" \
  --repository-root "$WEB_STARTER_CANDIDATE_ROOT" \
  --expected-candidate-commit "$(git rev-parse HEAD^{commit})" \
  --expected-candidate-version "$WEB_STARTER_CANDIDATE_VERSION" \
  --expected-candidate-tag "v$WEB_STARTER_CANDIDATE_VERSION" \
  --expected-compose-project "$WEB_STARTER_COMPOSE_PROJECT" \
  --expected-trace-prefix "$WEB_STARTER_MCP_TRACE_PREFIX" \
  --require-pass \
  --summary-output "$WEB_STARTER_CONTRACT_SUMMARY_DIR"
```

该命令产生的结果只证明所绑定候选和所指向隔离栈的 AC-33 运行契约。手工结果还必须进入与正式工作流等价的 raw-proof 门禁重算和 canonical-byte 核验，才能标记正式 `PASS`；未运行真实容器、未使用隔离栈真实签发凭据、候选为 dirty/SNAPSHOT、Trace 前缀不同或缺少 raw proof 时都不得标记。

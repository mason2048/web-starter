# V2-AC-34 / V2-AC-35 MCP 治理运行证据

本页定义 MCP Session 生命周期与应用层限流的候选绑定运行合同。正式发布账本的默认状态仍是 **NOT_COVERED**：runner 与独立 validator 已在仓库外的干净、非 SNAPSHOT 临时候选上完成过真实 MySQL、Redis、双 Nginx、HTTP、官方 SDK、优雅停机和重启演练，但该临时证据不能替代同一次正式 release job 的归档证据、完整 V1/V2 账本和 release gate。编译成功、mock 测试、接线完成、旧的临时摘要或直接调用 Redis registry 的测试都不能把新候选的 AC-34/35 自动写成 `PASS`。

## 验收边界

正式证据由两个不同 JVM 运行阶段组成：

1. `McpSdkGovernanceRuntimeIT` 连接隔离候选栈的真实 `/mcp`。它必须通过官方 MCP Java SDK 完成初始化和 `system.info`，并通过真实 Streamable HTTP 观测：
   - idle TTL 精确配置为 50 秒：一个 Session 在第 48 秒仍可用，另一个未触碰 Session 在第 51 秒调用 `system.info` 时返回 HTTP 404 / `SESSION_EXPIRED`；
   - absolute TTL 精确配置为 60 秒：在第 20、40、59 秒持续保持 idle 活跃，第 59 秒仍可用，第 61 秒调用 `system.info` 时返回 HTTP 404 / `SESSION_EXPIRED`；
   - 每主体最多 2 个 Session，第三个初始化返回 HTTP 429、正整数 `Retry-After` 和 `SESSION_LIMIT`；
   - 显式 `DELETE /mcp` 成功，随后旧 Session 返回 HTTP 404 / `SESSION_NOT_FOUND`；
   - 主体、OAuth client 和 destructive risk 三个相互隔离的桶分别触发 HTTP 429 / `Retry-After`；
   - `audit.list` 回读每个限流 Trace 的 `FAILED` / `RATE_LIMITED`，并核对主体测试使用同一 actor 的不同 PAT、client 测试使用不同 actor 的同一 OAuth client。
2. 第一阶段完成耗时的 idle / absolute TTL 观测后，必须用 `sdk.json` 通过官方 SDK 新建一个 fresh shutdown-probe Session，再把它的 Session ID 和创建时间写入仓库外的 `0600` 私有 state 文件。固定的 `orchestrate_mcp_governance_restart.py` 必须在 40 秒内记录旧应用进程、SIGTERM 成功退出、新应用进程及健康状态，同时证明应用镜像不变，Redis 容器、进程、镜像、restart count、命名卷和短期 marker 均跨应用重启保持连续。`McpSdkGovernanceShutdownRuntimeIT` 必须在该 fresh Session 创建后的 45 秒内，使用已超过限流窗口的 `delete.json` 建立当前健康对照 Session，再以原 `sdk.json` 调用旧 Session 并确认治理 Filter 返回 HTTP 404 / `SESSION_NOT_FOUND`。这样至少保留 5 秒 idle 余量和 15 秒 absolute 余量。若复用已超过 absolute TTL 的旧 Session、只等待 TTL、杀死进程后不探测、重建 Redis，或让官方 SDK 自己返回普通未知 Session 错误，测试都会失败。

`RedisMcpGovernanceIT` 只用于验证 Lua 原子性、精确时钟推进和 Redis key 行为；它不经过官方 SDK、Spring Security、Servlet Filter 或真实 HTTP，不能替代上述两个报告。

应用显式使用 graceful shutdown，生产配置把 Spring 每个关闭阶段限制为 10 秒，避免未关闭的 Streamable HTTP 长连接独占默认 30 秒关闭窗口，并为 40 秒的停机、重启和健康证明留下确定余量。

总运行验收先完成主栈的浏览器、OAuth、MCP、故障恢复与可观测性取证，保存其脱敏健康状态后再销毁主栈及临时卷，最后启动独立治理栈。这样 40 秒重启目标只度量治理候选自身，不受已经完成取证的另一套 Java、MySQL 与 Redis 容器争抢本机资源影响；治理栈仍使用独立 Compose 项目、端口、凭据、数据库和原始证据目录。

重启后的官方 SDK 断言复用 Maven 进程执行而不再额外启动 Surefire fork JVM，减少与业务恢复无关的进程冷启动时间；40 秒重启窗口和 45 秒端到端 Session 探测窗口保持不变。

## 固定验收配置

隔离栈必须使用以下值。改变任一值需要修改固定测试、validator、schema 和本文，并重新评审，不能只改运行参数让测试“更容易通过”。

```text
WEB_STARTER_MCP_SESSION_ENABLED=true
WEB_STARTER_MCP_SESSION_IDLE_TTL=50s
WEB_STARTER_MCP_SESSION_ABSOLUTE_TTL=60s
WEB_STARTER_MCP_SESSION_MAX_PER_SUBJECT=2
WEB_STARTER_MCP_RATE_LIMIT_ENABLED=true
WEB_STARTER_MCP_RATE_LIMIT_WINDOW=15s
WEB_STARTER_MCP_RATE_LIMIT_MAX_PER_SUBJECT=5
WEB_STARTER_MCP_RATE_LIMIT_MAX_PER_CLIENT=5
WEB_STARTER_MCP_RATE_LIMIT_MAX_READ=5
WEB_STARTER_MCP_RATE_LIMIT_MAX_WRITE=5
WEB_STARTER_MCP_RATE_LIMIT_MAX_DESTRUCTIVE=1
WEB_STARTER_MCP_RATE_LIMIT_MAX_PROTOCOL=5
WEB_STARTER_MCP_GOVERNANCE_EXPECTED_VERSION=<candidate non-SNAPSHOT version>
WEB_STARTER_MCP_GOVERNANCE_EXPECTED_GIT_COMMIT=<exact candidate commit>
```

主体和 client 的固定上限 5 对应官方 Streamable HTTP SDK 的完整最小生命周期：`initialize`、消息流 `GET`、`notifications/initialized`、一个 Tool 调用以及 graceful `DELETE`。所有五个 HTTP 请求都必须计入全局桶；不能通过忽略传输维护请求来绕过治理。重启后的当前健康对照使用另一个已冷却凭据，旧 Session 探测仍使用创建它的 `sdk.json`，避免把 Redis 限流连续性误判成 Session 清理失败。

两份 Java 运行测试和共享支持类是人工评审边界，validator 不从 proof 学习预期值：

| 固定源码 | 人工评审 SHA-256 |
|---|---|
| `McpSdkGovernanceRuntimeIT.java` | `03f9e6179d2b382c6cefe0b7416947a3bd5da208812c657a3227fceaee52b612` |
| `McpSdkGovernanceShutdownRuntimeIT.java` | `06a1155b1e389cf8bafaaba920e1c1c400b6403a6f912a3db6bdc9af586130be` |
| `McpGovernanceRuntimeSupport.java` | `644369d4ab15b7baf9ca0f073bf3ee4493ad4f5725e9ce62747e304f0a72c0bf` |

任何测试体、断言、官方 SDK 路径或共享 HTTP 支持代码变化都会被 producer 和独立 validator 拒绝；必须重新人工评审并同步两个固定映射及负向测试，不能由候选 proof 自行声明新哈希。

凭据目录必须位于仓库外、权限 `0700`；每个响应文件必须为 `0600`，内容是现有凭据创建或 OAuth token 响应。测试只在内存读取明文，raw proof 和公开 summary 都不保存 bearer。固定文件与语义如下：

| 文件 | 隔离 fixture 要求 |
|---|---|
| `sdk.json` | 独立主体；允许 `system.info`；用于官方 SDK 主流程，并在长耗时 TTL 观测结束后新建 fresh shutdown-probe Session |
| `session.json` | 独立 PAT 主体；用于同一主体 Session cap |
| `delete.json` | 独立 PAT；先用于显式 `DELETE /mcp` 及删除后的 404 观测；超过固定限流窗口后，在重启测试中建立当前健康对照 Session |
| `ttl.json` | 独立 PAT；只用于 idle / absolute TTL |
| `rate-subject-a.json`、`rate-subject-b.json` | 同一用户的两个不同 PAT；均允许 `system.info` |
| `rate-client-a.json`、`rate-client-b.json` | 不同用户、同一个 OAuth client 的 access token；允许测试 Tool |
| `rate-risk.json` | 独立主体；允许 `project.remove` |
| `audit.json` | 独立主体；允许 `audit.list` |

正式 runner 必须创建这些 fixture，并确认它们不复用其他验收流量。若主体或 client 关系不符合表格，审计身份断言会失败；不得通过降低断言或扩大限流阈值绕过。

## 原始证据与职责分离

raw 目录必须位于仓库外、由当前运行用户拥有且权限 `0700`，producer 写 proof 前只能包含四个固定 observation，完成后只能包含以下五个 `0600`、当前用户拥有、单硬链接文件：

- `TEST-dev.webstarter.mcp.acceptance.McpSdkGovernanceRuntimeIT.xml`
- `TEST-dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT.xml`
- `mcp-governance-shutdown-probe.properties`
- `mcp-governance-restart-receipt.json`
- `mcp-governance-runtime-proof.properties`

两个 Maven 测试必须各自写入不同的仓库外 `0700` 暂存目录，进程 `umask` 必须为 `077`，并设置 `-Dsurefire.useFile=false`。暂存目录必须只出现目标 XML；随后调用 producer 的 `stage_surefire_report`，用 `O_NOFOLLOW` 读取并以 `O_EXCL` 写入 raw。不得把 Surefire 默认生成的 `.txt`、另一个 reactor 模块报告或旧报告直接混入 raw。

当前锁定的 Maven/Surefire 配置已用 `McpRuntimeToolExpectationsTest` 做过真实兼容性诊断：上述参数在独立目录只生成一个 `0600` XML，没有 `.txt`。这只证明报告形状兼容，不是 AC-34/35 运行通过证据；正式候选仍必须对两份固定治理测试逐次执行同样检查。

producer 只接受两个精确 testcase 均为一次干净通过，并严格重算 restart receipt：receipt 中实际执行的 orchestrator SHA 必须等于候选 `scripts/orchestrate_mcp_governance_restart.py` blob；候选 version/commit、Compose project、Trace、SIGTERM/退出码、旧/新应用容器与镜像、PID/启动时间、健康状态、Redis 进程与卷/marker 连续性、私有 `nginx` 与 `mcp-public-nginx` 的容器/镜像/进程连续性、state SHA 和因果时间序列也必须一致。它还核对报告新鲜度、state 创建时间早于重启、固定 TTL、候选 source blob、clean worktree、非 SNAPSHOT 版本及 annotated `v<version>` tag，然后写 properties proof；它不会输出 `PASS`。

独立 validator 不导入 producer，会重新读取 XML、state、restart receipt、Git candidate blob、POM、官方 SDK 版本和所有 SHA-256，并在仍持有 raw 目录描述符与 receipt snapshot 时，把 receipt 中的应用、Nginx、Redis immutable reference 和 image ID 与 release gate 从 `runtimeVersionIdentity` 提供的六个期望值逐一比较，再生成由 [`v2-ac34-ac35-mcp-governance-summary.schema.json`](../security/v2-ac34-ac35-mcp-governance-summary.schema.json) 限定的 canonical summary。只有 receipt 独立通过后，summary 的 `gracefulRestart=true` 和 `ingressContinuity=true` 才成立；公开 summary 同时携带 Nginx image ID、不可变引用 SHA-256、固定 receipt 文件名、receipt SHA-256 和实际执行的 orchestrator SHA-256。Git 子进程使用固定可执行文件搜索路径和全新环境，禁用 replace objects，忽略外部 `GIT_DIR`、worktree、index、object store、alternate objects 及 `GIT_CONFIG_*` 注入，并拒绝候选仓库中的 replace refs 或 grafts；stdout/stderr 在读取时合计限流且有 20 秒硬超时，不在子进程结束后才检查大小。

producer 与 validator 对 raw、候选源码和自身 validator 使用目录描述符、`O_NOFOLLOW`、`fstat`、当前 UID、模式、单硬链接、分块大小上限和读前/读后 inode/metadata identity 检查；发出 proof 或 summary 前会再次检查 clean HEAD/tree/tag、全部候选 blob、raw 文件和目录 identity。

state 文件包含短期 Session ID，只能作为私有 raw evidence，不能上传为公开 Artifact；receipt 包含容器/镜像/进程身份，凭据目录、token 响应、两个 Surefire XML 和 properties proof 同样不得公开。允许公开的只有 validator 生成的 canonical summary；即使手工生成 summary，也不能改变本项目 AC-34/35 的 `NOT_COVERED` 状态，只有同一次 formal release run 的真实证据经 release gate 独立复核后才能改变。

## 候选演练顺序

以下命令是正式隔离候选 runner 的合同示例，不表示本次已经执行。开始前必须已有 clean detached、非 SNAPSHOT、annotated tag 候选，真实 MySQL/Redis 隔离栈，以及上表所列 fixture。

```bash
export WEB_STARTER_CANDIDATE_ROOT='/absolute/clean-detached-web-starter'
export WEB_STARTER_GOVERNANCE_RAW_DIR='/absolute/private/ac34-ac35-raw'
export WEB_STARTER_GOVERNANCE_SUMMARY_DIR='/absolute/private/ac34-ac35-summary'
export WEB_STARTER_MCP_GOVERNANCE_CREDENTIAL_DIR='/absolute/private/governance-credentials'
export WEB_STARTER_MCP_GOVERNANCE_STATE_FILE="$WEB_STARTER_GOVERNANCE_RAW_DIR/mcp-governance-shutdown-probe.properties"
export WEB_STARTER_MCP_GOVERNANCE_TRACE_PREFIX='release-governance'
export WEB_STARTER_MCP_BASE_URL='https://candidate-mcp.example.internal'
export WEB_STARTER_CANDIDATE_VERSION='2.0.0'
export WEB_STARTER_MCP_GOVERNANCE_COMPOSE_PROJECT='web-starter-governance-unique'
export WEB_STARTER_MCP_GOVERNANCE_EXPECTED_VERSION="$WEB_STARTER_CANDIDATE_VERSION"
export WEB_STARTER_MCP_GOVERNANCE_EXPECTED_GIT_COMMIT='<exact candidate commit>'
export WEB_STARTER_GOVERNANCE_MAIN_REPORT_DIR='/absolute/private/ac34-main-surefire'
export WEB_STARTER_GOVERNANCE_SHUTDOWN_REPORT_DIR='/absolute/private/ac34-shutdown-surefire'
export WEB_STARTER_APP_CONTAINER_ID='<exact 64-character app container id>'
export WEB_STARTER_REDIS_CONTAINER_ID='<exact 64-character redis container id>'
export WEB_STARTER_NGINX_CONTAINER_ID='<exact 64-character private nginx container id>'
export WEB_STARTER_PUBLIC_NGINX_CONTAINER_ID='<exact 64-character public nginx container id>'
export WEB_STARTER_APP_IMAGE_ID='sha256:<exact app image id>'
export WEB_STARTER_APP_IMAGE_REFERENCE='registry.internal/web-starter@sha256:<exact app digest>'
export WEB_STARTER_REDIS_IMAGE_ID='sha256:<exact redis image id>'
export WEB_STARTER_REDIS_IMAGE_REFERENCE='redis@sha256:<exact redis digest>'
export WEB_STARTER_NGINX_IMAGE_ID='sha256:<exact nginx image id>'
export WEB_STARTER_NGINX_IMAGE_REFERENCE='registry.internal/web-starter-nginx@sha256:<exact nginx digest>'

umask 077
mkdir -m 700 "$WEB_STARTER_GOVERNANCE_RAW_DIR"
mkdir -m 700 "$WEB_STARTER_GOVERNANCE_SUMMARY_DIR"
mkdir -m 700 "$WEB_STARTER_GOVERNANCE_MAIN_REPORT_DIR"
mkdir -m 700 "$WEB_STARTER_GOVERNANCE_SHUTDOWN_REPORT_DIR"
chmod 700 "$WEB_STARTER_MCP_GOVERNANCE_CREDENTIAL_DIR"
chmod 600 "$WEB_STARTER_MCP_GOVERNANCE_CREDENTIAL_DIR"/*.json

cd "$WEB_STARTER_CANDIDATE_ROOT"
export WEB_STARTER_GOVERNANCE_MAIN_STARTED_NS="$(python3 -c 'import time; print(time.time_ns())')"
./mvnw --batch-mode --no-transfer-progress \
  -pl web-starter-mcp -am \
  -Dtest=dev.webstarter.mcp.acceptance.McpSdkGovernanceRuntimeIT \
  -Dsurefire.failIfNoSpecifiedTests=false \
  -Dsurefire.useFile=false \
  -Dweb-starter.mcp.surefire-reports-directory="$WEB_STARTER_GOVERNANCE_MAIN_REPORT_DIR" \
  test

python3 - \
  "$WEB_STARTER_GOVERNANCE_MAIN_REPORT_DIR" \
  "$WEB_STARTER_GOVERNANCE_RAW_DIR" \
  'TEST-dev.webstarter.mcp.acceptance.McpSdkGovernanceRuntimeIT.xml' <<'PY'
import sys
from pathlib import Path
from scripts.create_mcp_governance_runtime_proof import stage_surefire_report
stage_surefire_report(Path(sys.argv[1]), sys.argv[3], Path(sys.argv[2]))
PY

# Redis 密码只能由既有 WEB_STARTER_REDIS_PASSWORD 环境变量注入，不能写入参数或 receipt。
export WEB_STARTER_GOVERNANCE_RESTART_STARTED_NS="$(python3 -c 'import time; print(time.time_ns())')"
python3 scripts/orchestrate_mcp_governance_restart.py \
  --repository-root "$WEB_STARTER_CANDIDATE_ROOT" \
  --state-file "$WEB_STARTER_MCP_GOVERNANCE_STATE_FILE" \
  --output "$WEB_STARTER_GOVERNANCE_RAW_DIR/mcp-governance-restart-receipt.json" \
  --compose-project "$WEB_STARTER_MCP_GOVERNANCE_COMPOSE_PROJECT" \
  --app-container-id "$WEB_STARTER_APP_CONTAINER_ID" \
  --redis-container-id "$WEB_STARTER_REDIS_CONTAINER_ID" \
  --nginx-container-id "$WEB_STARTER_NGINX_CONTAINER_ID" \
  --public-nginx-container-id "$WEB_STARTER_PUBLIC_NGINX_CONTAINER_ID" \
  --expected-app-image-id "$WEB_STARTER_APP_IMAGE_ID" \
  --expected-app-reference "$WEB_STARTER_APP_IMAGE_REFERENCE" \
  --expected-redis-image-id "$WEB_STARTER_REDIS_IMAGE_ID" \
  --expected-redis-reference "$WEB_STARTER_REDIS_IMAGE_REFERENCE" \
  --expected-nginx-image-id "$WEB_STARTER_NGINX_IMAGE_ID" \
  --expected-nginx-reference "$WEB_STARTER_NGINX_IMAGE_REFERENCE" \
  --candidate-version "$WEB_STARTER_CANDIDATE_VERSION" \
  --candidate-commit "$WEB_STARTER_MCP_GOVERNANCE_EXPECTED_GIT_COMMIT" \
  --trace-prefix "$WEB_STARTER_MCP_GOVERNANCE_TRACE_PREFIX"

./mvnw --batch-mode --no-transfer-progress \
  -pl web-starter-mcp -am \
  -Dtest=dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT \
  -Dsurefire.failIfNoSpecifiedTests=false \
  -Dsurefire.useFile=false \
  -Dweb-starter.mcp.surefire-reports-directory="$WEB_STARTER_GOVERNANCE_SHUTDOWN_REPORT_DIR" \
  test

python3 - \
  "$WEB_STARTER_GOVERNANCE_SHUTDOWN_REPORT_DIR" \
  "$WEB_STARTER_GOVERNANCE_RAW_DIR" \
  'TEST-dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT.xml' <<'PY'
import sys
from pathlib import Path
from scripts.create_mcp_governance_runtime_proof import stage_surefire_report
stage_surefire_report(Path(sys.argv[1]), sys.argv[3], Path(sys.argv[2]))
PY

python3 scripts/create_mcp_governance_runtime_proof.py \
  --repository-root "$WEB_STARTER_CANDIDATE_ROOT" \
  --raw-directory "$WEB_STARTER_GOVERNANCE_RAW_DIR" \
  --output "$WEB_STARTER_GOVERNANCE_RAW_DIR/mcp-governance-runtime-proof.properties" \
  --candidate-commit "$WEB_STARTER_MCP_GOVERNANCE_EXPECTED_GIT_COMMIT" \
  --candidate-version "$WEB_STARTER_CANDIDATE_VERSION" \
  --candidate-tag "v$WEB_STARTER_CANDIDATE_VERSION" \
  --compose-project "$WEB_STARTER_MCP_GOVERNANCE_COMPOSE_PROJECT" \
  --trace-prefix "$WEB_STARTER_MCP_GOVERNANCE_TRACE_PREFIX" \
  --main-started-at-epoch-ns "$WEB_STARTER_GOVERNANCE_MAIN_STARTED_NS" \
  --restart-started-at-epoch-ns "$WEB_STARTER_GOVERNANCE_RESTART_STARTED_NS"

python3 scripts/validate_mcp_governance_runtime_proof.py \
  --proof "$WEB_STARTER_GOVERNANCE_RAW_DIR/mcp-governance-runtime-proof.properties" \
  --repository-root "$WEB_STARTER_CANDIDATE_ROOT" \
  --expected-candidate-commit "$WEB_STARTER_MCP_GOVERNANCE_EXPECTED_GIT_COMMIT" \
  --expected-candidate-version "$WEB_STARTER_CANDIDATE_VERSION" \
  --expected-candidate-tag "v$WEB_STARTER_CANDIDATE_VERSION" \
  --expected-compose-project "$WEB_STARTER_MCP_GOVERNANCE_COMPOSE_PROJECT" \
  --expected-trace-prefix "$WEB_STARTER_MCP_GOVERNANCE_TRACE_PREFIX" \
  --expected-app-reference "$WEB_STARTER_APP_IMAGE_REFERENCE" \
  --expected-app-image-id "$WEB_STARTER_APP_IMAGE_ID" \
  --expected-nginx-reference "$WEB_STARTER_NGINX_IMAGE_REFERENCE" \
  --expected-nginx-image-id "$WEB_STARTER_NGINX_IMAGE_ID" \
  --expected-redis-reference "$WEB_STARTER_REDIS_IMAGE_REFERENCE" \
  --expected-redis-image-id "$WEB_STARTER_REDIS_IMAGE_ID" \
  --require-pass \
  --summary-output "$WEB_STARTER_GOVERNANCE_SUMMARY_DIR"
```

正式接线还必须保证：治理栈使用匹配 `web-starter-governance-*` 的独立 Compose project，且不得等于主验收栈或 AC26 栈；每个候选只执行一次这两个测试；优雅停止返回成功且应用旧进程真正退出；重启后健康检查通过；所有 cleanup 均有超时；失败时销毁隔离 Compose project；release gate 从 private raw proof 独立重算并逐字节核对公开 summary。缺少任一条件都保持 `NOT_COVERED`。

# V2-AC-26 JWKS 轮换运行验收

本验收用于证明同一候选镜像在真实 Authorization Server 与 MCP 公网入口上的签名键生命周期，不把单元测试、静态源码或“容器健康”当作运行通过。

脚本已接入发布工作流与总门禁，但本仓库当前没有一份现场 Docker 正式运行结果。接线本身不构成通过；只有受保护的发布 job 在干净候选上完成真实运行、独立验证和总门禁重算后，V2-AC-26 才能成为 `GATE_INDEPENDENTLY_VERIFIED`。

## 证明范围

每次运行固定执行以下阶段：

1. 用旧 active 私钥重建隔离运行栈，向真实 `/oauth2/token` 申请 Client Credentials JWT，并通过真实 `/mcp` 调用 `system.info`。
2. 用“新 active 私钥 + 旧 public-only retiring 公钥”重建同一栈；JWKS 必须同时发布两个 `kid`，新 JWT 必须使用新 `kid`，旧 JWT 必须在 retiring `exp` 之前继续调用 MCP。
3. 用新 JWT 调用 `audit.list`，按 Trace ID 回查旧、新 `system.info` 的 `SUCCESS` 调用审计。
4. 选择一个终态：
   - `expiry`：等待到 retiring `exp` 的不包含边界，确认 JWKS 只剩新键、旧 JWT 返回 HTTP 401，新 JWT 仍能调用 MCP；
   - `revocation`：在 `exp` 前用只给旧 public JWK 增加标准 `rev` 的 key-ring 重建运行栈，然后执行相同的旧 JWT 拒绝与新 JWT 连续性检查。

单次证据只证明选择的一个终态。若发布策略要求同时证明自然到期和紧急撤销，应在两个独立 `web-starter-ac26-*` 项目中各运行一次并分别保留证据，不能把其中一次改写成“两者都已通过”。

未知 JWT `kid` 和错误 active 配置目前只有候选源码及单元测试源码绑定，运行状态明确写为 `NOT_COVERED`；它们不会被包装成真实 HTTP 证据。

## 安全边界

producer 不接受 hook、Shell 字符串或自定义 Docker 子命令，并有以下硬限制：

- Compose 项目名必须匹配 `web-starter-ac26-*`，因此不能指向普通开发或生产项目；
- Compose 文件固定为候选提交中的 `compose.production.yaml`；可选 override 只能把 app 的 8081 端口映射到一个 `127.0.0.1` 非特权端口；
- env、运行 manifest、运行身份和三个 JWK Set 必须是仓库外的真实 0600 文件；公网和私网入口都必须绑定本机回环地址；
- app 与 Nginx 必须同时绑定运行身份中的 digest、image ID 和候选 OCI revision；每个阶段都检查三个容器已更换且健康，两个 Nginx 的实际 host port 只允许精确映射到 env 声明的 `127.0.0.1` 端口；
- 公网/私网 origin、端口、终态和 8 条 Trace ID 的公共前缀都由 validator 调用方再次固定；HTTP 客户端复用统一的全 3xx 拒绝器，禁止把 Basic/Bearer 带到重定向目标，并在创建 TLS context 前拒绝 `SSLKEYLOGFILE`；
- 每次变更只执行固定的 `up --no-deps --force-recreate --wait app nginx mcp-public-nginx`；
- 不执行 build、pull、down、remove、prune，也不删除任何 Docker 资源；
- Token、Client Secret、私钥 JWK、HTTP Body 和 Session ID 不写入证据。临时 phase env 只存在于 0700 临时目录并在结束时删除；
- 所有 0600 输入用 no-follow 文件描述符读取并核对前后文件身份；TLS 证书和私钥也先复制到本次 0700 临时目录，再交给专用 Compose 项目挂载；
- 原始证据目录为仓库外 0700，且只能包含两个 0600 文件：JSON 报告和对应 SHA-256 文件。

由于脚本会重建 app 和两个 Nginx 容器，它只能用于可丢弃的专用验收项目。producer 本身不删除项目；正式 runner 独占创建该项目，成功和失败路径都执行固定 `down --volumes --remove-orphans`，并确认项目标签下没有遗留容器、卷或网络后才允许继续。

## Key-ring 输入

三个输入都必须使用至少 3072 位 RSA、唯一且稳定的 `kid`：

- `initial.json`：仅旧 active JWK，包含完整私钥，不含 `exp`/`rev`；
- `rotated.json`：新 active JWK 含私钥且不含 `exp`/`rev`；旧 retiring JWK 只含相同 `n`/`e` 公钥，并带未来的标准 `exp` NumericDate；
- `revoked.json`（仅 `revocation`）：与 `rotated.json` 的键和 `exp` 完全相同，只给旧 retiring JWK 增加非空标准 `rev` 对象。

`expiry` 模式不得传 `--terminal-jwk-set`。`revocation` 模式必须传该文件。retiring 边界必须位于本次运行的有界等待窗口内，且旧 JWT 自身的 `exp` 必须晚于 key-ring 边界；否则无法排除“JWT 自己到期”的混淆，producer 会失败关闭。

## 生成真实运行证据

下例中的路径都应位于 CI 的私有临时目录，且候选目录应是干净、带 annotated release tag 的 detached worktree：

```bash
umask 077

python3 -B scripts/rehearse_jwks_rotation.py \
  --repository-root "$WEB_STARTER_CANDIDATE_VALIDATION_ROOT" \
  --runtime-manifest "$WEB_STARTER_AC26_RUNTIME_MANIFEST" \
  --runtime-identity "$WEB_STARTER_AC26_RUNTIME_IDENTITY" \
  --compose-env-file "$WEB_STARTER_AC26_COMPOSE_ENV" \
  --compose-override "$WEB_STARTER_AC26_MANAGEMENT_OVERRIDE" \
  --compose-project "$WEB_STARTER_AC26_COMPOSE_PROJECT" \
  --trace-prefix "$WEB_STARTER_AC26_TRACE_PREFIX" \
  --initial-jwk-set "$WEB_STARTER_AC26_INITIAL_JWK_SET" \
  --rotated-jwk-set "$WEB_STARTER_AC26_ROTATED_JWK_SET" \
  --old-kid "$WEB_STARTER_AC26_OLD_KID" \
  --new-kid "$WEB_STARTER_AC26_NEW_KID" \
  --terminal-mode expiry \
  --max-wait-seconds 180 \
  --output-dir "$WEB_STARTER_AC26_EVIDENCE_DIR"
```

本地自签 TLS 只允许与显式 `.test` 回环别名配合：

```bash
export WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS='mcp.ac26.webstarter.test'
export WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS='127.0.0.1'
export WEB_STARTER_ACCEPTANCE_INSECURE_TLS='true'
```

这些变量不能指向公网 DNS，也不能关闭非隔离主机的 TLS 校验。

## 独立验证与 canonical summary

validator 不调用 Docker 或网络，也不导入 producer。它独立重算 producer 所记录观察的语义一致性，验证文件权限与 TOCTOU、checksum、敏感内容、候选 Git blob、annotated tag、非 SNAPSHOT 版本、app/Nginx digest 与 image ID、origin/端口、容器切换链、JWT `kid/iat/exp`、真实 HTTP 开始/结束时间、三阶段 JWKS、公网 MCP 成功与 401、Trace/Audit 对应关系，然后生成排序且最小化的 canonical summary：

```bash
python3 -B scripts/validate_jwks_rotation_evidence.py \
  --repository-root "$WEB_STARTER_CANDIDATE_VALIDATION_ROOT" \
  --evidence "$WEB_STARTER_AC26_EVIDENCE_DIR/v2-ac26-jwks-rotation.json" \
  --runtime-identity "$WEB_STARTER_AC26_RUNTIME_IDENTITY" \
  --expected-candidate-commit "$GITHUB_SHA" \
  --expected-candidate-version "$WEB_STARTER_RELEASE_VERSION" \
  --expected-candidate-tag "$WEB_STARTER_RELEASE_TAG" \
  --expected-compose-project "$WEB_STARTER_AC26_COMPOSE_PROJECT" \
  --expected-app-reference "$WEB_STARTER_APP_IMAGE@$WEB_STARTER_APP_DIGEST" \
  --expected-app-image-id "$WEB_STARTER_AC26_APP_IMAGE_ID" \
  --expected-nginx-reference "$WEB_STARTER_NGINX_IMAGE@$WEB_STARTER_NGINX_DIGEST" \
  --expected-nginx-image-id "$WEB_STARTER_AC26_NGINX_IMAGE_ID" \
  --expected-public-origin "$WEB_STARTER_ACCEPTANCE_PUBLIC_BASE_URL" \
  --expected-private-origin "$WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL" \
  --expected-trace-prefix "$WEB_STARTER_AC26_TRACE_PREFIX" \
  --expected-terminal-mode expiry \
  --summary-output "$WEB_STARTER_AC26_SUMMARY_DIR/v2-ac26-jwks-rotation-summary.json"
```

summary 目录必须预先创建为 0700，目标文件不得已存在。canonical summary 只包含候选、镜像、Compose 项目、`kid`、终态、检查结论和哈希，不包含 URL、JWT、Secret、私钥或原始响应。

checksum 只证明文件内容未变，不是执行身份或 CI provenance。正式门禁必须在受保护、临时且不可复用的 job 中按“创建全新 O_EXCL 原始目录 → producer → 立即 validator → 复制 canonical summary”的顺序完成，并由工作流固定上述所有 `expected-*` 参数；任意后来上传的 raw JSON 不能单独升级为正式 PASS。若需要跨系统证明，应在工作流层增加受信任的 OIDC/attestation，这不由本地 JSON 自报替代。

当前正式工作流固定使用独立 `web-starter-ac26-<run>-<attempt>` Compose 项目、`release-ac26` Trace 前缀、回环私有入口 `http://127.0.0.1:28088`、`.test` 回环公网入口 `https://mcp.ac26.webstarter.test:28443` 和 `expiry` 终态。总门禁的 `build` 与 `verify` 都重新收到 raw 路径、Compose 项目和提交的终态；`build` 还要求逐字节匹配的 `v2-ac26-jwks-rotation-summary.json`。Actions Artifact 只上传这个 0600 canonical summary；raw 双文件、JWK Set、OAuth manifest、Token、Secret 和临时 env 均不进入公开上传清单。

## 结果解释

- producer 的退出码 0 只说明它完成并写出候选原始观察；validator 可拒绝不一致观察，但只有上述受保护 job 的连续执行才形成正式结论。
- `expiry` 或 `revocation` 的 `PASS` 证明真实 OAuth/JWKS/MCP 生命周期，但不证明未选择的另一个终态。
- `supplementalConfigurationGuards` 中的运行级未知 `kid` 与错误 active 配置仍为 `NOT_COVERED`。
- 当前未生成任何正式 AC26 证据，不能据此把 V2-AC-26 标为已验收。

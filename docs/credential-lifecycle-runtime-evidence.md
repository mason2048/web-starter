# 身份与凭据生命周期运行证据

四个级联失效场景使用的一次性用户必须在各自场景完成后删除，并通过同一私有管理入口回读 `404`、核对关联操作审计。正式摘要中的 `fixtureCleanup=PASS` 用于证明生命周期验收不会留下启用的管理员主体，从而污染后续“最后管理员”与 RBAC 验收。

本文定义 V2-AC-24、V2-AC-27、V2-AC-28 和 V2-AC-36 的正式运行验收边界。单元测试、接口存在、容器健康或 producer 自报 `PASS` 都不能替代该证据。

## 固定验收语义

正式 producer 必须在同一组已通过运行身份与 OAuth 边界验证的真实 MySQL、Redis、App、私有 Nginx 和公网 MCP Nginx 上完成以下检查：

- 分别创建四个一次性用户，并对密码重置、主体停用、主体删除和用户主动安全注销逐项验证；每项操作后的下一次 Web Session、OAuth access token、OAuth refresh token 和 PAT 请求都必须失效，且操作审计能按唯一 Trace ID 读回。
- 注入 active 与 retiring 两个不同版本的长期令牌 Pepper，用 retiring Pepper 构造只含哈希的数据库记录；旧 PAT 成功认证后必须在同一事实库中迁移为 active 版本哈希并更新最后使用时间，数据库转储和运行日志中不得出现明文令牌或 Pepper。
- 对真实机密 OAuth Client 执行两秒重叠窗口轮换；窗口内新旧 Secret 都可签发，窗口结束后旧 Secret 返回 `invalid_client`、新 Secret 继续工作，且轮换操作有相关审计。新 Secret 只允许在创建响应中出现一次。
- 重新执行 RBAC 与 Scope 交集、凭据吊销、内网 PAT/公网 OAuth 边界、非法 Host、非法 Origin 和失败审计负向用例。合法私有 Host 对照必须成功，非法 Host 只接受明确的 4xx 拒绝，不能把网络故障或 5xx 当成安全通过。

producer 生成的私有 `v2-credential-lifecycle-runtime.json` 只包含状态、HTTP 结果、哈希、候选身份、镜像引用、Trace ID 和时间，不保存密码、Cookie、Bearer Token、Client Secret 或 Pepper。它必须位于仓库和公开 Artifact 之外的独立 `0700` 目录，且目录中只能有这一份 `0600` 文件。

## 独立验证与候选绑定

`scripts/validate_credential_lifecycle_evidence.py` 不导入 producer，也不访问运行服务。它独立完成以下重算：

- 要求候选工作树 clean，Maven 与前端版本非 `SNAPSHOT`，实际注释 tag、HEAD commit 和 tree 一致；
- 逐项重放四类级联失效、Pepper 迁移、Client Secret 重叠窗口和统一负向安全结果；
- 将报告绑定到同次生成的 `runtime-version-identity.json`、`oauth-runtime.json`、Compose project、App/Nginx 不可变镜像引用及固定安全源码哈希；
- 扫描报告中是否出现 PAT、服务令牌或 JWT 形态的敏感材料；
- 只在全部条件成立时生成固定名称 `v2-credential-lifecycle-runtime-summary.json`，输出目录为新建空 `0700`，文件为 `0600`。

正式 release runner 必须设置：

```text
WEB_STARTER_RUN_CREDENTIAL_LIFECYCLE_FORMAL=true
WEB_STARTER_CREDENTIAL_LIFECYCLE_EVIDENCE_DIR=/absolute/private/raw-directory
WEB_STARTER_CANDIDATE_VALIDATION_ROOT=/absolute/clean-candidate
```

runner 先执行 producer，再从 clean candidate 执行 validator，随后以拒绝覆盖的方式把 canonical bytes 复制到 `artifacts/acceptance/v2-credential-lifecycle-runtime-summary.json`。release gate 再次从私有 raw 报告重算语义，并要求公开摘要逐字节相同；四个验收项共享这一份不可拆分的 canonical 证据，任一子条件失败都会使四项全部不能声明 `PASS`。

## 证据保留与结论边界

- 原始报告属于受控证据，不上传普通 Actions Artifact；公开包只保留 canonical summary。
- 无论成功还是失败，隔离栈都必须执行带超时的 Compose 清理并确认容器、网络和卷均无遗留；临时凭据在服务端吊销，含明文的一次性响应与运行环境文件按固定私有路径清理。
- 仓库中的默认验收模板继续保持 `NOT_COVERED`。只有真实 release ledger 针对最终 clean candidate 同时收到私有 raw、canonical summary、运行身份和 OAuth 报告，并由 release gate 独立复核后，才能记录 `GATE_INDEPENDENTLY_VERIFIED / PASS`。
- 一次本地演练只证明它绑定的 commit、tree、tag、镜像和 Compose project，不可转用于后续修改后的候选版本。

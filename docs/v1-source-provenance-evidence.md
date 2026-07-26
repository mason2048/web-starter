# V2-AC-01：冻结 V1 来源溯源证据

V2-AC-01 只证明 V2 发布候选可追溯到固定的 V1 历史来源。它不把历史验收记录冒充为当前候选的 V1 回归，也不声称重新验证了当年的仓库外运行产物。

## 固定历史锚点

独立 validator 必须直接从 Git 对象库重新解析以下不可变事实，任一缺失或漂移都 fail closed：

| 项目 | 固定值 |
|---|---|
| 注释 tag | `v1.0.0` |
| tag object | `406e73cca6f4d4e257c2aa08e58815d96b7ca722` |
| commit | `5ebdb238650d182c17e1493adf47aaa3324f19cb` |
| tree | `355c61a77f4dd0f16f0f3d945ee6c8d4f02d956a` |
| tag 注释 | `启程 Web Starter V1 verified baseline` |
| `git archive` SHA-256 | `79b220b5a4da72ea3d4bb98203add92bce83fc19e30cd24ebfa084c7bc360ff5` |
| V1 基线 | `docs/acceptance/v1-acceptance-baseline.md`，42 项：37 个 P0、5 个 P1 |
| V1 验收记录 | `docs/acceptance/v1-acceptance-2026-07-19.md`，42 项结果且恰好 42 项 PASS |
| 历史记录附表 | 12 项自动化声明、5 项最终勾选、最终结论 PASS |

基线和验收记录还同时绑定固定 Git blob 与内容 SHA-256。当前发布 commit 必须是上述 V1 commit 的后代；当前 tag 必须是指向当前 clean HEAD 的注释 tag，根 Maven 与前端版本必须一致、非 `SNAPSHOT`，并与当前 tag 版本一致。

## 证据边界

canonical summary 固定记录：

- `historicalExecutionTrust = TAGGED_RECORD_ONLY`：可确认的是冻结 tag 中存在完整的历史记录；
- `historicalRuntimeArtifacts = NOT_REVALIDATED`：历史记录提及的仓库外运行产物没有可验证哈希锚点，本项不重新背书；
- `currentCandidateV1Regression = NOT_CLAIMED`：V2-AC-01 不执行也不替代当前候选的 V1 42 项回归。

因此，即使 V2-AC-01 为 PASS，发布账本仍必须为 V1 的 42 个结果逐项提供当前候选证据。缺少这些证据时，总发布门禁仍为 FAIL；禁止把本摘要自动绑定到 V1 的 AC-01 至 AC-42。当前独立验证注册表只接受 `release_evidence_gate.py` 中逐项声明且由对应运行原始证据重算的 V1 结果；已经注册的项目也不能使用本历史摘要替代自己的证据，尚未注册的项目则不能仅靠历史记录或内容哈希声明 PASS。完整 current-candidate V1 regression 未闭环前，发布账本仍会 fail closed。

## Producer、validator 与文件策略

`create_v1_source_provenance_proof.py` 是无状态结论的观察 producer，只写两个文件：

- `v2-ac01-v1-source-provenance.json`
- `v2-ac01-v1-source-provenance.json.sha256`

目标目录必须预先存在、位于仓库外、为空且权限为 `0700`。两个文件以 `O_EXCL` 创建且权限为 `0600`；producer 不写 `status` 或 PASS。

`validate_v1_source_provenance_proof.py` 不导入 producer。它重新读取 Git tag、commit、tree、archive、基线、验收记录、当前候选及源码哈希，验证前后再次检查 raw 文件和候选身份，成功后只创建 `v2-ac01-v1-source-provenance-summary.json`。canonical summary 的父目录必须是真实 `0700` 目录，文件必须不存在并以 `O_EXCL`、`0600` 创建。

producer、validator 和 release gate 的 Git 调用只继承 `PATH`，并固定 C locale、`GIT_CONFIG_NOSYSTEM=1`、global/system config 为 `/dev/null`、`GIT_CONFIG_COUNT=0`、`GIT_NO_REPLACE_OBJECTS=1`。环境中的 config key/value、object directory、alternate object directory、index、worktree、Git dir 和 replace 注入不会进入子进程；release gate 还对 Git stdout/stderr 设置字节上限，超限立即终止并失败。

## 独立执行

以下命令中的候选目录必须是当前正式 tag 的 detached clean worktree；raw 与公开 artifact 路径只是示例：

```bash
mkdir -m 700 /absolute/private-v1-source
mkdir -m 700 /absolute/release-artifacts/acceptance

python3 -B scripts/create_v1_source_provenance_proof.py \
  --repository-root /absolute/private-clean-candidate \
  --expected-candidate-commit 0123456789abcdef0123456789abcdef01234567 \
  --expected-candidate-version 2.0.0 \
  --expected-candidate-tag v2.0.0 \
  --output-dir /absolute/private-v1-source

python3 -B scripts/validate_v1_source_provenance_proof.py \
  --repository-root /absolute/private-clean-candidate \
  --evidence /absolute/private-v1-source/v2-ac01-v1-source-provenance.json \
  --expected-candidate-commit 0123456789abcdef0123456789abcdef01234567 \
  --expected-candidate-version 2.0.0 \
  --expected-candidate-tag v2.0.0 \
  --summary-output /absolute/release-artifacts/acceptance/v2-ac01-v1-source-provenance-summary.json
```

release gate 的 `build` 必须同时收到 raw proof 和 canonical summary；`verify` 必须再次收到同一 raw proof。公开 Actions Artifact 只上传 canonical summary，raw 双文件进入受限、禁止覆盖且生命周期不短于发布镜像的归档。

## 可验证测试范围

仓库测试覆盖真实固定历史的正向解析，以及以下负向路径：轻量 tag、V1 tag 重定向、非后代候选、dirty 或 `SNAPSHOT` 候选、历史记录的 PASS/自动化/最终结论漂移、ambient Git 注入、raw checksum/权限/额外文件、canonical 文件名/权限/覆盖以及 Git 输出超限。测试通过只证明证据工具行为；只有正式发布工作流在实际 release tag 上产生并重放证据，才能把 V2-AC-01 记为 PASS。

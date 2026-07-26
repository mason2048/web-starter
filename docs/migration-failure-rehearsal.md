# V2-AC-07 迁移失败保护演练

`scripts/rehearse_migration_failure.py` 验证 V2-AC-07 中可独立证明的“迁移失败保护”部分。它不会修改现有 Compose 项目、数据库卷或生产配置，也不会把故障迁移加入正式 Flyway 目录。

## 1. 证明范围

脚本执行一次全新的隔离演练：

1. App 必须以本机已有的 `repository@sha256:<manifest-digest>` 提交摘要引用提供；MySQL、Redis 使用显式本地引用。三者先经 `docker image inspect` 解析为不可变 `sha256:` image ID，后续全部使用 ID 和 `--pull never`。App 的 RepoDigests 必须包含请求引用，且 OCI `version`/`revision` 标签必须分别等于候选版本和 Git HEAD。
2. 创建随机 `web-starter-ac07-<run-id>` internal network，以及同前缀的 MySQL、Redis、App 容器。所有资源都有本次 run ID、角色和 `dev.webstarter.acceptance=ac07` 标签。
3. MySQL 与 Redis 只使用容器内 tmpfs，不创建或复用 Docker 卷，不发布宿主机端口，也不连接现有网络。
4. 临时生成一个高版本、只包含必然失败 `SELECT` 的 Flyway 文件，以只读 bind mount 注入 `/ac07-migration`；App 根文件系统保持只读。
5. 证明基础迁移成功执行后，附加迁移导致 App 非零退出、readiness 从未成功、`Started WebStarterApplication` 未出现，并查询隔离 MySQL 确认故障版本的 `success=1` 行数为零。
6. MySQL、Redis 和 App 原始日志只在进程内检查秘密泄漏并计算 SHA-256；证据不保存原始日志、密码、Token 或 RSA 材料。
7. 清理前逐个校验精确名称和三项所有权标签，随后删除容器及 internal network，并确认没有残留对象。

此演练不执行迁移回滚，也不把通用向下回滚当作承诺。正式恢复策略仍是追加修复迁移，或者使用 V2-AC-40 已验证备份恢复。

## 2. 正式候选前提

正式执行不是开发工作树测试。仓库必须处于以下冻结状态：

- 当前目录是精确 Git worktree 根目录，HEAD 和 tree 在演练期间不变化；
- tracked、untracked、submodule 以及 skip-worktree/assume-unchanged 状态均为空；
- 根 Maven 版本与 `web-starter-web/package.json` 版本相同，且为非 `SNAPSHOT` 发布版本；
- `scripts/rehearse_migration_failure.py`、本 schema 与 `scripts/validate_v1_upgrade_evidence.py` 都已经提交；证据记录它们在候选 commit 中的字节 SHA-256；
- App 镜像由该候选构建，并带有精确的 `org.opencontainers.image.version=<release-version>` 和 `org.opencontainers.image.revision=<HEAD>` 标签；镜像已在本机 Docker store 中，可通过 digest 引用解析，演练不会拉取镜像。

当前开发版本仍是 `2.0.0-SNAPSHOT` 时，演练应安全拒绝，不能生成正式 PASS。

## 3. 执行

先确认三个镜像已存在于本机 Docker image store。输出目录必须位于仓库外、为空且权限为 `0700`：

```bash
evidence_dir="$(mktemp -d /private/tmp/web-starter-ac07-evidence.XXXXXX)"
chmod 700 "$evidence_dir"

python3 scripts/rehearse_migration_failure.py \
  --app-image 'registry.example.invalid/web-starter-app@sha256:<manifest-digest>' \
  --mysql-image 'mysql:8.4' \
  --redis-image 'redis:7.4-alpine' \
  --ac40-evidence '/private/path/to/v2-ac40-evidence.json' \
  --output-dir "$evidence_dir"
```

示例 registry 使用保留域名，不是部署地址。命令行不得传密码、Token、私钥或带凭据的 registry URL。工具不会登录或拉取镜像，也没有接受现有 Compose 项目名、宿主端口或卷名的参数。

输出目录包含：

- `v2-ac07-migration-failure.json`：脱敏结果，权限 `0600`；
- `v2-ac07-migration-failure.json.sha256`：结果文件校验和，权限 `0600`。

证据还记录候选 HEAD/tree/version、三份候选源码 SHA-256、App 请求引用的哈希与 manifest digest、三个不可变 image ID、App OCI 身份，以及独立 AC-40 结果文件的 SHA-256。

## 4. 独立验证与发布门禁输入

发布门禁必须使用实际 AC-07 和 AC-40 文件重新验证，不接受复制出来的状态或摘要：

```bash
python3 scripts/validate_migration_failure_evidence.py \
  --document "$evidence_dir/v2-ac07-migration-failure.json" \
  --repository-root "$PWD" \
  --ac40-evidence '/private/path/to/v2-ac40-evidence.json' \
  --ac40-dependency-seed '/private/path/to/ac40-dependency-seed' \
  --expected-ac40-dependency-seed-sha256 '<external-aggregate-sha256>' \
  --expected-app-image-id 'sha256:<app-config-image-id>' \
  --expected-app-reference 'registry.example.invalid/web-starter-app@sha256:<manifest-digest>' \
  --expected-mysql-image-id 'sha256:<mysql-image-id>' \
  --expected-redis-image-id 'sha256:<redis-image-id>' \
  --require-pass
```

独立验证器只使用 Python 标准库，不启动 Docker。它会重新计算 exact keys、九项故障检查、顶层状态/退出码、资源隔离与精确清理、临时迁移内容哈希、脱敏约束，并验证：

- AC-07 文件名固定，文件/目录模式为 `0600`/`0700`，目录只含结果和同名 checksum sibling；
- 顶层 PASS 绑定当前 clean Git HEAD/tree、统一非 SNAPSHOT 版本和三个候选 commit 文件的当前字节；
- App OCI version/revision 与候选一致，三个 image ID 与发布配置显式传入的预期值一致；
- `recovery.evidenceSha256` 与实际 AC-40 文件一致，再以同一私有 dependency seed 和外部 aggregate SHA-256 信任锚调用候选绑定的独立 AC-40 validator，并交叉核对 status/checkCount/acceptanceCount/phaseCount。

不带 `--require-pass` 时，预期镜像参数可省略，用于验证非 PASS 证据的结构和语义；带 `--require-pass` 时，三个 `--expected-*-image-id` 以及 `--expected-app-reference` 或 `--expected-app-digest` 至少其一是强制输入。正式门禁优先提供完整的 digest-bound reference，以便同时重算引用哈希和 manifest digest；这些值来自冻结发布清单或镜像解析步骤，不能从 AC-07 JSON 自己回填。有效的 `FAIL`、`NOT_COVERED`、`ENV_REQUIRED` 证据在不带 `--require-pass` 时返回 `0`，表示“证据有效”；带 `--require-pass` 时分别返回其状态对应的非零码，不能放行。

## 5. 状态语义

证据把两个边界分开：

- `failureProtection.status=PASS`：本次真实故障迁移满足非零退出、从未 ready、无成功 Flyway 记录、无秘密日志和精确清理要求；
- `recovery.status=PASS`：提供的 V2-AC-40 证据已经由独立验证器重新计算全部 phase/check/acceptance 状态，并绑定同一 clean Git candidate 的 commit、tree、工具、schema、adapter 与 runtime source 字节；
- `recovery.status=NOT_COVERED`：未提供完整 AC-40，或经独立验证后仍未覆盖；`FAIL` 和 `ENV_REQUIRED` 分别原样阻断或保留环境要求；
- 顶层只有 failure-protection 与 recovery 都为 `PASS` 时才是 `PASS/COMPLETE`。迁移保护失败为 `FAIL/FAILURE_PROTECTION_FAILED`，恢复失败为 `FAIL/RECOVERY_FAILED`，恢复需要环境为 `ENV_REQUIRED/RECOVERY_ENV_REQUIRED`，缺少恢复证据为 `NOT_COVERED/PENDING_AC40`。

`--ac40-evidence` 不信任 JSON 自报状态。绑定 AC-40 时，`--ac40-dependency-seed` 与 `--expected-ac40-dependency-seed-sha256` 也必须同时提供；只给路径、只给哈希或从 AC-40 JSON 回填信任锚都会失败。验证器调用独立的 `scripts/validate_v1_upgrade_evidence.py`，要求证据与种子都位于仓库外的私有目录，物理重扫种子并重新计算固定的 phase/check/acceptance exact-set，在 PASS 时核对当前工作树为 clean candidate、HEAD/tree 及所有工具和运行源码的 commit blob SHA-256。验证前后证据摘要必须一致。任意结构错误、伪造哈希、脏工作树、候选不匹配或自报 PASS 都会安全失败；只有独立重算结果为 PASS 才设置 `promotionAllowed=true`。

脚本只在顶层整项 `status=PASS` 时返回 `0`。顶层 `FAIL` 返回 `1`，安全、输入或编排错误返回 `2`，`NOT_COVERED` 或 `ENV_REQUIRED` 返回 `6`。因此 failure-protection 子项即使为 `PASS`，只要 AC-40 尚未通过，shell 和 CI 仍会得到退出码 `6`，不能把部分覆盖误判为整项通过。

## 6. 失败处理

- 不要编辑已发布的 Flyway 文件，也不要手工把失败记录改为成功。
- 先保留脱敏证据和对应镜像 ID，定位迁移脚本问题，再发布新的追加迁移或从已验证备份恢复。
- 如果脚本因标签不匹配拒绝清理，不得扩大删除范围；先人工核对随机资源名称及标签。
- `statusDetail=PENDING_AC40`、顶层 `NOT_COVERED` 和 failure-protection 子检查成功都不是发布放行依据，发布清单仍必须逐项绑定最终源码冻结候选。

发布 workflow 与 `release_evidence_gate` 已显式注册 AC-07，并在直接验证、账本 build 与账本 verify 三处传入同一私有 AC-40 dependency seed 和受保护的外部 SHA-256 信任锚。缺少任一原始输入、候选绑定或逐字节公开副本时，AC-07 保持未通过。

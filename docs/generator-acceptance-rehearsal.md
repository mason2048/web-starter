# 派生项目与生成模块验收演练

本入口与独立验证器共同覆盖 V2-AC-08 至 V2-AC-15。它不是普通生成命令，也不会把当前工作树中的未提交内容带入结果；只有 clean、非 `SNAPSHOT`、带精确注释 tag 的候选、真实不可变基础镜像、完整运行时门禁和独立语义重放同时成立时，才可能形成正式 `PASS`。

一个原始 bundle 可以完整覆盖八项 AC，但证据职责分为两组：

- AC08、AC09、AC11、AC12、AC13、AC15 由独立验证器在仓库外临时目录重新执行项目和模块生成边界，不接受生产器自报状态；
- AC10、AC14 由两个真实 MySQL/Redis/浏览器/OAuth/官方 MCP SDK 运行阶段证明，独立验证器再将运行阶段 Git tree、测试源、镜像身份和重放输出交叉绑定。

## 验收对象

`scripts/rehearse_generator_acceptance.py` 固定执行两个连续但独立留证的阶段：

1. 从候选 commit 的隔离 clone 运行 `project init`，生成不同工程名、产品名、包前缀、数据库名和环境变量前缀的项目；初始化临时 Git commit，并通过 `git archive` 导出不含 `.git`、未跟踪文件或符号链接的仓库外构建上下文，用该上下文构建 App/Nginx 镜像；
2. 先对“未增加业务模块”的派生项目执行完整不可变镜像运行时验收；
3. 在同一派生项目中依次执行模块 `validate`、`dry-run`、`generate --with-mcp`，形成第二个临时 commit；
4. 用第二个 commit 重建并推送至仅绑定回环地址的临时 Registry，执行空库迁移、REST、浏览器、403、409、审计、OAuth、默认 Tool 加精确生成 Tool、官方 MCP SDK 和故障语义验收；
5. 将每阶段的版本、commit、镜像 digest、image ID、OCI label、统一七层摘要及 Artifact 哈希交叉校验，拒绝重复 JSON 字段、非有限数值或敏感材料；
6. 清理两个 Compose 项目的运行中及已停止容器、卷、网络，临时 Registry、生成镜像引用、临时 Git clone、派生项目目录和未发布证据暂存目录；清理全部成功后才写最终 `generator-acceptance.json` 与精确 checksum；
7. `validate_generator_acceptance_evidence.py` 重新验证注释 tag、Maven/前端版本、候选 tree，以及生产器、验证器、Schema、生成器与运行证明源码 blob；随后在新的临时 clone 中重放 dry-run、非法输入、冲突和默认/显式 MCP 生成，并要求重放的两棵 Git tree 与真实运行阶段完全一致。

两个阶段都复用派生项目自己的 `scripts/run_release_runtime_acceptance.sh`，并显式传入期望模块集合。项目阶段期望空集合，模块阶段期望一个带 MCP 的固定模块；发现零模块、额外模块、测试 skipped/retry、错误 Surefire 报告或源文件在验收中漂移都会失败。

## 前置条件

- 候选仓库必须没有 tracked、untracked 或 staged 改动，Maven 与前端版本相同且非 `SNAPSHOT`，并存在指向 `HEAD` 的精确注释 tag `v<version>`；
- 输出目录必须不存在、位于仓库外，父目录不能是符号链接；
- 禁用业务词文件必须位于仓库外，内容由项目所有者维护；
- MySQL、Redis 与临时 OCI Registry 必须以 `name@sha256:<64-hex>` 形式提供，并已在本机精确解析到相同 RepoDigest；入口不会用可变标签替代；
- Java、Maven、Node、pnpm、Docker、Compose 和 Playwright Chromium 已准备；
- 本地 Docker 能向 `127.0.0.1` 回环 Registry 推送。镜像构建使用 `--pull=false`，但缺少固定 `FROM` 镜像时 Docker 仍可能拉取；Dockerfile 内 Maven、pnpm 与 apk 也可能访问软件源，因此该演练不等于离线构建。

## 正式调用格式

以下只是调用格式，不是已执行或已通过的证据：

```bash
python3 -B scripts/rehearse_generator_acceptance.py \
  --repository "$PWD" \
  --output /absolute/path/outside-repository/generator-acceptance-2.0.0 \
  --forbidden-terms /absolute/path/outside-repository/forbidden-terms.txt \
  --mysql-image 'mysql@sha256:<64-hex>' \
  --redis-image 'redis@sha256:<64-hex>' \
  --registry-image 'registry@sha256:<64-hex>'
```

默认派生身份为：

| 项目 | 默认值 |
|---|---|
| 工程名 | `journey-admin` |
| 产品名 | `启程派生管理系统` |
| Maven group / Java package | `dev.journey.admin` |
| 数据库 | `journey_admin` |
| 环境变量前缀 | `JOURNEY_ADMIN_` |
| 示例模块 | `asset` / `资产` |
| MCP | 显式启用，固定 `asset.list/get/create/update/remove` |

这些值可通过 CLI 的对应参数修改，但仍受项目与模块生成器的严格输入边界约束。演练不会修改模板仓库，也不会提交、打 tag、推送或发布候选仓库。

## 证据边界

成功输出目录必须位于仓库外，目录逐层为 `0700`，文件为 `0600`，并且只保留严格、脱敏 JSON：

- `stages/project/`：纯派生项目的运行证据；不得出现 `generated-module-runtime.json`；
- `stages/module/`：生成模块的运行证据，必须包含单模块 browser/MCP `PASS`；
- `generator-acceptance.json`：绑定候选 commit/tree/tag/tag object、非 SNAPSHOT 双版本、固定源码 blob、两个派生 commit/tree、两份 `git archive` 构建上下文 SHA-256、四个实际镜像 digest、每个 Artifact 的 SHA-256 和清理结果；
- `generator-acceptance.json.sha256`：只接受 `<sha256><两个空格>generator-acceptance.json` 的精确单行格式。

中间的 `generated-module-runtime.json` 不能单独证明 AC14；只有外层 `generator-acceptance.json` 在 runner 成功、资源清理和临时目录删除后发布，才是完整闭环证据。构建或静态测试通过仍不等于该演练通过。

当前仓库工作树未冻结为 clean V2 candidate 时，只能执行静态/单元门禁；不得把它们登记为 V2-AC-10 或 V2-AC-14 的运行时 `PASS`。

## 独立正式验证

生产器成功并不等于证据可登记。使用同一个候选仓库、原始 bundle 和相同的仓库外禁用词文件执行：

```bash
mkdir -m 700 /absolute/path/outside-repository/generator-summary-2.0.0
python3 -B scripts/validate_generator_acceptance_evidence.py \
  --repository-root "$PWD" \
  --evidence-directory /absolute/path/outside-repository/generator-acceptance-2.0.0 \
  --forbidden-terms /absolute/path/outside-repository/forbidden-terms.txt \
  --require-pass \
  --summary-output /absolute/path/outside-repository/generator-summary-2.0.0
```

验证器不会运行 Docker，也不会执行生成应用；它会重新构建候选中的离线 tooling，并在一次性 clone 中检查：

- 参数化项目 dry-run 无写入、占用目标/模板内目标/非法身份零写入；
- 真实派生项目身份、秘密扫描和禁用词扫描；
- 声明文件的 `validate`、`dry-run` 无写入，以及名称、表、迁移、权限 ID、菜单 ID、表/路由/权限编码冲突和表达式输入的零写入拒绝；
- 默认模块只含 Web + REST，显式 `--with-mcp` 才出现固定 Contributor、Schema、权限/风险和官方 SDK CRUD 测试；
- 重放项目 tree、显式 MCP 模块 tree，以及 migration/plan/browser/MCP 测试源码 SHA-256 与真实运行阶段一致；
- 运行证明脚本仍严格解析单次 Playwright 和 Surefire 结果，不把 skipped、retry、过期报告或单纯构建成功当成语义通过；
- 最后再次读取完整 bundle 和候选身份，拒绝验证期间的文件替换、候选漂移或 TOCTOU。

只有验证器生成的 `v2-generator-acceptance-summary.json` 才是可进入发布清单的无秘密 canonical 摘要；原始 bundle 继续留在私有仓库外位置，不应直接发布为普通 CI Artifact。

## 发布工作流接线

正式 release workflow 从受保护的 `WEB_STARTER_FORBIDDEN_TERMS` Secret 读取禁用词。它不会把 Secret 写到日志或仓库，而是在固定的 `${RUNNER_TEMP}` 子目录用 `O_EXCL` 创建非空 `0600` 文件；除词条分隔用的 LF 外，控制字符会直接阻断。MySQL、Redis 和临时 Registry 分别来自仓库变量 `WEB_STARTER_MYSQL_IMAGE`、`WEB_STARTER_REDIS_IMAGE`、`WEB_STARTER_REGISTRY_IMAGE`，三者都必须是 `repository@sha256:<64-hex>`。

生产器与独立验证器都从同一 detached、clean candidate worktree 执行。raw bundle 的目标在运行前必须不存在，canonical summary 的外部 `0700` 目录必须为空。验证器成功后，工作流才将 canonical、排序、无多余空白且以单个 LF 结尾的摘要用 `O_EXCL` 逐字节复制为 `artifacts/acceptance/v2-generator-acceptance-summary.json`，权限仍为 `0600`。release gate 会再次以 raw bundle、原始禁用词和 clean candidate 独立调用验证器，并要求公开摘要与重算结果逐字节相同。

raw bundle、禁用词文件和私有 summary 目录均不上传；普通 Actions Artifact 只包含 canonical public summary。原始材料必须进入受限长期归档，才可在未来完整重放 AC08–15。生产器只清理自己以随机 run ID 精确标记的 Compose、Registry、镜像和临时生成树；workflow 不使用递归删除或通配符代替该清理。当前 dirty、`SNAPSHOT`、无精确注释 tag 的工作树仍不能形成正式 PASS。

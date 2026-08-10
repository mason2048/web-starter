# 供应链与发布镜像

本文定义 V2 的 AC-43/44 仓库发布门禁。它约束“什么 digest 可以进入发布 Compose”，不把一次静态扫描、镜像构建或容器健康误写为全栈验收通过。

## 发布链路

`.github/workflows/release-supply-chain.yml` 仅由语义化版本 tag 或显式手动输入启动，并按以下顺序执行：

1. 整个发布 job 固定绑定 GitHub Environment `release`。Environment 审批完成后，runner 的第一个步骤只使用内置 `github.token` 调用 GitHub REST `GET /repos/{owner}/{repo}/environments/release`，复核环境名和至少一个非空 `required_reviewers` 规则并创建私密输出目录；它不读取任何自定义 Secret。紧接的第二个步骤才读取唯一的 `release` Environment Secret `WEB_STARTER_AC40_DEPENDENCY_SEED_ANCHORS`，严格解析四个 AC40 锚并核对 Artifact/来源 run 元数据。两步都位于 checkout、Registry 登录、其他 Secret 和任何 package-write 操作之前，任一步失败即停；不引入 PAT 或 GitHub App Token。随后才执行仓库策略、后端 `verify` 和前端全部质量门禁。CI/发布使用的第三方 GitHub Actions 固定到完整 commit SHA，Maven Wrapper 校验发行包 SHA-256，两个 Dockerfile 的全部基础镜像固定到官方 tag 对应的 multi-platform digest；Dependabot 分别维护 Actions、Maven、npm 与两个 Dockerfile 的更新提案，更新后仍须重新验收。
2. 使用 `git archive GITHUB_SHA` 在仓库外生成只含该 commit 的构建上下文，再由 Build Push Action 构建 App 与 Nginx 候选镜像；工作区中由测试生成、被 Git 忽略或未跟踪的文件不会进入候选。同时启用 BuildKit provenance/SBOM attestation，并推送到受控 Registry。
3. 使用锁定版本且校验发布方 checksum 的 Syft，分别生成后端可执行 JAR、前端依赖树、App 最终镜像和 Nginx 最终镜像 CycloneDX JSON SBOM。
4. 使用锁定版本且校验发布方 checksum 的 Trivy，通过 `release_trivy.py` 从仓库外的临时工作目录启动扫描，显式指定受控的 `trivy-release.yaml`、`trivy-secret-release.yaml` 和空 ignore 文件，并移除全部 `TRIVY_*` 环境变量；仓库根目录中自动加载的 `trivy.yaml`/`trivy-secret.yaml` 不能改变发布扫描。扫描目标只能是 `repository@sha256`，不能用 tag、源码目录或另一次本地构建替代。
5. `release_security_gate.py` 核对报告与 SBOM 的 digest 绑定，并对 Trivy 顶层结构、Results、Vulnerabilities、Secrets 及每个 finding 的必需字段执行 fail-closed 校验：任意 Critical 漏洞、任意镜像秘密发现或未获批准的 High 漏洞都会阻断。
6. 使用本次实际 App/Nginx digest 和显式配置的 MySQL/Redis digest 展开 `compose.production.yaml`，再执行生产 Compose 策略；缺少 `WEB_STARTER_MYSQL_IMAGE` 或 `WEB_STARTER_REDIS_IMAGE` 仓库变量即失败。
7. 在 `${RUNNER_TEMP}` 下分别创建互不复用的 `0700` V1 source provenance、V1 AC-15 transport parity、generator、AC40、AC07、AC26、AC29、AC41、credential lifecycle、MCP CRUD、MCP Tool contract 和 MCP governance 原始证据目录，并为当前 commit/tag 建立 detached、clean、`0700` 的 candidate validation worktree；正式 producer 与 validator 从该 worktree 的脚本和候选源码运行，主 checkout 中已产生的 `artifacts`、扫描工具和构建输出既不被删除，也不能参与候选绑定。V2-AC-01 producer 先记录无 PASS 自报的固定 V1 tag/commit/tree/baseline/历史记录观察，独立 validator 再从 Git 对象库重算 42 项定义、42 项历史 PASS、12 项自动化声明、5 项最终勾选、当前候选后代关系与源码哈希；只公开 `0600` canonical summary，明确标记历史运行产物未重验且不声明当前候选 V1 回归。AC-15 在同一 clean candidate 中单独执行固定 Spring Context 测试，证明 REST/MCP 三个适配器持有同一个真实 `ProjectServiceImpl` Bean，并扫描 MCP 生产字节码不存在 Project Mapper/持久层引用；私密 Surefire XML 与 properties 由专用 validator 重算，只公开 `0600` canonical summary，build/verify 两阶段都必须接入原始 proof。生成器禁用词只从受保护的 `WEB_STARTER_FORBIDDEN_TERMS` Secret 通过 `O_EXCL` 落到仓库外 `0600` 文件，MySQL、Redis、Registry 只接受三个对应仓库变量中的 digest reference；raw 输出运行前必须不存在，summary 目录必须是空 `0700`。两阶段真实运行和独立语义重放完成后，仅将 canonical generator summary 逐字节复制到公开 artifact。AC40 不读取 runner 预置绝对路径：工作流从 `release` Environment Secret 的 canonical JSON 一次性取得同一仓库中的不可变 Artifact ID、来源 workflow run ID、Linux/x86_64 原始 tar SHA-256 和 canonical seed aggregate SHA-256；受信 producer commit 不是 Secret 字段，而必须与本次 release `GITHUB_SHA` 完全相同。它同时核对 Artifact `workflow_run.repository_id`、`head_repository_id`、`head_sha`，并另外读取来源 workflow run，要求同仓库、同 release commit、`event=workflow_dispatch`、workflow path 固定为 `.github/workflows/build-ac40-dependency-seed.yml`、`status=completed` 且 `conclusion=success`。固定 commit 的 `actions/download-artifact` 下载后，candidate worktree 中的 `build_v1_upgrade_dependency_seed.py extract-verify` 是唯一解包入口；工作流自身不再维护第二份 tar 解包器。构建器先核对 archive 模式和双 SHA-256 锚，再拒绝额外根、重复/逃逸路径、硬链接、特殊文件、非 Playwright 链接及逃逸/循环 Playwright 链接，最后重扫物理种子。SDK Maven、pnpm 和 Playwright 随后只使用候选绑定且摘要验证后的私密副本并强制离线、无下载重试。完整 V1→V2 升级/恢复演练经独立验证器确认 AC40 后，以 `O_EXCL` 生成 byte-identical `0600` 公开 JSON（raw sibling checksum 不上传）；最后用本次 release App digest、MySQL digest、Redis digest 和实际 AC40 原始结果执行 AC07。任一报告缺失、权限不是 `0600`、checksum 不匹配、候选、种子、Artifact 来源或镜像身份漂移都会立即失败。
8. 主全栈运行使用严格匹配 `web-starter-ac41-*` 的独立 Compose project。runner 生成并验证 `runtime-version-identity.json` 后，另建固定 `web-starter-ac26-*` 项目和独立 MySQL/Redis 卷，以 `release-ac26` Trace、固定回环私有/公网端口和提交的 `expiry` 或 `revocation` 终态执行真实 OAuth/JWKS/MCP 轮换；clean candidate validator 绑定 App/Nginx digest reference、image ID、commit/version/tag、三阶段容器切换和审计，并只公开 0600 canonical summary。AC26 成功与失败路径都销毁专用卷并确认无项目资源遗留。主栈完成运行身份与 OAuth 边界检查后，再以四个一次性用户、active/retiring Pepper、真实机密 Client 和内外网 MCP 入口执行 V2-AC-24/27/28/36；每个一次性用户在对应场景后必须删除、回读 `404` 并核对清理审计，避免污染后续最后管理员和 RBAC 验收。clean candidate validator 重算级联失效、fixture 清理、Pepper 迁移、Client Secret 重叠窗口、统一负向安全回归、源码哈希和镜像身份，只公开 `v2-credential-lifecycle-runtime-summary.json`。官方 MCP SDK CRUD 测试只执行一次；AC33 专用官方 SDK Tool contract 测试也只执行一次，不重跑或替代 CRUD。AC34/35 再使用严格匹配 `web-starter-governance-*`、且不同于主栈和 AC26 的第三个隔离 Compose project，以独立 MySQL/Redis 卷执行 Session TTL/上限/DELETE、主体/Client/风险限流、审计和真实 SIGTERM 重启；它固定产出两个 Surefire XML、shutdown state、外部重启 receipt 与 proof properties 五个私有文件。三组 MCP 证明都从同一 commit/tag 的 detached clean validation worktree编译执行，原始文件留在 `${RUNNER_TEMP}` 的独立 `0700` 目录；Token 不进入 raw proof 或上传清单，成功和失败路径都执行带超时的 `down --volumes --remove-orphans` 并确认项目资源清空。三个 proof producer/独立 validator 均针对该 worktree 绑定源码，validator 先在 runner 私有 `0700` 目录生成 canonical summary，再以 `O_EXCL` 逐字节复制为公开 `0600` artifact。runner 再从运行身份中严格读取 App digest reference 和 image ID，用 clean candidate worktree执行 AC29；浏览器、OAuth、故障恢复和七层统一验证完成后，在主栈清理前执行 AC41 formal。Compose 私密环境文件只通过结构化 `--env-file` 传入，不经 shell `source`。AC07/AC41 JSON 及 checksum、AC29 JSON、AC26、credential lifecycle 与 MCP governance canonical summary 进入 `artifacts/acceptance`；credential lifecycle 原始报告、AC26 raw 双文件、governance raw 五文件、JWK Set、临时 OAuth material 和其他私有目录均不进入公开 Actions Artifact。
9. `release_evidence_gate.py` 要求实际的注释 Git tag 指向当前 commit，按本次 UTC 发布日重新评估安全摘要并绑定原始 SBOM/Trivy 报告哈希，核对 Java/Actuator、App/Nginx OCI 身份以及 App/Nginx/MySQL/Redis 四个实际运行容器的 digest reference 与 image ID，并校验后端、前端、策略、容器、浏览器、OAuth、MCP 七层统一验证摘要的内容哈希，把镜像 digest、四份 SBOM 校验和、实际生产 Compose 与策略摘要、部署 digest 环境文件、全部 Flyway 文件与校验和、V1/V2 验收结果合并为 `release-evidence.json`；只有注册到门禁独立语义验证器的验收项能够声明 `PASS`，仅有一个哈希匹配且内容自称 `{"status":"PASS"}` 的文件不构成通过证据。`build` 与 `verify` 都必须收到 V2-AC-01 raw proof，并分别重算固定注释 `v1.0.0`、其 commit/tree、冻结基线与历史验收记录、当前 release 后代关系和作用域；`build` 还要求其 canonical summary 逐字节一致。V1 AC-40 的两次调用都必须收到仓库外禁用词文件和独立参考仓库，由门禁重新扫描固定工程结构并核对参考仓库前后指纹；`build` 还逐字节核对 `v1-ac40-project-isolation-summary.json`，完整合同见[工程隔离证据](./v1-project-isolation-evidence.md)。两次调用也都必须收到 AC26 raw 报告、固定隔离 Compose 项目和提交终态，由门禁重算该 `expiry` 或 `revocation` 模式；`build` 还要求 AC26 canonical summary 与重算结果逐字节一致。AC34/35 同样要求 governance 私有 proof、独立 `web-starter-governance-*` 项目和 canonical public summary；门禁重算候选源码、五个 raw 文件、真实 app/Redis reference 与 image ID，并拒绝治理项目复用主栈或 AC26。V2-AC-40 的两次调用还必须显式接入同一份公开 dependency-seed provenance receipt；门禁把它作为 `release-evidence.json.inputs.ac40DependencySeedProvenance` 的 content-addressed 输入，并与独立重算后的 `source.dependencySeed` aggregate、manifest、platform、architecture 逐项交叉验证。其他 generator、AC07/AC29/AC40/AC41 与 MCP proof 参数同样缺一即失败。所有门禁 Git 子进程使用 allowlist 环境、禁用 replace object 并限制 stdout/stderr 字节数。门禁步骤结束后（包括失败路径），工作流只按固定 `${RUNNER_TEMP}` 子路径处理 validation worktree，并在确认它不是符号链接、确为当前 release commit 的 Git 顶层且与主 checkout 共用 Git common dir 后，使用精确 `git worktree remove --force` 和 `git worktree prune` 清理；不使用递归删除、通配符或未解析变量。
10. 证据文件先计算 `SHA256SUMS` 并成功上传，之后才检查 Registry 版本 tag。tag 不存在时提升候选 digest；tag 已精确指向同一 digest 时允许幂等恢复；指向不同 digest 或查询遇到网络、认证、Registry 异常时失败。安全门禁、生产 Compose 策略、完整证据或证据上传任一失败都不会执行提升；版本 tag 仍只是便捷索引，部署始终使用 digest。

### `release` Environment 管理员配置

仓库管理员必须在 **Settings → Environments** 创建名称精确为 `release` 的 Environment，并配置至少一个 Required reviewer；建议同时开启 Prevent self-review，并将 deployment branches/tags 限制到本仓库的发布策略。每次 job 在 runner 启动前都必须先由该 Environment 的 reviewer 审批。runner 启动后仍会独立调用官方 [Environment REST API](https://docs.github.com/en/rest/deployments/environments?apiVersion=2026-03-10#get-an-environment) 检查 `name`、`protection_rules[].type=required_reviewers` 和非空 `reviewers`，不能仅凭 job 已进入 Environment 就假设保护规则仍存在。

V1 AC-40 还要求该 Environment 配置 `WEB_STARTER_REFERENCE_REPOSITORY`、`WEB_STARTER_REFERENCE_REPOSITORY_COMMIT` 两个 Variables，且参考仓库必须公开可见、不得与当前发布仓库同名（大小写不敏感）。工作流先通过不带认证头的 GitHub REST 请求核对 public 可见性，再在隔离 Git 配置、禁用交互式凭据的环境中以匿名 HTTPS 精确拉取固定 commit；不要求、读取或传入 PAT、GitHub App Token 或 `github.token`。检出后仍拒绝 dirty checkout、Git link 和 commit 漂移；`WEB_STARTER_FORBIDDEN_TERMS` Secret 同时作为 V1 工程隔离与生成器隔离的外部词表。权限与完整合同见[工程隔离证据](./v1-project-isolation-evidence.md)。

正式发布前，先在 GitHub Actions 手动运行 `.github/workflows/build-ac40-dependency-seed.yml`：运行分支选择器和 `version` 输入必须指向同一个已存在的注释语义版本 tag。该 job 同样经过 `release` Environment 审批，并复用生成器已有的 `WEB_STARTER_FORBIDDEN_TERMS` Environment Secret；不需要再维护一份普通变量词表。它只在 `ubuntu-24.04` Linux/x86_64 runner 的全新 `0700` 根中，从 HTTPS Maven Central、npmjs 和 Playwright 官方下载源解析当前锁定闭包，不读取 runner 或开发机的 Maven、pnpm、Corepack、Playwright 共享缓存。构建器拒绝本项目 Maven 产物、非 Central 来源、校验和漂移、敏感配置、凭据材料和非规范 tar；浏览器必须真实启动后才允许用固定 SHA 的 `upload-artifact` v7 直接上传原始 tar。管理员复核 job summary 和 receipt/provenance artifact 后，将其中的 raw tar Artifact ID、producer run ID、archive SHA-256 与 aggregate SHA-256 写入下面的单一 canonical Environment Secret，再触发同一 tag 的发布流程。Artifact 当前保留 90 天，过期后不能继续复用旧锚。

四个 AC40 锚必须合并为 `release` Environment 中唯一的 Secret `WEB_STARTER_AC40_DEPENDENCY_SEED_ANCHORS`。值必须是 UTF-8 单行 canonical JSON：字段只能且必须为 `aggregateSha256`、`archiveSha256`、`artifactId`、`workflowRunId`，字段按字典序排列，无空白、换行、重复键或额外键；两个 ID 是正整数，两个摘要是 64 位小写 SHA-256。下面仅是格式示例，摘要和 ID 都是占位值，不能直接用于发布：

```json
{"aggregateSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","archiveSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","artifactId":123456789,"workflowRunId":987654321}
```

同名 Repository Secret 或 Organization Secret **禁止配置**。GitHub 的 `secrets` 上下文会让 Environment Secret 覆盖较低层级的同名值，但 Environment Secret 缺失时无法由表达式证明没有回落到 Repository/Organization Secret；因此管理员必须把“同名低层 Secret 不存在”纳入配置审查。发布第一步只使用内置 `github.token` 读取 [Environment metadata](https://docs.github.com/en/rest/deployments/environments?apiVersion=2026-03-10#get-an-environment)，因为 Environment variables REST 需要 `Environments: read`，而 `GITHUB_TOKEN permissions` 没有可授予的对应 scope；工作流不再调用 variables REST，也不引入 PAT/App Token。第二步在 Environment 审批后读取上述唯一 Secret，独立拒绝空值、重复键、额外键、非 canonical 编码和格式错误，随后立即从进程环境移除原值。producer SHA 直接取不可变的本次 `GITHUB_SHA`，不能由 Secret 覆盖。更新锚 bundle 必须由管理员完成，并重新触发一次新的 Environment 审批。

Artifact 元数据中的 `workflow_run.head_repository_id` 与 `head_sha` 来自官方 [Get an artifact](https://docs.github.com/en/rest/actions/artifacts?apiVersion=2026-03-10#get-an-artifact) 响应；来源运行的 `status`、`conclusion`、`repository.id`、`head_repository.id` 与 `head_sha` 则来自官方 [Get a workflow run](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#get-a-workflow-run) 响应。两份响应必须交叉一致且结论为 `success`，Artifact digest 或 aggregate digest 单独匹配都不够。

`extract-verify` 生成的私密 builder receipt 保留在 `${RUNNER_TEMP}` 的 `0700` 目录；工作流另外生成并上传 `artifacts/acceptance/v2-ac40-dependency-seed-provenance.json`，其中只含 Environment 名、Artifact ID、run ID、head repository ID、producer SHA、archive/aggregate/manifest SHA-256、platform 与 architecture，并由 `SHA256SUMS` 覆盖。门禁只接受 `artifacts` 根内这个固定路径上的 caller-owned、单链接、普通 `0600` canonical JSON，要求 exact schema/kind、`environment=release`、正整数身份、producer SHA 等于 release commit、Linux/x86_64 和合法 SHA-256；其内容哈希已进入 `release-evidence.json`，V2-AC-40 必须同时绑定升级演练与该 provenance receipt 才能成为独立验证的 `PASS`。这证明发布门禁使用的 dependency seed 与受保护 Artifact、release commit 和 AC40 运行证据一致；它不替代私密 builder receipt、原始 tar 或 AC40 raw 的长期受控归档。

安全发布 Artifact 包含后端、前端和两个由本仓库构建的最终镜像（App、Nginx）的 SBOM、漏洞报告、脱敏门禁摘要、实际展开的生产 Compose、Compose 策略摘要、Java/Actuator/OCI 运行身份、四个运行容器的不可变 image ID、七层统一验证摘要、V2-AC-01、V1 AC-40、generator、tooling lifecycle、AC26、credential lifecycle、observability 与 MCP governance canonical summary、V2-AC-40 公开 JSON 与 dependency-seed provenance receipt、AC07/AC41 公开逐字节副本及 sibling checksum、AC29 公开逐字节副本、MCP CRUD 与 MCP Tool contract canonical summary、完整发布证据、Git commit、版本、镜像 digest、部署镜像变量和 `SHA256SUMS`。原始七层日志仅保留在隔离运行目录并在清理时删除；发布 Artifact 只保存不含命令行与凭据的逐层状态。V2-AC-01 raw 双文件、V1 AC-40 的外部禁用词与参考仓库、tooling lifecycle 原始报告与临时环境文件、credential lifecycle 原始报告、两份 observability 原始指标报告、AC26 raw/JWK/OAuth material、generator raw bundle/禁用词/private summary、原始 V2-AC-40/AC07/AC29/AC41 目录、dependency-seed builder 私密 receipt、三份 MCP raw proof、Token 响应、detached validation worktree 和原始秘密报告不会上传；这些受控原始证据必须另行进入受限长期归档。

MySQL 与 Redis 是外部维护的部署输入，不属于本仓库构建的两个最终镜像。当前工作流只验证它们在生产 Compose 中使用显式 `repository@sha256`，不会为其生成 SBOM 或扫描报告，也不会把它们计入 AC-43 的 App/Nginx 发布镜像证据。目标环境在宣称“全栈供应链通过”前，必须另行保存精确 MySQL/Redis digest 对应的来源审批、SBOM 和漏洞/秘密扫描证据；缺少这些环境证据时，全栈第三方镜像状态只能是 `ENV_REQUIRED` 或 `NOT_COVERED`，不能折算为 `PASS`。

tag push 与手动发布按目标 release tag 使用同一个并发组，避免同一工作流内部从不同 ref 同时提升同名 tag。工作流先确认候选引用仍是扫描过的 digest，再只把“明确不存在”的 tag 写入；已有同 digest tag 视为幂等成功，已有不同 digest tag 拒绝覆盖，未知查询错误也拒绝继续。App 成功而 Nginx 暂时失败后，只有重跑生成完全相同的候选 digest 才能幂等续跑；否则必须调查构建不可重复原因并使用新的预发布版本，不能覆盖旧 tag。这仍不能替代 Registry 侧的不可覆盖策略。部署和发布证据以 digest 为信任锚点，外部主体若能绕过 Registry 权限重写 tag，版本 tag 本身不构成可信证据。

正式 20+2 运行报告另有独立边界：workflow 在 `${RUNNER_TEMP}` 创建专用
`0700` raw 目录；detached candidate 通过
`pnpm install --frozen-lockfile --offline` 使用前序校验已填充的 store，随后
复核 tracked/index clean 和本地 Playwright 1.61.1。runner 拒绝外部 MCP
预期变量，`build` 与 `verify` 都从 raw 重算 exact 20 Playwright + 2 official
SDK 语义并匹配 canonical bytes。只有 canonical summary 上传；raw 四文件不
进入 Actions Artifact。映射的 PASS 同时绑定本次
`runtime-version-identity.json` 与 `release-runtime-acceptance.json` 的
commit、tag 和镜像 digest，canonical 不能单独证明运行镜像身份。

20 个浏览器用例中的 `AC-08` 会停用并重新启用发布 owner，因此该主体在
浏览器阶段之前签发的 PAT 必须随 security epoch 前移而永久失效。runner
不会放宽这一生命周期规则，也不会把旧 PAT 继续交给后续 SDK；浏览器阶段
结束后，它通过公网 TLS 登录重新确认同一个 owner，再仅经回环私有入口签发
精确包含 `system:info`、`project:list`、`audit:list` 的新 PAT。一次性明文
只写入仓库外 `${RUNNER_TEMP}` 下 owned `0700` 目录中的 single-link `0600`
文件，不打印、不上传，并且先供私有
`McpSdkProjectListRuntimeIT` 使用。七层统一验证不会第二次执行这组有状态的
20+2；其 browser/MCP 层分别从同一 raw 和候选身份重跑独立 validator，MCP
层同时复核单次 CRUD/事务 proof。browser proof 复核后再签发一枚隔离的相同
最小 Scope PAT，仅供后续 OAuth 私/公网 PAT 边界及非 formal 的 live SDK
消费，旧 PAT 始终保持失效。

## AC-45 发布证据清单

发布工作流不会根据测试日志猜测或自动补写验收状态。创建注释 tag `vX.Y.Z` 前，必须在同一 commit 中跟踪并显式提供 `release/evidence/vX.Y.Z.json`；文件遵循 [`release-acceptance-input.schema.json`](../security/release-acceptance-input.schema.json)，发布清单遵循 [`release-evidence.schema.json`](../security/release-evidence.schema.json)。输入只记录脱敏、可追溯的证据引用，不得复制密码、Cookie、Authorization Header、Token、私钥、扫描器秘密命中上下文或带凭据的 URL。

验收输入只声明 tag 和 version，故意不包含 `gitCommit`。一个被提交的文件无法可靠写入“包含它自己的 commit hash”；任何更新都会再次改变 commit。门禁从实际注释 tag 派生 commit，确认 tag、HEAD 与工作流 commit 完全相同，再使用 `git show <commit>:<path>` 逐字节验证验收输入确实属于该 commit。最终 `release-evidence.json` 仍记录并绑定派生出的完整 Git commit 和 tag object。

输入的发布身份必须与工作流完全相同：

```json
{
  "schemaVersion": 1,
  "release": {
    "tag": "v2.0.0",
    "version": "2.0.0"
  },
  "suites": {
    "v1": {
      "results": [
        {
          "id": "AC-01",
          "status": "NOT_COVERED",
          "observedAt": "2026-07-19T10:00:00+08:00",
          "evidence": ["artifact://acceptance/v1-ac-01.json#sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
        }
      ]
    },
    "v2": {"results": []}
  }
}
```

片段中的数组只是格式说明，不能直接用于发布。每条引用必须使用无凭据、无路径回退且带 64 位小写 SHA-256 的内容寻址格式：`repo://` 由门禁读取 release commit 中的字节核验，`artifact://` 由门禁读取本次 `artifacts` 中的文件核验。两者都必须真实存在、可读取且哈希完全一致；`external://`、占位文字、可变 URL、路径回退和没有真实 SHA-256 的引用在任何状态下都会失败。真实文件必须包含 V1 基线的 42 项和 V2 的 AC-01 至 AC-44；级别从已提交的基线读取，不能由输入覆盖。`V2-AC-45` 不允许在输入中自称通过，它由本门禁在完成全部绑定校验后产生，因此最终清单仍完整包含 V2 的 45 项。

内容哈希只是最低门槛，不代表验收语义成立。最终账本使用三个互斥的信任等级：`CONTENT_HASH_VERIFIED` 只说明非 PASS 结果的源文件可读取且哈希一致；`GATE_INDEPENDENTLY_VERIFIED` 说明门禁已经重算注册验证器的结构、发布身份、digest 和具体 PASS 条件，并自动绑定实际 artifact；`GATE_DERIVED` 只用于门禁派生的 `V2-AC-45`。当前独立验证注册表固定为：

| 验收项 | 门禁独立重算 | 自动绑定 artifact |
|---|---|---|
| V2-AC-01 | 从 Git 对象库解析固定注释 `v1.0.0`、tag object、commit/tree、archive、42 项冻结定义与 42 项历史记录，核对 12 项自动化声明、5 项最终结论、当前候选 ancestry 和源码哈希；只承认 `TAGGED_RECORD_ONLY`，不声称重验历史运行产物或当前候选 V1 回归 | `v2-ac01-v1-source-provenance-summary.json` canonical 摘要 |
| V2-AC-02 | Maven/前端版本、Java/Actuator/OCI 与发布版本、commit、镜像 digest 一致 | `release-images.json`、`runtime-version-identity.json` |
| AC-01；V2-AC-03 | 从空 MySQL/Redis 命名卷启动，完整执行 Flyway，并使用只存在于运行环境的初始化管理员凭据完成真实登录、CRUD、权限拒绝和审计；因此同时证明首次启动创建管理员和 V2 空库安装 | `release-runtime-acceptance.json` |
| V2-AC-07 | 独立验证迁移故障保护，并复核实际 AC40 恢复证据；App 与三项运行 image ID 均取自运行身份报告 | `v2-ac07-migration-failure.json` 的逐字节公开副本 |
| AC-42；V2-AC-08 至 V2-AC-15 | 对仓库外 raw bundle、外部禁用词和 clean candidate 重放项目/模块生成边界，交叉核对两个真实运行阶段、不可变镜像、完整清理及逐项 coverage；完整生成器闭环同时作为 V1 独立 CRUD 模块扩展能力的更强证明 | `v2-generator-acceptance-summary.json` canonical 摘要 |
| AC-02、AC-37；V2-AC-16、V2-AC-17 | 从独立 raw 重算 22 项 doctor 清单、首次管理员真实登录、数据库密码哈希指纹、初始密码从私有环境原子移除、同一密码重启后再次登录、密码哈希不变、两段运行日志明文命中数为零、两次四服务健康启动、默认 down 保留命名卷、重启前后确定性 Project 行数及完整字段 SHA-256、三种危险删除在 Docker 前拒绝、重启身份稳定和二次确认后的零资源清理；绑定 clean candidate、专用 Compose project 与四项运行镜像身份。AC-02 还要求同一账本绑定七层统一验证中的仓库秘密策略；AC-37 还要求同一账本同时绑定生产 Compose 展开模型、唯一入口策略、运行身份和完整发布运行验收 | `v2-tooling-lifecycle-runtime-summary.json` canonical 摘要；AC-02 另含 `unified-verify-summary.json`；AC-37 另含 `production-compose.json`、`production-compose-policy.json`、`runtime-version-identity.json`、`release-runtime-acceptance.json` |
| AC-17、AC-18、AC-19、AC-20、AC-21、AC-22、AC-23、AC-24、AC-34；V2-AC-24、V2-AC-27、V2-AC-28、V2-AC-36 | 从独立 `0700` 私有 raw 重算四类身份级联失效、长期令牌 Pepper 成功认证后迁移、OAuth Client Secret 重叠窗口、RBAC/Scope/吊销/Host/Origin/内外网边界与相关审计；AC-17 用真实用户签发 PAT，证明明文只在创建响应出现、列表只返回提示，数据库记录为 64 位哈希并绑定用户，Scope 缺失返回 403，短期 Token 到期前 200/到期后 401，吊销和 IP 不匹配均为 401，成功认证回写最后使用时间且列表可读回期限、IP 与吊销状态；AC-18 通过真实管理 API 创建启用且绑定角色的服务账号，签发两个长期令牌，证明角色移除即时 403、恢复角色后可用、显式吊销只使目标 Token 401、同账号另一个 Token 仍为 200；随后禁用账号使全部既有 Token 及数据库记录失效，重新启用不复活旧 Token，但可签发新的可用 Token，并读回全部管理操作审计；AC-19 从管理 API 读回预注册 Client 并完成密钥轮换，OAuth 元数据不得暴露 `registration_endpoint`，`/connect/register` 与 `/oauth2/register` 必须 404，真实已登录浏览器提交未登记 Redirect URI 必须 400 且无 Location；AC-20 结合真实浏览器 Authorization Code + PKCE S256 + 公网 MCP 初始化，另逐次记录短时 Bearer 有效期、失效前 MCP 200，以及密码重置、主体禁用/删除和安全注销后 access token 下一请求 401、refresh token `invalid_grant`；AC-21 通过绑定服务账号的 Client Credentials 签发不超过一小时且 `exp-iat=expires_in` 的 JWT，随后回收角色并证明原 Token 下一请求 401，再恢复角色签发新 Token 并成功初始化，同时读回两次操作审计；AC-22 同时绑定真实浏览器及官方 SDK，覆盖 PAT、服务账号令牌和 OAuth 的允许路径，以及 RBAC 允许但 Scope 拒绝、Scope 允许但 RBAC 拒绝两侧交集；AC-23 对 PAT 与服务账号长期令牌分别验证私有入口初始化成功、公网入口 401，并以 Client Credentials 公网初始化证明 OAuth 外网 Agent 正常；AC-24 从实际 Authorization Server/Protected Resource Metadata、Client Credentials JWT 和无凭据 MCP 401 读回 Issuer、唯一 Audience、授权服务器、Bearer method 及精确 `WWW-Authenticate resource_metadata`，并将 OAuth 验证器源码纳入 canonical source hash；秘密保护另将管理员和四个临时用户的密码、CSRF、Cookie、PAT、OAuth Token、Client Secret、Basic Authorization 编码值和 Pepper 纳入真实数据库转储及运行日志字面扫描，并拒绝日志中的 Cookie/Authorization Header；AC-34 同时绑定错误/审计响应脱敏结果。全部证据绑定 clean candidate、运行身份、OAuth 报告、Compose project、不可变 App/Nginx 引用和固定源码哈希 | `v2-credential-lifecycle-runtime-summary.json` canonical 摘要；AC-19/20/22/23/34 另含 `release-runtime-test-reports-summary.json`，九项均含 `runtime-version-identity.json`、`release-runtime-acceptance.json` |
| V2-AC-26 | 从仓库外 raw 双文件按提交的 `expiry` 或 `revocation` 模式重算真实 OAuth 签发、active/retiring JWKS、旧新 JWT、MCP 401/连续性、审计 Trace、专用 Compose 与 App/Nginx 不可变身份 | `v2-ac26-jwks-rotation-summary.json` canonical 摘要 |
| V2-AC-29 | 使用真实运行 App 的 digest reference/image ID 独立重算 15 个危险生产配置、hardened control、Java 21 probe、隔离和精确清理 | `v2-ac29-production-fail-fast.json` 的逐字节公开副本 |
| V2-AC-18 | 后端、前端、策略、容器、浏览器、OAuth、MCP 七层状态逐项为 PASS | `unified-verify-summary.json` |
| AC-38 | 独立验证器从 clean candidate、注释 tag、Git Blob 与逐文件 SHA-256 重算日志、备份恢复、升级回滚和 RSA 轮换文档，并要求 Flyway 版本连续且恢复说明同步到当前最高版本；运行侧同时绑定匿名聚合健康、MySQL/Redis readiness/liveness 与可观测性摘要。源码证明或真实运行任一缺失都不能提升为 PASS | `v1-ac38-operations-documentation-summary.json`、`v2-observability-runtime-summary.json`、`release-runtime-acceptance.json` |
| AC-39 | 同一七层 `verify` 的策略层固定执行仓库策略单元测试和当前 clean candidate 的真实秘密扫描；生产 fail-fast 演练另证明开发 RSA、缺失 RSA、空值及占位秘密等危险生产配置拒绝启动。门禁同时绑定 `DeveloperCommands`、仓库扫描器和两份摘要，任一缺失或失败均不提升为 PASS | `unified-verify-summary.json`、`v2-ac29-production-fail-fast.json` |
| AC-40 | 门禁现场重算固定通用工程结构，以受保护禁用词扫描当前候选零命中，并要求独立参考仓库的 HEAD、status、worktree、index 与未跟踪内容指纹在每次评估前后完全相同；摘要不保存词条、参考路径或参考仓库内容 | `v1-ac40-project-isolation-summary.json` |
| AC-41 | 同一七层 `verify` 中后端固定执行 Maven `verify`；前端固定顺序执行 lint、typecheck、unit test 和 production build。任一步失败都会保留对应私有步骤日志、使该层非 PASS，并阻断聚合摘要和发布门禁 | `unified-verify-summary.json` |
| V2-AC-19、V2-AC-20、V2-AC-22 | 从私有 20+2 报告绑定并复核 OpenAPI→TypeScript 漂移链、标准 CRUD、类型化导航、bundle budget 与固定浏览器质量语义；要求同候选七层 frontend PASS、运行身份和全栈报告，V2-AC-20 另要求 generator canonical 证据；公共 MCP 入口的契约与 Explorer 候选路径必须逐项 404 | `release-runtime-test-reports-summary.json`、`unified-verify-summary.json`、`runtime-version-identity.json`、`release-runtime-acceptance.json`；V2-AC-20 另含 `v2-generator-acceptance-summary.json` |
| AC-15 | 在 clean candidate 中执行固定 Spring Context 集成测试，重算 REST/MCP 三个适配器共享同一 `ProjectServiceImpl` Bean、直接依赖边界以及整个 MCP 生产字节码中 Project Mapper/持久层引用为零；同时绑定测试、实现、POM、producer、validator 和 Schema 的提交字节 | `v1-ac15-project-transport-parity-summary.json` canonical 摘要 |
| AC-16；V2-AC-31、V2-AC-32 | 在隔离 MySQL 栈临时安装只命中固定 Trace 的操作审计 `CHECK` 约束，通过官方 MCP SDK 让 `project.create` 在业务插入后、成功审计写入时失败；随后从真实数据库核对项目、成功操作审计和幂等预留全部回滚，`REQUIRES_NEW` 失败 MCP 审计精确保留一条，约束完整清理；同一次 SDK 用例继续证明成功业务行、操作审计和 MCP 成功审计共同提交，以及写操作并发、重试和冲突语义。独立验证器重算私有 Surefire 报告、数据库 receipt、固定 Trace/哈希/计数、clean candidate 与事务相关源码 | `mcp-crud-runtime-proof-summary.json` canonical 摘要 |
| AC-03～AC-14、AC-19、AC-20、AC-22、AC-23、AC-25～AC-36；V2-AC-19、V2-AC-20、V2-AC-21、V2-AC-22、V2-AC-23、V2-AC-25、V2-AC-30、V2-AC-39 | 从私有 raw 重算精确 20 个 Playwright 与 2 个官方 SDK 结果，绑定固定源码、commit/tree/tag/version 和报告 digest，并交叉要求本次 digest-bound 运行身份与全栈验收；AC-03 以真实登录接口证明错误密码与不存在账号统一返回 401，正确密码建立 HTTP-only `WEB_STARTER_SESSION`，同一浏览器随后读取 `/api/auth/me` 成功，并按固定 Trace ID 精确读回成功与失败登录审计；AC-04 以两个真实浏览器 Session 证明定向退出，普通退出后在新上下文重放原 Cookie 仍为 401，管理员禁用用户后原 Session 下一请求为 401 且重新启用不复活，并额外要求 Redis 丢失演练证明已认证 Session 对应的隔离 Redis 数据存在且清空后旧 Cookie 立即失效；AC-05 从十一份 Web Controller 与 Spring Security logout 端点独立重算 36 条写路由，真实浏览器对每条路由分别发送缺失和错误 CSRF 的请求，精确要求 72 次 403、匿名登录不建立 Session、每次已认证探测后 `/api/auth/me` 仍为 200，且九个管理域的完整数据快照与 Session 数量前后不变；AC-06～AC-14 分别以真实页面和 API 证明用户全生命周期、角色并发与即时撤权、管理员连续性、菜单撤权、按钮与 API 双层权限、权限字典、非敏感配置、Project 查询以及 Project 写入/乐观锁/逻辑删除；AC-32 在同一真实浏览器 Session 中对用户、角色、菜单、配置、Project、个人令牌、服务账号和 OAuth Client 执行创建与清理，为每次写请求固定唯一 Trace ID，并从操作审计接口精确读回主体、资源、成功结果、非负耗时与脱敏详情；AC-35 逐页打开登录、概览、项目、用户、角色、菜单、配置、三类日志、PAT、服务账号和 OAuth Client 页面，对八个主操作表单执行打开/取消，并对三类日志执行真实筛选刷新；登录质量用例以固定 Trace ID 触发成功/失败并从真实审计接口核对用户名、结果、IP、User-Agent、Trace ID 与密码脱敏；官方 SDK 还以精确 Trace ID 读回成功、权限拒绝、校验失败和业务失败四类 MCP 审计，核对 Tool、权限、服务账号主体、Token/Client、IP、耗时、错误码及脱敏；第二个 SDK 用例另证明 `project:list` 最小权限主体不能读取 `system:info` Resource，并通过真实私有入口拒绝非法 Host/Origin。AC-26 另外绑定专用 Tool contract proof，AC-29 另外绑定生产 fail-fast 演练；AC-30 只声明 `tools/list` 精确七名与 unknown Tool 拒绝，不外推任意实现安全；V2-AC-20 另绑定生成器和统一验证，V2-AC-22 另绑定统一验证，V2-AC-39 还保留 V1 upgrade 绑定 | `release-runtime-test-reports-summary.json`、`runtime-version-identity.json`、`release-runtime-acceptance.json`；AC-04 另含 `v2-ac41-redis-loss.json`，AC-26 另含 `mcp-tool-contract-runtime-proof-summary.json`，AC-29 另含 `v2-ac29-production-fail-fast.json`，V2-AC-39 另含 `v2-v1-upgrade-rehearsal.json` |
| V2-AC-33 | 从私有两文件 proof 重放官方 SDK Tool 契约结果，核对精确 7 Tool、写 schema/annotation、稳定错误、V1 无键写兼容以及 commit/tree/version/tag/Compose/Trace 绑定 | `mcp-tool-contract-runtime-proof-summary.json` canonical 摘要 |
| V2-AC-34、V2-AC-35 | 从私有五文件 proof 重放官方 SDK Session TTL/上限/DELETE、主体/Client/风险限流及审计结果；核对外部 SIGTERM 重启、Redis 连续性、clean candidate 源码、独立 `web-starter-governance-*` 项目以及 App/Redis digest reference 与 image ID | `mcp-governance-runtime-summary.json` canonical 摘要 |
| V2-AC-37 | 重算运维端点授权矩阵、固定低基数指标族及标签域、登录/审计/MCP/Session/Hikari/三个协议入口/限流相对基线增量，并核对含 Trace ID 的 ECS `protocol_request` 日志；绑定 clean candidate、主栈 Compose、运行身份和 App/Nginx 不可变身份 | `v2-observability-runtime-summary.json` canonical 摘要 |
| V2-AC-38 | MySQL/Redis readiness/liveness 故障恢复与公网运维端点隐藏检查为 PASS | `release-runtime-acceptance.json` |
| V2-AC-40 | 独立验证 V1→V2 升级、恢复、凭据兼容、浏览器/MCP 与精确清理；SDK、pnpm、Chromium 依赖由候选/平台绑定的私密种子离线提供，并重新绑定 clean candidate；门禁交叉核对受保护 Artifact provenance | `v2-v1-upgrade-rehearsal.json` 的逐字节公开副本、`v2-ac40-dependency-seed-provenance.json` |
| AC-04；V2-AC-41 | 独立重算已认证会话存在时 Redis `DBSIZE >= 1`、Redis `FLUSHDB` 后 `DBSIZE = 0`、旧 Session 401、重新登录、MySQL 指纹、审计递增和零资源删除；四项镜像期望均取自运行身份报告。AC-04 还必须同时绑定真实浏览器普通退出与禁用用户的下一请求失效 | `v2-ac41-redis-loss.json` 的逐字节公开副本；AC-04 另含 `release-runtime-test-reports-summary.json`、`runtime-version-identity.json`、`release-runtime-acceptance.json` |
| V2-AC-42 | 不可变镜像、双入口、浏览器、OAuth、PAT 边界与官方 MCP SDK 检查为 PASS | `release-runtime-acceptance.json` |
| V2-AC-43 | SBOM、实际镜像 digest、Trivy 原始报告和漏洞例外策略重新求值为 PASS | `release-images.json`、`security-gate-summary.json` |
| V2-AC-44 | 展开的生产 Compose、Dockerfile 与容器硬化策略重新校验为 PASS | `production-compose.json`、`production-compose-policy.json` |

上述注册表以外的验收项即使引用一个哈希匹配的 `{"status":"PASS"}` artifact，也会被结构性拒绝；`verify_git=False` 只供隔离单元测试跳过 Git tag/checkout 绑定，不会跳过这一语义门禁。尚未注册独立验证器的结果应保持 `NOT_COVERED`、`ENV_REQUIRED` 或 `FAIL`，门禁允许据此生成可审阅的 FAIL ledger，但不会把它提升为可发布清单。

状态只能是 `PASS`、`FAIL`、`NOT_COVERED`、`ENV_REQUIRED`。缺少任一 P0/P1、证据引用为空、任一状态不是 `PASS`、未注册项声明 `PASS`、tag 不存在或不是注释 tag、tag/HEAD/commit 不一致、根 Maven/前端版本仍是 `SNAPSHOT` 或与 tag 不一致、安全门禁不是 PASS、生产 Compose/策略摘要/部署环境未绑定本次 digest、镜像或 SBOM digest 漂移、Flyway 文件变化，都会在镜像版本 tag 提升前失败。`NOT_COVERED` 和 `ENV_REQUIRED` 永远不会折算为通过；脚本也没有跳过 Git 绑定、语义注册表或放宽 P1 的命令行选项。

工作流内的构建调用等价于以下命令；所有输入文件都必须已经真实产生，缺少任何一个不会自动补默认值：

```bash
python3 -B scripts/release_evidence_gate.py build \
  --repository-root . \
  --artifacts-root /absolute/release-artifacts \
  --acceptance-results release/evidence/v2.0.0.json \
  --release-images /absolute/release-artifacts/release-images.json \
  --security-summary /absolute/release-artifacts/security-gate-summary.json \
  --production-compose /absolute/release-artifacts/production-compose.json \
  --production-policy /absolute/release-artifacts/production-compose-policy.json \
  --deployment-images /absolute/release-artifacts/deployment-images.env \
  --runtime-identity /absolute/release-artifacts/runtime-version-identity.json \
  --runtime-acceptance /absolute/release-artifacts/release-runtime-acceptance.json \
  --candidate-validation-root /absolute/private-clean-candidate \
  --v1-source-provenance-proof /absolute/private-v1-source/v2-ac01-v1-source-provenance.json \
  --v1-source-provenance-summary-artifact /absolute/release-artifacts/acceptance/v2-ac01-v1-source-provenance-summary.json \
  --v1-operations-documentation-proof /absolute/private-v1-ac38/v1-ac38-operations-documentation-proof.json \
  --v1-operations-documentation-summary-artifact /absolute/release-artifacts/acceptance/v1-ac38-operations-documentation-summary.json \
  --v1-project-isolation-forbidden-terms /absolute/private-generator/forbidden-terms.txt \
  --v1-project-isolation-reference-repository /absolute/read-only/reference-repository \
  --v1-project-isolation-summary-artifact /absolute/release-artifacts/acceptance/v1-ac40-project-isolation-summary.json \
  --release-runtime-test-reports-directory /absolute/private-release-runtime-reports \
  --release-runtime-test-reports-summary-artifact /absolute/release-artifacts/acceptance/release-runtime-test-reports-summary.json \
  --migration-failure-evidence /absolute/private-ac07/v2-ac07-migration-failure.json \
  --migration-failure-ac40-evidence /absolute/private-ac40/v2-v1-upgrade-rehearsal.json \
  --migration-failure-artifact /absolute/release-artifacts/acceptance/v2-ac07-migration-failure.json \
  --v1-upgrade-evidence /absolute/private-ac40/v2-v1-upgrade-rehearsal.json \
  --v1-upgrade-artifact /absolute/release-artifacts/acceptance/v2-v1-upgrade-rehearsal.json \
  --ac40-dependency-seed /absolute/private-ac40/dependency-seed \
  --expected-ac40-dependency-seed-sha256 '<protected-aggregate-sha256>' \
  --ac40-dependency-seed-provenance /absolute/release-artifacts/acceptance/v2-ac40-dependency-seed-provenance.json \
  --redis-loss-evidence /absolute/private-ac41/v2-ac41-redis-loss.json \
  --redis-loss-artifact /absolute/release-artifacts/acceptance/v2-ac41-redis-loss.json \
  --mcp-crud-proof /absolute/private-mcp-proof/mcp-crud-runtime-proof.properties \
  --mcp-crud-summary-artifact /absolute/release-artifacts/acceptance/mcp-crud-runtime-proof-summary.json \
  --observability-baseline /absolute/release-artifacts/operational-metrics-baseline.json \
  --observability-runtime /absolute/release-artifacts/operational-metrics-runtime.json \
  --observability-summary-artifact /absolute/release-artifacts/acceptance/v2-observability-runtime-summary.json \
  --tooling-lifecycle-report /absolute/private-tooling/v2-tooling-lifecycle-runtime.json \
  --tooling-lifecycle-summary-artifact /absolute/release-artifacts/acceptance/v2-tooling-lifecycle-runtime-summary.json \
  --tooling-lifecycle-compose-project web-starter-tooling-123-1 \
  --jwks-rotation-evidence /absolute/private-ac26/v2-ac26-jwks-rotation.json \
  --jwks-rotation-summary-artifact /absolute/release-artifacts/acceptance/v2-ac26-jwks-rotation-summary.json \
  --jwks-rotation-compose-project web-starter-ac26-123-1 \
  --jwks-rotation-terminal-mode expiry \
  --mcp-tool-contract-proof /absolute/private-mcp-contract-proof/mcp-tool-contract-runtime-proof.properties \
  --mcp-tool-contract-summary-artifact /absolute/release-artifacts/acceptance/mcp-tool-contract-runtime-proof-summary.json \
  --mcp-governance-proof /absolute/private-mcp-governance-proof/mcp-governance-runtime-proof.properties \
  --mcp-governance-summary-artifact /absolute/release-artifacts/acceptance/mcp-governance-runtime-summary.json \
  --mcp-governance-compose-project web-starter-governance-123-1 \
  --generator-acceptance-bundle /absolute/private-generator/raw-bundle \
  --generator-forbidden-terms /absolute/private-generator/forbidden-terms.txt \
  --generator-acceptance-artifact /absolute/release-artifacts/acceptance/v2-generator-acceptance-summary.json \
  --production-fail-fast-evidence /absolute/private-ac29/v2-ac29-production-fail-fast.json \
  --production-fail-fast-artifact /absolute/release-artifacts/acceptance/v2-ac29-production-fail-fast.json \
  --tag v2.0.0 \
  --version 2.0.0 \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --output /absolute/release-artifacts/release-evidence.json
```

本地独立复核完整受控归档时使用同一个 commit、完整 Git tag 和证据目录；该目录还必须包含 `release-images.json` 所引用的受限原始 secret report。普通 Actions Artifact 故意不上传秘密命中上下文，因此只能核对已生成账本和公开校验和，不能单独重放完整安全门禁：

```bash
python3 -B scripts/release_evidence_gate.py verify \
  --repository-root . \
  --artifacts-root /absolute/release-artifacts \
  --manifest /absolute/release-artifacts/release-evidence.json \
  --candidate-validation-root /absolute/private-clean-candidate \
  --v1-source-provenance-proof /absolute/private-v1-source/v2-ac01-v1-source-provenance.json \
  --v1-operations-documentation-proof /absolute/private-v1-ac38/v1-ac38-operations-documentation-proof.json \
  --v1-project-isolation-forbidden-terms /absolute/private-generator/forbidden-terms.txt \
  --v1-project-isolation-reference-repository /absolute/read-only/reference-repository \
  --release-runtime-test-reports-directory /absolute/private-release-runtime-reports \
  --migration-failure-evidence /absolute/private-ac07/v2-ac07-migration-failure.json \
  --migration-failure-ac40-evidence /absolute/private-ac40/v2-v1-upgrade-rehearsal.json \
  --v1-upgrade-evidence /absolute/private-ac40/v2-v1-upgrade-rehearsal.json \
  --ac40-dependency-seed /absolute/private-ac40/dependency-seed \
  --expected-ac40-dependency-seed-sha256 '<protected-aggregate-sha256>' \
  --ac40-dependency-seed-provenance /absolute/release-artifacts/acceptance/v2-ac40-dependency-seed-provenance.json \
  --redis-loss-evidence /absolute/private-ac41/v2-ac41-redis-loss.json \
  --mcp-crud-proof /absolute/private-mcp-proof/mcp-crud-runtime-proof.properties \
  --observability-baseline /absolute/release-artifacts/operational-metrics-baseline.json \
  --observability-runtime /absolute/release-artifacts/operational-metrics-runtime.json \
  --tooling-lifecycle-report /absolute/private-tooling/v2-tooling-lifecycle-runtime.json \
  --tooling-lifecycle-compose-project web-starter-tooling-123-1 \
  --jwks-rotation-evidence /absolute/private-ac26/v2-ac26-jwks-rotation.json \
  --jwks-rotation-compose-project web-starter-ac26-123-1 \
  --jwks-rotation-terminal-mode expiry \
  --mcp-tool-contract-proof /absolute/private-mcp-contract-proof/mcp-tool-contract-runtime-proof.properties \
  --mcp-governance-proof /absolute/private-mcp-governance-proof/mcp-governance-runtime-proof.properties \
  --mcp-governance-compose-project web-starter-governance-123-1 \
  --generator-acceptance-bundle /absolute/private-generator/raw-bundle \
  --generator-forbidden-terms /absolute/private-generator/forbidden-terms.txt \
  --tag v2.0.0 \
  --version 2.0.0 \
  --commit 0123456789abcdef0123456789abcdef01234567
```

验证器会逐字节核验每个 `repo://` 与 `artifact://`；不可读取的仓库外引用没有任何例外通道。V2-AC-01 必须从同一 raw 双文件重新解析固定 V1 历史与当前候选 ancestry；V1 AC-40 必须在 `build` 和 `verify` 两次调用中对同一受保护禁用词与参考仓库重新扫描，并与 canonical 摘要完全一致。generator raw bundle 与同一禁用词必须在 clean candidate 上重放并逐字节匹配 canonical public summary；AC26 必须以相同 Compose 项目和终态重算 raw 双文件，AC07/V2-AC-40/AC41 也先在仓库外 `0700` 原始目录完成独立语义验证；AC07 direct validator、账本 `build` 与 `verify` 都必须同时取得 V2-AC-40 raw、私有 dependency seed 和受保护的外部 aggregate SHA-256，V2-AC-40 provenance receipt 也必须显式提供并与同次物理重扫得到的 seed 身份一致，manifest 仅改 path 或 hash 也会导致重算不一致；observability 必须从同次主栈运行的 baseline/runtime 指标报告重算授权、标签域、增量与结构化 Trace；MCP CRUD、MCP Tool contract 与 MCP governance summary 同样必须由各自 raw proof 重算且逐字节相同，其中 governance 还必须提供独立 Compose 项目并重核 app/Redis 运行身份。`verify` 仍需这些受控 raw 输入，因此只保留公开副本不能完整重放。Actions Artifact 当前只保留 90 天，且不含原始 secret report；正式发布必须把 `release-evidence.json`、`SHA256SUMS`、公开安全证据以及受严格访问控制的 V2-AC-01 raw、V1 AC-40 禁用词/参考仓库身份、AC26 raw、generator raw/禁用词、AC07/V2-AC-40/AC41 原始证据、V2-AC-40 dependency seed/外部锚来源、observability baseline/runtime、三份 MCP raw proof 和原始 secret report 同步到禁止覆盖、生命周期不短于发布镜像的受控归档。完成长期归档前，不能宣称具备长期可追溯、可重放的发布证据。V2-AC-01 的固定值、证据作用域和独立命令见 [冻结 V1 来源溯源证据](v1-source-provenance-evidence.md)，V2-AC-37 的固定观测面见[可观测性运行证据](observability-runtime-evidence.md)。

`releaseRuntimeTestReports` 的 `verify` 同样需要原始四文件目录，不能仅凭
公开 summary 重放。正式长期归档必须把这份 raw 与 V1 provenance、AC26、
generator、AC07/40/41、MCP proofs 和 secret reports 一样放入禁止覆盖且
生命周期不短于镜像的受控存储；它不属于公开上传清单。完整固定映射和
非目标见 [releaseRuntimeTestReports adapter](acceptance/release-runtime-test-reports.md)。

## High 漏洞例外

例外只允许写入 `security/high-vulnerability-exceptions.json`。空清单是默认状态；每条例外必须精确匹配：

- `image`：`app` 或 `nginx`；
- `vulnerabilityId`、`packageName` 和 `installedVersion`；
- 稳定的 `id`；
- 可追责的 `owner`；
- ISO 日期 `expiresOn`；当天有效，过期即阻断；
- 不少于 20 字符的具体风险接受原因。

Critical 和秘密不接受例外。未匹配当前扫描结果的例外也会阻断，防止过期决策长期滞留。修改例外属于安全评审变更，不能由发布工作流自动生成，也不能把 owner 写成占位值。

## 生产 Compose 策略

`compose.production.yaml` 是独立文件，不继承含 `build` 的本地开发 Compose。所有服务镜像必须是 `repository@sha256:<64-hex>`；App 和两个 Nginx 还强制：

- 服务集合固定为 `mysql`、`redis`、`app`、`nginx`、`mcp-public-nginx`；不得追加调试、代理或运维 Sidecar；
- 顶层、逐服务和环境变量均采用允许列表；未知 `logging`、`labels`、运行参数或 `JAVA_TOOL_OPTIONS` 等注入即失败，避免把日志外送、运行时代理或未评审设置藏进展开后的模型；
- 网络固定为 `app` 与 `internal:true` 的 `data`：MySQL/Redis 只能加入 `data`，两个 Nginx 只能加入 `app`，只有 App 同时加入两者；
- 显式数字非 root UID/GID；
- 只读根文件系统；
- `no-new-privileges:true`；
- `cap_drop: ALL` 且不增加 capability；
- 只有带大小、`noexec`、`nosuid`、`nodev` 的 `/tmp` tmpfs；
- 禁止设备/GPU、host user/cgroup/IPC/PID/network namespace、`unconfined` 或其他未批准的 `security_opt`、`volumes_from`、Compose config/secret、生命周期命令钩子，以及 `/tmp` 以外的显式或隐式 tmpfs；
- 主命令、Entrypoint 和健康探针采用逐服务白名单；除安全引用 MySQL 密码的固定探针外拒绝 Shell，避免通过命令覆写绕过已扫描镜像；
- 挂载使用逐服务目标白名单：MySQL/Redis 命名数据卷和公网 Nginx 恰好两个只读 TLS 文件；TLS bind 强制 `create_host_path:false`，Docker Socket 与其他挂载即使只读也拒绝；
- CPU、内存和 PID 上限；
- App、MySQL 和 Redis 不直接发布端口；
- App 必须注入专用运维用户名和至少 32 字符的运维密码；这些凭据不得出现在其他服务环境中；
- 私有 Nginx 只允许显式绑定 loopback、RFC1918 或 IPv6 ULA 地址，默认 `127.0.0.1`，拒绝空值、`0.0.0.0`、`::`、主机名和公网 IP；
- 公网 Nginx 使用镜像内的固定 public-only 配置，TLS 挂载只读。

CI 先运行 `docker compose config --format json` 展开全部变量，再由 `production_compose_policy.py` 检查实际模型。该过程不启动容器：

```bash
docker compose --env-file /absolute/validation.env \
  -f compose.production.yaml config --format json \
  > /tmp/web-starter-production-compose.json
python3 scripts/production_compose_policy.py \
  --compose-json /tmp/web-starter-production-compose.json
```

`validation.env` 必须只放格式合法、无实际权限的验证占位值。展开后的 JSON 包含所有环境变量值，不得使用生产 Secret 生成后归档，也不得把该文件上传为普通 CI Artifact；策略摘要只绑定其 SHA-256 和 PASS/FAIL 结果。

策略单元测试不需要 Docker：

```bash
python3 -B -m unittest discover -s scripts -p 'test_*.py'
```

## 证据边界

仓库当前可静态证明策略脚本会拒绝可变镜像、现场 build、拓扑/命令/端口/挂载漂移、root/可写/提权容器、Critical、无责任人或过期的 High 例外、秘密命中以及报告 digest 漂移。只有发布工作流真实构建并扫描 Registry 中的 App/Nginx 目标 digest 后，才能把 AC-43 记录为这两个仓库构建镜像的运行证据；这不包含 MySQL/Redis 的供应链证明。只有不可变镜像在目标 Compose 中实际启动并检查容器身份、最终命令、网络、端口、挂载、capability、namespace 和资源限制后，才能形成 AC-44 的运行证据。静态策略不能证明宿主内核或容器运行时实际执行了这些隔离项；两者也都不能替代第三方镜像审批、浏览器、OAuth、MCP、迁移和恢复验收。

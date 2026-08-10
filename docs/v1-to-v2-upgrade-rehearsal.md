# V1 → V2 升级与恢复演练入口

`scripts/rehearse_v1_to_v2_upgrade.py` 是 V1 → V2 升级演练的固定入口。它绑定：

- 注释 tag `v1.0.0`；
- commit `5ebdb238650d182c17e1493adf47aaa3324f19cb`；
- V1 Flyway V1–V3 的逐字节内容；
- `security/v2-v1-upgrade-rehearsal.schema.json` 的 exact check set；
- 唯一的随机 `web-starter-ac40-<12 hex>` Compose 项目、随机源库和只允许新建的恢复库；
- 只绑定到 `127.0.0.1` 的三个随机端口。

顶层、阶段和检查只允许 `PASS`、`FAIL`、`NOT_COVERED`、`ENV_REQUIRED`。只有 exact check set 全部为 `PASS`、精确资源清理通过且私密 runtime 已删除时返回 `0`；行为失败返回 `1`；未覆盖或缺少环境返回 `6`；参数或安全输入错误返回 `2`。`--preflight-only` 即使所有预检成功也固定不能成为升级通过证据。

## V1 tag 与当前 adapter 的边界

固定 V1 tag 的 `scripts/` 只有：

- `scripts/repository_policy.py`
- `scripts/test_repository_policy.py`

它不包含 `prepare_release_runtime_acceptance.py`、恢复脚本或 OAuth runtime verifier。演练使用的是**当前 V2 候选 commit 的 release adapter 快照**：正式运行要求 HEAD 和 tree 为 40 位 Git 对象、HEAD 继承 V1、工作树无修改和未跟踪文件、索引无 `assume-unchanged`/`skip-worktree`；随后从该 commit 逐字节复制 adapter、证据校验器和运行时源码到私密目录并记录 SHA-256。工作区文件与 commit 任一字节不同时，在启动 Docker 前失败。adapter 以绝对脚本路径执行，并明确设置：

```text
PYTHONPATH=<private-snapshot>/scripts:<private-snapshot>
<absolute-python> -B <private-snapshot>/scripts/prepare_release_runtime_acceptance.py ...
```

禁止使用 `python -m scripts.prepare_release_runtime_acceptance`。第八次手工演练就是因为包模块解析到了工作区的 `scripts`，而同目录顶层导入 `acceptance_network` 不可见，导致任何请求发出前失败。固定入口会先运行每个 adapter 的 `--help` 导入预检，且 V1 tag 脚本清单不是上述两个文件时立即失败。

## PKCS#8 与第六、七次缺陷

V1 代码使用 `PKCS8EncodedKeySpec`。固定入口用以下可移植流程生成并预检 V1 私钥：

1. `openssl genpkey` 生成临时 PEM；
2. `openssl pkcs8 -topk8 -nocrypt -outform DER` 生成传给 V1 的 PKCS#8 DER；
3. `openssl pkcs8 -inform DER -nocrypt` 解码；
4. 解码结果必须以 `BEGIN PRIVATE KEY` 开头；
5. 从 X.509 DER 公钥计算与 V1 Java 实现相同的 SHA-256/Base64URL `kid`。

升级用 JWK Set 会把 V1 公钥作为只读 retiring key，并显式设置 `exp`：从生成时刻起覆盖 V1 的两小时 access-token TTL，再增加 15 分钟时钟余量。演练会同时校验适配器参数和生成文档中的 `exp`，防止 JWK Set 工具接口演进后静默丢失旧令牌验证窗口。

不会调用 `openssl pkey -check`。LibreSSL 不支持该选项并会把 `check` 当成 cipher 名，第七次手工演练因此在应用启动前失败。转换成 V2 JWK Set 所需的 PKCS#1 仅用于私密 runtime；V1 应用环境始终得到 PKCS#8 DER。

## 固定阶段和真实证据

状态机顺序固定为：

1. `source-freeze`
2. `cryptographic-preflight`
3. `runtime-preflight`
4. `v1-fixtures`
5. `backup-restore`
6. `v2-migration`
7. `credential-compatibility`
8. `runtime-acceptance`
9. `lifecycle-readback`
10. `cleanup`

后续阶段不能越过前一阶段。一个检查第一次被观察后不可改写，即使第一次状态是 `NOT_COVERED`。演练不会读取外部“PASS”JSON，也不支持操作者注入任意 hook 命令。

浏览器验收通过 `http://localhost:<随机端口>` 访问只绑定回环地址的私有 Nginx，以使用浏览器对本机开发地址的 Secure Cookie 特例；不得改用数值型 HTTP 回环地址，也不得把生产 Cookie 降级为非 Secure。该本机特例只服务于隔离演练，不代表正式部署入口：目标环境的私有管理端仍必须由组织内受信 HTTPS 入口承载并单独验收。

当前 release adapter 会创建 V1 Project、PAT、OAuth client 和 client-credentials access token。固定入口另外通过 V1 已存在的 `/api/security/service-accounts/{id}/tokens` 明确签发一个服务账号长期令牌，并签发一个专供最终吊销验证的 PAT；两份明文都只进入 0600 私密文件。V2 必须实际验证旧服务令牌；最终阶段会吊销专用 PAT、禁用服务账号，分别证明旧令牌返回 401，并从管理 API 读回 PAT 的 `revokedAt` 和服务账号的 `enabled=false`。

固定入口现在会使用已登录且只含内存 CookieJar 的 opener，在 V1 真实执行 Authorization Code + PKCE S256。30x 回调绝不跟随；authorization code、state 和 verifier 只存在于调用栈，既不写文件也不进入日志。私密 0600 文件只保存 client ID、redirect URI、access token 和 refresh token。V1 阶段同时要求：

- 实际 JWT 的 `kid`、`alg`、issuer、audience、scope、`exp` 和 `expires_in` 一致；
- 官方 MCP SDK 使用 A0 通过 V1 公共入口；
- `oauth2_authorization` 只保存 `hmac$<SHA-256>`，refresh family/history 保存同一 HMAC 的 generation 0；
- family/history 未吊销、未消费且剩余有效期不少于 30 分钟。

升级后，入口先用升级前 client-credentials access token完成第一笔 V2 外部调用，再要求 A0 通过 V2 公共入口、R0 只提交一次并轮换为 A1/R1、A0 因 latest-only 策略返回 401、A1 通过官方 SDK。随后只重放一次 R0并要求 `invalid_grant`，再要求 R1也为 `invalid_grant`、A0/A1 均为 401、authorization 被删除、family/history 以 `REFRESH_TOKEN_REUSE` 整族吊销、两个 access JTI 均已吊销。只有上述 HTTP、SDK 和数据库读回全部成立时，才记录：

```text
PASS / V1_REFRESH_ROTATION_REUSE_PASS
```

若运行在签发或验证前停止，该检查保持 `NOT_COVERED`；网络结果不明确时固定失败且不得重试一次性 code、R0 或 replay 请求。

代码里写有完整 Docker 适配不等于已经通过演练。在新的正式运行产出 schema 与独立语义校验均合法的完整证据之前，V2-AC-04/05/06/39/40 仍按实际检查状态报告。

## 独立证据门禁

正式使用证据时必须通过文件级校验入口，并启用 `--require-pass`：

```bash
python3 -B scripts/validate_v1_upgrade_evidence.py \
  --document /absolute/private/evidence-directory/v1-to-v2-upgrade.json \
  --repository-root /absolute/path/to/clean/web-starter \
  --dependency-seed /absolute/private/ac40-dependency-seed \
  --expected-dependency-seed-sha256 <protected-canonical-aggregate-sha256> \
  --require-pass
```

任何顶层 `PASS` 都会被重新绑定到 `--repository-root` 指定的当前 Git 候选：`source.v2Commit` 必须等于 `HEAD`，`source.v2Tree` 必须等于 `HEAD^{tree}`，索引不得有 `skip-worktree`、`assume-unchanged` 或非正常条目，工作树不得有已跟踪或未跟踪变化。校验器会从该 commit 读取并逐字节重算演练工具、schema、adapter 快照和 runtime source 的全部 SHA-256，同时要求工作区文件与 commit blob 完全一致。声明内部彼此一致但不匹配 Git 对象/真实字节的伪造证据会失败。这个过程只执行只读 Git 查询，不运行 Docker。

不加 `--require-pass` 时，语义合法的 `NOT_COVERED`、`ENV_REQUIRED` 或 `FAIL` 文档仍以校验器进程码 `0` 表示“文档合法”，不能作为放行门禁；加上后分别按证据状态返回非零。生产器私密快照调用的 `validate_document(document)` 仅负责结构与交叉字段语义检查，以便在证据写出前自检；它不替代上述文件级 Git 候选绑定。

## 离线依赖种子

`--dependency-seed` 是必填参数。它只服务于 AC40 内的 Maven 官方 SDK 测试、pnpm 安装和 Playwright Chromium，不替代 Docker 镜像构建依赖。种子必须位于仓库外，根目录及全部真实子目录为当前用户所有的 `0700`，`manifest.json` 为 `0600`；普通文件必须仅有 owner 权限且至少 owner 可读。Maven、Corepack、pnpm 组件中的符号链接一律拒绝；只有 `playwright-browsers` 可保留 Chromium/Framework 自带的相对符号链接，且每条链接都必须非悬空、非循环，解析后仍位于该组件内部。所有硬链接、特殊文件、`.lastUpdated`、`.part`、`.partial`、`.tmp`、`.lock`、`.download`、`.aria2` 以及 Maven 仓库中的 `dev/webstarter` 本地构件都会被拒绝。

顶层布局固定为：

```text
dependency-seed/
├── manifest.json
├── maven-home/
├── maven-repository/
├── corepack-home/
├── pnpm-store/
└── playwright-browsers/
```

manifest 固定绑定当前候选执行 `web-starter-mcp -am` 时进入 reactor 的全部 POM（根项目、core、system、security、project、mcp）、Maven Wrapper properties 与脚本、前端 package/lockfile、Playwright 配置，以及当前 `platform`/`architecture`。版本固定为 Maven 3.9.15、pnpm 9.15.9、Playwright 1.61.1 和 Chromium revision 1228；每个组件记录 `path`、确定性 `treeSha256`、`fileCount` 和 `byteCount`。入口会重新计算这些值，再把五个组件逐项复制到本次 `0700` 私密 runtime 并重新计算摘要。源种子随后不再参与执行，也不会把绝对路径写入公开证据。

Maven Wrapper home 必须已经含有当前 `distributionUrl` 对应的完整可执行分发目录；Maven repository 必须已有所需第三方 POM/JAR，且不含本项目安装产物。`corepack-home/v1/pnpm/9.15.9/package.json` 必须声明 `9.15.9`，pnpm v3 store 必须已有内容，Playwright cache 必须含 `chromium-1228/INSTALLATION_COMPLETE` 和可执行 Chromium。运行时所有 Maven 命令都带 `--offline`，pnpm 固定 `--frozen-lockfile --ignore-scripts --offline` 并设置 `COREPACK_ENABLE_NETWORK=0`；入口不执行 `playwright install`，也不对依赖失败重试。种子缺件会直接失败，绝不会切换到用户目录缓存或联网补齐。

正式种子只能通过仓库内的构建器从五个显式缓存目录生成。构建器会把权限规范化为私有模式，排除 Maven `dev/webstarter` 本地产物、非 pnpm 9 使用的 store 代际、非 9.15.9 的 Corepack pnpm 包以及 Playwright 仅用于垃圾回收且含本机绝对路径的 `.links`，然后先用 producer 校验物理种子，再生成只有一个 `dependency-seed/` 根的确定性 tar 和 `0600` receipt：

```bash
python3 -B scripts/build_v1_upgrade_dependency_seed.py build \
  --repository-root /absolute/path/to/clean-candidate \
  --maven-home /absolute/cache/maven-home \
  --maven-repository /absolute/cache/maven-repository \
  --corepack-home /absolute/cache/corepack-home \
  --pnpm-store-root /absolute/cache/pnpm-store \
  --playwright-browsers /absolute/cache/playwright-browsers \
  --seed-output /absolute/private/dependency-seed \
  --archive-output /absolute/private/web-starter-ac40-dependency-seed-linux-x86_64.tar \
  --receipt-output /absolute/private/dependency-seed-receipt.json
```

接收端在解包前必须同时拿到受保护的 tar SHA-256 和 canonical aggregate SHA-256。`extract-verify` 先验证原始 archive 字节，再逐成员拒绝路径穿越、额外根、隐式父目录、链接祖先写入、硬链接和特殊文件，最后对解包后的物理种子重跑 producer 校验；它不会调用通用 `tar.extract*`：

```bash
python3 -B scripts/build_v1_upgrade_dependency_seed.py extract-verify \
  --repository-root /absolute/path/to/clean-candidate \
  --archive /absolute/private/web-starter-ac40-dependency-seed-linux-x86_64.tar \
  --expected-archive-sha256 <protected-archive-sha256> \
  --expected-aggregate-sha256 <protected-canonical-aggregate-sha256> \
  --seed-output /absolute/private/materialized-dependency-seed \
  --receipt-output /absolute/private/materialized-receipt.json
```

本地演练仍通过 `--dependency-seed /absolute/path` 显式传入仓库外目录，但发布工作流**不假设 GitHub 托管 runner 预置任何绝对路径**。CI 只接受在同一仓库中预先生成、审核并上传的 Linux/x86_64 原始 tar Artifact，下载位置固定为 `${RUNNER_TEMP}`。本机 Darwin/arm64 或 Darwin/x86_64 种子不能提供给 CI：manifest 的 `platform`/`architecture`、Playwright Chromium 二进制和可能存在的原生依赖都不匹配，不能通过复制或改写 manifest 复用；必须在受控 Linux/x86_64 环境重新构建完整种子。

CI 管理员不再维护四个 Repository Variables。正式发布前，先在同一仓库手动运行
`.github/workflows/build-ac40-dependency-seed.yml`，并使运行分支选择器和 `version`
输入同时指向同一个已存在的注释语义版本 tag。该 producer 必须经过受保护的
`release` Environment 审批；完成后从 job summary 取得由工作流生成的 canonical
anchor bundle。

四个锚只允许作为 `release` Environment Secret
`WEB_STARTER_AC40_DEPENDENCY_SEED_ANCHORS` 的一个 UTF-8 单行 canonical JSON 值整体维护：

```json
{"aggregateSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","archiveSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","artifactId":123456789,"workflowRunId":987654321}
```

示例值不能用于发布。字段只能且必须为按字典序排列的 `aggregateSha256`、
`archiveSha256`、`artifactId`、`workflowRunId`，不得有空白、换行、重复键或额外键；
两个 ID 必须是正整数，两个摘要必须是 64 位小写 SHA-256。同名 Repository Secret、
Organization Secret 和旧的四个 Repository Variables 都不得配置或继续使用。
其中 Artifact ID 必须是 GitHub 分配的不可变 ID，禁止以名称或“latest”查找；run ID
必须绑定上传该 Artifact 的固定 workflow run；archive 摘要必须同时等于 Artifact REST
元数据、下载字节重算和 builder receipt；aggregate 摘要由 producer 与独立 validator
根据已验证 manifest/layout、平台、版本、当前候选源码和五个组件实际内容重算，不能用
tar 摘要代替。完整管理员配置、审批顺序与字段约束以
[`supply-chain.md`](./supply-chain.md#release-environment-管理员配置) 为准。

Artifact 文件名固定为 `web-starter-ac40-dependency-seed-linux-x86_64.tar`，内部只能有一个 `dependency-seed/` 根。为保留 `0700` 目录、owner-only 文件权限以及 `playwright-browsers` 内受允许的相对符号链接，上传端应直接归档该目录，禁止先解引用链接；再通过 `actions/upload-artifact@v7` 的 `archive: false` 上传这一单文件。普通 ZIP Artifact 会把目录/文件权限归一化，也不能可靠表达这组链接，因此不能作为本种子的发布输入。发布工作流使用固定 commit 的 `actions/download-artifact` v8.0.1 按 Artifact ID 和 run ID 下载，并显式采用 `digest-mismatch: error`；下载前还会通过 GitHub REST API 核对仓库、ID、run ID、固定文件名、过期状态和 digest。安全解包会拒绝其他组件的符号链接、全部硬链接/特殊文件、逃逸或循环链接，以及通过链接祖先写入的 tar 成员。GitHub 官方说明见 [download-artifact 的不可变 ID、跨 workflow run 和权限保持说明](https://github.com/actions/download-artifact/tree/3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c) 与 [Actions Artifact REST API](https://docs.github.com/en/rest/actions/artifacts?apiVersion=2026-03-10#get-an-artifact)。

该 Environment Secret 共同承载发布输入信任锚，只能由受控管理员在审核 producer
结果后整体更新；更新后必须重新触发 Environment 审批。Artifact 过期、bundle
缺失或非 canonical、任一字段错误、下载字节漂移、安全解包失败、平台不匹配或
canonical aggregate 不一致都会在启动 AC40 容器前失败；发布工作流不会自行从公网
生成、补依赖或回退到 runner/user cache。

## 资源和秘密边界

- 私密 runtime 目录为 0700；密码、Cookie、Token、Client Secret、OAuth 私钥和证据文件保持 0600，PKCE code/verifier/state 不持久化。只有给固定 uid 101 Nginx 只读挂载的临时 TLS bind 副本为 0644，且始终直接位于该 0700 目录内、不打印、不上传并在结束时删除。
- 对外证据只含状态、稳定 detail code、数量和 SHA-256；保存前做 secret-shaped 扫描。
- Container、Volume、Network 必须同时带 `dev.webstarter.upgrade=v1-to-v2`、随机 run label 和 Compose project label，删除前逐个 inspect。
- V1 和 V2 App/Nginx 构建镜像都必须带 owner/run/role 三个镜像 label；V2 镜像还必须带等于冻结候选 commit 的 OCI revision。
- V2 App/Nginx 不接受外部预构建镜像。入口从冻结候选 commit 的完整 Git archive 各构建一次，记录不可变 image ID，并要求私网和公网入口共同使用这两个 ID。
- 外部提供的 MySQL/Redis 镜像拒绝裸 `sha256:<id>`，只建立随机临时 alias。启动后逐个校验 V1/V2 五个服务的实际容器 image ID；删除 alias 前后都必须证明原始命名引用仍解析为同一 ID。
- 不调用 `docker compose down --volumes`、`docker system prune`、宽泛 volume 删除或数据库删除。
- `EXACT_OWNED_CLEANUP` 只覆盖本次 run 可精确归属的 Container、Volume、Network、临时 image tag 和 owner/run/role 标记镜像。Docker daemon 的共享 BuildKit 缓存不具备可靠的逐 run ownership，属于受信运行时缓存且不计入该断言；入口不会为追求“干净”而宽泛 prune 用户缓存。
- 私密目录只在 sentinel 的 owner/run ID 完全匹配时递归删除。

## 调用形态

下面只是调用格式，不是已经执行或通过的证据。MySQL/Redis 两个命名镜像引用必须已存在于本地；V2 App/Nginx 由入口从冻结候选 commit 构建。四次 `docker build` 使用 `--pull=false`，不会强制刷新本地已有的基础镜像，但缺少 `FROM` 镜像时 Docker 仍可能拉取；Dockerfile 内的构建步骤也可能访问软件源，因此该入口不是完整的离线镜像构建门禁。`--dependency-seed` 只保证 SDK、pnpm 和浏览器验收阶段不下载依赖。历史 V1 Dockerfile 使用可变基础镜像标签，所以这次重建只证明固定 V1 源码在本次所记录 image ID 上的升级兼容行为，不声称逐字节复现曾发布的 V1 镜像，也不替代 V2 供应链 digest/SBOM 门禁：

```bash
python3 -B scripts/rehearse_v1_to_v2_upgrade.py \
  --output-dir /absolute/private/empty/evidence-directory \
  --dependency-seed /absolute/private/ac40-dependency-seed \
  --expected-dependency-seed-sha256 <protected-canonical-aggregate-sha256> \
  --mysql-image mysql:8.4 \
  --redis-image redis:7.4-alpine
```

只验证固定 preflight（仍会从冻结源码构建并精确清理本次 V1/V2 镜像及 MySQL/Redis 临时 alias）：

```bash
python3 -B scripts/rehearse_v1_to_v2_upgrade.py \
  --preflight-only \
  --output-dir /absolute/private/empty/evidence-directory \
  --dependency-seed /absolute/private/ac40-dependency-seed \
  --expected-dependency-seed-sha256 <protected-canonical-aggregate-sha256> \
  --mysql-image mysql:8.4 \
  --redis-image redis:7.4-alpine
```

无 Docker 回归入口是：

```bash
python3 -B -m unittest discover -s scripts -p 'test*.py'
```

它证明入口、状态机、命令构造、导入边界、PKCS#8 计划、Git/镜像绑定、资源 ownership、PKCE/refresh 协议防护、证据语义和退出码策略；不证明真实 MySQL、Redis、浏览器、OAuth 或 MCP 升级成功。

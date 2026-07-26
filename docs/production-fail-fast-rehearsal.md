# V2-AC-29 生产配置 fail-fast 正式重演

V2-AC-29 由两个职责分离的脚本组成：

- `scripts/rehearse_production_fail_fast.py` 运行隔离容器，只写入脱敏观测；
- `scripts/validate_production_fail_fast_evidence.py` 不调用 Docker，从 Git 对象、调用方提供的镜像身份和脱敏计数独立重算结论。

producer 的 `"status":"PASS"` 不是正式通过。只有 validator 带 `--require-pass` 成功退出，才可以把该产物作为 AC29 的候选正式证据。

## 正式候选前置条件

producer 和 validator 都会 fail closed 地检查：

1. `--repository-root` 是精确 Git worktree 根目录；
2. `HEAD`、tree 和 `v<version>` 注释 tag 指向同一 commit；轻量 tag 不被接受；
3. 根 Maven、`web-starter-admin` 父版本和前端版本完全相同，且不是 `SNAPSHOT`；
4. worktree 包括 untracked 文件在内完全干净；所有 tracked entry 必须是普通 `H` 状态，`skip-worktree`、`assume-unchanged` 和异常 index 状态都会失败；
5. producer、validator、JSON Schema、生产配置 Validator/Initializer、启动 wiring、根和 Admin POM、前端版本清单、`application.yml` 与 Dockerfile 都是该 commit 的普通 blob，workspace 字节与 committed blob 完全一致；
6. App 必须由调用方以 `repository@sha256:<manifest>` 提供。producer 将它解析为本地不可变 image ID，要求 RepoDigest 精确匹配，并核对 OCI `version`/`revision` 与候选版本/commit；
7. 输出目录位于仓库外，目录权限恰好为 `0700`，开始时为空且不是符号链接。

当前 dirty worktree 或 `2.0.0-SNAPSHOT` 只能做开发期单元测试，不能生成正式 PASS。

## 隔离与秘密边界

每个容器固定使用以下约束：

- `docker run --rm --pull never --network none`；
- Docker logging driver 固定为 `none`，原始 stdout/stderr 只经 attach stream 进入 producer 内存；
- 只读根文件系统、drop all capabilities、`no-new-privileges`；
- 不发布端口、不使用 host bind 或 named volume；仅创建受限 `/tmp` tmpfs；
- 始终以解析后的 immutable image ID 运行，而不是 tag；
- 容器名只能是本次随机 `web-starter-ac29-*` 名称，并同时带 AC29 owner 和 run ID 标签；
- 清理只定位精确名称，发现容器后必须同时核对 64 位 container ID、精确 Docker name 和两个 owner 标签，再按 immutable container ID 删除并确认零残留；正常 `--rm` 已清理和显式 owned cleanup 分别计数。

OpenSSL 通过 stdin/stdout 内存管道生成和转换 3072-bit RSA 材料，不创建私钥 fixture 文件。密码、Pepper、RSA、原始环境、fixture 和原始应用日志不会进入证据目录。Docker 命令只写 `--env KEY`，值从子进程环境注入；证据只保留日志字节数、SHA-256、脱敏计数和不含值的命令契约哈希。日志一旦包含任一本次 fixture literal，producer 立即安全失败，也不会指出或回显泄漏值。

## 精确验收语义

固定 15 个危险配置按顺序运行：HTTP Issuer、localhost Issuer、HTTP Audience、非 Secure Cookie、允许开发 RSA、空秘密、占位秘密、缺失 RSA、宽泛 Host、本机 Host、宽泛 Origin、HTTP Origin、危险日志级别、运维用户名复用和运维密码复用。

每个危险用例必须满足：

1. 超时前非零退出；
2. 该用例的完整 `Unsafe production configuration: ...` 消息恰好出现一次；
3. 拒绝消息之前 Tomcat、Flyway、Hikari 和数据库连接 marker 均为零；
4. changed environment key、expected rejection hash、命令哈希、checks、failures 和 status 能由 validator 精确重建。

hardened networkless control 必须通过生产安全策略，不能出现任何 `Unsafe production configuration`，随后必须出现明确的数据库连接失败 marker 并非零退出。仅看到 Flyway/Hikari 启动字样不足以通过。

另有一个使用同一 immutable image ID 的 networkless Java probe：它覆盖相同的只读、无端口、无挂载和 owned cleanup 约束，以 `java -XshowSettings:properties -version` 读取脱敏身份。`java.specification.version` 和 `java.runtime.version` 都必须是 Java 21，vendor/runtime 字符串还必须通过严格安全字符检查。

## 执行

先由发布流程或操作者冻结调用方信任的 digest reference 和本地 image ID。不要从证据文件反向复制这两个参数：

```bash
APP_REFERENCE='registry.example.invalid/web-starter-app@sha256:<64-lowercase-hex>'
APP_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$APP_REFERENCE")"
AC29_OUTPUT="$(mktemp -d /private/tmp/web-starter-ac29-evidence.XXXXXX)"
chmod 700 "$AC29_OUTPUT"
```

在 clean、注释 tag 对应的 release candidate 上运行 producer：

```bash
python3 scripts/rehearse_production_fail_fast.py \
  --repository-root "$PWD" \
  --image "$APP_REFERENCE" \
  --output-dir "$AC29_OUTPUT" \
  --timeout-seconds 60
```

然后独立复核同一目录：

```bash
python3 scripts/validate_production_fail_fast_evidence.py \
  --repository-root "$PWD" \
  --evidence "$AC29_OUTPUT/v2-ac29-production-fail-fast.json" \
  --expected-app-reference "$APP_REFERENCE" \
  --expected-app-image-id "$APP_IMAGE_ID" \
  --require-pass
```

validator 的两个 expected image 参数都是必填项。它不会信任 artifact 自己声明的 reference 或 image ID。

## 公开证据与防伪检查

输出目录必须且只能包含两个 `0600` 普通文件：

- `v2-ac29-production-fail-fast.json`；
- `v2-ac29-production-fail-fast.json.sha256`。

validator 会验证 sibling checksum 的精确单行格式，拒绝 duplicate JSON key、NaN/Infinity、secret-shaped 内容、额外文件、符号链接、权限漂移和超过 2 MiB 的文件。验证前后会比较 report/checksum 的 device、inode、size、mtime、mode、hash 和字节，并在语义复核后再次完整验证 Git candidate/source/tag，从而拒绝证据或源码的中途替换。

即使攻击者同步更新 JSON 和 checksum，伪造 checks/status、候选 HEAD/tree/tag、source hash、OCI version/revision、image reference/ID、Java 21 身份、隔离命令或 cleanup 计数，仍会被独立语义重算拒绝。

## 退出码

- producer：`0` 表示形成了全部运行观测为 PASS 的脱敏报告；`1` 表示形成了语义为 FAIL 的脱敏报告；`2` 表示候选、镜像、路径、依赖、秘密泄漏或 Docker ownership 等安全前置条件失败。
- validator：`0` 表示独立验证为 PASS；`1` 表示产物结构有效但独立结论为 FAIL，或 `--require-pass` 未满足；`2` 表示产物、候选或调用方期望绑定无效。

## 发布接线边界

release workflow 在 `${RUNNER_TEMP}` 创建独立 `0700` raw evidence 目录和指向 release commit/tag 的 detached、clean candidate worktree。主 checkout 中的构建、扫描和 `artifacts` 输出不能参与候选绑定。主全栈启动后，runner 先用真实运行容器生成并验证 `runtime-version-identity.json`，再从该受控报告取得 App digest reference 和 image ID；producer 与 validator 都从 candidate worktree 执行，validator 固定带 `--require-pass`，不会从 AC29 artifact 反向信任镜像身份。

raw report 与 sibling checksum 必须一直留在 `${RUNNER_TEMP}` 的 `0700` 目录中，两个文件均为 `0600`，且不会列入 Actions Artifact。验证成功后，runner 使用 `O_EXCL` 创建 `artifacts/acceptance/v2-ac29-production-fail-fast.json` 的 `0600` byte-identical 公开副本；release evidence gate 的 `build` 和 `verify` 都接收 raw report，`build` 还接收公开副本，并以同一份运行身份中的 App reference/image ID 重新调用独立 validator。单纯的 `{"status":"PASS"}`、内容哈希匹配或可变 image tag 都不能形成通过语义。

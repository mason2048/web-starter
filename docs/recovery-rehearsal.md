# V2 备份、恢复与 Redis 丢失演练

本文定义 V2-AC-40 与 V2-AC-41 的仓库级执行入口和证据边界。脚本不会删除数据库、Docker 卷或 Compose 项目，也不会默认覆盖现有数据库。

> 当前仓库只证明脚本契约和静态安全检查通过。只有在隔离 Compose 项目中实际执行对应流程并保存报告，才能产生运行证据；未执行的真实登录、OAuth、MCP 或浏览器步骤不得标为 `PASS`。

## 1. 工具与安全边界

| 工具 | 作用 | 强制护栏 |
|---|---|---|
| `scripts/recovery_backup.py` | 产生一致的 MySQL 逻辑备份包 | 输出必须在 Git 工作区之外；默认要求 `app` 已停止；数据库名必须与容器内 `MYSQL_DATABASE` 完全一致 |
| `scripts/recovery_restore.py` | 校验备份包并导入新数据库 | 只接受 `web-starter-ac40-*` 隔离项目及其自有 MySQL 具名卷；目标名只能是 `<源库>_restore_<suffix>`；已存在即拒绝；没有覆盖或强制选项；导入账号仅有新库权限 |
| `scripts/rehearse_redis_loss.py` | 执行 V2-AC-41 | 项目名必须是 `web-starter-ac41-*`；MySQL/Redis 必须使用该项目拥有的具名卷；URL 必须是该项目私有 Nginx 的回环端口；只执行选定 Redis DB 的 `FLUSHDB` |

脚本需要 Python 3、Docker Engine 和 Docker Compose v2。凭据由 Compose 容器环境读取；AC-41 的 Web 登录账号只通过以下进程环境变量传入：

```bash
export WEB_STARTER_REHEARSAL_USERNAME='isolated-rehearsal-admin'
export WEB_STARTER_REHEARSAL_PASSWORD='set-outside-the-repository'
```

不要把变量值写入命令行、演练报告或仓库。备份 SQL 本身包含业务数据和凭据哈希，必须按秘密数据存储、加密和授权访问。

## 2. V2-AC-40 备份包

### 2.1 建立一致性边界

AC-40 的行数清单必须与 SQL 处于同一个无写入窗口。脚本不会擅自停止服务；先由操作者停止所有应用写入者，并确认 MySQL 仍在运行。`--confirm-no-external-writers` 是操作者对该隔离环境的显式确认，而不是脚本仅凭容器状态做出的推断：

```bash
export WEB_STARTER_DRILL_PROJECT='web-starter-ac40-20260719a'
docker compose --project-name "$WEB_STARTER_DRILL_PROJECT" \
  -f compose.yaml -f compose.dev.yaml stop nginx app
docker compose --project-name "$WEB_STARTER_DRILL_PROJECT" \
  -f compose.yaml -f compose.dev.yaml ps
```

`--allow-live-source` 只适合明确接受行数竞态的日常逻辑备份。该模式会在清单中写入 `ac40Eligible=false`，不能作为 AC-40 通过证据。

### 2.2 创建备份

输出目录必须在仓库外并位于受控存储。版本参数应使用与运行镜像绑定的不可变发布版本或候选版本：

```bash
python3 scripts/recovery_backup.py \
  --compose-project "$WEB_STARTER_DRILL_PROJECT" \
  --compose-file compose.yaml \
  --compose-file compose.dev.yaml \
  --expected-database web_starter \
  --release-version 2.0.0-rc.1 \
  --confirm-no-external-writers \
  --output-dir /secure-backups/web-starter
```

成功后产生权限为 `0700/0600` 的独立目录：

```text
web-starter-backup-<UTC>-<random>/
├── database.sql
├── database.sql.sha256
├── flyway-history.tsv
├── critical-row-counts.tsv
├── manifest.json
└── manifest.json.sha256
```

`manifest.json` 绑定应用版本、镜像标识、Git commit/工作区状态、源 Compose 项目、源数据库、一致性模式、SQL 字节数和三个清单文件的 SHA-256。工具先从 `flyway-history.tsv` 识别当前 schema profile，再校验该版本必须存在的核心表；随后从 `information_schema` 枚举并统计源库的全部实际基础表（`flyway_schema_history` 已由独立文件逐字节记录，不重复计数）。因此 V1/Flyway V3 备份不会查询 V2/Flyway V5 才新增的 MCP 幂等表，V7 备份则必须包含该表；通过复制规范生成的业务表也会进入清单，不能被固定表列表静默遗漏。

当前恢复工具显式支持 Flyway V1—V7。遇到更高版本会失败关闭，必须先更新表引入版本映射与回归测试，不能使用旧工具为未知 schema 生成看似完整的备份。

### 2.3 先做零写入恢复计划

`--plan` 只校验包、校验和和目标命名，不连接 Docker：

```bash
export WEB_STARTER_BACKUP_PACKAGE='/secure-backups/web-starter/web-starter-backup-...'
python3 scripts/recovery_restore.py \
  --package "$WEB_STARTER_BACKUP_PACKAGE" \
  --compose-project "$WEB_STARTER_DRILL_PROJECT" \
  --confirm-project "$WEB_STARTER_DRILL_PROJECT" \
  --target-database web_starter_restore_20260719a \
  --plan
```

### 2.4 只恢复到新数据库

真实恢复必须指定一个尚不存在的报告文件；目标库可以省略，由脚本安全生成。下面同时产生一个只把 `app` 指向恢复库的 Compose override，供后续运行验收使用：

```bash
export WEB_STARTER_RESTORE_REPORT='/secure-backups/web-starter/evidence/ac40-restore.json'
export WEB_STARTER_RESTORE_OVERRIDE='/private/tmp/web-starter-ac40-restored.yaml'
python3 scripts/recovery_restore.py \
  --package "$WEB_STARTER_BACKUP_PACKAGE" \
  --compose-project "$WEB_STARTER_DRILL_PROJECT" \
  --confirm-project "$WEB_STARTER_DRILL_PROJECT" \
  --target-database web_starter_restore_20260719a \
  --compose-file compose.yaml \
  --compose-file compose.dev.yaml \
  --report-file "$WEB_STARTER_RESTORE_REPORT" \
  --runtime-override-file "$WEB_STARTER_RESTORE_OVERRIDE"
```

恢复流程按以下顺序执行：

1. 先校验 manifest、SQL、Flyway、schema profile、必需表/实际表清单、逐表行数及 SHA-256，并拒绝符号链接和路径穿越。
2. 校验目标项目以 `web-starter-ac40-` 开头，且 MySQL 数据目录是该项目 label 所拥有的具名卷；共享卷、bind mount 和外部卷均拒绝。
3. 查询目标库是否存在；任何已存在目标都直接拒绝。
4. 创建新库，再创建随机临时 MySQL 账号。该账号只拥有新库权限，不能修改源库。
5. 导入 SQL 后立即删除临时账号和容器内临时 option 文件。
6. 要求恢复库实际基础表全集与 manifest 完全一致，再逐表比对行数并逐字节比对 Flyway 历史；缺表、多表或行数不匹配均失败并保留新库供调查，不自动删除。
7. 只有显式要求 runtime override 时，才授予既有应用账号对恢复库的权限。

### 2.5 恢复后的真实验收

数据库导入成功仍不是 AC-40 通过。使用生成的 override 启动同一候选镜像，使应用连接恢复库：

```bash
docker compose --project-name "$WEB_STARTER_DRILL_PROJECT" \
  -f compose.yaml -f compose.dev.yaml -f "$WEB_STARTER_RESTORE_OVERRIDE" \
  up --no-build -d app nginx
```

随后必须在恢复库上保存以下独立证据：

| 必须执行 | 最小证据 |
|---|---|
| 真实浏览器登录 | 浏览器网络结果、页面主体和对应登录审计 |
| Project CRUD | 创建、读取、更新、删除的请求结果与数据库/操作审计回读 |
| 权限拒绝 | 低权限账号真实 HTTP 403 与失败审计 |
| OAuth | PKCE 或 Client Credentials 的真实 Token 流程和受保护资源访问 |
| MCP | 官方 MCP SDK 建连并调用允许 Tool，MySQL 中存在关联 MCP 审计 |

恢复报告故意写入 `runtimeAcceptance=NOT_RUN` 和上述待办。只有这些证据全部通过后，外层验收记录才能把 V2-AC-40 标为 `PASS`。

移除生成的 override 后，Compose 才会重新指向源库。删除演练库和演练卷不属于这些脚本的职责，必须由获授权人员在证据归档后单独确认；禁止使用未经核对的 `down -v`。

## 3. V2-AC-41 Redis 数据丢失

### 3.1 准备专属隔离栈

必须新建以 `web-starter-ac41-` 开头的 Compose 项目并分配未占用的回环端口。不要对日常开发项目 `web-starter` 执行本演练。正式证据必须运行已发布的不可变候选镜像；正式演练还要通过启用 TLS 的公网测试入口建立 `Secure` Session Cookie，因此以下命令启动 AC-41 所需的五个服务：

```bash
export WEB_STARTER_AC41_PROJECT='web-starter-ac41-20260719a'
export WEB_STARTER_HTTP_PORT=18088
export WEB_STARTER_DB_PORT=13360
export WEB_STARTER_REDIS_PORT=16390
docker compose --project-name "$WEB_STARTER_AC41_PROJECT" \
  -f compose.production.yaml up --no-build -d mysql redis app nginx mcp-public-nginx
```

在执行破坏性步骤前，脚本会读取 Docker label 并证明：

- MySQL、Redis、App、Nginx 的 resolved Compose reference、容器 reference、不可变 image ID 与操作者单独传入的期望值完全一致，四个容器 ID 各不相同；
- App、Nginx 镜像的 OCI version/revision 与当前 Git 候选版本/commit 一致，App 内 Java specification/runtime version 均为 21；
- `/var/lib/mysql` 和 `/data` 都是该项目 label 所拥有的具名卷，不接受 bind mount 或外部卷；
- MySQL 和 Redis 的卷名必须不同，并与 resolved Compose volume 名称交叉绑定；
- `formal` 模式的 `--base-url` 必须是显式映射到该项目 `mcp-public-nginx:8443` 的保留 `.test` HTTPS 地址，并且该主机只在当前进程中解析到回环地址；诊断模式才允许映射到 `nginx:8080` 的私有 HTTP 地址；
- MySQL 容器数据库名与 `--expected-database` 一致；
- 首次真实登录已产生 Redis Session 数据。

### 3.2 正式候选与证据目录

`formal` 模式在任何 Docker 调用之前要求：Git HEAD/Tree 不变、工作区和未跟踪文件均为空、index 没有 `skip-worktree`/`assume-unchanged`，根 Maven 与前端版本相等且不是 `SNAPSHOT`。报告绑定演练工具、公共 recovery helper、独立 validator、JSON Schema、两个版本文件及全部 Compose 文件在该 commit 中的 blob SHA-256。

当前仓库版本仍为 `2.0.0-SNAPSHOT`，因此现在只能执行诊断演练，不能产生正式 `PASS`。锁定非 SNAPSHOT 候选版本并提交干净工作区后，才可运行下面的正式命令。

每份正式报告使用仓库外的专属空目录。该目录必须为 `0700`，且验证时只能包含报告和同名 `.sha256` 两个 `0600` 文件；不要在其中放操作笔记、日志或截图：

```bash
export WEB_STARTER_AC41_EVIDENCE_DIR='/secure-evidence/web-starter/ac41-20260720a'
mkdir -m 0700 "$WEB_STARTER_AC41_EVIDENCE_DIR"
export WEB_STARTER_AC41_REPORT="$WEB_STARTER_AC41_EVIDENCE_DIR/v2-ac41-redis-loss.json"
```

期望 reference 必须是完整的 `registry/name@sha256:<64 hex>`；期望 image ID 必须是 Docker 实际解析出的 `sha256:<64 hex>`。这些值应来自候选发布清单，而不是从演练报告回填：

```bash
export WEB_STARTER_AC41_EXPECTED_APP_REFERENCE='registry.example.invalid/web-starter/app@sha256:<64-hex>'
export WEB_STARTER_AC41_EXPECTED_APP_IMAGE_ID='sha256:<64-hex>'
export WEB_STARTER_AC41_EXPECTED_NGINX_REFERENCE='registry.example.invalid/web-starter/nginx@sha256:<64-hex>'
export WEB_STARTER_AC41_EXPECTED_NGINX_IMAGE_ID='sha256:<64-hex>'
export WEB_STARTER_AC41_EXPECTED_MYSQL_REFERENCE='mysql@sha256:<64-hex>'
export WEB_STARTER_AC41_EXPECTED_MYSQL_IMAGE_ID='sha256:<64-hex>'
export WEB_STARTER_AC41_EXPECTED_REDIS_REFERENCE='redis@sha256:<64-hex>'
export WEB_STARTER_AC41_EXPECTED_REDIS_IMAGE_ID='sha256:<64-hex>'
```

### 3.3 执行正式演练

```bash
export WEB_STARTER_REHEARSAL_USERNAME='isolated-rehearsal-admin'
export WEB_STARTER_REHEARSAL_PASSWORD='set-outside-the-repository'
export WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS='mcp.ac41.webstarter.test'
export WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS='127.0.0.1'
# 仅用于回环、自签名的验收证书；正式内网证书应删除此项并使用系统信任链。
export WEB_STARTER_ACCEPTANCE_INSECURE_TLS='true'
python3 scripts/rehearse_redis_loss.py \
  --compose-project "$WEB_STARTER_AC41_PROJECT" \
  --confirm-project "$WEB_STARTER_AC41_PROJECT" \
  --compose-file compose.production.yaml \
  --expected-database web_starter \
  --mode formal \
  --base-url https://mcp.ac41.webstarter.test:18443 \
  --report-file "$WEB_STARTER_AC41_REPORT" \
  --expected-app-reference "$WEB_STARTER_AC41_EXPECTED_APP_REFERENCE" \
  --expected-app-image-id "$WEB_STARTER_AC41_EXPECTED_APP_IMAGE_ID" \
  --expected-nginx-reference "$WEB_STARTER_AC41_EXPECTED_NGINX_REFERENCE" \
  --expected-nginx-image-id "$WEB_STARTER_AC41_EXPECTED_NGINX_IMAGE_ID" \
  --expected-mysql-reference "$WEB_STARTER_AC41_EXPECTED_MYSQL_REFERENCE" \
  --expected-mysql-image-id "$WEB_STARTER_AC41_EXPECTED_MYSQL_IMAGE_ID" \
  --expected-redis-reference "$WEB_STARTER_AC41_EXPECTED_REDIS_REFERENCE" \
  --expected-redis-image-id "$WEB_STARTER_AC41_EXPECTED_REDIS_IMAGE_ID"
```

脚本执行并验证以下真实顺序：

1. 通过隔离的 HTTPS 入口和 CSRF 保护的登录接口创建带 `Secure` 属性的 Web Session，`/api/auth/me` 返回 200；正式模式禁止用私有 HTTP 入口伪造生产会话语义。
2. 对 MySQL 的业务/配置、RBAC、凭据及哈希元数据生成只在内存中计算的 SHA-256 指纹，并记录三类审计行数。
3. 只对应用实际配置的 Redis DB 执行一次 `FLUSHDB`；不执行 `FLUSHALL`，不停止 Redis，不删除卷。
4. 旧 Session 再访问 `/api/auth/me` 必须返回 401。
5. 使用全新的 Cookie 容器重新登录并再次访问成功；为覆盖 Redis 清空后的短暂恢复窗口，最多尝试 5 次、每次间隔 1 秒，报告记录实际 `reloginAttempts`，持续失败仍阻断。
6. MySQL 业务、RBAC 和凭据指纹必须完全不变；三类审计行数不得减少，登录审计必须增加。

只有全部断言通过、内存中报告先通过独立 validator，并且落盘报告/校验和再次通过 validator，正式报告才会写入 `mode=formal,status=PASS`。报告不保存 Cookie、CSRF Token、密码、PAT、OAuth Token 或数据库内容。独立复核命令为：

```bash
python3 scripts/validate_redis_loss_evidence.py \
  --document "$WEB_STARTER_AC41_REPORT" \
  --expected-app-reference "$WEB_STARTER_AC41_EXPECTED_APP_REFERENCE" \
  --expected-app-image-id "$WEB_STARTER_AC41_EXPECTED_APP_IMAGE_ID" \
  --expected-nginx-reference "$WEB_STARTER_AC41_EXPECTED_NGINX_REFERENCE" \
  --expected-nginx-image-id "$WEB_STARTER_AC41_EXPECTED_NGINX_IMAGE_ID" \
  --expected-mysql-reference "$WEB_STARTER_AC41_EXPECTED_MYSQL_REFERENCE" \
  --expected-mysql-image-id "$WEB_STARTER_AC41_EXPECTED_MYSQL_IMAGE_ID" \
  --expected-redis-reference "$WEB_STARTER_AC41_EXPECTED_REDIS_REFERENCE" \
  --expected-redis-image-id "$WEB_STARTER_AC41_EXPECTED_REDIS_IMAGE_ID"
```

validator 只使用 Python 标准库和只读 Git 查询，不连接 Docker、Redis、MySQL 或网络。它重新计算严格字段集合、候选 commit/tree/source hashes、版本、镜像交叉绑定、Java 21、隔离卷、选定 DB 的 `FLUSHDB`、Session 失效/重登录、MySQL 指纹、审计单调性、秘密形态、目录权限及 sibling checksum；并在语义校验后再次读取报告和校验和，拒绝验证期间替换。

### 3.4 诊断模式不是验收证据

如果候选尚未锁定，可将同一命令改为 `--mode diagnostic` 并省略八个 `--expected-*-reference/image-id` 参数。诊断仍会真实执行选定 Redis DB 的丢失流程，并写入报告及校验和，但固定标记为 `mode=diagnostic,status=DIAGNOSTIC,formalEvidence=false`。正式 validator 必须拒绝该报告，它不能让 V2-AC-41 通过。

当前 `release_evidence_gate.py` 与 release workflow 尚未接入本证据；在接线完成前，validator 单独通过也不等于整体发布门禁已通过。

## 4. 不接触运行环境的验证

以下命令只运行参数、包完整性和静态安全测试，不连接 Docker，因此只能证明脚本契约，不能证明 AC-40/41 运行通过：

```bash
PYTHONPYCACHEPREFIX=/private/tmp/web-starter-recovery-pycache \
  python3 -m unittest -v \
    scripts.test_recovery_harness \
    scripts.test_validate_redis_loss_evidence
```

覆盖项包括：校验和/报告替换、验证中 TOCTOU 替换、重复 JSON key、非有限数字、秘密形态、伪造 source hash、候选漂移、镜像错配、Java/容器/卷唯一性、证据目录附件、关键表完整性、新库命名、AC-41 项目前缀、审计单调性、零写入 `--plan`，以及禁止卷/数据库广域删除命令。

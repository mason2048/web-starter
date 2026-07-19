# 本地开发与内网部署

## 部署拓扑

```text
Browser / MCP Agent
        |
        v
      Nginx
   /       \
静态前端   Spring Boot 单体
              |        \
            MySQL      Redis
```

- Nginx 是唯一默认对外端口。
- MySQL 和 Redis 位于内部容器网络，不直接暴露给内网用户。
- `compose.dev.yaml` 仅为本机调试映射数据库、Redis 和后端端口。
- `compose.public-mcp.yaml` 在保留私有管理入口的同时增加独立 HTTPS 公网 MCP 入口；公网入口只开放 OAuth/MCP 所需路径。
- Web API 与 MCP 运行在同一个 Spring Boot 进程中，共享业务服务、事务和审计。

## 环境准备

- JDK 21
- Docker Engine / Docker Desktop 与 Compose V2
- Node.js 24 和 pnpm 9（仅前端本地开发需要）

复制 `.env.example` 为 `.env`，替换全部 `replace-with-...` 占位值。生产环境必须使用密码管理系统或部署平台注入环境变量，不要把 `.env` 提交到 Git。

## 完整容器启动

```bash
docker compose up --build -d
docker compose ps
curl --fail --silent --show-error http://localhost:8088/actuator/health/readiness
```

默认从 `http://localhost:8088` 访问。首次空库启动需要设置：

- `WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME`
- `WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD`
- `WEB_STARTER_TOKEN_PEPPER`
- `WEB_STARTER_OAUTH_RSA_PRIVATE_KEY` 与 `WEB_STARTER_OAUTH_RSA_PUBLIC_KEY`，或仅在本地把 `WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED` 设为 `true`

部署完成后应移除 Bootstrap 管理员密码环境变量，并在系统中修改初始密码。

Compose 会把本地构建结果标记为 `web-starter-app:local` 和 `web-starter-nginx:local`。发布环境应设置 `WEB_STARTER_APP_IMAGE`、`WEB_STARTER_NGINX_IMAGE` 和不可变的 `WEB_STARTER_IMAGE_TAG`，从镜像仓库拉取后使用 `--no-build` 启动；不要把可变的 `latest` 当作回滚点。

## 私网管理 + 公网 MCP 双入口

基础 `compose.yaml` 的 `http://localhost:8088` 是私有入口，Nginx 总是覆盖 `X-Web-Starter-Ingress: private`。叠加 `compose.public-mcp.yaml` 后会增加本地验收地址 `https://mcp.localhost:8443`，该入口总是覆盖为 `public`，应用因此拒绝 PAT 和服务账号长期令牌，但接受符合 Issuer/Audience 的短时 OAuth Token。两个入口都只连接同一个 `app` 服务。

### 本地自签证书验收

自签证书只用于本机协议和入口边界验收，不得用于生产。下面的证书写入系统临时目录，不进入仓库或 Docker 构建上下文；需要 OpenSSL 1.1.1 或更高版本：

```bash
WEB_STARTER_LOCAL_TLS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/web-starter-tls.XXXXXX")"
chmod 700 "$WEB_STARTER_LOCAL_TLS_DIR"
openssl req -x509 -newkey rsa:3072 -sha256 -days 7 -nodes \
  -keyout "$WEB_STARTER_LOCAL_TLS_DIR/privkey.pem" \
  -out "$WEB_STARTER_LOCAL_TLS_DIR/fullchain.pem" \
  -subj '/CN=mcp.localhost' \
  -addext 'subjectAltName=DNS:mcp.localhost'
chmod 600 "$WEB_STARTER_LOCAL_TLS_DIR/privkey.pem"

export WEB_STARTER_PUBLIC_TLS_CERT_FILE="$WEB_STARTER_LOCAL_TLS_DIR/fullchain.pem"
export WEB_STARTER_PUBLIC_TLS_KEY_FILE="$WEB_STARTER_LOCAL_TLS_DIR/privkey.pem"
export WEB_STARTER_PUBLIC_MCP_PORT=8443
export WEB_STARTER_OAUTH_ISSUER='https://mcp.localhost:8443'
export WEB_STARTER_OAUTH_RESOURCE_AUDIENCE='https://mcp.localhost:8443/mcp'
export WEB_STARTER_MCP_ALLOWED_HOSTS='localhost,localhost:8088,mcp.localhost,mcp.localhost:8443'
export WEB_STARTER_MCP_ALLOWED_ORIGINS='http://localhost:8088,https://mcp.localhost:8443'

docker compose --env-file .env \
  -f compose.yaml -f compose.public-mcp.yaml \
  up --build -d
docker compose --env-file .env \
  -f compose.yaml -f compose.public-mcp.yaml \
  ps
curl --fail --silent --show-error \
  --cacert "$WEB_STARTER_PUBLIC_TLS_CERT_FILE" \
  --resolve mcp.localhost:8443:127.0.0.1 \
  https://mcp.localhost:8443/.well-known/oauth-protected-resource/mcp
```

使用独立的 `mcp.localhost` 是为了避免公网入口的 HSTS 影响私有 `http://localhost:8088`。现代浏览器通常会把 `.localhost` 解析到回环地址；若本机环境不支持，应配置仅本机可见的 hosts 记录，不能改用公网 DNS。

本地 `.env` 可以保留 `WEB_STARTER_COOKIE_SECURE=false` 以便同时使用私有 HTTP 管理端；公网 Nginx 仍会为 `WEB_STARTER_SESSION` 和 `XSRF-TOKEN` 强制添加 `Secure`。生产环境必须同时设置 `WEB_STARTER_COOKIE_SECURE=true`，不能依赖这一条边缘补偿。

验收时至少分别执行：私有入口 PAT 调用成功、公网入口同一 PAT 返回 401、公网 Authorization Code + PKCE 调用成功、公网 Client Credentials 调用成功。MCP 客户端必须显式信任该本地证书，不能在生产使用 `--insecure` 或关闭 TLS 校验。

### 生产双入口

生产部署使用同一个叠加文件，但必须满足以下条件：

1. `WEB_STARTER_PUBLIC_TLS_CERT_FILE` 和 `WEB_STARTER_PUBLIC_TLS_KEY_FILE` 指向密码管理系统或部署平台落盘的只读真实证书文件；禁止把证书私钥复制到仓库、镜像或 `.env`。
2. 设置稳定的 HTTPS `WEB_STARTER_OAUTH_ISSUER` 与 `/mcp` Audience，显式列出正式 Host/Origin，并设置 `WEB_STARTER_COOKIE_SECURE=true`。
3. 把 `WEB_STARTER_PUBLIC_MCP_PORT` 设为正式监听端口（通常为 443），通过防火墙只开放公网 MCP 入口。`WEB_STARTER_HTTP_BIND_ADDRESS` 应绑定受控内网地址或 `127.0.0.1`，不得把私有 8088 入口发布到公网。
4. 私有管理端也必须通过组织内受信 HTTPS 入口访问。公网 DNS、负载均衡和防火墙不得回源到私有入口；否则长期令牌边界失效。
5. 如果公网 Nginx 前还有负载均衡器，先以明确 CIDR 配置 `set_real_ip_from`/`real_ip_header`，再使用真实客户端地址；禁止直接信任任意客户端发送的 `X-Forwarded-*`。

生产镜像启动示例：

```bash
export WEB_STARTER_APP_IMAGE='registry.example.internal/web-starter/app'
export WEB_STARTER_NGINX_IMAGE='registry.example.internal/web-starter/nginx'
export WEB_STARTER_IMAGE_TAG='1.0.0'
docker compose --env-file /run/secrets/web-starter.env \
  -f compose.yaml -f compose.public-mcp.yaml \
  pull app nginx mcp-public-nginx
docker compose --env-file /run/secrets/web-starter.env \
  -f compose.yaml -f compose.public-mcp.yaml \
  up --no-build -d
```

## 本地分进程开发

只启动数据依赖：

```bash
docker compose -f compose.yaml -f compose.dev.yaml up -d mysql redis
```

启动后端：

```bash
export WEB_STARTER_DB_URL='jdbc:mysql://127.0.0.1:33060/web_starter?useUnicode=true&characterEncoding=utf8&preserveInstants=true&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true&allowPublicKeyRetrieval=true&useSSL=false'
export WEB_STARTER_DB_USERNAME='web_starter'
export WEB_STARTER_DB_PASSWORD='local-only-value'
export WEB_STARTER_REDIS_HOST='127.0.0.1'
export WEB_STARTER_REDIS_PORT='63790'
export WEB_STARTER_REDIS_PASSWORD='local-only-value'
export WEB_STARTER_TOKEN_PEPPER='local-only-value-with-at-least-32-characters'
export WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME='admin'
export WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD='replace-with-a-local-password'
export WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED='true'
export WEB_STARTER_SERVER_PORT='18080'
./mvnw -DskipTests package
java -jar web-starter-admin/target/web-starter-admin-1.0.0.jar
```

启动前端：

```bash
cd web-starter-web
pnpm install
pnpm dev
```

Vite 开发代理把 `/api`、`/mcp`、`/oauth2` 和 `/.well-known` 转发到本地后端。

## 外网 MCP

外网 MCP 必须使用独立 HTTPS 域名和稳定的 OAuth Issuer。`compose.public-mcp.yaml` 会把 `deploy/nginx/external-mcp.conf` 作为只读配置挂载到独立公网 Nginx：

- 只暴露 `/mcp`、OAuth 端点、登录所需的最小静态资源与认证 API，以及 `/.well-known` 元数据。
- 不暴露完整管理端路由和普通业务 `/api/**`。
- Nginx 覆盖 `X-Web-Starter-Ingress: public`，应用据此拒绝长期 PAT 和服务账号令牌。
- 外网用户 Agent 使用 Authorization Code + PKCE。
- 外网无人值守 Agent 使用 Client Credentials 换取短时访问令牌。
- `WEB_STARTER_OAUTH_ISSUER` 必须与浏览器和 Agent 访问到的 HTTPS Issuer 完全一致。
- 外网 HTTPS 部署必须设置 `WEB_STARTER_COOKIE_SECURE=true`；仅本地 HTTP 开发允许为 `false`。
- `WEB_STARTER_MCP_ALLOWED_HOSTS` 必须显式加入正式 MCP 主机名；非标准端口也必须包含在白名单中。Nginx 会保留客户端看到的 Host 与端口，并覆盖所有 `X-Forwarded-*` 请求头。
- 浏览器型 Agent 还必须在 `WEB_STARTER_MCP_ALLOWED_ORIGINS` 中显式加入其完整 HTTPS Origin；服务端 Agent 不发送 `Origin` 时仍会强制校验 `Host`。
- 随附的内外网 Nginx 配置对 `/mcp` 设置了按来源 IP 的请求速率和并发连接上限；正式环境应根据可信 Agent 数量调优，但不得删除这一保护。
- MCP Client 结束任务时必须发送带 `Mcp-Session-Id` 的 `DELETE /mcp` 释放会话。SDK 2.0 的 Servlet 传输当前没有会话 TTL 配置，入口限流和客户端主动释放是 V1 的必要运维约束；应监控应用内存并在 SDK 提供原生 TTL 后升级。

例如正式入口为 `https://mcp.example.internal`：

```bash
export WEB_STARTER_MCP_ALLOWED_HOSTS='mcp.example.internal'
export WEB_STARTER_MCP_ALLOWED_ORIGINS='https://mcp.example.internal,https://approved-agent.example'
```

本地默认白名单只覆盖 `localhost`、`127.0.0.1` 和 `[::1]`（含有端口和无端口形式），不适用于生产域名。

### 官方 MCP SDK 运行验收

仓库提供三组显式运行的 `*RuntimeIT`。它们不会被普通 `mvn verify` 自动执行，必须指向可丢弃的验收环境，并使用真实签发的 Token：

- `McpSdkRuntimeIT`：初始化、7 个 Tool、Resource、Prompt、读操作和权限拒绝。
- `McpSdkProjectListRuntimeIT`：低权限主体的 `project.list` 与实时 RBAC 回收。
- `McpSdkCrudRuntimeIT`：`project.create/get/update/remove` 与 `audit.list` 的完整写链路。

Token 签发响应必须保存在仓库外的 `0600` 文件；测试只从文件读取 `token` 或 `access_token`，不会把明文写入日志。示例：

```bash
chmod 600 /absolute/private/token-response.json
export WEB_STARTER_MCP_BASE_URL='https://mcp.example.internal'
export WEB_STARTER_MCP_TOKEN_RESPONSE_FILE='/absolute/private/token-response.json'
export WEB_STARTER_MCP_OWNER_ID='<decimal-user-id>'
export WEB_STARTER_MCP_PROJECT_ID='<existing-project-id>'
export WEB_STARTER_MCP_TRACE_PREFIX='acceptance-unique-prefix'

./mvnw -B -ntp -pl web-starter-mcp -am \
  -Dtest=dev.webstarter.mcp.acceptance.McpSdkRuntimeIT \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

低权限和 CRUD 验收只需替换 `-Dtest` 类名；低权限回收后的复测额外设置 `WEB_STARTER_MCP_EXPECT_PROJECT_LIST_DENIED=true`。使用内部 CA 或本地自签证书时，应把 CA 导入临时 Java truststore 并通过 `JAVA_TOOL_OPTIONS` 指定，不得关闭 TLS 验证。所有验收 Token 应在结束后立即吊销。

生产环境不要使用临时生成的 RSA 密钥。应用接受单行 Base64 编码的 PKCS#8 私钥和 X.509 公钥。以下命令必须在受控临时目录或离线密钥工作站执行，不要在仓库目录执行：

```bash
WEB_STARTER_RSA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/web-starter-rsa.XXXXXX")"
chmod 700 "$WEB_STARTER_RSA_DIR"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "$WEB_STARTER_RSA_DIR/oauth-private.pem"
chmod 600 "$WEB_STARTER_RSA_DIR/oauth-private.pem"
openssl pkcs8 -topk8 -nocrypt -in "$WEB_STARTER_RSA_DIR/oauth-private.pem" \
  -outform DER | openssl base64 -A
openssl pkey -in "$WEB_STARTER_RSA_DIR/oauth-private.pem" \
  -pubout -outform DER | openssl base64 -A
```

把两条 Base64 输出分别注入 `WEB_STARTER_OAUTH_RSA_PRIVATE_KEY` 和 `WEB_STARTER_OAUTH_RSA_PUBLIC_KEY`，不要写入仓库、镜像层或普通部署日志。密钥必须由密码管理系统托管。

### RSA 签名密钥轮换与回退

V1 使用单个活动签名密钥，不提供双密钥重叠签发。更换公钥后，旧公钥签发的 Access Token 会立即失效；这是明确的安全取舍，不能把它描述成无感轮换。按以下步骤执行计划轮换：

1. 在变更窗口前把 Access Token TTL 降到可接受的最短值，至少等待一个旧 TTL，停止长时间自动化任务，并保存当前密钥版本的密码管理系统引用；不得导出到普通文件或工单。
2. 离线生成新的 3072 位 RSA 密钥对，将私钥和公钥作为一个不可分割的版本写入密码管理系统，记录变更人、变更时间和回退版本引用。
3. 先在预发布环境注入新版本，确认应用启动、Authorization Server Metadata、JWKS、Authorization Code + PKCE、Client Credentials 和一次真实 MCP 调用均通过。
4. 在生产环境一次性替换公私钥并滚动重建应用。部署后确认 JWKS 的 `kid` 已变化，重新获取的 Token 能调用 MCP，旧 Token 被拒绝；通知 Agent 重新授权或换取 Token。
5. 如果启动、换 Token 或 MCP 验证失败，立即把密钥引用切回上一个完整版本并重建应用。回退后重新执行元数据、换 Token 和 MCP 调用验证；轮换期间签发的 Token 将失效。
6. 成功后保留旧密钥的受控回退引用至变更观察期结束，再按密钥管理策略销毁；不得把旧私钥长期保留在部署主机。

紧急泄露处置不等待旧 TTL：立即换键、撤销已登记的 OAuth Token、禁用受影响 Client 或主体，并要求所有 Agent 重新授权。轮换和回退都必须留下变更审计，但审计内容不得包含任何密钥材料。

## 健康检查

- 存活：`GET /actuator/health/liveness`
- 就绪：`GET /actuator/health/readiness`
- 聚合健康：`GET /actuator/health`

私有 `nginx` 的容器健康检查通过私有入口读取应用 readiness；`mcp-public-nginx` 使用仅监听容器回环地址的 `/healthz`，同时验证公网 Nginx 和上游应用。可用以下命令读回状态：

```bash
docker compose ps
docker compose -f compose.yaml -f compose.public-mcp.yaml \
  exec -T mcp-public-nginx \
  wget -q -O - http://127.0.0.1:8081/healthz
```

健康状态只证明进程和被检查依赖的当前状态，不等同于登录、业务事务或 MCP 工具可用。部署验收仍需执行真实用例。

## 日志与故障定位

- 容器现场使用 `docker compose logs --since 30m app nginx` 查看；双入口部署同时查看 `mcp-public-nginx`。生产环境应接入受控的集中日志系统并配置容量、保留期和访问权限，不能依赖容器可写层长期保存。
- 应用日志以 Trace ID 串联入口错误；登录日志、操作审计和 MCP 调用日志以 MySQL 为事实来源。排障时先按 Trace ID 关联，避免在普通日志中复制请求头、Cookie 或 Token。
- 监控至少覆盖 Nginx 5xx、应用启动失败、健康探针、数据库连接池、Redis 连接、OAuth 换 Token 失败率和 MCP 失败率。
- 导出日志用于工单前必须再次检查并脱敏；禁止输出密码、`Authorization`、Session Cookie、完整 PAT、服务账号令牌、OAuth Client Secret、Pepper 或私钥。

## 备份与恢复

MySQL 备份必须包含业务、审计和安全凭据表。Redis 不是业务事实来源；Redis 丢失只允许造成 Session 失效。生产环境应按本组织的 RPO/RTO 设置频率、异地副本、保留期和加密策略，下面命令只是一次可验证的逻辑全量备份：

```bash
umask 077
export WEB_STARTER_BACKUP_DIR='/secure-backups/web-starter'
mkdir -p "$WEB_STARTER_BACKUP_DIR"
export WEB_STARTER_BACKUP_FILE="$WEB_STARTER_BACKUP_DIR/web_starter-$(date -u +%Y%m%dT%H%M%SZ).sql"
docker compose exec -T mysql sh -ec \
  'exec mysqldump --single-transaction --quick --routines --events --triggers --no-tablespaces --set-gtid-purged=OFF -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' \
  > "$WEB_STARTER_BACKUP_FILE"
test -s "$WEB_STARTER_BACKUP_FILE"
chmod 600 "$WEB_STARTER_BACKUP_FILE"
openssl dgst -sha256 "$WEB_STARTER_BACKUP_FILE" > "$WEB_STARTER_BACKUP_FILE.sha256"
```

备份文件和校验文件必须加密后传送到受控备份存储，不能放在仓库、容器可写层或普通工单。每次 Flyway 升级前先完成备份；已应用迁移不得修改。

恢复演练先导入独立数据库，不覆盖当前 `web_starter`：

```bash
export WEB_STARTER_RESTORE_DB="web_starter_restore_$(date -u +%Y%m%d%H%M%S)"
docker compose exec -T -e WEB_STARTER_RESTORE_DB="$WEB_STARTER_RESTORE_DB" mysql sh -ec \
  'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE $WEB_STARTER_RESTORE_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"'
docker compose exec -T -e WEB_STARTER_RESTORE_DB="$WEB_STARTER_RESTORE_DB" mysql sh -ec \
  'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" "$WEB_STARTER_RESTORE_DB"' \
  < "$WEB_STARTER_BACKUP_FILE"
docker compose exec -T -e WEB_STARTER_RESTORE_DB="$WEB_STARTER_RESTORE_DB" mysql sh -ec \
  'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -Nse "SELECT COUNT(*) FROM $WEB_STARTER_RESTORE_DB.flyway_schema_history"'
```

恢复演练还必须抽查管理员、权限、项目、操作审计和 MCP 审计记录，并把耗时与校验和写入演练记录。确认记录完成后，才可由获授权人员删除演练数据库。

灾难恢复覆盖生产库属于破坏性操作，只能在已批准维护窗口执行：停止 `app` 和两个入口，记录当前卷和镜像标签，使用与备份 Flyway 版本兼容的应用镜像，重新创建 `web_starter` 后导入已验证备份，再启动应用。恢复后必须重新执行登录、Project CRUD、权限拒绝、OAuth 换 Token 和真实 MCP 调用；不要使用 `docker compose down -v`，它会删除持久卷。

## 升级与回滚

发布前给应用和 Nginx 使用同一个不可变版本标签，并推送到受控镜像仓库：

```bash
export WEB_STARTER_APP_IMAGE='registry.example.internal/web-starter/app'
export WEB_STARTER_NGINX_IMAGE='registry.example.internal/web-starter/nginx'
export WEB_STARTER_IMAGE_TAG='1.0.0'
docker compose build --pull app nginx
docker compose push app nginx
docker image inspect "$WEB_STARTER_APP_IMAGE:$WEB_STARTER_IMAGE_TAG" --format '{{json .RepoDigests}}'
docker image inspect "$WEB_STARTER_NGINX_IMAGE:$WEB_STARTER_IMAGE_TAG" --format '{{json .RepoDigests}}'
docker compose exec -T mysql sh -ec \
  'exec mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -Nse "SELECT version, success FROM flyway_schema_history ORDER BY installed_rank DESC LIMIT 1"'
```

升级步骤：

1. 记录当前 Git 版本、镜像标签与 digest、Flyway 版本和配置版本，完成并验证数据库备份。
2. 在空库预发布环境使用目标镜像执行迁移，完成 Web、OAuth、MCP、审计和双入口验收。
3. 生产拉取目标镜像后使用 `docker compose -f compose.yaml -f compose.public-mcp.yaml up --no-build -d`，不得在生产主机临时构建。
4. 检查三个应用层容器健康状态，再执行真实登录、Project CRUD、权限拒绝和 MCP 调用。观察 Nginx 5xx、连接池、OAuth/MCP 失败率和审计写入。

应用回滚命令只切换到已记录的不可变标签：

```bash
export WEB_STARTER_IMAGE_TAG='0.9.0'
docker compose -f compose.yaml -f compose.public-mcp.yaml \
  pull app nginx mcp-public-nginx
docker compose -f compose.yaml -f compose.public-mcp.yaml \
  up --no-build -d app nginx mcp-public-nginx
```

如果目标升级执行了不向后兼容的数据库迁移，不得直接运行旧应用。优先发布向前修复迁移；确需恢复旧数据库时，进入维护窗口并使用已演练的升级前备份。回滚后重新执行完整运行验收，而不能只看容器 `Up` 或健康检查。

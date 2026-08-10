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
- `WEB_STARTER_CREDENTIAL_PEPPER` 可选；未设置时为 V1 兼容而回退到 `WEB_STARTER_TOKEN_PEPPER`。轮换步骤见[安全模型](security.md#长期令牌-pepper-轮换)
- `WEB_STARTER_MANAGEMENT_USERNAME` 与 `WEB_STARTER_MANAGEMENT_PASSWORD`：独立运维身份；密码至少 32 个随机字符，不得与 Web 管理员或其他秘密复用
- `WEB_STARTER_OAUTH_RSA_PRIVATE_KEY` 与 `WEB_STARTER_OAUTH_RSA_PUBLIC_KEY`，或仅在本地把 `WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED` 设为 `true`

部署完成后应移除 Bootstrap 管理员密码环境变量，并在系统中修改初始密码。

Compose 会把本地构建结果标记为 `web-starter-app:local` 和 `web-starter-nginx:local`。生产部署不复用这个开发模型，而使用独立的 `compose.production.yaml`；该文件没有 `build`，并要求应用、Nginx、MySQL 和 Redis 都使用完整的 `repository@sha256` 引用。应用与 Nginx digest 只能取自已经通过供应链门禁的发布证据，不能使用 `latest` 或仅靠版本 tag。

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
chmod 644 \
  "$WEB_STARTER_LOCAL_TLS_DIR/privkey.pem" \
  "$WEB_STARTER_LOCAL_TLS_DIR/fullchain.pem"

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

上面的 `0644` 只用于临时自签证书的 Docker bind-source 副本：宿主父目录仍为当前用户独占的 `0700`，因此其他宿主用户无法遍历读取；容器内固定的非 root Nginx 用户 `101` 则可以读取挂载文件。该目录不得复用于生产密钥，验收结束后应删除。

本地 `.env` 可以保留 `WEB_STARTER_COOKIE_SECURE=false` 以便同时使用私有 HTTP 管理端；公网 Nginx 仍会为 `WEB_STARTER_SESSION` 和 `XSRF-TOKEN` 强制添加 `Secure`。生产环境必须同时设置 `WEB_STARTER_COOKIE_SECURE=true`，不能依赖这一条边缘补偿。

验收时至少分别执行：私有入口 PAT 调用成功、公网入口同一 PAT 返回 401、公网 Authorization Code + PKCE 调用成功、公网 Client Credentials 调用成功。MCP 客户端必须显式信任该本地证书，不能在生产使用 `--insecure` 或关闭 TLS 校验。

### 生产双入口

生产部署使用独立的 `compose.production.yaml`，不能把开发 Compose 叠加成生产模型，并必须满足以下条件：

1. `WEB_STARTER_PUBLIC_TLS_CERT_FILE` 和 `WEB_STARTER_PUBLIC_TLS_KEY_FILE` 指向密码管理系统或部署平台落盘的只读真实证书文件；禁止把证书私钥复制到仓库、镜像或 `.env`。
2. 设置 `WEB_STARTER_RUNTIME_MODE=production`、稳定的 HTTPS `WEB_STARTER_OAUTH_ISSUER` 与 `/mcp` Audience，显式列出正式 Host/Origin，并设置 `WEB_STARTER_COOKIE_SECURE=true`。
3. 把 `WEB_STARTER_PUBLIC_MCP_PORT` 设为正式监听端口（通常为 443），通过防火墙只开放公网 MCP 入口。`WEB_STARTER_HTTP_BIND_ADDRESS` 默认且推荐使用 `127.0.0.1`；确需跨主机回源时，只能填写已由主机防火墙、路由和上游访问控制共同约束的 RFC1918 地址或 IPv6 ULA。生产策略拒绝空值、`0.0.0.0`、`::`、主机名和公网 IP，私有 8088 入口不得发布到公网。
4. 私有管理端也必须通过组织内受信 HTTPS 入口访问。公网 DNS、负载均衡和防火墙不得回源到私有入口；否则长期令牌边界失效。
5. 如果公网 Nginx 前还有负载均衡器，先以明确 CIDR 配置 `set_real_ip_from`/`real_ip_header`，再使用真实客户端地址；禁止直接信任任意客户端发送的 `X-Forwarded-*`。
6. App 与两个 Nginx 容器强制使用固定数字非 root 用户，根文件系统只读，只允许受控 `/tmp` tmpfs。TLS 文件必须对 Nginx 的 `101:101` 只读可读；两个源文件必须已存在，Compose 使用 `bind.create_host_path:false`，不会把拼错或缺失的文件静默创建成目录。在 Linux 主机上应由部署系统把真实私钥设置为 `101:101` 所有并使用 `0400`（证书可使用 `0440`），不能把生产私钥改成全局可读或全局可写来绕过权限问题。
7. 生产 Compose 的五个服务、两个网络、服务入网关系、命令、健康探针、端口和挂载均为固定白名单；不允许调试 Sidecar、设备/GPU、host user/cgroup/IPC/PID/network namespace、未批准的 `security_opt`、生命周期命令钩子、`volumes_from`、Compose config/secret 或额外 tmpfs。挂载仅允许 MySQL/Redis 命名数据卷及公网 Nginx 的两个只读 TLS 文件；不得挂载 Docker Socket，也不能以“只读”为理由增加宿主文件。
8. 通过密码管理系统分别注入 `WEB_STARTER_MANAGEMENT_USERNAME` 与至少 32 个随机字符的 `WEB_STARTER_MANAGEMENT_PASSWORD`。生产 Compose 和应用启动校验都会拒绝缺失、弱值、占位值、Web 管理员同名或与其他应用秘密复用的配置。

生产镜像启动示例：

```bash
export WEB_STARTER_APP_IMAGE='registry.example.internal/web-starter/app'
export WEB_STARTER_NGINX_IMAGE='registry.example.internal/web-starter/nginx'
export WEB_STARTER_APP_DIGEST='sha256:<64-hex-from-release-evidence>'
export WEB_STARTER_NGINX_DIGEST='sha256:<64-hex-from-release-evidence>'
export WEB_STARTER_MYSQL_IMAGE='mysql:8.4@sha256:<verified-64-hex>'
export WEB_STARTER_REDIS_IMAGE='redis:7.4-alpine@sha256:<verified-64-hex>'
docker compose --env-file /run/secrets/web-starter.env \
  -f compose.production.yaml pull
docker compose --env-file /run/secrets/web-starter.env \
  -f compose.production.yaml up --no-build -d
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
java -jar web-starter-admin/target/web-starter-admin-2.0.0-SNAPSHOT.jar
```

启动前端：

```bash
cd web-starter-web
pnpm install
pnpm dev
```

Vite 开发代理把 `/api`、`/mcp`、`/oauth2` 和 `/.well-known` 转发到本地后端。

## 外网 MCP

外网 MCP 必须使用独立 HTTPS 域名和稳定的 OAuth Issuer。公网 Nginx 配置已经作为只读内容固化在 Nginx 镜像中；`compose.public-mcp.yaml` 用于本地双入口验收，`compose.production.yaml` 则直接选择镜像内的 `/etc/nginx/nginx-public.conf`，避免生产主机用可变配置覆盖已扫描镜像：

- 只暴露 `/mcp`、OAuth 端点、登录所需的最小静态资源与认证 API，以及 `/.well-known` 元数据。
- 不暴露完整管理端路由和普通业务 `/api/**`。
- Nginx 覆盖 `X-Web-Starter-Ingress: public`，应用据此拒绝长期 PAT 和服务账号令牌。
- 外网用户 Agent 使用 Authorization Code + PKCE。
- 外网无人值守 Agent 使用 Client Credentials 换取短时访问令牌。
- `WEB_STARTER_OAUTH_ISSUER` 必须与浏览器和 Agent 访问到的 HTTPS Issuer 完全一致。
- 外网 HTTPS 部署必须设置 `WEB_STARTER_COOKIE_SECURE=true`；仅本地 HTTP 开发允许为 `false`。
- `WEB_STARTER_MCP_ALLOWED_HOSTS` 必须显式加入正式 MCP 主机名；非标准端口也必须包含在白名单中。Nginx 会保留客户端看到的 Host 与端口，并覆盖所有 `X-Forwarded-*` 请求头。
- 浏览器型 Agent 还必须在 `WEB_STARTER_MCP_ALLOWED_ORIGINS` 中显式加入其完整 HTTPS Origin；服务端 Agent 不发送 `Origin` 时仍会强制校验 `Host`。
- 随附的内外网 Nginx 配置对 `/mcp` 设置了按来源 IP 的请求速率和并发连接上限；公网默认保持每分钟 120 次的持续速率，并允许 120 次短时突发，以容纳官方 SDK 的初始化、发现、调用、审计读取和显式关闭序列，以及同一 NAT 后的少量独立 Agent。正式环境应根据可信 Agent 数量调优，但不得删除这一保护，也不应把突发值降到一次正常 SDK 工作流都会被中断的水平。
- MCP Client 结束任务时必须发送带 `Mcp-Session-Id` 的 `DELETE /mcp` 释放会话。V2 在官方 SDK Servlet 传输之前使用 Redis 可重建索引强制执行空闲 TTL、绝对 TTL 和每主体 Session 上限；过期或不属于当前 Caller/Client 的 Session 在进入 SDK 前返回 404。SDK 仍负责协议级显式 DELETE 和优雅关闭节点内 Session。
- 应用在 Nginx IP 限流之外，按实时 Caller 主体、OAuth Client（内部令牌使用凭据 ID）和 Tool 的 `read/write/destructive/protocol` 风险级别执行原子 Redis 固定窗口限流。429 总是携带 `Retry-After`，限流事件只把低基数风险级别写入指标，并将结果写入 MCP 审计。

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
- `McpSdkCrudRuntimeIT`：通过官方 SDK 验证 `project.create/update/remove` 的并发首次调用、同参重放、异参冲突和稳定结果；再以短生命周期 Web 管理会话读回 MCP/业务操作审计，证明每个写操作只提交一次且审计不泄露令牌或幂等键明文。

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

低权限和 CRUD 验收需替换 `-Dtest` 类名；低权限回收后的复测额外设置 `WEB_STARTER_MCP_EXPECT_PROJECT_LIST_DENIED=true`。CRUD 验收还需要通过 `WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL`、`WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME` 和 `WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD` 建立短生命周期 Web 会话，以独立读回业务操作审计；PAT 仍只发送给 `/mcp`。使用内部 CA 或本地自签证书时，应把 CA 导入临时 Java truststore 并通过 `JAVA_TOOL_OPTIONS` 指定，不得关闭 TLS 验证。所有验收 Token 应在结束后立即吊销。

发布运行验收只执行一次 `McpSdkCrudRuntimeIT`。正式模式下测试本身在 detached、clean 的 candidate validation worktree 中编译执行，并把独立 Surefire XML 和证明清单写入仓库外的 `0700` 临时目录，文件保持 `0600`；清单绑定测试类与方法、测试源码、根 POM、MCP 模块 POM、报告哈希、发布 commit/tree/version/tag、隔离 Compose project 和审计 Trace 前缀。证明生成器与随后 `bin/web-starter verify` 的 MCP 层都会各自以只读 Git 命令确认 workspace 正好是仓库 top-level、`HEAD^{commit}`/`HEAD^{tree}` 等于候选身份、索引没有 skip-worktree/assume-unchanged，并且包含未跟踪文件在内的工作树保持 clean；三份源码的 candidate commit blob 还必须与工作区逐字节一致。统一验证不接受布尔跳过或自报 PASS，也不会再次写入业务数据；它独立解析私有 XML，要求恰好 1 个测试且 failure/error/skip/flake/retry 全为 0，并重新计算全部源码和报告哈希。任何陈旧报告、源码漂移、Git 身份或状态不一致、权限过宽或 XML/清单字段异常都会使该层失败。原始 Surefire 报告可能包含运行时系统属性，仅保留在任务结束即删除的私有目录，不作为公开发布附件。

生产环境不要使用临时生成的 RSA 密钥。首选由密钥管理系统注入单行 JSON JWK Set，并用 `WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID` 指定唯一活动 `kid`；活动 RSA JWK 必须包含私钥材料，retiring 验证键可以只含公钥。单行 Base64 编码的 PKCS#8 私钥和 X.509 公钥仅保留为单密钥兼容方式。以下兼容方式命令必须在受控临时目录或离线密钥工作站执行，不要在仓库目录执行：

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

把两条 Base64 输出分别注入 `WEB_STARTER_OAUTH_RSA_PRIVATE_KEY` 和 `WEB_STARTER_OAUTH_RSA_PUBLIC_KEY`。使用 JWK Set 时这两个变量保持为空，并注入 `WEB_STARTER_OAUTH_RSA_JWK_SET` 与 `WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID`。所有私钥都必须由密码管理系统托管，不得写入仓库、镜像层、普通部署日志或验收附件。

### RSA 签名密钥轮换与回退

计划轮换使用 active/retiring 多 `kid`，按以下步骤执行：

1. 离线生成新的至少 3072 位 RSA 密钥对并写入密钥管理系统；保留当前公钥作为 retiring 验证键，不再把旧私钥分发给应用。
2. 生成同时包含新活动私钥 JWK 与旧 retiring 公钥 JWK 的 JWK Set，将 `WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID` 指向新 `kid`。`kid` 必须稳定、唯一且与密钥版本可追溯；每个 retiring JWK 必须带标准 `exp` NumericDate，明确记录不包含截止时刻的 retain-until，active JWK 不得带 `exp` 或 `rev`。
3. 先在预发布环境验证 JWKS 同时发布两个公钥、新 Token 头使用活动 `kid`、旧 Token 在保留窗口内仍可调用 MCP，以及 PKCE、Client Credentials 和撤销检查不回退。
4. 在生产环境滚动部署同一 key-ring 版本。保留窗口至少覆盖旧 Access Token 的最大剩余 TTL；窗口内不得删除 retiring 公钥。
5. 到达 retiring JWK 的 `exp` 后先验证旧 Token 已被拒绝，再从 JWK Set 移除旧公钥并再次滚动部署；新 Token 必须继续正常。只有这一步完成后才销毁旧密钥版本。
6. 若轮换失败，把活动 `kid` 与完整 key-ring 引用回退到上一受控版本，并重新执行元数据、JWKS、换 Token 和真实 MCP 调用验证。

紧急泄露处置不等待旧 TTL：立即换键，在 retiring JWK 上写入标准 `rev` 对象并滚动部署受控 key-ring，同时撤销已登记的 OAuth Token、禁用受影响 Client 或主体，并要求所有 Agent 重新授权。`rev` 一旦存在就立即拒绝该键，不能把 `revoked_at` 当作未来调度时间。轮换和回退都必须留下变更审计，但审计内容不得包含任何密钥材料。

## 健康检查

- 存活：`GET /actuator/health/liveness`
- 就绪：`GET /actuator/health/readiness`
- 聚合健康：`GET /actuator/health`

readiness 会实际检查 MySQL 与 Redis；数据库验证使用有限的 2 秒
`Connection.isValid`，连接池获取连接默认最多等待 5 秒。可通过
`WEB_STARTER_DB_CONNECTION_TIMEOUT_MS` 和
`WEB_STARTER_DB_VALIDATION_TIMEOUT_MS` 调整连接池上限，但 validation 必须短于
connection timeout。liveness 不依赖外部组件，依赖故障时仍应保持 200。

私有 `nginx` 的容器健康检查通过私有入口读取应用 readiness；`mcp-public-nginx` 使用仅监听容器回环地址的 `/healthz`，同时验证公网 Nginx 和上游应用。可用以下命令读回状态：

```bash
docker compose ps
docker compose -f compose.yaml -f compose.public-mcp.yaml \
  exec -T mcp-public-nginx \
  wget -q -O - http://127.0.0.1:8081/healthz
```

健康状态只证明进程和被检查依赖的当前状态，不等同于登录、业务事务或 MCP 工具可用。部署验收仍需执行真实用例。

## 运维指标认证

管理服务器使用独立于 Web Session、OAuth、PAT 和服务账号的 Spring Security 认证边界：

- `/actuator/health`、`/actuator/health/liveness`、`/actuator/health/readiness` 保持匿名，只返回探针所需信息。
- `/actuator/info`、`/actuator/metrics/**`、`/actuator/prometheus` 只接受专用运维 HTTP Basic 凭据。
- 未配置凭据的开发实例对非健康端点保持 401；生产实例缺少凭据会在接流量前启动失败。
- 普通 Web 登录 Session 即使有效，也不能读取运维端点。
- 私有和公网 Nginx 均对 `info`、`metrics`、`prometheus` 返回 404；生产 Compose 不发布 App 的 8081 端口。

HTTP Basic 只能在容器回环、受控运维网络或 TLS/mTLS 运维代理后使用。远程采集不得把 8081 暴露到公网，也不得在命令行参数、Shell 历史或日志中携带密码。采集器应从密码管理系统读取凭据；人工诊断可使用权限 0600、仓库外的 curl 配置文件，例如：

```bash
curl --config /run/secrets/web-starter-operations.curl \
  http://127.0.0.1:8081/actuator/metrics
```

该配置文件由部署平台生成并应包含 `user = "<operations-user>:<operations-password>"`；用后立即清理。不能把它提交到仓库或作为验收附件。验收必须分别证明匿名/错误凭据为 401、专用凭据为 200、两个 Nginx 入口为 404，并以真实 REST 与 MCP 行为验证计数增量。发布候选的固定指标、结构化 Trace、原始报告和独立门禁边界见[可观测性运行证据](observability-runtime-evidence.md)。

## 日志与故障定位

- 容器现场使用 `docker compose logs --since 30m app nginx` 查看；双入口部署同时查看 `mcp-public-nginx`。生产环境应接入受控的集中日志系统并配置容量、保留期和访问权限，不能依赖容器可写层长期保存。
- 应用日志以 Trace ID 串联入口错误；登录日志、操作审计和 MCP 调用日志以 MySQL 为事实来源。排障时先按 Trace ID 关联，避免在普通日志中复制请求头、Cookie 或 Token。
- 监控至少覆盖 Nginx 5xx、应用启动失败、健康探针、数据库连接池、Redis 连接、OAuth 换 Token 失败率和 MCP 失败率。
- 导出日志用于工单前必须再次检查并脱敏；禁止输出密码、`Authorization`、Session Cookie、完整 PAT、服务账号令牌、OAuth Client Secret、Pepper 或私钥。

## 备份与恢复

MySQL 备份必须包含业务、审计和安全凭据表。Redis 不是业务事实来源；Redis 丢失只允许造成 Session 失效。生产环境应按本组织的 RPO/RTO 设置频率、异地副本、保留期、加密策略和恢复授权。

V2 不再使用散落的手工 `mysqldump`/`mysql` 命令作为验收证据。仓库提供带目标校验、校验和、版本、Flyway、关键行数和隔离演练报告的安全入口，完整步骤见 [V2 备份、恢复与 Redis 丢失演练](./recovery-rehearsal.md)。恢复默认只能创建 `<源库>_restore_*` 新库；工具没有覆盖、删库或删卷选项。

迁移发布前还必须执行 [V2-AC-07 迁移失败保护演练](./migration-failure-rehearsal.md)：使用显式本地不可变镜像，在无宿主端口、无共享卷、随机 internal network 的隔离环境中只读注入故障 Flyway 文件，证明应用非零退出、从未 ready 且失败版本没有 `success=1` 记录。该子项通过但 V2-AC-40 尚未完整通过时，V2-AC-07 顶层只能标记为 `NOT_COVERED`，并以 `statusDetail=PENDING_AC40` 说明依赖。

备份包必须加密后传送到受控备份存储，不能放在仓库、容器可写层或普通工单。每次 Flyway 升级前先使用仓库官方入口完成备份；该入口按源库 Flyway 版本校验必需表，并把当时实际存在的全部基础表写入清单，旧版本不会查询尚未引入的表。恢复时缺表、多表或行数差异都会失败。已应用迁移不得修改。数据库恢复成功仍需重新执行真实登录、Project CRUD、权限拒绝、OAuth 和官方 MCP SDK 调用，不能只看 SQL 导入或容器健康。

覆盖生产库属于独立的破坏性灾难恢复操作，不由仓库脚本自动执行，只能在已批准维护窗口由获授权人员按组织 Runbook 完成。

## 升级与回滚

发布镜像只能由 `release-supply-chain` 工作流构建。工作流先推送 commit 候选镜像，再针对实际 digest 生成 SBOM、扫描秘密和漏洞；门禁通过后才把同一 digest 提升为版本 tag。完整策略和证据见[供应链与发布镜像](supply-chain.md)。生产主机不执行 `docker build` 或 `docker compose build`。

```bash
python3 scripts/release_security_gate.py \
  --manifest /absolute/release-evidence/release-images.json \
  --exceptions security/high-vulnerability-exceptions.json \
  --output /absolute/release-evidence/security-gate-summary.rechecked.json
docker compose --env-file /run/secrets/web-starter.env \
  -f compose.production.yaml exec -T mysql sh -ec \
  'exec mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -Nse "SELECT version, success FROM flyway_schema_history ORDER BY installed_rank DESC LIMIT 1"'
```

升级步骤：

1. 记录当前 Git 版本、镜像标签与 digest、Flyway 版本和配置版本，完成并验证数据库备份。
2. 在空库预发布环境使用目标镜像执行迁移，完成 Web、OAuth、MCP、审计和双入口验收。
3. 从门禁证据复制镜像仓库和 digest，使用 `docker compose -f compose.production.yaml up --no-build -d`；该 Compose 的静态策略检查会拒绝 `build`、可变镜像和降级的 App/Nginx 隔离配置。
4. 检查三个应用层容器健康状态，再执行真实登录、Project CRUD、权限拒绝和 MCP 调用。观察 Nginx 5xx、连接池、OAuth/MCP 失败率和审计写入。

应用回滚只切换到上一次发布证据中记录的不可变 digest：

```bash
export WEB_STARTER_APP_DIGEST='sha256:<previous-app-digest>'
export WEB_STARTER_NGINX_DIGEST='sha256:<previous-nginx-digest>'
docker compose --env-file /run/secrets/web-starter.env \
  -f compose.production.yaml pull app nginx mcp-public-nginx
docker compose --env-file /run/secrets/web-starter.env \
  -f compose.production.yaml up --no-build -d app nginx mcp-public-nginx
```

如果目标升级执行了不向后兼容的数据库迁移，不得直接运行旧应用。优先发布向前修复迁移；确需恢复旧数据库时，进入维护窗口并使用已演练的升级前备份。回滚后重新执行完整运行验收，而不能只看容器 `Up` 或健康检查。

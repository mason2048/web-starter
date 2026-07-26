# V1 Compose 与 V2 开发工具生命周期运行证据

AC-02、AC-37、V2-AC-16 与 V2-AC-17 共用一组真实 Docker 运行证据。普通单元测试只能证明命令参数构造，不能证明一次性管理员密码在首次初始化后已从环境移除、重启不会覆盖既有密码、运行日志不泄露明文、本机依赖可诊断、`up --wait` 真正等到服务健康、默认 `down` 保留卷、真实业务数据跨重启保留，或危险删除在调用 Docker 前被拒绝。AC-02 还必须绑定同一候选的七层统一验证，以复用仓库秘密扫描结果；AC-37 还必须同时绑定生产 Compose 展开模型、生产入口策略、同一候选的运行身份和完整发布运行验收。本报告不能单独证明仓库无秘密或 Nginx 是生产默认唯一用户入口。

## 隔离演练

发布工作流为本次 commit 创建独立 `web-starter-tooling-*` Compose project、四个动态回环端口以及仓库外 `0600` 环境文件。环境文件使用一次性随机秘密，只传给 Compose 和工具进程，不写入报告或 Artifact。

演练固定执行：

1. 确认该 Compose project 没有容器、卷或网络遗留。
2. 执行 `doctor`，要求 Java、Maven Wrapper、Node、pnpm、Docker Engine、Compose、`up --wait`、工作区文件、私有环境文件、必需配置和四个端口的 22 项清单全部为 `PASS`；报告只保留状态、可操作说明和完整输出哈希，不保留配置值。
3. 通过 `WEB_STARTER_APP_REFERENCE` 与 `WEB_STARTER_NGINX_REFERENCE` 强制使用 App/Nginx 的完整不可变 digest reference，并为 MySQL/Redis 注入已验证 digest reference 后执行 `up --no-build`；不得退回候选 tag。四服务必须全部 `running/healthy`。用一次性随机管理员密码完成真实 CSRF + HTTP Session 登录，数据库内只读取 `password_hash` 的 SHA-256，并扫描第一次运行日志确认明文密码命中数为零。
4. 通过 MySQL 容器内客户端写入一条由 Compose project 确定、内容固定的 `biz_project` 记录并读取数据库侧 SHA-256；SQL 仅走标准输入，数据库密码只从容器环境读取，不进入命令参数或报告。
5. 执行不带 `--volumes` 的默认 `down`；容器和网络必须消失，MySQL/Redis 两个命名卷必须保留。随后以 `0600` 临时文件和原子替换从私有环境文件中清空管理员初始密码，不删除其他配置。
6. 分别验证“只有确认参数但无 `--volumes`”“确认项目名不一致”“非交互且缺少确认”三条路径在调用 Docker 前失败，且保留卷不发生变化。
7. 再次 `up --no-build`，要求四服务恢复健康且 image ID 不变；使用第一次的密码再次完成真实登录，数据库密码哈希指纹必须不变，第二次运行日志的明文命中数仍为零。再次读取同一 Project，行数必须仍为 1，数据库侧 SHA-256 必须与重启前以及验证器根据固定字段独立重算的结果完全一致。
8. 最后使用 `--volumes --confirm-delete-volumes <exact-project>` 显式清理；该专用项目的容器、网络和卷必须全部为零。

`compose.yaml` 的普通本地开发仍使用 `WEB_STARTER_APP_IMAGE`、`WEB_STARTER_NGINX_IMAGE` 与 `WEB_STARTER_IMAGE_TAG`，但完整 `WEB_STARTER_APP_REFERENCE`/`WEB_STARTER_NGINX_REFERENCE` 存在时必须优先使用；MySQL 和 Redis 保留本地默认值，同时允许发布演练通过 `WEB_STARTER_MYSQL_IMAGE` 与 `WEB_STARTER_REDIS_IMAGE` 注入完整 digest reference。生产仍只使用独立的 `compose.production.yaml`。

## 独立验证与发布绑定

原始 `v2-tooling-lifecycle-runtime.json` 位于仓库和公开 Artifact 之外的独立 `0700` 目录。主全栈运行生成 `runtime-version-identity.json` 后，clean candidate 中的独立验证器重新核对：

- 注释 tag、commit、tree、版本和固定源码哈希；
- 22 项 Doctor 清单、低泄漏报告结构和精确退出码；
- 两次真实管理员登录、环境中初始密码已清空、重启前后数据库密码哈希指纹不变、两段运行日志明文命中数为零；
- 两次健康启动、默认保留卷、Project 确定性身份、重启前后业务行数与内容指纹、拒绝路径零副作用和显式清理零资源；
- 四个容器的 digest reference 与 image ID 均和主发布栈运行身份一致。

只有 canonical `v2-tooling-lifecycle-runtime-summary.json` 进入公开发布 Artifact；它只保留登录状态、Session 是否建立、密码哈希的二次 SHA-256、日志哈希与命中计数，不保留初始密码、Cookie、CSRF Token、数据库密码或原始日志。最终发布门禁再次读取受控 raw、重跑验证器并逐字节比较 canonical 摘要；缺少 raw、Compose project、两次登录、密码移除、不变的哈希指纹、零日志命中、确定性业务行、运行身份或任一状态漂移都会拒绝 AC-02、AC-37 与 V2-AC-16/17 的 `PASS`。即使本摘要通过，AC-02 缺少同一候选的七层统一验证或 AC-37 缺少生产 Compose/策略、运行身份和完整发布运行验收时，仍会 fail closed。

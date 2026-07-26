# web-starter V2 验收证据模板

> 使用时复制为带日期的记录，并绑定同一个 clean candidate commit、版本、镜像 digest 与证据目录。默认状态必须保持 `NOT_COVERED`，只有证据直接覆盖完整通过标准时才能改为 `PASS`。

## 1. 候选与环境身份

| 项目 | 记录 |
|---|---|
| V2 tag / version |  |
| V2 Git commit / clean 状态 |  |
| V1 source tag / commit | `v1.0.0` / `5ebdb238650d182c17e1493adf47aaa3324f19cb` |
| 验收日期 / 执行人 |  |
| 操作系统 / 架构 |  |
| Java / Maven |  |
| Node.js / pnpm |  |
| Docker Engine / Compose |  |
| 浏览器 / Playwright |  |
| MySQL image `@sha256` |  |
| Redis image `@sha256` |  |
| App image `@sha256` |  |
| Nginx image `@sha256` |  |
| OAuth Issuer / Resource Audience |  |
| V1 数据快照清单 SHA-256 |  |
| 证据根目录 / 清单 SHA-256 |  |

证据不得包含密码、Cookie、Token、PKCE verifier、Client Secret、Pepper、私钥或未脱敏的 Compose 配置。原始运行日志仅保留在受限临时目录；发布目录只接受允许字段的结构化、脱敏证据。

## 2. 结果和证据类型

- `PASS`：证据直接覆盖该项全部通过条件，并绑定本表中的同一候选身份。
- `FAIL`：行为与冻结基线矛盾。
- `NOT_COVERED`：未执行、只完成部分路径，或现有证据强度不足。
- `ENV_REQUIRED`：需要具体目标环境才能完成；不等于通过。

证据类型使用 `static`、`unit`、`integration`、`container`、`browser`、`protocol`、`recovery`、`supply-chain` 或 `target-env`。构建、单元测试、容器 healthy、HTTP 200 或页面可打开不能替代更强的运行时证据。

本模板用于人工审阅和逐项追踪，不是发布门禁的可信输入本身。正式发布账本中的 `PASS` 还必须由 `scripts/release_evidence_gate.py` 已注册的独立语义验证器重新计算，并绑定实际 `repo://` 或 `artifact://` 字节；文件哈希正确、自报 `status=PASS` 或本表人工填写为 PASS 都不能自动放行。尚未接入独立验证器的项目必须保持 `NOT_COVERED`，直到验证链完成。

## 3. V2 逐项账本

| ID | 级别 | 验收域 | 状态 | 证据类型 | 命令 / Artifact / SHA-256 | 缺口或备注 |
|---|---|---|---|---|---|---|
| V2-AC-01 | P0 | V1 来源 | NOT_COVERED |  |  |  |
| V2-AC-02 | P0 | 版本信息 | NOT_COVERED |  |  |  |
| V2-AC-03 | P0 | 空库安装 | NOT_COVERED |  |  |  |
| V2-AC-04 | P0 | V1 原地升级 | NOT_COVERED |  |  |  |
| V2-AC-05 | P0 | 凭据兼容 | NOT_COVERED |  |  |  |
| V2-AC-06 | P0 | 协议兼容 | NOT_COVERED |  |  |  |
| V2-AC-07 | P0 | 迁移失败保护 | NOT_COVERED |  |  |  |
| V2-AC-08 | P0 | 项目初始化 | NOT_COVERED |  |  |  |
| V2-AC-09 | P0 | 输出边界 | NOT_COVERED |  |  |  |
| V2-AC-10 | P0 | 项目可运行 | NOT_COVERED |  |  |  |
| V2-AC-11 | P0 | 模块生成 | NOT_COVERED |  |  |  |
| V2-AC-12 | P0 | 安全预检 | NOT_COVERED |  |  |  |
| V2-AC-13 | P0 | 显式 MCP | NOT_COVERED |  |  |  |
| V2-AC-14 | P0 | 生成模块闭环 | NOT_COVERED |  |  |  |
| V2-AC-15 | P0 | 生成器隔离 | NOT_COVERED |  |  |  |
| V2-AC-16 | P1 | 环境诊断 | NOT_COVERED |  |  |  |
| V2-AC-17 | P1 | 安全启停 | NOT_COVERED |  |  |  |
| V2-AC-18 | P0 | 统一验证 | NOT_COVERED |  |  |  |
| V2-AC-19 | P1 | API 契约 | NOT_COVERED |  |  |  |
| V2-AC-20 | P1 | 前端复用 | NOT_COVERED |  |  |  |
| V2-AC-21 | P1 | 页面状态 | NOT_COVERED |  |  |  |
| V2-AC-22 | P1 | 前端质量 | NOT_COVERED |  |  |  |
| V2-AC-23 | P0 | 个人安全 | NOT_COVERED |  |  |  |
| V2-AC-24 | P0 | 级联失效 | NOT_COVERED |  |  |  |
| V2-AC-25 | P0 | 登录防护 | NOT_COVERED |  |  |  |
| V2-AC-26 | P0 | JWKS 轮换 | NOT_COVERED |  |  |  |
| V2-AC-27 | P0 | Pepper 轮换 | NOT_COVERED |  |  |  |
| V2-AC-28 | P0 | Client 密钥轮换 | NOT_COVERED |  |  |  |
| V2-AC-29 | P0 | Production fail-fast | NOT_COVERED |  |  |  |
| V2-AC-30 | P1 | 凭据管理 | NOT_COVERED |  |  |  |
| V2-AC-31 | P0 | 写操作幂等 | NOT_COVERED |  |  |  |
| V2-AC-32 | P0 | 幂等冲突 | NOT_COVERED |  |  |  |
| V2-AC-33 | P0 | Tool 契约 | NOT_COVERED |  |  |  |
| V2-AC-34 | P0 | Session 生命周期 | NOT_COVERED |  |  |  |
| V2-AC-35 | P0 | 应用级限流 | NOT_COVERED |  |  |  |
| V2-AC-36 | P0 | 统一安全回归 | NOT_COVERED |  |  |  |
| V2-AC-37 | P1 | 日志与指标 | NOT_COVERED |  |  |  |
| V2-AC-38 | P0 | 健康语义 | NOT_COVERED |  |  |  |
| V2-AC-39 | P1 | Trace 检索 | NOT_COVERED |  |  |  |
| V2-AC-40 | P0 | 恢复演练 | NOT_COVERED |  |  |  |
| V2-AC-41 | P0 | Redis 丢失 | NOT_COVERED |  |  |  |
| V2-AC-42 | P0 | 全栈发布门禁 | NOT_COVERED |  |  |  |
| V2-AC-43 | P0 | 供应链 | NOT_COVERED |  |  |  |
| V2-AC-44 | P0 | 容器硬化 | NOT_COVERED |  |  |  |
| V2-AC-45 | P0 | 发布清单 | NOT_COVERED |  |  |  |

## 4. 必须单独留证的运行路径

| 路径 | 必需证据 | Artifact / SHA-256 | 结果 |
|---|---|---|---|
| V2 空库 | Flyway、登录、Project CRUD、403、审计、OAuth、MCP |  | NOT_COVERED |
| V1 → V2 | 升级前后数据清单、凭据策略、协议兼容、审计读回 |  | NOT_COVERED |
| 项目初始化 | 派生身份、后端/前端门禁、扫描、空库 Compose、登录 |  | NOT_COVERED |
| 模块生成 | 迁移、REST CRUD、409、403、审计、浏览器、可选 MCP SDK、清理 |  | NOT_COVERED |
| 身份与凭据 | Session、级联失效、限速、JWKS/Pepper/Client Secret 轮换 |  | NOT_COVERED |
| MCP 治理 | 并发幂等、冲突、Schema、Session TTL/上限/DELETE、429、审计 |  | NOT_COVERED |
| 可观测与故障 | 指标、Trace、MySQL/Redis readiness/liveness、公共端点 404 |  | NOT_COVERED |
| 恢复 | 备份清单、新库恢复、登录/CRUD/403/OAuth/MCP、Redis 丢失 |  | NOT_COVERED |
| 供应链 | 同一 digest、SBOM、秘密/漏洞门禁、容器硬化、发布清单 |  | NOT_COVERED |
| V1 全量回归 | V1 的 42 项逐项结果及交叉引用 |  | NOT_COVERED |

## 5. 目标环境独立账本

以下项目通常先记录为 `ENV_REQUIRED`；它们不阻止通用仓库形成 V2，但未完成时不能声称具体环境生产就绪。

| 项目 | 状态 | 证据 / 责任人 / 到期日 |
|---|---|---|
| 正式 DNS、CA、续期、防火墙、负载均衡、可信代理链 | ENV_REQUIRED |  |
| 组织密钥托管、集中日志、指标、告警与访问审批 | ENV_REQUIRED |  |
| 真实备份介质、异地保留、RPO/RTO 与恢复责任 | ENV_REQUIRED |  |
| 内网 Agent、外网 Agent、容量、并发、时延与稳定性 | ENV_REQUIRED |  |

## 6. 失败、例外与最终结论

每个失败项记录原因、影响、修复 commit、复测 artifact。Critical 漏洞没有例外；High 漏洞例外必须包含责任人、理由和到期日。P1 只有用户明确书面接受才可不阻断，且仍保留原始状态和缺口。

- [ ] 45 项均有明确状态，没有空白项
- [ ] 36 项 P0 全部为 `PASS`
- [ ] 9 项 P1 全部为 `PASS`，或有用户明确接受记录
- [ ] V1 42 项回归全部有独立证据
- [ ] 没有把 `NOT_COVERED` / `ENV_REQUIRED`、静态检查或构建成功折算为运行时 `PASS`
- [ ] tag、commit、版本、镜像 digest、SBOM、Flyway 和 Artifact 哈希互相一致
- [ ] 临时凭据、私钥、原始日志和隔离 Compose 资源已清理

结论：`PASS / FAIL / INCOMPLETE`

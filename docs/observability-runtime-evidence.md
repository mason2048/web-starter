# V2 可观测性运行证据

V2-AC-37 只有在真实发布栈产生指标增量、结构化 Trace 日志，并由 clean release candidate 中的独立验证器重算后才能声明 `PASS`。应用启动、Actuator 返回 200、日志中出现一个 Trace ID 或指标文件自报 `status: PASS` 都不能单独满足本项。

## 固定观测面

运维端口保留匿名健康检查；`info`、`metrics` 和 `prometheus` 只接受独立运维身份。正式验收核对匿名、错误凭据和正确凭据的完整授权矩阵，并要求以下指标族存在：

- 操作审计、审计持久化失败和登录尝试；
- MCP 调用次数与耗时、Session 生命周期和限流；
- Web/OAuth/MCP 协议请求与统一限流；
- HikariCP 连接使用情况。

所有自定义标签值来自提交的有限枚举。禁止把用户名、主体 ID、Client ID、Token、Trace ID、项目 ID、路径参数、IP 或异常文本写成指标标签。Trace ID 只进入受控结构化日志和审计字段。

## 正式证据流程

1. 主栈就绪后，以专用运维凭据生成权限为 `0600` 的 `operational-metrics-baseline.json`。
2. 执行真实登录、Project 事务、OAuth、MCP Tool、Session 和限流用例。
3. 生成 `operational-metrics-runtime.json`，要求登录、审计、MCP 次数与耗时、Session、三个协议入口、限流和 Hikari 使用量都相对基线增加。
4. 从 App 容器日志提取一条 `protocol_request` ECS 记录，只保留时间、级别、Trace ID、入口、方法、结果和原始行哈希；凭据形态内容会被拒绝。
5. clean、annotated-tag candidate 中的 `validate_observability_evidence.py` 重新读取两份原始报告、`runtime-version-identity.json` 和固定源码，核对 commit、tag、版本、Compose project、App/Nginx digest reference 与 image ID。
6. 仅把 canonical `v2-observability-runtime-summary.json` 放入发布 Artifact；发布门禁再次执行同一语义验证并逐字节比较摘要。

两份原始指标报告不进入公开 Artifact，但必须与其他受控 raw 发布证据一起长期归档，否则将来无法完整重放 V2-AC-37。

## 证据边界

该证据证明当前候选在隔离发布栈中的指标授权、低基数维度、关键行为增量和结构化 Trace 关联。它不证明目标公司的集中日志平台、告警路由、容量、保留期、时钟同步、网络隔离或值班响应已经配置；这些仍是实际部署环境的 `ENV_REQUIRED` 验收项。

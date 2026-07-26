# V2 前端基础契约

本说明记录 V2-AC-19～22 的仓库侧自动门禁。它不能替代真实浏览器、390px、键盘或无障碍验收，也不能把一次生产构建等同于部署通过。

## 私有 API 契约

`web-starter-web/contracts/private-api.openapi.json` 是 OpenAPI 3.1 私有管理入口契约。当前把可复制的 Project CRUD 作为强类型参考闭环：每个 operation 都声明请求/响应 TypeScript 类型绑定，`pnpm contract:check` 重新渲染 `src/api/generated/privateApiContract.ts` 并逐字比较。契约或生成类型任一侧单独变化都会失败；`src/api/projects.ts` 实际使用生成的 method、path、CSRF 和请求/响应类型。

扩展契约时运行：

```bash
cd web-starter-web
pnpm contract:write
pnpm contract:check
```

生成文件必须连同 OpenAPI 差异一起审查，不能跳过 `contract:check` 手工修改生成结果。公共 MCP 虚拟主机不发布这份管理契约；公共入口的 Explorer、契约 URL 和非白名单路径是否为 404 仍需在隔离部署上采集 HTTP 运行证据。

## 单一导航清单

`src/navigation/manifest.ts` 是应用页面唯一清单，并派生：

- Vue Router 子路由；
- 桌面和移动侧栏；
- 面包屑；
- `⌘/Ctrl + K` 命令搜索。

离线模块生成器只向清单锚点写入一条记录，不再分别修改 Router 和 Sidebar。清单单测检查路径/名称唯一性以及四个投影的一致性。

## CRUD 与页面状态

Project 和离线生成模块共同使用 `useStandardCrudPage`。该基础件负责：

- 只接受正整数页码和 `[10, 20, 50]` 页大小；
- 对状态查询采用 allow-list；
- 将 `page`、`size`、`keyword`、`status` 写入 URL，并响应浏览器前进/后退；
- 统一加载、空态、成功和错误 phase；
- 将 400/401/403/404/409/429/500+ 转成固定页面状态并保留 Trace ID。

客户端未知地址进入显式 404 页面；HTTP 401 仍由全局会话失效流程返回登录页，403 由路由守卫进入无权页面。单元测试只证明解析、映射和组件契约，不证明真实浏览器行为。

## Bundle budget

`bundle-budget.json` 是生产构建的硬门禁，按未压缩字节限制入口 JS、异步 JS、CSS、其他单文件和生产目录总量。Vite 输出 manifest 后，`scripts/check-bundle-budget.mjs` 必须找到 entry 和所有产物；预算、manifest 或产物缺失都会失败。当前预算为：

| 项目 | 上限 |
| --- | ---: |
| 入口 JavaScript | 850,000 B |
| 单个异步 JavaScript | 350,000 B |
| 单个 CSS | 400,000 B |
| 其他单文件 | 500,000 B |
| 生产产物总量 | 1,800,000 B |

`pnpm build` 固定依次执行契约漂移检查、TypeScript 检查、Vite 生产构建、bundle budget 和 production mount smoke；不能只运行 `vite build` 作为验收证据。mount smoke 会从真实 Vite manifest 加载最终 ESM entry，在隔离 DOM 中实际执行并确认 Vue 根节点已挂载，能够阻断“构建成功但生产 chunk 初始化时报错、页面空白”的回归。它仍不替代真实浏览器业务流程。

## 仍需运行时验收

- 桌面、平板和 390px 下完成真实登录、Project 查询/分页和 CRUD；
- 键盘完整操作命令搜索、侧栏、表单、抽屉和确认框，检查焦点顺序与可见焦点；
- 使用真实 401/403/404/409/429/500 响应核对文案、Trace ID 和恢复动作；
- 执行基础无障碍扫描并人工核对语义、标签和对比度；
- 从公共 MCP HTTPS 入口请求管理 OpenAPI/Explorer 候选 URL并确认全部 404。

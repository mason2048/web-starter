import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test, expect, type Browser, type Page } from '@playwright/test'

interface RuntimeManifest {
  schemaVersion: number
  privateBaseUrl: string
  publicBaseUrl: string
  ownerId: string
  projectId: string
  accountUserId: string
  publicClientId: string
  redirectUri: string
  credentialFixtures: {
    longUnusedName: string
    expiringName: string
    revokedName: string
    restrictedName: string
  }
  tokenFiles: {
    accountUser: string
    patCrud: string
  }
}

interface AccountUserCredential {
  username: string
  password: string
}

interface CsrfRouteProbe {
  method: 'POST' | 'PUT' | 'DELETE'
  template: string
  probePath: string
  authentication: 'ANONYMOUS' | 'ADMIN'
  bodyKind: 'NONE' | 'EMPTY_JSON' | 'LOGIN'
}

interface CsrfRouteMatrix {
  schemaVersion: number
  routes: CsrfRouteProbe[]
}

interface PageData<T> {
  records: T[]
  total: number
  page: number
  size: number
}

interface LoginAudit {
  id: string
  username: string
  result: string
  ipAddress: string
  userAgent: string
  traceId: string
  createdAt: string
}

interface OperationAudit {
  id: string
  actorType: string
  actorId: string
  actorName: string
  module: string
  action: string
  resourceType: string
  resourceId: string
  result: string
  requestMethod?: string
  requestPath?: string
  ipAddress?: string
  durationMs: number
  detailJson?: string
  traceId: string
  createdAt: string
}

interface MutationEnvelope<T> {
  data?: T
  traceId?: string
}

interface IdentifiedResource {
  id: string | number
  version?: number
}

interface ManagedUser extends IdentifiedResource {
  username: string
  displayName?: string
  email?: string
  mobile?: string
  status: 'ENABLED' | 'DISABLED'
  version: number
  roleIds: Array<string | number>
}

interface CreatedOAuthClient {
  client: IdentifiedResource
}

interface McpAudit {
  id: string
  actorId: string
  actorName: string
  toolName: string
  result: string
  errorCode?: string
  idempotencyKeyHash?: string
  replayed?: boolean
  traceId: string
  createdAt: string
}

interface TraceAudit {
  traceId: string
  loginLogs: LoginAudit[]
  operationLogs: OperationAudit[]
  mcpCalls: McpAudit[]
  truncated: boolean
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`${name} is required`)
  return value
}

function runtimeManifest(): RuntimeManifest {
  const document = JSON.parse(
    readFileSync(requiredEnvironment('WEB_STARTER_ACCEPTANCE_MANIFEST'), 'utf8'),
  ) as RuntimeManifest
  if (document.schemaVersion !== 1) throw new Error('Unsupported release runtime manifest')
  return document
}

function accountUserCredential(runtime: RuntimeManifest): AccountUserCredential {
  const document = JSON.parse(readFileSync(runtime.tokenFiles.accountUser, 'utf8')) as AccountUserCredential
  if (!document.username || !document.password) throw new Error('Invalid account-security credential file')
  return document
}

function csrfRouteMatrix(): CsrfRouteMatrix {
  const document = JSON.parse(
    readFileSync(new URL('../../security/web-csrf-route-matrix.json', import.meta.url), 'utf8'),
  ) as CsrfRouteMatrix
  if (document.schemaVersion !== 1 || document.routes.length === 0) {
    throw new Error('Invalid Web CSRF route matrix')
  }
  return document
}

function bearerFromFile(path: string): string {
  const document = JSON.parse(readFileSync(path, 'utf8')) as { token?: string; access_token?: string }
  const value = document.token || document.access_token
  if (!value) throw new Error('Invalid bearer response file')
  return value
}

async function authenticatedGet<T>(
  page: Page,
  baseUrl: string,
  path: string,
  params: Record<string, string | number>,
): Promise<T> {
  const url = new URL(path, baseUrl)
  Object.entries(params).forEach(([name, value]) => url.searchParams.set(name, String(value)))
  const response = await page.request.get(url.toString())
  if (response.status() !== 200) {
    throw new Error(`SAFE_HTTP_STATUS_${response.status()}`)
  }
  const envelope = await response.json() as { data?: T }
  if (!envelope.data) throw new Error('Authenticated audit query returned no data')
  return envelope.data
}

async function authenticatedMutation<T>(
  page: Page,
  method: 'POST' | 'PUT' | 'DELETE',
  path: string,
  traceId: string,
  payload?: unknown,
  expectResponseData = true,
): Promise<T> {
  const result = await page.evaluate(async (request) => {
    const csrfResponse = await fetch('/api/auth/csrf')
    const csrfEnvelope = await csrfResponse.json() as {
      data?: { headerName?: string; token?: string }
    }
    const headerName = csrfEnvelope.data?.headerName || 'X-XSRF-TOKEN'
    const token = csrfEnvelope.data?.token
    if (csrfResponse.status !== 200 || !token) throw new Error('CSRF token missing')
    const headers: Record<string, string> = {
      [headerName]: token,
      'X-Trace-Id': request.traceId,
    }
    if (request.payload !== undefined) headers['Content-Type'] = 'application/json'
    const response = await fetch(request.path, {
      method: request.method,
      headers,
      body: request.payload === undefined ? undefined : JSON.stringify(request.payload),
    })
    let envelope: MutationEnvelope<T> | undefined
    try {
      envelope = await response.json() as MutationEnvelope<T>
    } catch {
      envelope = undefined
    }
    return {
      status: response.status,
      responseTraceId: response.headers.get('X-Trace-Id'),
      envelope,
    }
  }, { method, path, traceId, payload })
  if (result.status !== 200) {
    throw new Error(`Authenticated mutation failed with status ${result.status}`)
  }
  if (result.responseTraceId !== traceId || result.envelope?.traceId !== traceId) {
    throw new Error('Authenticated mutation did not preserve its exact Trace ID')
  }
  if (expectResponseData && result.envelope.data === undefined) {
    throw new Error('Authenticated mutation returned no data')
  }
  return result.envelope.data as T
}

async function expectCompleteOperationAudit(
  page: Page,
  baseUrl: string,
  expected: {
    traceId: string
    actorId: string
    module: string
    action: string
    resourceType: string
    resourceId: string
    requestMethod?: string
  },
  forbiddenValues: string[] = [],
): Promise<OperationAudit> {
  const result = await authenticatedGet<PageData<OperationAudit>>(
    page,
    baseUrl,
    '/api/logs/operation',
    { page: 1, size: 20, traceId: expected.traceId },
  )
  expect(result.total).toBe(1)
  expect(result.records).toHaveLength(1)
  const record = result.records[0]
  expect(record).toMatchObject({
    actorId: expected.actorId,
    module: expected.module,
    action: expected.action,
    resourceType: expected.resourceType,
    resourceId: expected.resourceId,
    result: 'SUCCESS',
    traceId: expected.traceId,
  })
  expect(record.actorType).toMatch(/^[A-Z][A-Z0-9_]{1,31}$/)
  expect(record.actorName).not.toHaveLength(0)
  expect(record.durationMs).toBeGreaterThanOrEqual(0)
  expect(record.createdAt).not.toHaveLength(0)
  if (expected.requestMethod) expect(record.requestMethod).toBe(expected.requestMethod)
  expect(record.detailJson ?? null).toBeNull()
  assertAuditRedacted(record, forbiddenValues)
  return record
}

async function expectNoAuditRecords(
  page: Page,
  baseUrl: string,
  path: string,
  params: Record<string, string | number>,
): Promise<void> {
  const result = await authenticatedGet<PageData<unknown>>(page, baseUrl, path, params)
  expect(result.total).toBe(0)
  expect(result.records).toEqual([])
}

function absentTrace(value: string): string {
  return `absent-${createHash('sha256').update(value).digest('hex').slice(0, 20)}`
}

function occurredWindow(value: string): { occurredFrom: string; occurredTo: string } {
  const zoned = /(?:Z|[+-]\d\d:\d\d)$/.test(value) ? value : `${value}Z`
  const milliseconds = Date.parse(zoned)
  if (!Number.isFinite(milliseconds)) throw new Error('Audit timestamp is invalid')
  return {
    occurredFrom: new Date(milliseconds - 60_000).toISOString().slice(0, 19),
    occurredTo: new Date(milliseconds + 60_000).toISOString().slice(0, 19),
  }
}

function assertAuditRedacted(document: unknown, forbiddenValues: string[]): void {
  const encoded = JSON.stringify(document)
  if (forbiddenValues.some((value) => value && encoded.includes(value))) {
    throw new Error('Audit response exposed a forbidden secret value')
  }
  if (/"(?:access_token|refresh_token|client_secret|password|authorization|cookie|tokenHash|requestBody|responseBody)"\s*:/i.test(encoded)) {
    throw new Error('Audit response exposed a forbidden secret field')
  }
}

async function login(
  page: Page,
  baseUrl: string,
  username = requiredEnvironment('WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME'),
  password = requiredEnvironment('WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD'),
  destination = '/overview',
): Promise<void> {
  const loginUrl = new URL('/login', baseUrl)
  loginUrl.searchParams.set('redirect', destination)
  await page.goto(loginUrl.toString())
  await expect(page).toHaveTitle(/启程 Web Starter/)
  await expect(page.getByRole('heading', { name: '欢迎登录', exact: true })).toBeVisible()
  await page.getByPlaceholder('请输入用户名').fill(username)
  await page.getByPlaceholder('请输入密码').fill(password)
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await expect(page).toHaveURL((url) => url.pathname === destination)
  if (destination === '/overview') {
    await expect(page.getByRole('heading', { name: '概览', exact: true })).toBeVisible()
  }
}

async function expectCompleteCsrfWriteMatrix(
  browser: Browser,
  adminPage: Page,
  runtime: RuntimeManifest,
  loginCredential: AccountUserCredential,
): Promise<void> {
  const matrix = csrfRouteMatrix()
  const anonymousRoutes = matrix.routes.filter((route) => route.authentication === 'ANONYMOUS')
  const adminRoutes = matrix.routes.filter((route) => route.authentication === 'ADMIN')
  expect(anonymousRoutes).toHaveLength(1)

  for (const mode of ['ABSENT', 'WRONG'] as const) {
    const anonymousContext = await browser.newContext()
    try {
      const anonymousPage = await anonymousContext.newPage()
      await anonymousPage.goto(`${runtime.privateBaseUrl}/login`)
      const observation = await anonymousPage.evaluate(async (input) => {
        const csrfResponse = await fetch('/api/auth/csrf')
        const csrfEnvelope = await csrfResponse.json() as {
          data?: { headerName?: string }
        }
        const headerName = csrfEnvelope.data?.headerName
        if (csrfResponse.status !== 200 || !headerName) {
          throw new Error('CSRF metadata missing for anonymous write matrix')
        }
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          'X-Trace-Id': input.traceId,
        }
        if (input.mode === 'WRONG') headers[headerName] = 'invalid-csrf-proof'
        const response = await fetch(input.route.probePath, {
          method: input.route.method,
          headers,
          body: JSON.stringify(input.credential),
        })
        const meStatus = (await fetch('/api/auth/me')).status
        return { status: response.status, meStatus }
      }, {
        route: anonymousRoutes[0],
        credential: loginCredential,
        mode,
        traceId: `${requiredEnvironment('WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX')}-csrf-login-${mode.toLowerCase()}`,
      })
      expect(observation.status, `POST /api/auth/login ${mode} CSRF`).toBe(403)
      expect(observation.meStatus, `POST /api/auth/login ${mode} created a Session`).toBe(401)
    } finally {
      await anonymousContext.close()
    }
  }

  const csrfHeader = await adminPage.evaluate(async () => {
    const response = await fetch('/api/auth/csrf')
    const envelope = await response.json() as { data?: { headerName?: string } }
    if (response.status !== 200 || !envelope.data?.headerName) {
      throw new Error('CSRF metadata missing for authenticated write matrix')
    }
    return envelope.data.headerName
  })
  const statePaths = [
    '/api/users?page=1&size=100',
    '/api/roles?page=1&size=100',
    '/api/permissions',
    '/api/menus',
    '/api/configs?page=1&size=100',
    '/api/projects?page=1&size=100',
    '/api/security/oauth-clients',
    '/api/security/personal-tokens',
    '/api/security/service-accounts',
    '/api/security/me/sessions',
  ]
  const captureState = async (): Promise<Record<string, string | number>> => adminPage.evaluate(
    async (paths) => {
      const entries: Array<[string, string | number]> = []
      for (const path of paths) {
        const response = await fetch(path, { headers: { Accept: 'application/json' } })
        const envelope = await response.json() as { data?: unknown }
        if (response.status !== 200 || envelope.data === undefined) {
          throw new Error(`CSRF side-effect snapshot failed for ${path}`)
        }
        entries.push([
          path,
          path === '/api/security/me/sessions' && Array.isArray(envelope.data)
            ? envelope.data.length
            : JSON.stringify(envelope.data),
        ])
      }
      return Object.fromEntries(entries)
    },
    statePaths,
  )
  const stateBefore = await captureState()
  for (const [index, route] of adminRoutes.entries()) {
    for (const mode of ['ABSENT', 'WRONG'] as const) {
      const observation = await adminPage.evaluate(async (input) => {
        const headers: Record<string, string> = {
          'X-Trace-Id': input.traceId,
        }
        if (input.route.bodyKind !== 'NONE') headers['Content-Type'] = 'application/json'
        if (input.mode === 'WRONG') headers[input.csrfHeader] = 'invalid-csrf-proof'
        const response = await fetch(input.route.probePath, {
          method: input.route.method,
          headers,
          body: input.route.bodyKind === 'NONE' ? undefined : '{}',
        })
        const meStatus = (await fetch('/api/auth/me')).status
        return { status: response.status, meStatus }
      }, {
        route,
        mode,
        csrfHeader,
        traceId: `${requiredEnvironment('WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX')}-csrf-${index}-${mode.toLowerCase()}`,
      })
      const label = `${route.method} ${route.template} ${mode} CSRF`
      expect(observation.status, label).toBe(403)
      expect(observation.meStatus, `${label} changed the authenticated Session`).toBe(200)
    }
  }
  expect(await captureState()).toEqual(stateBefore)
}

test.describe.configure({ mode: 'serial' })

test('private Web UI performs Project CRUD, trace correlation and responsive rendering', async ({ page }) => {
  const runtime = runtimeManifest()
  const consoleErrors: string[] = []
  const pageErrors: string[] = []
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text())
  })
  page.on('pageerror', (error) => pageErrors.push(error.message))

  await login(page, runtime.privateBaseUrl)
  // The first unauthenticated /auth/me probe deliberately returns 401 while
  // deciding whether /login should redirect. Validate application exceptions,
  // then start the authenticated-flow console gate from a clean boundary.
  expect(pageErrors).toEqual([])
  consoleErrors.length = 0
  await page.goto(`${runtime.privateBaseUrl}/projects`)
  await expect(page.getByRole('heading', { name: '项目示例' })).toBeVisible()

  const suffix = Date.now().toString(36).toUpperCase()
  const code = `BROWSER_RELEASE_${suffix}`
  await page.getByRole('button', { name: '新建项目' }).click()
  await page.getByPlaceholder('请输入项目名称').fill('浏览器发布验收项目')
  await page.getByPlaceholder('请输入项目编码').fill(code)
  const ownerSelect = page.getByRole('combobox', { name: /负责人$/ })
  await ownerSelect.click()
  const ownerListboxId = await ownerSelect.getAttribute('aria-controls')
  if (!ownerListboxId) throw new Error('项目负责人下拉框缺少 aria-controls')
  const ownerListbox = page.locator(`[id="${ownerListboxId}"]`)
  await expect(ownerListbox).toHaveAccessibleName('项目负责人')
  const ownerOptions = ownerListbox.getByRole('option')
  await expect(ownerOptions.first()).toBeVisible()
  await ownerOptions.first().click()
  await page.getByPlaceholder('请输入项目说明（可选）').fill('由不可变镜像浏览器门禁创建')
  await page.getByRole('button', { name: '保存' }).click()
  await expect(page.getByText('项目创建成功')).toBeVisible()

  let row = page.getByRole('row').filter({ hasText: code })
  await expect(row).toHaveCount(1)
  await expect(row.getByText('浏览器发布验收项目')).toBeVisible()
  await row.getByRole('button', { name: '编辑' }).click()
  const editDrawer = page.getByRole('dialog', { name: '编辑项目' })
  const editSave = editDrawer.getByRole('button', { name: '保存' })
  await expect(editDrawer).toBeVisible()
  // A trial click waits for the opening transition to become stable without
  // submitting. This prevents a stale closing drawer from accepting input.
  await editSave.click({ trial: true })
  const editedName = '浏览器发布验收项目已更新'
  const nameInput = editDrawer.getByPlaceholder('请输入项目名称')
  await nameInput.fill(editedName)
  await expect(nameInput).toHaveValue(editedName)
  const updateRequest = page.waitForRequest((request) =>
    request.method() === 'PUT' && new URL(request.url()).pathname.startsWith('/api/projects/'),
  )
  await editSave.click()
  const submittedUpdate = (await updateRequest).postDataJSON() as { name?: string }
  expect(submittedUpdate.name).toBe(editedName)
  await expect(page.getByText('项目更新成功')).toBeVisible()

  row = page.getByRole('row').filter({ hasText: code })
  await expect(row.getByText(editedName)).toBeVisible()
  await row.getByRole('button', { name: '删除' }).click()
  const confirmation = page.getByRole('dialog', { name: '删除项目' })
  await expect(confirmation).toBeVisible()
  await confirmation.getByRole('button', { name: '删除' }).click()
  await expect(page.getByText('项目已删除')).toBeVisible()
  await expect(page.getByRole('row').filter({ hasText: code })).toHaveCount(0)

  await page.goto(`${runtime.privateBaseUrl}/logs/operation?module=project`)
  await expect(page.getByRole('heading', { name: '操作审计' })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'REMOVE' }).first()).toBeVisible()
  const traceButtons = page.getByRole('button').filter({ hasText: /^[A-Za-z0-9_-]{8,128}$/ })
  expect(await traceButtons.count()).toBeGreaterThan(0)
  await traceButtons.first().click()
  await expect(page.getByRole('dialog', { name: 'Trace 调用链' })).toBeVisible()
  await expect(page.getByText('记录数')).toBeVisible()

  await page.goto(`${runtime.privateBaseUrl}/definitely-not-a-route`)
  await expect(page.getByRole('heading', { name: '页面不存在' })).toBeVisible()

  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`${runtime.privateBaseUrl}/projects`)
  await expect(page.getByRole('heading', { name: '项目示例' })).toBeVisible()
  const dimensions = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
  }))
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth)
  expect(consoleErrors).toEqual([])
})

test('all frozen management pages expose usable primary browser controls', async ({ page }) => {
  test.setTimeout(120_000)
  const runtime = runtimeManifest()
  await login(page, runtime.privateBaseUrl)

  await page.goto(`${runtime.privateBaseUrl}/overview`)
  await page.waitForLoadState('networkidle')
  await expect(page.getByRole('heading', { name: '概览', exact: true })).toBeVisible()
  await expect(page.getByRole('region', { name: '系统统计' })).toBeVisible()
  await expect(page.getByRole('link', { name: /项目示例/ })).toBeVisible()
  await expect(page.locator('.request-error')).toHaveCount(0)

  const createSurfaces = [
    { path: '/projects', heading: '项目示例', action: '新建项目', dialog: '新建项目' },
    { path: '/users', heading: '用户管理', action: '新建用户', dialog: '新建用户' },
    { path: '/roles', heading: '角色权限', action: '新建角色', dialog: '新建角色' },
    { path: '/menus', heading: '菜单权限', action: '新建菜单', dialog: '新建菜单权限' },
    { path: '/configs', heading: '系统配置', action: '新建配置', dialog: '新建配置' },
    {
      path: '/security/personal-tokens',
      heading: '个人访问令牌',
      action: '签发个人令牌',
      dialog: '签发个人访问令牌',
    },
    {
      path: '/security/service-accounts',
      heading: '服务账号',
      action: '新建服务账号',
      dialog: '新建服务账号',
    },
    {
      path: '/security/oauth-clients',
      heading: 'OAuth 客户端',
      action: '注册 OAuth 客户端',
      dialog: '注册 OAuth 客户端',
    },
  ] as const
  for (const surface of createSurfaces) {
    await page.goto(`${runtime.privateBaseUrl}${surface.path}`)
    await page.waitForLoadState('networkidle')
    await expect(page.getByRole('heading', { name: surface.heading, exact: true })).toBeVisible()
    await expect(page.locator('.request-error')).toHaveCount(0)
    await page.getByRole('button', { name: surface.action, exact: true }).click()
    const dialog = page.getByRole('dialog', { name: surface.dialog, exact: true })
    await expect(dialog).toBeVisible()
    await dialog.getByRole('button', { name: '取消', exact: true }).click()
    await expect(dialog).not.toBeVisible()
  }

  const logSurfaces = [
    {
      path: '/logs/login',
      heading: '登录日志',
      filter: '搜索用户名',
      endpoint: '/api/logs/login',
    },
    {
      path: '/logs/operation',
      heading: '操作审计',
      filter: '搜索操作人',
      endpoint: '/api/logs/operation',
    },
    {
      path: '/logs/mcp',
      heading: 'MCP 调用日志',
      filter: '搜索调用者',
      endpoint: '/api/logs/mcp',
    },
  ] as const
  for (const surface of logSurfaces) {
    await page.goto(`${runtime.privateBaseUrl}${surface.path}`)
    await page.waitForLoadState('networkidle')
    await expect(page.getByRole('heading', { name: surface.heading, exact: true })).toBeVisible()
    await page.getByPlaceholder(surface.filter).fill('management-page-acceptance')
    const response = page.waitForResponse((candidate) => {
      const url = new URL(candidate.url())
      return candidate.request().method() === 'GET' && url.pathname === surface.endpoint
    })
    await page.getByRole('button', { name: '刷新', exact: true }).click()
    expect((await response).status()).toBe(200)
    await expect(page.locator('.request-error')).toHaveCount(0)
  }
})

test('management write domains persist complete operation audit records', async ({ page }) => {
  test.setTimeout(120_000)
  const runtime = runtimeManifest()
  const suffix = randomBytes(6).toString('hex')
  const suffixUpper = suffix.toUpperCase()
  const actorId = String(runtime.ownerId)
  const trace = (domain: string, action: string) => `v1-ac32-${domain}-${action}-${suffix}`
  const password = `Ac32-${randomBytes(18).toString('base64url')}!9a`
  await login(page, runtime.privateBaseUrl)

  const roleTrace = trace('role', 'create')
  const role = await authenticatedMutation<IdentifiedResource>(
    page,
    'POST',
    '/api/roles',
    roleTrace,
    {
      code: `AC32_${suffixUpper}`,
      name: `AC-32 审计角色 ${suffix}`,
      description: '候选版本操作审计验收',
      status: 'ENABLED',
      permissionIds: [],
      menuIds: [],
    },
  )
  await expectCompleteOperationAudit(page, runtime.privateBaseUrl, {
    traceId: roleTrace,
    actorId,
    module: 'roles',
    action: 'CREATE',
    resourceType: 'role',
    resourceId: String(role.id),
    requestMethod: 'POST',
  })

  const userTrace = trace('user', 'create')
  const user = await authenticatedMutation<IdentifiedResource>(
    page,
    'POST',
    '/api/users',
    userTrace,
    {
      username: `ac32_user_${suffix}`,
      displayName: `AC-32 审计用户 ${suffix}`,
      password,
      email: `ac32-${suffix}@example.invalid`,
      mobile: null,
      status: 'ENABLED',
      roleIds: [],
    },
  )
  await expectCompleteOperationAudit(page, runtime.privateBaseUrl, {
    traceId: userTrace,
    actorId,
    module: 'users',
    action: 'CREATE',
    resourceType: 'user',
    resourceId: String(user.id),
    requestMethod: 'POST',
  }, [password])

  const menuTrace = trace('menu', 'create')
  const menu = await authenticatedMutation<IdentifiedResource>(
    page,
    'POST',
    '/api/menus',
    menuTrace,
    {
      parentId: null,
      name: `AC-32 审计菜单 ${suffix}`,
      path: `/ac32-${suffix}`,
      component: 'views/Ac32AuditView',
      icon: null,
      sortOrder: 999,
      visible: true,
      status: 'ENABLED',
      permissionCode: `acceptance:ac32:${suffix}`,
    },
  )
  await expectCompleteOperationAudit(page, runtime.privateBaseUrl, {
    traceId: menuTrace,
    actorId,
    module: 'menus',
    action: 'CREATE',
    resourceType: 'menu',
    resourceId: String(menu.id),
    requestMethod: 'POST',
  })

  const configTrace = trace('config', 'create')
  const config = await authenticatedMutation<IdentifiedResource>(
    page,
    'POST',
    '/api/configs',
    configTrace,
    {
      configKey: `acceptance.audit.${suffix}`,
      configValue: 'enabled',
      valueType: 'STRING',
      description: 'AC-32 候选版本操作审计验收',
    },
  )
  await expectCompleteOperationAudit(page, runtime.privateBaseUrl, {
    traceId: configTrace,
    actorId,
    module: 'configs',
    action: 'CREATE',
    resourceType: 'config',
    resourceId: String(config.id),
    requestMethod: 'POST',
  })

  const projectTrace = trace('project', 'create')
  const project = await authenticatedMutation<IdentifiedResource>(
    page,
    'POST',
    '/api/projects',
    projectTrace,
    {
      name: `AC-32 审计项目 ${suffix}`,
      code: `AC32_PROJECT_${suffixUpper}`,
      ownerId: runtime.ownerId,
      status: 'PLANNING',
      description: 'AC-32 候选版本操作审计验收',
    },
  )
  await expectCompleteOperationAudit(page, runtime.privateBaseUrl, {
    traceId: projectTrace,
    actorId,
    module: 'project',
    action: 'CREATE',
    resourceType: 'project',
    resourceId: String(project.id),
  })

  const personalTokenTrace = trace('personal-token', 'issue')
  const personalToken = await authenticatedMutation<IdentifiedResource>(
    page,
    'POST',
    '/api/security/personal-tokens',
    personalTokenTrace,
    {
      name: `AC-32 审计令牌 ${suffix}`,
      scopes: ['system:info'],
      allowedIpCidrs: [],
      expiresAt: null,
    },
  )
  await expectCompleteOperationAudit(page, runtime.privateBaseUrl, {
    traceId: personalTokenTrace,
    actorId,
    module: 'security',
    action: 'ISSUE_TOKEN',
    resourceType: 'token',
    resourceId: String(personalToken.id),
    requestMethod: 'POST',
  })

  const serviceAccountTrace = trace('service-account', 'create')
  const serviceAccount = await authenticatedMutation<IdentifiedResource>(
    page,
    'POST',
    '/api/security/service-accounts',
    serviceAccountTrace,
    {
      code: `ac32_${suffix}`,
      displayName: `AC-32 审计服务账号 ${suffix}`,
      description: '候选版本操作审计验收',
      roleIds: [],
    },
  )
  await expectCompleteOperationAudit(page, runtime.privateBaseUrl, {
    traceId: serviceAccountTrace,
    actorId,
    module: 'security',
    action: 'CREATE',
    resourceType: 'service-account',
    resourceId: String(serviceAccount.id),
    requestMethod: 'POST',
  })

  const oauthTrace = trace('oauth-client', 'create')
  const oauth = await authenticatedMutation<CreatedOAuthClient>(
    page,
    'POST',
    '/api/security/oauth-clients',
    oauthTrace,
    {
      clientId: `ac32-client-${suffix}`,
      clientName: `AC-32 审计 OAuth 客户端 ${suffix}`,
      authenticationMethods: ['none'],
      grantTypes: ['authorization_code'],
      redirectUris: [`https://ac32-${suffix}.example.invalid/callback`],
      scopes: ['system:info'],
      requireConsent: true,
      serviceAccountId: null,
    },
  )
  await expectCompleteOperationAudit(page, runtime.privateBaseUrl, {
    traceId: oauthTrace,
    actorId,
    module: 'security',
    action: 'CREATE',
    resourceType: 'oauth-client',
    resourceId: String(oauth.client.id),
    requestMethod: 'POST',
  })

  const cleanupOperations: Array<{
    domain: string
    method: 'PUT' | 'DELETE'
    path: string
    payload?: unknown
    module: string
    action: string
    resourceType: string
    resourceId: string
  }> = [
    {
      domain: 'oauth-client',
      method: 'PUT' as const,
      path: `/api/security/oauth-clients/${encodeURIComponent(String(oauth.client.id))}`,
      payload: {
        clientName: `AC-32 审计 OAuth 客户端 ${suffix}`,
        authenticationMethods: ['none'],
        grantTypes: ['authorization_code'],
        redirectUris: [`https://ac32-${suffix}.example.invalid/callback`],
        scopes: ['system:info'],
        requireConsent: true,
        serviceAccountId: null,
        enabled: false,
      },
      module: 'security',
      action: 'UPDATE',
      resourceType: 'oauth-client',
      resourceId: String(oauth.client.id),
    },
    {
      domain: 'service-account',
      method: 'DELETE' as const,
      path: `/api/security/service-accounts/${serviceAccount.id}`,
      module: 'security',
      action: 'DISABLE',
      resourceType: 'service-account',
      resourceId: String(serviceAccount.id),
    },
    {
      domain: 'personal-token',
      method: 'DELETE' as const,
      path: `/api/security/personal-tokens/${personalToken.id}`,
      module: 'security',
      action: 'REVOKE_TOKEN',
      resourceType: 'token',
      resourceId: String(personalToken.id),
    },
    {
      domain: 'project',
      method: 'DELETE' as const,
      path: `/api/projects/${project.id}?version=${project.version ?? 0}`,
      module: 'project',
      action: 'REMOVE',
      resourceType: 'project',
      resourceId: String(project.id),
    },
    {
      domain: 'config',
      method: 'DELETE' as const,
      path: `/api/configs/${config.id}`,
      module: 'configs',
      action: 'REMOVE',
      resourceType: 'config',
      resourceId: String(config.id),
    },
    {
      domain: 'menu',
      method: 'DELETE' as const,
      path: `/api/menus/${menu.id}`,
      module: 'menus',
      action: 'REMOVE',
      resourceType: 'menu',
      resourceId: String(menu.id),
    },
    {
      domain: 'user',
      method: 'DELETE' as const,
      path: `/api/users/${user.id}`,
      module: 'users',
      action: 'REMOVE',
      resourceType: 'user',
      resourceId: String(user.id),
    },
    {
      domain: 'role',
      method: 'DELETE' as const,
      path: `/api/roles/${role.id}`,
      module: 'roles',
      action: 'REMOVE',
      resourceType: 'role',
      resourceId: String(role.id),
    },
  ]
  for (const operation of cleanupOperations) {
    const cleanupTrace = trace(operation.domain, 'cleanup')
    await authenticatedMutation<null>(
      page,
      operation.method,
      operation.path,
      cleanupTrace,
      operation.payload,
      false,
    )
    await expectCompleteOperationAudit(page, runtime.privateBaseUrl, {
      traceId: cleanupTrace,
      actorId,
      module: operation.module,
      action: operation.action,
      resourceType: operation.resourceType,
      resourceId: operation.resourceId,
      requestMethod: operation.domain === 'project' ? undefined : operation.method,
    }, [password])
  }
})

test('public OAuth authorization-code flow requires PKCE and yields a usable MCP token', async ({ page }) => {
  const runtime = runtimeManifest()
  const verifier = randomBytes(48).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  const state = randomBytes(16).toString('hex')
  const authorization = new URL(`${runtime.publicBaseUrl}/oauth2/authorize`)
  authorization.search = new URLSearchParams({
    response_type: 'code',
    client_id: runtime.publicClientId,
    redirect_uri: runtime.redirectUri,
    scope: 'system:info project:list',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
  }).toString()

  await page.goto(authorization.toString())
  const loginUrl = new URL(page.url())
  expect(loginUrl.pathname).toBe('/login')
  expect(loginUrl.searchParams.get('redirect')).toContain('/oauth2/authorize?')
  await page.getByPlaceholder('请输入用户名').fill(requiredEnvironment('WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME'))
  await page.getByPlaceholder('请输入密码').fill(requiredEnvironment('WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD'))
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await page.waitForURL((url) => url.origin + url.pathname === runtime.redirectUri && url.searchParams.has('code'))

  const callback = new URL(page.url())
  expect(callback.searchParams.get('state')).toBe(state)
  const code = callback.searchParams.get('code')
  expect(code).toBeTruthy()
  const tokenResponse = await page.evaluate(async (request) => {
    const response = await fetch('/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(request),
    })
    return { status: response.status, body: await response.json() }
  }, {
    grant_type: 'authorization_code',
    client_id: runtime.publicClientId,
    redirect_uri: runtime.redirectUri,
    code: code!,
    code_verifier: verifier,
  })
  expect(tokenResponse.status).toBe(200)
  const token = tokenResponse.body as { access_token?: string; token_type?: string }
  expect(token.token_type?.toLowerCase()).toBe('bearer')
  expect(token.access_token).toBeTruthy()

  const initialize = await page.evaluate(async (accessToken) => {
    const response = await fetch('/mcp', {
      method: 'POST',
      headers: {
        Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'X-Trace-Id': 'release-pkce-browser-initialize',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-11-25',
          capabilities: {},
          clientInfo: { name: 'release-pkce-browser', version: '1.0.0' },
        },
      }),
    })
    return {
      status: response.status,
      body: await response.text(),
      sessionId: response.headers.get('mcp-session-id'),
    }
  }, token.access_token!)
  expect(initialize.status).toBe(200)
  expect(initialize.body).toContain('2025-11-25')
  expect(initialize.sessionId).toMatch(/^[A-Za-z0-9._-]{8,256}$/)

  const sessionClose = await page.evaluate(async ({ accessToken, sessionId }) => {
    const response = await fetch('/mcp', {
      method: 'DELETE',
      headers: {
        Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'Mcp-Session-Id': sessionId,
        'X-Trace-Id': 'release-pkce-browser-close',
      },
    })
    return { status: response.status, body: await response.text() }
  }, { accessToken: token.access_token!, sessionId: initialize.sessionId! })
  expect([200, 202, 204]).toContain(sessionClose.status)
  expect(sessionClose.body).toBe('')

  const invalidAuthorization = new URL(authorization)
  const unregisteredRedirect = `${runtime.redirectUri}/unregistered`
  invalidAuthorization.searchParams.set('redirect_uri', unregisteredRedirect)
  invalidAuthorization.searchParams.set('state', randomBytes(16).toString('hex'))
  const invalidRedirectResponse = await page.evaluate(async (url) => {
    const response = await fetch(url, { redirect: 'manual' })
    return {
      status: response.status,
      location: response.headers.get('location'),
    }
  }, invalidAuthorization.toString())
  expect(invalidRedirectResponse.status).toBe(400)
  expect(invalidRedirectResponse.location).toBeNull()

  for (const registrationPath of ['/connect/register', '/oauth2/register']) {
    const registrationResponse = await page.evaluate(async (request) => {
      const response = await fetch(request.path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request.data),
        redirect: 'manual',
      })
      return {
        status: response.status,
        location: response.headers.get('location'),
      }
    }, {
      path: registrationPath,
      data: {
          client_name: 'forbidden-dynamic-client',
          redirect_uris: ['https://attacker.example.invalid/callback'],
      },
    })
    expect(registrationResponse.status).toBe(404)
    expect(registrationResponse.location).toBeNull()
  }
})

test('personal security manages real browser sessions and prevents self-elevation', async ({ browser }) => {
  const runtime = runtimeManifest()
  const account = accountUserCredential(runtime)
  const firstContext = await browser.newContext()
  const secondContext = await browser.newContext()
  const firstPage = await firstContext.newPage()
  const secondPage = await secondContext.newPage()

  try {
    await login(firstPage, runtime.privateBaseUrl, account.username, account.password, '/security/account')
    const cleanupStatus = await firstPage.evaluate(async () => {
      const csrfResponse = await fetch('/api/auth/csrf')
      const csrfEnvelope = await csrfResponse.json() as {
        data?: { headerName?: string; token?: string }
      }
      const headerName = csrfEnvelope.data?.headerName || 'X-XSRF-TOKEN'
      const token = csrfEnvelope.data?.token
      if (!token) throw new Error('CSRF token missing')
      return (await fetch('/api/security/me/sessions/others', {
        method: 'DELETE',
        headers: { [headerName]: token },
      })).status
    })
    expect(cleanupStatus).toBe(200)
    await login(secondPage, runtime.privateBaseUrl, account.username, account.password, '/security/account')

    await firstPage.goto(`${runtime.privateBaseUrl}/security/account`)
    await expect(firstPage.getByRole('heading', { name: '个人安全', exact: true })).toBeVisible()
    await expect(firstPage.getByText('当前会话', { exact: true })).toHaveCount(1)
    await expect(firstPage.locator('[data-testid^="session-"]')).toHaveCount(2)

    const selfElevationStatus = await firstPage.evaluate(async (userId) => {
      const csrfResponse = await fetch('/api/auth/csrf')
      const csrfEnvelope = await csrfResponse.json() as {
        data?: { headerName?: string; token?: string }
      }
      const headerName = csrfEnvelope.data?.headerName || 'X-XSRF-TOKEN'
      const token = csrfEnvelope.data?.token
      if (!token) throw new Error('CSRF token missing')
      const response = await fetch(`/api/users/${encodeURIComponent(userId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', [headerName]: token },
        body: JSON.stringify({
          displayName: '个人安全验收用户',
          status: 'ENABLED',
          version: 0,
          roleIds: ['1'],
        }),
      })
      return response.status
    }, runtime.accountUserId)
    expect(selfElevationStatus).toBe(403)

    await firstPage.getByTestId('revoke-other-sessions').click()
    await firstPage.getByRole('button', { name: '确认退出其他设备' }).click()
    await expect(firstPage.getByText('已退出 1 个其他 Session')).toBeVisible()
    await expect(firstPage.locator('[data-testid^="session-"]')).toHaveCount(1)
    const revokedStatus = await secondPage.evaluate(async () => (await fetch('/api/auth/me')).status)
    expect(revokedStatus).toBe(401)

    const sessionCookie = (await firstContext.cookies(runtime.privateBaseUrl))
      .find((cookie) => cookie.name === 'WEB_STARTER_SESSION')
    if (!sessionCookie?.value || !sessionCookie.httpOnly) {
      throw new Error('Active account session cookie is missing before logout acceptance')
    }
    const logoutStatus = await firstPage.evaluate(async () => {
      const csrfResponse = await fetch('/api/auth/csrf')
      const csrfEnvelope = await csrfResponse.json() as {
        data?: { headerName?: string; token?: string }
      }
      const headerName = csrfEnvelope.data?.headerName || 'X-XSRF-TOKEN'
      const token = csrfEnvelope.data?.token
      if (!token) throw new Error('CSRF token missing')
      return (await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { [headerName]: token },
      })).status
    })
    expect(logoutStatus).toBe(204)
    const replayContext = await browser.newContext()
    try {
      await replayContext.addCookies([sessionCookie])
      const replayPage = await replayContext.newPage()
      const replayResponse = await replayPage.request.get(
        `${runtime.privateBaseUrl}/api/auth/me`,
      )
      expect(replayResponse.status()).toBe(401)
    } finally {
      await replayContext.close()
    }
    await login(firstPage, runtime.privateBaseUrl, account.username, account.password, '/security/account')

    const replacementPassword = `V2-${randomBytes(30).toString('base64url')}!9a`
    await firstPage.getByTestId('current-password').fill(account.password)
    await firstPage.getByTestId('new-password').fill(replacementPassword)
    await firstPage.getByTestId('confirm-password').fill(replacementPassword)
    await firstPage.getByTestId('change-password').click()
    await expect(firstPage).toHaveURL(/\/login\?reason=password-changed$/)

    await login(
      firstPage,
      runtime.privateBaseUrl,
      account.username,
      replacementPassword,
      '/security/account',
    )
    await firstPage.goto(`${runtime.privateBaseUrl}/security/account`)
    await firstPage.getByTestId('current-password').fill(replacementPassword)
    await firstPage.getByTestId('new-password').fill(account.password)
    await firstPage.getByTestId('confirm-password').fill(account.password)
    await firstPage.getByTestId('change-password').click()
    await expect(firstPage).toHaveURL(/\/login\?reason=password-changed$/)
    await login(firstPage, runtime.privateBaseUrl, account.username, account.password, '/security/account')

    const adminContext = await browser.newContext()
    const adminPage = await adminContext.newPage()
    let managedUser: ManagedUser | undefined
    try {
      await login(adminPage, runtime.privateBaseUrl)
      await expectCompleteCsrfWriteMatrix(browser, adminPage, runtime, account)
      const currentUser = await authenticatedGet<ManagedUser>(
        adminPage,
        runtime.privateBaseUrl,
        `/api/users/${encodeURIComponent(runtime.accountUserId)}`,
        {},
      )
      if (String(currentUser.id) !== runtime.accountUserId || currentUser.status !== 'ENABLED') {
        throw new Error('Account-security acceptance user is not enabled')
      }
      managedUser = currentUser
      managedUser = await authenticatedMutation<ManagedUser>(
        adminPage,
        'PUT',
        `/api/users/${encodeURIComponent(runtime.accountUserId)}`,
        `${requiredEnvironment('WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX')}-web-session-disable`,
        {
          displayName: currentUser.displayName || currentUser.username,
          email: currentUser.email || null,
          mobile: currentUser.mobile || null,
          status: 'DISABLED',
          version: currentUser.version,
          roleIds: currentUser.roleIds,
        },
      )
      const disabledSessionStatus = await firstPage.evaluate(
        async () => (await fetch('/api/auth/me')).status,
      )
      expect(disabledSessionStatus).toBe(401)
      managedUser = await authenticatedMutation<ManagedUser>(
        adminPage,
        'PUT',
        `/api/users/${encodeURIComponent(runtime.accountUserId)}`,
        `${requiredEnvironment('WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX')}-web-session-enable`,
        {
          displayName: managedUser.displayName || managedUser.username,
          email: managedUser.email || null,
          mobile: managedUser.mobile || null,
          status: 'ENABLED',
          version: managedUser.version,
          roleIds: managedUser.roleIds,
        },
      )
      const revivedSessionStatus = await firstPage.evaluate(
        async () => (await fetch('/api/auth/me')).status,
      )
      expect(revivedSessionStatus).toBe(401)
    } finally {
      if (managedUser) {
        const latestUser = await authenticatedGet<ManagedUser>(
          adminPage,
          runtime.privateBaseUrl,
          `/api/users/${encodeURIComponent(runtime.accountUserId)}`,
          {},
        )
        if (latestUser.status === 'DISABLED') {
          await authenticatedMutation<ManagedUser>(
            adminPage,
            'PUT',
            `/api/users/${encodeURIComponent(runtime.accountUserId)}`,
            `${requiredEnvironment('WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX')}-web-session-cleanup`,
            {
              displayName: latestUser.displayName || latestUser.username,
              email: latestUser.email || null,
              mobile: latestUser.mobile || null,
              status: 'ENABLED',
              version: latestUser.version,
              roleIds: latestUser.roleIds,
            },
          )
        }
      }
      await adminContext.close()
    }
  } finally {
    await secondContext.close()
    await firstContext.close()
  }
})

test('credential management filters lifecycle states without redisplaying secrets', async ({ page }) => {
  const runtime = runtimeManifest()
  await login(page, runtime.privateBaseUrl)
  await page.goto(`${runtime.privateBaseUrl}/security/personal-tokens`)
  await expect(page.getByRole('heading', { name: '个人访问令牌', exact: true })).toBeVisible()
  await expect(page.getByTestId('one-time-secret')).toHaveCount(0)

  const filter = page.getByTestId('personal-token-filter')
  const selectFilter = async (label: string): Promise<void> => {
    await filter.click()
    await page.getByRole('option', { name: label, exact: true }).click()
  }
  const rowNamed = (name: string) => page.getByRole('row').filter({ hasText: name })

  await selectFilter('30 天内到期')
  await expect(rowNamed(runtime.credentialFixtures.expiringName)).toHaveCount(1)
  await selectFilter('已吊销')
  await expect(rowNamed(runtime.credentialFixtures.revokedName)).toHaveCount(1)
  await selectFilter('受 IP 限制')
  await expect(rowNamed(runtime.credentialFixtures.restrictedName)).toHaveCount(1)

  // The runtime fixture is intentionally fresh. Advance only the browser's
  // display clock to exercise the 90-day lifecycle filter without mutating the
  // database or weakening server-side expiry semantics.
  const future = Date.now() + 91 * 24 * 60 * 60 * 1000
  await page.evaluate((value) => {
    Date.now = () => value
  }, future)
  await selectFilter('90 天未使用')
  await expect(rowNamed(runtime.credentialFixtures.longUnusedName)).toHaveCount(1)
  await expect(page.getByTestId('one-time-secret')).toHaveCount(0)
})

test('audit search filters login operation and MCP records with correlated redacted traces', async ({ page }) => {
  // This scenario deliberately proves three independent filter matrices before
  // opening the correlated browser view. Keep its budget independent from the
  // short UI scenarios so a loaded release runner cannot consume the default
  // 30-second budget before the final browser request is observed.
  test.setTimeout(90_000)
  const runtime = runtimeManifest()
  const username = requiredEnvironment('WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME')
  const adminPassword = requiredEnvironment('WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD')
  const patBearer = bearerFromFile(runtime.tokenFiles.patCrud)
  const mcpCreateTrace = `${requiredEnvironment('WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX')}-create-first`
  await login(page, runtime.privateBaseUrl)

  const loginPage = await authenticatedGet<PageData<LoginAudit>>(
    page,
    runtime.privateBaseUrl,
    '/api/logs/login',
    { page: 1, size: 20, username, result: 'SUCCESS', traceId: mcpCreateTrace },
  )
  expect(loginPage.records).toHaveLength(1)
  const loginRecord = loginPage.records.find((record) =>
    record.username === username && record.traceId === mcpCreateTrace,
  )
  if (!loginRecord) throw new Error('Exact login audit fixture was not found')
  const loginFilters = {
    page: 1,
    size: 20,
    username,
    result: 'SUCCESS',
    traceId: loginRecord.traceId,
    ...occurredWindow(loginRecord.createdAt),
  }
  const exactLogin = await authenticatedGet<PageData<LoginAudit>>(
    page,
    runtime.privateBaseUrl,
    '/api/logs/login',
    loginFilters,
  )
  expect(exactLogin.total).toBe(1)
  expect(exactLogin.records).toHaveLength(1)
  expect(String(exactLogin.records[0].id)).toBe(String(loginRecord.id))
  expect(loginRecord.ipAddress).not.toHaveLength(0)
  expect(loginRecord.userAgent).not.toHaveLength(0)
  const { occurredFrom: loginFrom, occurredTo: loginTo, ...loginWithoutTime } = loginFilters
  for (const filters of [
    { ...loginFilters, username: `${username}-absent` },
    { ...loginFilters, result: 'FAILURE' },
    { ...loginFilters, traceId: absentTrace(loginRecord.traceId) },
    { ...loginWithoutTime, occurredFrom: '2099-01-01T00:00:00' },
    { ...loginWithoutTime, occurredTo: '1900-01-01T00:00:00' },
  ]) {
    await expectNoAuditRecords(page, runtime.privateBaseUrl, '/api/logs/login', filters)
  }
  expect(loginFrom).not.toBe(loginTo)

  const mcpPage = await authenticatedGet<PageData<McpAudit>>(
    page,
    runtime.privateBaseUrl,
    '/api/logs/mcp',
    {
      page: 1,
      size: 20,
      toolName: 'project.create',
      result: 'SUCCESS',
      traceId: mcpCreateTrace,
    },
  )
  const mcpRecord = mcpPage.records.find((record) =>
    record.toolName === 'project.create'
    && record.replayed === false
    && /^[0-9a-f]{64}$/.test(record.idempotencyKeyHash || '')
    && record.traceId === mcpCreateTrace,
  )
  if (!mcpRecord) throw new Error('Exact MCP audit fixture was not found')
  const mcpFilters = {
    page: 1,
    size: 20,
    actorName: mcpRecord.actorName,
    toolName: 'project.create',
    result: 'SUCCESS',
    traceId: mcpRecord.traceId,
    ...occurredWindow(mcpRecord.createdAt),
  }
  const exactMcp = await authenticatedGet<PageData<McpAudit>>(
    page,
    runtime.privateBaseUrl,
    '/api/logs/mcp',
    mcpFilters,
  )
  expect(exactMcp.total).toBe(1)
  expect(exactMcp.records).toHaveLength(1)
  expect(String(exactMcp.records[0].id)).toBe(String(mcpRecord.id))
  const { occurredFrom: mcpFrom, occurredTo: mcpTo, ...mcpWithoutTime } = mcpFilters
  for (const filters of [
    { ...mcpFilters, actorName: `${mcpRecord.actorName}-absent` },
    { ...mcpFilters, toolName: 'project.absent' },
    { ...mcpFilters, result: 'FAILED' },
    { ...mcpFilters, traceId: absentTrace(mcpRecord.traceId) },
    { ...mcpWithoutTime, occurredFrom: '2099-01-01T00:00:00' },
    { ...mcpWithoutTime, occurredTo: '1900-01-01T00:00:00' },
  ]) {
    await expectNoAuditRecords(page, runtime.privateBaseUrl, '/api/logs/mcp', filters)
  }
  expect(mcpFrom).not.toBe(mcpTo)

  const operationByTrace = await authenticatedGet<PageData<OperationAudit>>(
    page,
    runtime.privateBaseUrl,
    '/api/logs/operation',
    { page: 1, size: 20, traceId: mcpRecord.traceId },
  )
  const operationRecord = operationByTrace.records.find((record) =>
    record.module === 'project'
    && record.action === 'CREATE'
    && record.resourceType === 'project'
    && Boolean(record.resourceId),
  )
  if (!operationRecord) throw new Error('Correlated operation audit fixture was not found')
  const operationFilters = {
    page: 1,
    size: 20,
    actorName: operationRecord.actorName,
    module: 'project',
    resourceType: 'project',
    resourceId: operationRecord.resourceId,
    result: 'SUCCESS',
    traceId: mcpRecord.traceId,
    ...occurredWindow(operationRecord.createdAt),
  }
  const exactOperation = await authenticatedGet<PageData<OperationAudit>>(
    page,
    runtime.privateBaseUrl,
    '/api/logs/operation',
    operationFilters,
  )
  expect(exactOperation.total).toBe(1)
  expect(exactOperation.records).toHaveLength(1)
  expect(String(exactOperation.records[0].id)).toBe(String(operationRecord.id))
  expect(operationRecord.actorId).toBe(mcpRecord.actorId)
  expect(operationRecord.actorName).toBe(mcpRecord.actorName)
  const {
    occurredFrom: operationFrom,
    occurredTo: operationTo,
    ...operationWithoutTime
  } = operationFilters
  for (const filters of [
    { ...operationFilters, actorName: `${operationRecord.actorName}-absent` },
    { ...operationFilters, module: 'absent-module' },
    { ...operationFilters, resourceType: 'absent-resource' },
    { ...operationFilters, resourceId: `${operationRecord.resourceId}-absent` },
    { ...operationFilters, result: 'FAILURE' },
    { ...operationFilters, traceId: absentTrace(mcpRecord.traceId) },
    { ...operationWithoutTime, occurredFrom: '2099-01-01T00:00:00' },
    { ...operationWithoutTime, occurredTo: '1900-01-01T00:00:00' },
  ]) {
    await expectNoAuditRecords(page, runtime.privateBaseUrl, '/api/logs/operation', filters)
  }
  expect(operationFrom).not.toBe(operationTo)

  const trace = await authenticatedGet<TraceAudit>(
    page,
    runtime.privateBaseUrl,
    `/api/logs/trace/${encodeURIComponent(mcpRecord.traceId)}`,
    {},
  )
  expect(trace.traceId).toBe(mcpRecord.traceId)
  expect(trace.truncated).toBe(false)
  expect(trace.loginLogs).toHaveLength(1)
  expect(trace.operationLogs).toHaveLength(1)
  expect(trace.mcpCalls).toHaveLength(1)
  expect(String(trace.loginLogs[0].id)).toBe(String(loginRecord.id))
  expect(trace.loginLogs[0]).toMatchObject({
    username,
    result: 'SUCCESS',
    traceId: mcpRecord.traceId,
  })
  expect(String(trace.operationLogs[0].id)).toBe(String(operationRecord.id))
  expect(trace.operationLogs[0]).toMatchObject({
    module: 'project',
    action: 'CREATE',
    resourceType: 'project',
    resourceId: operationRecord.resourceId,
    traceId: mcpRecord.traceId,
  })
  expect(trace.operationLogs[0].detailJson ?? null).toBeNull()
  expect(String(trace.mcpCalls[0].id)).toBe(String(mcpRecord.id))
  expect(trace.mcpCalls[0]).toMatchObject({
    toolName: 'project.create',
    result: 'SUCCESS',
    replayed: false,
    traceId: mcpRecord.traceId,
  })
  expect(loginRecord.createdAt.localeCompare(operationRecord.createdAt)).toBeLessThanOrEqual(0)
  expect(operationRecord.createdAt.localeCompare(mcpRecord.createdAt)).toBeLessThanOrEqual(0)
  assertAuditRedacted(
    { exactLogin, exactOperation, exactMcp, trace },
    [adminPassword, patBearer],
  )

  await page.goto(`${runtime.privateBaseUrl}/logs/mcp`)
  await page.getByPlaceholder('搜索调用者').fill(mcpRecord.actorName)
  await page.getByPlaceholder('搜索工具名称').fill('project.create')
  await page.getByPlaceholder('Trace ID').fill(mcpRecord.traceId)
  const filteredResponse = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return url.pathname === '/api/logs/mcp'
      && url.searchParams.get('actorName') === mcpRecord.actorName
      && url.searchParams.get('toolName') === 'project.create'
      && url.searchParams.get('traceId') === mcpRecord.traceId
      && url.searchParams.get('result') === 'SUCCESS'
  })
  const resultFilter = page.getByRole('combobox', { name: '调用结果', exact: true })
  await resultFilter.focus()
  await expect(resultFilter).toBeFocused()
  await resultFilter.press('ArrowDown')
  await expect(page.getByRole('option', { name: '成功', exact: true })).toBeVisible()
  await resultFilter.press('ArrowDown')
  await resultFilter.press('Enter')
  const uiResponse = await filteredResponse
  expect(uiResponse.status()).toBe(200)
  const uiEnvelope = await uiResponse.json() as { data?: PageData<McpAudit> }
  expect(uiEnvelope.data?.total).toBe(1)
  expect(uiEnvelope.data?.records).toHaveLength(1)
  expect(String(uiEnvelope.data?.records[0].id)).toBe(String(mcpRecord.id))
  await expect(page.getByRole('row').filter({ hasText: mcpRecord.traceId })).toHaveCount(1)
  await page.getByRole('button', { name: mcpRecord.traceId, exact: true }).click()
  const traceDialog = page.getByRole('dialog', { name: 'Trace 调用链' })
  await expect(traceDialog).toBeVisible()
  await expect(traceDialog.getByTestId('trace-login-count')).toHaveText('登录 1')
  await expect(traceDialog.getByTestId('trace-operation-count')).toHaveText('操作 1')
  await expect(traceDialog.getByTestId('trace-mcp-count')).toHaveText('MCP 1')
  await expect(traceDialog.getByText(`登录 · ${username}`, { exact: true })).toBeVisible()
  await expect(traceDialog.getByText('操作 · project · CREATE', { exact: true })).toBeVisible()
  await expect(traceDialog.getByText(`资源 project ${operationRecord.resourceId}`, { exact: false })).toBeVisible()
  await expect(traceDialog.getByText('MCP · project.create', { exact: true })).toBeVisible()
  await expect(traceDialog.getByText('凭据已脱敏', { exact: false })).toBeVisible()
  const renderedTrace = await traceDialog.textContent()
  if ([adminPassword, patBearer].some((secret) => secret && renderedTrace?.includes(secret))) {
    throw new Error('Trace dialog exposed forbidden credential material')
  }
})

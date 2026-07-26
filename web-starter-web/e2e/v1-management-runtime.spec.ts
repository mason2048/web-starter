import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { expect, test, type BrowserContext, type Page, type Response } from '@playwright/test'

interface RuntimeManifest {
  schemaVersion: number
  privateBaseUrl: string
  ownerId: string
}

interface PageData<T> {
  records: T[]
  total: number
  page: number
  size: number
}

interface ManagedUser {
  id: string
  username: string
  displayName?: string
  email?: string
  mobile?: string
  status: 'ENABLED' | 'DISABLED'
  version: number
  roleIds: string[]
}

interface ManagedRole {
  id: string
  code: string
  name: string
  description?: string
  status: 'ENABLED' | 'DISABLED'
  version: number
  permissionIds: string[]
  menuIds: string[]
}

interface ManagedPermission {
  id: string
  code: string
  name: string
  type: string
  description?: string
  status: 'ENABLED' | 'DISABLED'
}

interface ManagedConfig {
  id: string
  configKey: string
  configValue: string
  valueType: string
  description?: string
  builtin: boolean
}

interface ManagedProject {
  id: string
  name: string
  code: string
  ownerId: string
  ownerName: string
  status: 'PLANNING' | 'IN_PROGRESS' | 'ARCHIVED'
  description?: string
  version: number
}

interface OperationAudit {
  actorId: string
  module: string
  action: string
  resourceType: string
  resourceId: string
  result: string
  durationMs: number
  traceId: string
}

interface CurrentAccess {
  permissions: string[]
  menuIds: string[]
}

interface MutationObservation<T> {
  status: number
  data?: T
  traceId?: string
  message?: string
}

const ADMIN_ROLE_ID = '1'
const PROJECT_LIST_PERMISSION_ID = '1101'
const PROJECT_CREATE_PERMISSION_ID = '1102'
const PROJECT_MENU_ID = '2002'

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`${name} is required`)
  return value
}

function runtimeManifest(): RuntimeManifest {
  const document = JSON.parse(
    readFileSync(requiredEnvironment('WEB_STARTER_ACCEPTANCE_MANIFEST'), 'utf8'),
  ) as RuntimeManifest
  if (document.schemaVersion !== 1 || !document.privateBaseUrl || !document.ownerId) {
    throw new Error('Invalid release runtime manifest')
  }
  return document
}

function suffix(): string {
  return randomBytes(6).toString('hex')
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
  await page.getByPlaceholder('请输入用户名').fill(username)
  await page.getByPlaceholder('请输入密码').fill(password)
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await expect(page).toHaveURL((url) => url.pathname === destination)
}

async function getData<T>(
  page: Page,
  baseUrl: string,
  path: string,
  expectedStatus = 200,
): Promise<T> {
  const response = await page.request.get(new URL(path, baseUrl).toString())
  expect(response.status(), `GET ${path}`).toBe(expectedStatus)
  const envelope = await response.json() as { data?: T }
  if (expectedStatus === 200 && envelope.data === undefined) {
    throw new Error(`GET ${path} returned no data`)
  }
  return envelope.data as T
}

async function mutation<T>(
  page: Page,
  method: 'POST' | 'PUT' | 'DELETE',
  path: string,
  payload?: unknown,
  traceId = `v1-management-${suffix()}`,
): Promise<MutationObservation<T>> {
  return page.evaluate(async (request) => {
    const csrfResponse = await fetch('/api/auth/csrf')
    const csrfEnvelope = await csrfResponse.json() as {
      data?: { headerName?: string; token?: string }
    }
    const token = csrfEnvelope.data?.token
    const headerName = csrfEnvelope.data?.headerName || 'X-XSRF-TOKEN'
    if (csrfResponse.status !== 200 || !token) throw new Error('CSRF token missing')
    const headers: Record<string, string> = {
      [headerName]: token,
      'X-Trace-Id': request.traceId,
      Accept: 'application/json',
    }
    if (request.payload !== undefined) headers['Content-Type'] = 'application/json'
    const response = await fetch(request.path, {
      method: request.method,
      headers,
      body: request.payload === undefined ? undefined : JSON.stringify(request.payload),
    })
    let envelope: { data?: T; traceId?: string; message?: string } = {}
    try {
      envelope = await response.json() as typeof envelope
    } catch {
      // A body is not required for successful DELETE operations.
    }
    return {
      status: response.status,
      data: envelope.data,
      traceId: envelope.traceId || response.headers.get('X-Trace-Id') || undefined,
      message: envelope.message,
    }
  }, { method, path, payload, traceId })
}

async function requireMutation<T>(
  page: Page,
  method: 'POST' | 'PUT' | 'DELETE',
  path: string,
  payload?: unknown,
): Promise<T> {
  const result = await mutation<T>(page, method, path, payload)
  expect(result.status, `${method} ${path}`).toBe(200)
  return result.data as T
}

async function cleanup(
  page: Page,
  method: 'PUT' | 'DELETE',
  path: string,
  payload?: unknown,
): Promise<void> {
  let result = await mutation(page, method, path, payload)
  if (result.status === 401) {
    await login(page, runtimeManifest().privateBaseUrl)
    result = await mutation(page, method, path, payload)
  }
  expect([200, 404], `cleanup ${method} ${path}`).toContain(result.status)
}

async function createRole(
  page: Page,
  code: string,
  name: string,
  permissionIds: string[] = [],
  menuIds: string[] = [],
): Promise<ManagedRole> {
  return requireMutation<ManagedRole>(page, 'POST', '/api/roles', {
    code,
    name,
    description: 'V1 当前候选运行验收',
    status: 'ENABLED',
    permissionIds,
    menuIds,
  })
}

async function createUser(
  page: Page,
  username: string,
  password: string,
  roleIds: string[],
): Promise<ManagedUser> {
  return requireMutation<ManagedUser>(page, 'POST', '/api/users', {
    username,
    displayName: `运行验收用户 ${username}`,
    password,
    email: `${username}@example.invalid`,
    mobile: null,
    status: 'ENABLED',
    roleIds,
  })
}

async function operationAudit(
  page: Page,
  baseUrl: string,
  traceId: string,
  expected: Pick<OperationAudit, 'module' | 'action' | 'resourceType' | 'resourceId'>,
): Promise<void> {
  const result = await getData<PageData<OperationAudit>>(
    page,
    baseUrl,
    `/api/logs/operation?page=1&size=20&traceId=${encodeURIComponent(traceId)}`,
  )
  expect(result.total).toBe(1)
  expect(result.records).toHaveLength(1)
  expect(result.records[0]).toMatchObject({
    ...expected,
    result: 'SUCCESS',
    traceId,
  })
  expect(result.records[0].durationMs).toBeGreaterThanOrEqual(0)
}

function responseTrace(response: Response): string {
  const traceId = response.headers()['x-trace-id']
  if (!traceId) throw new Error('UI mutation response has no Trace ID')
  return traceId
}

async function apiStatus(page: Page, path: string): Promise<number> {
  return page.evaluate(async (target) => (await fetch(target)).status, path)
}

async function closeContext(context: BrowserContext | undefined): Promise<void> {
  if (context) await context.close()
}

test.describe.configure({ mode: 'serial' })

test('AC-06 user management completes the full browser lifecycle with operation audits', async ({ browser, page }) => {
  test.setTimeout(150_000)
  const runtime = runtimeManifest()
  const id = suffix()
  const username = `ac06_${id}`
  const initialPassword = `Ac06-${randomBytes(18).toString('base64url')}!9a`
  const resetPassword = `Ac06R-${randomBytes(18).toString('base64url')}!9a`
  const roleCode = `AC06_${id.toUpperCase()}`
  const roleName = `AC-06 页面角色 ${id}`
  let role: ManagedRole | undefined
  let user: ManagedUser | undefined
  let verificationContext: BrowserContext | undefined

  await login(page, runtime.privateBaseUrl)
  try {
    role = await createRole(page, roleCode, roleName)
    await page.goto(`${runtime.privateBaseUrl}/users`)
    await expect(page.getByRole('heading', { name: '用户管理', exact: true })).toBeVisible()

    await page.getByRole('button', { name: '新建用户', exact: true }).click()
    const createDrawer = page.getByRole('dialog', { name: '新建用户' })
    await createDrawer.getByPlaceholder('请输入用户名').fill(username)
    await createDrawer.getByPlaceholder('至少 12 个字符').fill(initialPassword)
    await createDrawer.getByPlaceholder('请输入姓名').fill(`AC-06 用户 ${id}`)
    await createDrawer.getByPlaceholder('name@example.com').fill(`${username}@example.invalid`)
    const roleSelect = createDrawer.getByRole('combobox', { name: '角色' })
    await roleSelect.focus()
    await roleSelect.press('ArrowDown')
    await page.getByRole('option', { name: roleName, exact: true }).click()
    await page.keyboard.press('Escape')
    await expect(createDrawer.getByText(roleName, { exact: true })).toBeVisible()
    const createResponsePromise = page.waitForResponse((response) =>
      response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/users',
    )
    await createDrawer.getByRole('button', { name: '保存', exact: true }).click()
    const createResponse = await createResponsePromise
    expect(createResponse.status()).toBe(200)
    user = ((await createResponse.json()) as { data: ManagedUser }).data
    await expect(page.getByText('用户创建成功')).toBeVisible()
    let row = page.getByRole('row').filter({ hasText: username })
    await expect(row).toHaveCount(1)
    await expect(row.getByText(roleName, { exact: true })).toBeVisible()
    await operationAudit(page, runtime.privateBaseUrl, responseTrace(createResponse), {
      module: 'users',
      action: 'CREATE',
      resourceType: 'user',
      resourceId: user.id,
    })

    await row.getByRole('button', { name: '编辑', exact: true }).click()
    let editDrawer = page.getByRole('dialog', { name: '编辑用户' })
    await editDrawer.getByPlaceholder('请输入姓名').fill(`AC-06 用户已停用 ${id}`)
    const statusSwitch = editDrawer.getByRole('switch')
    await expect(statusSwitch).toHaveAttribute('aria-checked', 'true')
    await statusSwitch.focus()
    await statusSwitch.press('Space')
    const disableResponsePromise = page.waitForResponse((response) =>
      response.request().method() === 'PUT'
      && new URL(response.url()).pathname === `/api/users/${user!.id}`,
    )
    await editDrawer.getByRole('button', { name: '保存', exact: true }).click()
    const disableResponse = await disableResponsePromise
    expect(disableResponse.status()).toBe(200)
    user = ((await disableResponse.json()) as { data: ManagedUser }).data
    row = page.getByRole('row').filter({ hasText: username })
    await expect(row.getByText('停用', { exact: true })).toBeVisible()
    await operationAudit(page, runtime.privateBaseUrl, responseTrace(disableResponse), {
      module: 'users',
      action: 'UPDATE',
      resourceType: 'user',
      resourceId: user.id,
    })

    await row.getByRole('button', { name: '编辑', exact: true }).click()
    editDrawer = page.getByRole('dialog', { name: '编辑用户' })
    const enableSwitch = editDrawer.getByRole('switch')
    await expect(enableSwitch).toHaveAttribute('aria-checked', 'false')
    await enableSwitch.focus()
    await enableSwitch.press('Space')
    const enableResponsePromise = page.waitForResponse((response) =>
      response.request().method() === 'PUT'
      && new URL(response.url()).pathname === `/api/users/${user!.id}`,
    )
    await editDrawer.getByRole('button', { name: '保存', exact: true }).click()
    const enableResponse = await enableResponsePromise
    expect(enableResponse.status()).toBe(200)
    user = ((await enableResponse.json()) as { data: ManagedUser }).data
    row = page.getByRole('row').filter({ hasText: username })
    await expect(row.getByText('启用', { exact: true })).toBeVisible()

    await row.getByRole('button', { name: '重置密码', exact: true }).click()
    const passwordDialog = page.getByRole('dialog', { name: '重置用户密码' })
    await passwordDialog.getByPlaceholder('12 至 128 个字符').fill(resetPassword)
    await passwordDialog.getByPlaceholder('再次输入以确认').fill(resetPassword)
    await passwordDialog.getByRole('button', { name: '确认重置', exact: true }).click()
    const resetConfirmation = page.getByRole('dialog', { name: '确认密码重置' })
    const resetResponsePromise = page.waitForResponse((response) =>
      response.request().method() === 'PUT'
      && new URL(response.url()).pathname === `/api/users/${user!.id}/password`,
    )
    await resetConfirmation.getByRole('button', { name: '确认重置', exact: true }).click()
    const resetResponse = await resetResponsePromise
    expect(resetResponse.status()).toBe(200)
    await expect(page.getByText('用户密码已重置')).toBeVisible()
    await operationAudit(page, runtime.privateBaseUrl, responseTrace(resetResponse), {
      module: 'users',
      action: 'RESET_PASSWORD',
      resourceType: 'user',
      resourceId: user.id,
    })

    verificationContext = await browser.newContext()
    const verificationPage = await verificationContext.newPage()
    await login(verificationPage, runtime.privateBaseUrl, username, resetPassword, '/forbidden')
    expect(await apiStatus(verificationPage, '/api/auth/me')).toBe(200)
    await closeContext(verificationContext)
    verificationContext = undefined

    row = page.getByRole('row').filter({ hasText: username })
    await row.getByRole('button', { name: '删除', exact: true }).click()
    const deleteDialog = page.getByRole('dialog', { name: '删除用户' })
    const deleteResponsePromise = page.waitForResponse((response) =>
      response.request().method() === 'DELETE'
      && new URL(response.url()).pathname === `/api/users/${user!.id}`,
    )
    await deleteDialog.getByRole('button', { name: '确定', exact: true }).click()
    const deleteResponse = await deleteResponsePromise
    expect(deleteResponse.status()).toBe(200)
    await expect(page.getByText('用户已删除')).toBeVisible()
    await expect(page.getByRole('row').filter({ hasText: username })).toHaveCount(0)
    await operationAudit(page, runtime.privateBaseUrl, responseTrace(deleteResponse), {
      module: 'users',
      action: 'REMOVE',
      resourceType: 'user',
      resourceId: user.id,
    })
    user = undefined
  } finally {
    await closeContext(verificationContext)
    if (user) await cleanup(page, 'DELETE', `/api/users/${user.id}`)
    if (role) await cleanup(page, 'DELETE', `/api/roles/${role.id}`)
  }
})

test('AC-07 role CRUD assigns permissions and menus, rejects stale versions and revokes the next request', async ({ browser, page }) => {
  test.setTimeout(120_000)
  const runtime = runtimeManifest()
  const id = suffix()
  const code = `AC07_${id.toUpperCase()}`
  const name = `AC-07 浏览器角色 ${id}`
  const username = `ac07_${id}`
  const password = `Ac07-${randomBytes(18).toString('base64url')}!9a`
  let role: ManagedRole | undefined
  let user: ManagedUser | undefined
  let userContext: BrowserContext | undefined

  await login(page, runtime.privateBaseUrl)
  try {
    await page.goto(`${runtime.privateBaseUrl}/roles`)
    await page.getByRole('button', { name: '新建角色', exact: true }).click()
    const drawer = page.getByRole('dialog', { name: '新建角色' })
    await drawer.getByPlaceholder('请输入角色名称').fill(name)
    await drawer.getByPlaceholder('例如 PROJECT_MANAGER').fill(code)
    await drawer.getByRole('textbox', { name: '角色说明' }).fill('权限、菜单和并发版本运行验收')
    const projectListCheckbox = drawer.getByRole('checkbox', { name: /project:list/ })
    await expect(projectListCheckbox).toBeAttached()
    await drawer.locator('label.el-checkbox').filter({ hasText: 'project:list' }).click()
    await expect(projectListCheckbox).toBeChecked()
    await drawer.locator('.el-tree-node').filter({ hasText: '项目管理' }).first()
      .locator('.el-checkbox').click()
    const createResponsePromise = page.waitForResponse((response) =>
      response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/roles',
    )
    await drawer.getByRole('button', { name: '保存', exact: true }).click()
    const createResponse = await createResponsePromise
    expect(createResponse.status()).toBe(200)
    role = ((await createResponse.json()) as { data: ManagedRole }).data
    expect(role.permissionIds.map(String)).toContain(PROJECT_LIST_PERMISSION_ID)
    expect(role.menuIds.map(String)).toContain(PROJECT_MENU_ID)
    await expect(page.getByRole('row').filter({ hasText: code })).toHaveCount(1)

    const updated = await mutation<ManagedRole>(page, 'PUT', `/api/roles/${role.id}`, {
      name,
      description: '首次并发更新',
      status: 'ENABLED',
      version: role.version,
      permissionIds: role.permissionIds,
      menuIds: role.menuIds,
    })
    expect(updated.status).toBe(200)
    const stale = await mutation<ManagedRole>(page, 'PUT', `/api/roles/${role.id}`, {
      name,
      description: '旧版本不得覆盖',
      status: 'ENABLED',
      version: role.version,
      permissionIds: role.permissionIds,
      menuIds: role.menuIds,
    })
    expect(stale.status).toBe(409)
    role = updated.data!

    user = await createUser(page, username, password, [role.id])
    userContext = await browser.newContext()
    const userPage = await userContext.newPage()
    await login(userPage, runtime.privateBaseUrl, username, password, '/forbidden')
    const initialAccess = await getData<CurrentAccess>(
      userPage, runtime.privateBaseUrl, '/api/auth/me',
    )
    expect(initialAccess.permissions).toContain('project:list')
    expect(initialAccess.menuIds.map(String)).toContain(PROJECT_MENU_ID)
    await userPage.goto(`${runtime.privateBaseUrl}/projects`)
    await expect(userPage).toHaveURL((url) => url.pathname === '/projects')
    expect(await apiStatus(userPage, '/api/projects?page=1&size=1')).toBe(200)

    const revoked = await mutation<ManagedRole>(page, 'PUT', `/api/roles/${role.id}`, {
      name,
      description: '权限已回收',
      status: 'ENABLED',
      version: role.version,
      permissionIds: [],
      menuIds: [],
    })
    expect(revoked.status).toBe(200)
    role = revoked.data!
    expect(await apiStatus(userPage, '/api/projects?page=1&size=1')).toBe(403)

    await cleanup(page, 'DELETE', `/api/users/${user.id}`)
    user = undefined
    await page.goto(`${runtime.privateBaseUrl}/roles`)
    const roleRow = page.getByRole('row').filter({ hasText: code })
    await roleRow.getByRole('button', { name: '删除', exact: true }).click()
    const deleteDialog = page.getByRole('dialog', { name: '删除角色' })
    const deleteResponsePromise = page.waitForResponse((response) =>
      response.request().method() === 'DELETE'
      && new URL(response.url()).pathname === `/api/roles/${role!.id}`,
    )
    await deleteDialog.getByRole('button', { name: '确定', exact: true }).click()
    expect((await deleteResponsePromise).status()).toBe(200)
    await expect(page.getByText('角色已删除')).toBeVisible()
    role = undefined
  } finally {
    await closeContext(userContext)
    if (user) await cleanup(page, 'DELETE', `/api/users/${user.id}`)
    if (role) await cleanup(page, 'DELETE', `/api/roles/${role.id}`)
  }
})

test('AC-08 administrator continuity rejects self lockout, last-admin loss and built-in role weakening', async ({ browser, page }) => {
  test.setTimeout(120_000)
  const runtime = runtimeManifest()
  const id = suffix()
  const username = `ac08_admin_${id}`
  const password = `Ac08-${randomBytes(18).toString('base64url')}!9a`
  let secondAdmin: ManagedUser | undefined
  let secondContext: BrowserContext | undefined
  let ownerDisabled = false

  await login(page, runtime.privateBaseUrl)
  const owner = await getData<ManagedUser>(
    page, runtime.privateBaseUrl, `/api/users/${runtime.ownerId}`,
  )
  const administratorRole = await getData<ManagedRole>(
    page, runtime.privateBaseUrl, `/api/roles/${ADMIN_ROLE_ID}`,
  )
  expect((await mutation(page, 'DELETE', `/api/users/${owner.id}`)).status).toBe(409)
  expect((await mutation(page, 'PUT', `/api/users/${owner.id}`, {
    displayName: owner.displayName || owner.username,
    email: owner.email || null,
    mobile: owner.mobile || null,
    status: 'DISABLED',
    version: owner.version,
    roleIds: owner.roleIds,
  })).status).toBe(409)
  expect((await mutation(page, 'DELETE', `/api/roles/${ADMIN_ROLE_ID}`)).status).toBe(409)
  expect((await mutation(page, 'PUT', `/api/roles/${ADMIN_ROLE_ID}`, {
    name: administratorRole.name,
    description: administratorRole.description || null,
    status: 'DISABLED',
    version: administratorRole.version,
    permissionIds: administratorRole.permissionIds,
    menuIds: administratorRole.menuIds,
  })).status).toBe(409)
  expect((await mutation(page, 'PUT', `/api/roles/${ADMIN_ROLE_ID}`, {
    name: administratorRole.name,
    description: administratorRole.description || null,
    status: 'ENABLED',
    version: administratorRole.version,
    permissionIds: [],
    menuIds: administratorRole.menuIds,
  })).status).toBe(409)
  expect((await mutation(page, 'PUT', `/api/roles/${ADMIN_ROLE_ID}`, {
    name: administratorRole.name,
    description: administratorRole.description || null,
    status: 'ENABLED',
    version: administratorRole.version,
    permissionIds: administratorRole.permissionIds,
    menuIds: [],
  })).status).toBe(409)

  try {
    secondAdmin = await createUser(page, username, password, [ADMIN_ROLE_ID])
    secondContext = await browser.newContext()
    const secondPage = await secondContext.newPage()
    await login(secondPage, runtime.privateBaseUrl, username, password, '/overview')
    const currentOwner = await getData<ManagedUser>(
      secondPage, runtime.privateBaseUrl, `/api/users/${runtime.ownerId}`,
    )
    const disabledOwner = await mutation<ManagedUser>(
      secondPage,
      'PUT',
      `/api/users/${currentOwner.id}`,
      {
        displayName: currentOwner.displayName || currentOwner.username,
        email: currentOwner.email || null,
        mobile: currentOwner.mobile || null,
        status: 'DISABLED',
        version: currentOwner.version,
        roleIds: currentOwner.roleIds,
      },
    )
    expect(disabledOwner.status).toBe(200)
    ownerDisabled = true

    const currentSecond = await getData<ManagedUser>(
      secondPage, runtime.privateBaseUrl, `/api/users/${secondAdmin.id}`,
    )
    const lastAdminDemotion = await mutation(
      secondPage,
      'PUT',
      `/api/users/${currentSecond.id}`,
      {
        displayName: currentSecond.displayName || currentSecond.username,
        email: currentSecond.email || null,
        mobile: currentSecond.mobile || null,
        status: 'ENABLED',
        version: currentSecond.version,
        roleIds: [],
      },
    )
    expect(lastAdminDemotion.status).toBe(409)

    const latestOwner = await getData<ManagedUser>(
      secondPage, runtime.privateBaseUrl, `/api/users/${runtime.ownerId}`,
    )
    const enabledOwner = await mutation<ManagedUser>(
      secondPage,
      'PUT',
      `/api/users/${latestOwner.id}`,
      {
        displayName: latestOwner.displayName || latestOwner.username,
        email: latestOwner.email || null,
        mobile: latestOwner.mobile || null,
        status: 'ENABLED',
        version: latestOwner.version,
        roleIds: latestOwner.roleIds,
      },
    )
    expect(enabledOwner.status).toBe(200)
    ownerDisabled = false

    await login(page, runtime.privateBaseUrl)
    await cleanup(page, 'DELETE', `/api/users/${secondAdmin.id}`)
    secondAdmin = undefined
  } finally {
    if (ownerDisabled && secondContext) {
      const secondPage = secondContext.pages()[0]
      const latestOwner = await getData<ManagedUser>(
        secondPage, runtime.privateBaseUrl, `/api/users/${runtime.ownerId}`,
      )
      await mutation(secondPage, 'PUT', `/api/users/${latestOwner.id}`, {
        displayName: latestOwner.displayName || latestOwner.username,
        email: latestOwner.email || null,
        mobile: latestOwner.mobile || null,
        status: 'ENABLED',
        version: latestOwner.version,
        roleIds: latestOwner.roleIds,
      })
      ownerDisabled = false
    }
    await closeContext(secondContext)
    if (secondAdmin) {
      await login(page, runtime.privateBaseUrl)
      await cleanup(page, 'DELETE', `/api/users/${secondAdmin.id}`)
    }
  }
})

test('AC-09 withdrawing a role menu removes navigation and routes the existing user to 403', async ({ browser, page }) => {
  const runtime = runtimeManifest()
  const id = suffix()
  const username = `ac09_${id}`
  const password = `Ac09-${randomBytes(18).toString('base64url')}!9a`
  let role: ManagedRole | undefined
  let user: ManagedUser | undefined
  let userContext: BrowserContext | undefined
  await login(page, runtime.privateBaseUrl)
  try {
    role = await createRole(
      page,
      `AC09_${id.toUpperCase()}`,
      `AC-09 菜单角色 ${id}`,
      [PROJECT_LIST_PERMISSION_ID],
      [PROJECT_MENU_ID],
    )
    user = await createUser(page, username, password, [role.id])
    userContext = await browser.newContext()
    const userPage = await userContext.newPage()
    await login(userPage, runtime.privateBaseUrl, username, password, '/forbidden')
    const initialAccess = await getData<CurrentAccess>(
      userPage, runtime.privateBaseUrl, '/api/auth/me',
    )
    expect(initialAccess.permissions).toContain('project:list')
    expect(initialAccess.menuIds.map(String)).toContain(PROJECT_MENU_ID)
    await userPage.goto(`${runtime.privateBaseUrl}/projects`)
    await expect(userPage).toHaveURL((url) => url.pathname === '/projects')
    await expect(userPage.getByRole('menuitem', { name: '项目示例', exact: true })).toBeVisible()
    expect(await apiStatus(userPage, '/api/projects?page=1&size=1')).toBe(200)

    role = await requireMutation<ManagedRole>(page, 'PUT', `/api/roles/${role.id}`, {
      name: role.name,
      description: role.description || null,
      status: 'ENABLED',
      version: role.version,
      permissionIds: [PROJECT_LIST_PERMISSION_ID],
      menuIds: [],
    })
    await userPage.reload()
    await expect(userPage.getByRole('menuitem', { name: '项目示例', exact: true })).toHaveCount(0)
    await userPage.goto(`${runtime.privateBaseUrl}/projects`)
    await expect(userPage).toHaveURL((url) => url.pathname === '/forbidden')
    await expect(userPage.getByRole('main').getByText('无权访问', { exact: true })).toBeVisible()
    expect(await apiStatus(userPage, '/api/projects?page=1&size=1')).toBe(200)
  } finally {
    await closeContext(userContext)
    if (user) await cleanup(page, 'DELETE', `/api/users/${user.id}`)
    if (role) await cleanup(page, 'DELETE', `/api/roles/${role.id}`)
  }
})

test('AC-10 missing create permission hides the button and the manual API call still returns 403', async ({ browser, page }) => {
  const runtime = runtimeManifest()
  const id = suffix()
  const username = `ac10_${id}`
  const password = `Ac10-${randomBytes(18).toString('base64url')}!9a`
  const code = `AC10_DENIED_${id.toUpperCase()}`
  let role: ManagedRole | undefined
  let user: ManagedUser | undefined
  let userContext: BrowserContext | undefined
  await login(page, runtime.privateBaseUrl)
  try {
    role = await createRole(
      page,
      `AC10_${id.toUpperCase()}`,
      `AC-10 只读角色 ${id}`,
      [PROJECT_LIST_PERMISSION_ID],
      [PROJECT_MENU_ID],
    )
    expect(role.permissionIds.map(String)).not.toContain(PROJECT_CREATE_PERMISSION_ID)
    user = await createUser(page, username, password, [role.id])
    userContext = await browser.newContext()
    const userPage = await userContext.newPage()
    await login(userPage, runtime.privateBaseUrl, username, password, '/forbidden')
    const initialAccess = await getData<CurrentAccess>(
      userPage, runtime.privateBaseUrl, '/api/auth/me',
    )
    expect(initialAccess.permissions).toContain('project:list')
    expect(initialAccess.permissions).not.toContain('project:create')
    expect(initialAccess.menuIds.map(String)).toContain(PROJECT_MENU_ID)
    await userPage.goto(`${runtime.privateBaseUrl}/projects`)
    await expect(userPage).toHaveURL((url) => url.pathname === '/projects')
    await expect(userPage.getByRole('button', { name: '新建项目', exact: true })).toHaveCount(0)
    const denied = await mutation(userPage, 'POST', '/api/projects', {
      name: '不应创建的项目',
      code,
      ownerId: user.id,
      status: 'PLANNING',
      description: '按钮隐藏不能替代 API 权限',
    })
    expect(denied.status).toBe(403)
    const list = await getData<PageData<ManagedProject>>(
      userPage,
      runtime.privateBaseUrl,
      `/api/projects?page=1&size=20&keyword=${encodeURIComponent(code)}`,
    )
    expect(list.total).toBe(0)
  } finally {
    await closeContext(userContext)
    if (user) await cleanup(page, 'DELETE', `/api/users/${user.id}`)
    if (role) await cleanup(page, 'DELETE', `/api/roles/${role.id}`)
  }
})

test('AC-11 permission dictionary enforces unique codes, controllable status and protected assignments', async ({ page }) => {
  const runtime = runtimeManifest()
  const id = suffix()
  const code = `acceptance:ac11:${id}`
  let permission: ManagedPermission | undefined
  await login(page, runtime.privateBaseUrl)
  try {
    permission = await requireMutation<ManagedPermission>(page, 'POST', '/api/permissions', {
      code,
      name: `AC-11 临时权限 ${id}`,
      type: 'API',
      description: '权限字典运行验收',
      status: 'ENABLED',
    })
    const duplicate = await mutation(page, 'POST', '/api/permissions', {
      code,
      name: `AC-11 重复权限 ${id}`,
      type: 'API',
      description: '不得创建',
      status: 'ENABLED',
    })
    expect(duplicate.status).toBe(409)
    permission = await requireMutation<ManagedPermission>(
      page,
      'PUT',
      `/api/permissions/${permission.id}`,
      {
        code,
        name: `AC-11 临时权限 ${id}`,
        type: 'API',
        description: '状态已停用',
        status: 'DISABLED',
      },
    )
    expect(permission.status).toBe('DISABLED')
    const filtered = await getData<ManagedPermission[]>(
      page,
      runtime.privateBaseUrl,
      `/api/permissions?keyword=${encodeURIComponent(code)}&status=DISABLED`,
    )
    expect(filtered).toHaveLength(1)
    expect(filtered[0].id).toBe(permission.id)
    expect((await mutation(page, 'DELETE', `/api/permissions/${PROJECT_LIST_PERMISSION_ID}`)).status)
      .toBe(409)
    expect((await mutation(page, 'DELETE', `/api/permissions/${permission.id}`)).status).toBe(200)
    permission = undefined
  } finally {
    if (permission) await cleanup(page, 'DELETE', `/api/permissions/${permission.id}`)
  }
})

test('AC-12 non-sensitive configuration is maintained in the browser while secret-like keys are rejected', async ({ page }) => {
  test.setTimeout(90_000)
  const runtime = runtimeManifest()
  const id = suffix()
  const key = `acceptance.ac12.${id}`
  let config: ManagedConfig | undefined
  await login(page, runtime.privateBaseUrl)
  try {
    await page.goto(`${runtime.privateBaseUrl}/configs`)
    await page.getByRole('button', { name: '新建配置', exact: true }).click()
    const createDrawer = page.getByRole('dialog', { name: '新建配置' })
    await createDrawer.getByPlaceholder('例如 system.page-size').fill(key)
    const valueTypeSelect = createDrawer.getByRole('combobox', { name: '值类型' })
    await valueTypeSelect.focus()
    await valueTypeSelect.press('ArrowDown')
    await page.getByRole('option', { name: 'STRING', exact: true }).click()
    await createDrawer.getByRole('textbox', { name: '配置值' }).fill('enabled')
    await createDrawer.getByRole('textbox', { name: '说明' }).fill('AC-12 页面配置验收')
    const createResponsePromise = page.waitForResponse((response) =>
      response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/configs',
    )
    await createDrawer.getByRole('button', { name: '保存', exact: true }).click()
    const createResponse = await createResponsePromise
    expect(createResponse.status()).toBe(200)
    config = ((await createResponse.json()) as { data: ManagedConfig }).data
    let row = page.getByRole('row').filter({ hasText: key })
    await expect(row.getByText('enabled', { exact: true })).toBeVisible()

    await row.getByRole('button', { name: '编辑', exact: true }).click()
    const editDrawer = page.getByRole('dialog', { name: '编辑配置' })
    await editDrawer.getByRole('textbox', { name: '配置值' }).fill('disabled')
    const updateResponsePromise = page.waitForResponse((response) =>
      response.request().method() === 'PUT'
      && new URL(response.url()).pathname === `/api/configs/${config!.id}`,
    )
    await editDrawer.getByRole('button', { name: '保存', exact: true }).click()
    const updateResponse = await updateResponsePromise
    expect(updateResponse.status()).toBe(200)
    config = ((await updateResponse.json()) as { data: ManagedConfig }).data
    row = page.getByRole('row').filter({ hasText: key })
    await expect(row.getByText('disabled', { exact: true })).toBeVisible()

    for (const marker of ['password', 'secret', 'token', 'credential', 'private-key']) {
      const secretValue = `forbidden-${marker}-${id}`
      const denied = await mutation(page, 'POST', '/api/configs', {
        configKey: `acceptance.${marker}.${id}`,
        configValue: secretValue,
        valueType: 'STRING',
        description: '不得落库',
      })
      expect(denied.status).toBe(400)
      expect(JSON.stringify(denied)).not.toContain(secretValue)
      const missing = await getData<PageData<ManagedConfig>>(
        page,
        runtime.privateBaseUrl,
        `/api/configs?page=1&size=20&keyword=${encodeURIComponent(`acceptance.${marker}.${id}`)}`,
      )
      expect(missing.total).toBe(0)
    }

    await row.getByRole('button', { name: '删除', exact: true }).click()
    const deleteDialog = page.getByRole('dialog', { name: '删除配置' })
    const deleteResponsePromise = page.waitForResponse((response) =>
      response.request().method() === 'DELETE'
      && new URL(response.url()).pathname === `/api/configs/${config!.id}`,
    )
    await deleteDialog.getByRole('button', { name: '确定', exact: true }).click()
    expect((await deleteResponsePromise).status()).toBe(200)
    await expect(page.getByText('配置已删除')).toBeVisible()
    config = undefined
  } finally {
    if (config) await cleanup(page, 'DELETE', `/api/configs/${config.id}`)
  }
})

test('AC-13 project list supports paging cap keyword status filters and browser details', async ({ page }) => {
  const runtime = runtimeManifest()
  const id = suffix()
  const keyword = `AC13_${id.toUpperCase()}`
  const projects: ManagedProject[] = []
  await login(page, runtime.privateBaseUrl)
  try {
    for (const [index, status] of (['PLANNING', 'IN_PROGRESS', 'ARCHIVED'] as const).entries()) {
      projects.push(await requireMutation<ManagedProject>(page, 'POST', '/api/projects', {
        name: `${keyword} 项目 ${index + 1}`,
        code: `${keyword}_${index + 1}`,
        ownerId: runtime.ownerId,
        status,
        description: `AC-13 ${status} 详情`,
      }))
    }
    const firstPage = await getData<PageData<ManagedProject>>(
      page,
      runtime.privateBaseUrl,
      `/api/projects?page=1&size=1&keyword=${keyword}`,
    )
    expect(firstPage).toMatchObject({ total: 3, page: 1, size: 1 })
    expect(firstPage.records).toHaveLength(1)
    const capped = await getData<PageData<ManagedProject>>(
      page,
      runtime.privateBaseUrl,
      `/api/projects?page=1&size=999&keyword=${keyword}`,
    )
    expect(capped.size).toBe(200)
    expect(capped.records).toHaveLength(3)
    const filtered = await getData<PageData<ManagedProject>>(
      page,
      runtime.privateBaseUrl,
      `/api/projects?page=1&size=20&keyword=${keyword}&status=IN_PROGRESS`,
    )
    expect(filtered.total).toBe(1)
    expect(filtered.records[0].status).toBe('IN_PROGRESS')
    const detail = await getData<ManagedProject>(
      page,
      runtime.privateBaseUrl,
      `/api/projects/${filtered.records[0].id}`,
    )
    expect(detail).toMatchObject({
      code: `${keyword}_2`,
      description: 'AC-13 IN_PROGRESS 详情',
    })

    await page.goto(`${runtime.privateBaseUrl}/projects`)
    const search = page.getByPlaceholder('搜索项目名称或编码')
    await search.fill(keyword)
    await search.press('Enter')
    await expect(page.getByRole('row').filter({ hasText: `${keyword}_2` })).toHaveCount(1)
    const statusSelect = page.locator('.filter-row .el-select')
    await statusSelect.click()
    await page.getByRole('option', { name: '进行中', exact: true }).click()
    const row = page.getByRole('row').filter({ hasText: `${keyword}_2` })
    await expect(row).toHaveCount(1)
    await expect(page.getByRole('row').filter({ hasText: `${keyword}_1` })).toHaveCount(0)
    await row.getByRole('button', { name: '查看', exact: true }).click()
    const detailDrawer = page.getByRole('dialog', { name: '项目详情' })
    await expect(detailDrawer.getByPlaceholder('请输入项目编码')).toHaveValue(`${keyword}_2`)
    await expect(detailDrawer.getByPlaceholder('请输入项目说明（可选）')).toHaveValue('AC-13 IN_PROGRESS 详情')
  } finally {
    for (const project of projects.reverse()) {
      await cleanup(page, 'DELETE', `/api/projects/${project.id}?version=${project.version}`)
    }
  }
})

test('AC-14 project writes enforce uniqueness validation optimistic conflict and logical deletion', async ({ page }) => {
  const runtime = runtimeManifest()
  const id = suffix()
  const code = `AC14_${id.toUpperCase()}`
  let project: ManagedProject | undefined
  await login(page, runtime.privateBaseUrl)
  try {
    project = await requireMutation<ManagedProject>(page, 'POST', '/api/projects', {
      name: `AC-14 项目 ${id}`,
      code,
      ownerId: runtime.ownerId,
      status: 'PLANNING',
      description: '创建、更新、逻辑删除和冲突验收',
    })
    expect(project.code).toBe(code)
    const duplicate = await mutation(page, 'POST', '/api/projects', {
      name: `AC-14 重复项目 ${id}`,
      code: code.toLowerCase(),
      ownerId: runtime.ownerId,
      status: 'PLANNING',
      description: '不得创建',
    })
    expect(duplicate.status).toBe(409)
    const invalid = await mutation(page, 'POST', '/api/projects', {
      name: '',
      code: 'invalid code with spaces',
      ownerId: runtime.ownerId,
      status: 'UNKNOWN',
      description: '不得创建',
    })
    expect(invalid.status).toBe(400)

    const oldVersion = project.version
    project = await requireMutation<ManagedProject>(
      page,
      'PUT',
      `/api/projects/${project.id}`,
      {
        name: `AC-14 项目已更新 ${id}`,
        ownerId: runtime.ownerId,
        status: 'IN_PROGRESS',
        description: '更新成功',
        version: oldVersion,
      },
    )
    expect(project.version).toBe(oldVersion + 1)
    const stale = await mutation(page, 'PUT', `/api/projects/${project.id}`, {
      name: '旧版本不得覆盖',
      ownerId: runtime.ownerId,
      status: 'ARCHIVED',
      description: '不得写入',
      version: oldVersion,
    })
    expect(stale.status).toBe(409)

    const removed = await mutation(
      page,
      'DELETE',
      `/api/projects/${project.id}?version=${project.version}`,
    )
    expect(removed.status).toBe(200)
    expect(await apiStatus(page, `/api/projects/${project.id}`)).toBe(404)
    const missing = await getData<PageData<ManagedProject>>(
      page,
      runtime.privateBaseUrl,
      `/api/projects?page=1&size=20&keyword=${code}`,
    )
    expect(missing.total).toBe(0)
    project = undefined
  } finally {
    if (project) {
      await cleanup(page, 'DELETE', `/api/projects/${project.id}?version=${project.version}`)
    }
  }
})

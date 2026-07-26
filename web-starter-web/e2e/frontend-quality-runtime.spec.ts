import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test, expect, type Locator, type Page, type Response, type Route } from '@playwright/test'

interface RuntimeManifest {
  schemaVersion: number
  privateBaseUrl: string
  publicBaseUrl: string
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

interface ExpectedProjectPage {
  page: string
  size: string
  keyword: string
  status: string
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

async function login(page: Page, baseUrl: string, redirect = '/projects'): Promise<void> {
  const redirectUrl = new URL(redirect, baseUrl)
  const loginUrl = new URL('/login', baseUrl)
  loginUrl.searchParams.set('redirect', `${redirectUrl.pathname}${redirectUrl.search}`)
  await page.goto(loginUrl.toString())
  await page.getByPlaceholder('请输入用户名').fill(
    requiredEnvironment('WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME'),
  )
  await page.getByPlaceholder('请输入密码').fill(
    requiredEnvironment('WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD'),
  )
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await expect(page).toHaveURL((url) =>
    url.pathname === redirectUrl.pathname && url.search === redirectUrl.search,
  )
  await expect(page.getByRole('heading', { name: '项目示例', exact: true })).toBeVisible()
}

function pageEnvelope(url: string): string {
  const query = new URL(url).searchParams
  const page = Number(query.get('page') ?? '1')
  const size = Number(query.get('size') ?? '10')
  const keyword = query.get('keyword') ?? ''
  const empty = keyword === 'EMPTY'
  return JSON.stringify({
    code: 0,
    message: 'OK',
    data: {
      records: empty
        ? []
        : [{
            id: 'quality-project-1',
            name: keyword || 'Quality Project',
            code: 'QUALITY_PROJECT',
            ownerId: '1',
            ownerName: 'Quality Owner',
            status: query.get('status') || 'IN_PROGRESS',
            description: 'Browser quality fixture',
            version: 0,
            createdAt: '2026-07-19T00:00:00Z',
            updatedAt: '2026-07-19T00:00:00Z',
          }],
      total: empty ? 0 : 45,
      page,
      size,
    },
  })
}

async function fulfillProjectPage(route: Route): Promise<void> {
  await route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: pageEnvelope(route.request().url()),
  })
}

async function waitForProjectPage(
  page: Page,
  expected: ExpectedProjectPage,
  observedRequests: string[],
): Promise<Response> {
  try {
    return await page.waitForResponse((candidate) => {
      const url = new URL(candidate.url())
      return candidate.request().method() === 'GET'
        && url.pathname === '/api/projects'
        && Object.entries(expected).every(([name, value]) => url.searchParams.get(name) === value)
    })
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new Error(
      `Expected project page response ${JSON.stringify(expected)}; observed ${JSON.stringify(observedRequests)}; ${detail}`,
    )
  }
}

async function submitProjectSearch(
  page: Page,
  search: Locator,
  keyword: string,
  observedRequests: string[],
): Promise<Response> {
  await search.fill(keyword)
  const [response] = await Promise.all([
    waitForProjectPage(page, {
      page: '1',
      size: '20',
      keyword,
      status: 'IN_PROGRESS',
    }, observedRequests),
    search.press('Enter'),
  ])
  expect(response.status()).toBe(200)
  return response
}

test.describe.configure({ mode: 'serial' })

test('real login endpoint applies generic progressive protection without blocking another account', async ({ page }) => {
  const runtime = runtimeManifest()
  const tracePrefix = requiredEnvironment('WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX')
  const executionId = randomBytes(6).toString('hex')
  const failedTrace = `${tracePrefix}-login-${executionId}-failure`
  const successTrace = `${tracePrefix}-login-${executionId}-success`
  const invalidPassword = 'deliberately-invalid-browser-password'
  const adminUsername = requiredEnvironment('WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME')
  const adminPassword = requiredEnvironment('WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD')
  await page.goto(new URL('/login', runtime.privateBaseUrl).toString())

  const csrf = await page.evaluate(async () => {
    const response = await fetch('/api/auth/csrf')
    const envelope = await response.json() as {
      data?: { headerName?: string; token?: string }
    }
    const token = envelope.data?.token
    if (!response.ok || !token) throw new Error('CSRF token missing for login protection acceptance')
    return { headerName: envelope.data?.headerName || 'X-XSRF-TOKEN', token }
  })
  const attempt = async (username: string, password: string, traceId: string): Promise<{
    status: number
    retryAfter: string | null
    code?: number
    message?: string
    rawBody: string
  }> => page.evaluate(async (input) => {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Trace-Id': input.traceId,
        [input.csrf.headerName]: input.csrf.token,
      },
      body: JSON.stringify({ username: input.username, password: input.password }),
    })
    const rawBody = await response.text()
    const body = JSON.parse(rawBody) as { code?: number; message?: string }
    return {
      status: response.status,
      retryAfter: response.headers.get('Retry-After'),
      code: body.code,
      message: body.message,
      rawBody,
    }
  }, { username, password, traceId, csrf })

  const existingFailure = await attempt(
    adminUsername,
    invalidPassword,
    failedTrace,
  )
  expect(existingFailure.status).toBe(401)
  expect(existingFailure.code).toBe(4001)
  expect(existingFailure.rawBody).not.toContain(invalidPassword)
  expect(existingFailure.rawBody).not.toContain(adminPassword)
  expect(existingFailure.rawBody).not.toMatch(/"(?:password|authorization|cookie|access_token|refresh_token|client_secret|requestBody|responseBody)"\s*:/i)

  const missingUsername = `missing-quality-${Date.now().toString(36)}`
  let firstMissingFailure: Awaited<ReturnType<typeof attempt>> | null = null
  let rateLimited: Awaited<ReturnType<typeof attempt>> | null = null
  for (let count = 0; count < 40; count += 1) {
    const response = await attempt(
      missingUsername,
      invalidPassword,
      `${tracePrefix}-login-${executionId}-missing-${count}`,
    )
    if (!firstMissingFailure && response.status === 401) firstMissingFailure = response
    if (response.status === 429) {
      rateLimited = response
      break
    }
  }
  expect(firstMissingFailure?.code).toBe(existingFailure.code)
  expect(firstMissingFailure?.message).toBe(existingFailure.message)
  expect(rateLimited?.code).toBe(4290)
  expect(Number(rateLimited?.retryAfter)).toBeGreaterThan(0)
  expect(firstMissingFailure?.rawBody).not.toContain(invalidPassword)
  expect(rateLimited?.rawBody).not.toContain(invalidPassword)

  const unaffectedAccount = await attempt(
    adminUsername,
    adminPassword,
    successTrace,
  )
  expect(unaffectedAccount.status).toBe(200)
  expect(unaffectedAccount.code).toBe(0)

  const sessionCookie = (await page.context().cookies(runtime.privateBaseUrl))
    .find((cookie) => cookie.name === 'WEB_STARTER_SESSION')
  if (!sessionCookie?.value) throw new Error('SAFE_SESSION_COOKIE_MISSING')
  if (!sessionCookie.httpOnly) throw new Error('SAFE_SESSION_COOKIE_NOT_HTTP_ONLY')
  const sessionProbe = await page.evaluate(async () => {
    const response = await fetch('/api/auth/me', {
      headers: { Accept: 'application/json' },
    })
    return {
      status: response.status,
      body: await response.text(),
    }
  })
  expect(sessionProbe.status).toBe(200)
  expect(sessionProbe.body).not.toContain(invalidPassword)
  expect(sessionProbe.body).not.toContain(adminPassword)
  const currentCaller = JSON.parse(sessionProbe.body) as {
    data?: { callerType?: string; subjectId?: string; username?: string }
  }
  expect(currentCaller.data).toMatchObject({
    callerType: 'USER',
    username: adminUsername,
  })
  expect(currentCaller.data?.subjectId).not.toHaveLength(0)

  const auditByTrace = async (traceId: string, result: string): Promise<PageData<LoginAudit>> => {
    const response = await page.evaluate(async (input) => {
      const query = new URLSearchParams({
        page: '1',
        size: '20',
        username: input.username,
        result: input.result,
        traceId: input.traceId,
      })
      const auditResponse = await fetch(`/api/logs/login?${query.toString()}`, {
        headers: { Accept: 'application/json' },
      })
      return {
        status: auditResponse.status,
        body: await auditResponse.text(),
      }
    }, { username: adminUsername, result, traceId })
    expect(response.status).toBe(200)
    expect(response.body).not.toContain(invalidPassword)
    expect(response.body).not.toContain(adminPassword)
    expect(response.body).not.toMatch(/"(?:password|authorization|cookie|tokenHash|requestBody|responseBody)"\s*:/i)
    const envelope = JSON.parse(response.body) as { data?: PageData<LoginAudit> }
    if (!envelope.data) throw new Error('Login audit response did not contain page data')
    return envelope.data
  }

  const failedAudit = await auditByTrace(failedTrace, 'FAILURE')
  const successAudit = await auditByTrace(successTrace, 'SUCCESS')
  for (const [audit, expectedResult, expectedTrace] of [
    [failedAudit, 'FAILURE', failedTrace],
    [successAudit, 'SUCCESS', successTrace],
  ] as const) {
    expect(audit.total).toBe(1)
    expect(audit.records).toHaveLength(1)
    expect(audit.records[0]).toMatchObject({
      username: adminUsername,
      result: expectedResult,
      traceId: expectedTrace,
    })
    expect(audit.records[0].ipAddress).not.toHaveLength(0)
    expect(audit.records[0].userAgent).not.toHaveLength(0)
  }
})

test('query, pagination, loading, empty and validation states remain usable in a real browser', async ({ page }) => {
  const runtime = runtimeManifest()
  const listPattern = '**/api/projects?**'
  const initialPath = '/projects?page=2&size=20&keyword=Initial&status=IN_PROGRESS'
  const observedProjectRequests: string[] = []
  let releaseInitialPage!: () => void
  const initialPageGate = new Promise<void>((resolve) => {
    releaseInitialPage = resolve
  })
  page.on('request', (request) => {
    const url = new URL(request.url())
    if (url.pathname === '/api/projects') observedProjectRequests.push(url.toString())
  })
  await page.route(listPattern, async (route) => {
    if (new URL(route.request().url()).searchParams.get('keyword') === 'Initial') {
      await initialPageGate
    }
    await fulfillProjectPage(route)
  })
  const initialResponse = waitForProjectPage(page, {
    page: '2',
    size: '20',
    keyword: 'Initial',
    status: 'IN_PROGRESS',
  }, observedProjectRequests)
  await login(page, runtime.privateBaseUrl, initialPath)
  await expect(page.locator('.el-loading-mask')).toBeVisible()
  releaseInitialPage()
  expect((await initialResponse).status()).toBe(200)
  await expect(page.getByRole('cell', { name: 'Initial', exact: true })).toBeVisible()
  await expect(page.locator('.el-loading-mask')).toBeHidden()
  await expect(page).toHaveURL((url) =>
    url.searchParams.get('page') === '2'
      && url.searchParams.get('size') === '20'
      && url.searchParams.get('keyword') === 'Initial'
      && url.searchParams.get('status') === 'IN_PROGRESS',
  )

  const search = page.getByPlaceholder('搜索项目名称或编码')
  await submitProjectSearch(page, search, 'Roadmap', observedProjectRequests)
  await expect(page).toHaveURL((url) =>
    url.searchParams.get('page') === '1' && url.searchParams.get('keyword') === 'Roadmap',
  )
  await expect(page.locator('.el-loading-mask')).toBeHidden()
  await expect(page.getByRole('cell', { name: 'Roadmap', exact: true })).toBeVisible()

  const pageTwoResponse = waitForProjectPage(page, {
    page: '2',
    size: '20',
    keyword: 'Roadmap',
    status: 'IN_PROGRESS',
  }, observedProjectRequests)
  const [, response] = await Promise.all([
    page.locator('.el-pager li.number').filter({ hasText: /^2$/ }).click(),
    pageTwoResponse,
  ])
  expect(response.status()).toBe(200)
  await expect(page).toHaveURL((url) => url.searchParams.get('page') === '2')
  await expect(page.locator('.el-loading-mask')).toBeHidden()
  await expect(page.getByRole('cell', { name: 'Roadmap', exact: true })).toBeVisible()

  await submitProjectSearch(page, search, 'EMPTY', observedProjectRequests)
  await expect(page).toHaveURL((url) =>
    url.searchParams.get('page') === '1' && url.searchParams.get('keyword') === 'EMPTY',
  )
  await expect(page.locator('.el-loading-mask')).toBeHidden()
  await expect(page.getByText('暂无项目数据', { exact: true })).toBeVisible()

  await page.getByRole('button', { name: '新建项目', exact: true }).click()
  const drawer = page.getByRole('dialog', { name: '新建项目' })
  await expect(drawer).toBeVisible()
  await drawer.getByRole('button', { name: '保存', exact: true }).click()
  const validationErrors = drawer.locator('.el-form-item__error')
  await expect(validationErrors.filter({ hasText: /^请输入项目名称$/ })).toBeVisible()
  await expect(validationErrors.filter({ hasText: /^请输入项目编码$/ })).toBeVisible()
  await expect(validationErrors.filter({ hasText: /^请选择负责人$/ })).toBeVisible()
})

test('401, 403, 404, 409, 429 and 500 states have stable browser behavior and trace IDs', async ({ page }) => {
  const runtime = runtimeManifest()
  await login(page, runtime.privateBaseUrl)
  const listPattern = '**/api/projects?**'

  const errorCases = [
    { status: 403, code: 4003, title: '没有操作权限' },
    { status: 404, code: 4004, title: '资源不存在' },
    { status: 409, code: 4090, title: '数据已发生变化' },
    { status: 429, code: 4290, title: '请求过于频繁' },
    { status: 500, code: 5000, title: '服务器处理失败' },
  ] as const

  for (const errorCase of errorCases) {
    await page.unroute(listPattern)
    const traceId = `quality-browser-${errorCase.status}`
    await page.route(listPattern, async (route) => {
      await route.fulfill({
        status: errorCase.status,
        contentType: 'application/json',
        headers: errorCase.status === 429 ? { 'Retry-After': '7' } : {},
        body: JSON.stringify({
          code: errorCase.code,
          message: 'Sanitized runtime failure',
          data: null,
          traceId,
        }),
      })
    })
    await page.goto(`${runtime.privateBaseUrl}/projects?page=1&size=10&keyword=ERR${errorCase.status}`)
    await expect(page.getByText(errorCase.title, { exact: true })).toBeVisible()
    await expect(page.getByText(`Trace ID：${traceId}`, { exact: true })).toBeVisible()
  }

  await page.unroute(listPattern)
  await page.route(listPattern, async (route) => {
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({
        code: 4001,
        message: 'Invalid or expired session',
        data: null,
        traceId: 'quality-browser-401',
      }),
    })
  })
  await page.goto(`${runtime.privateBaseUrl}/projects?page=1&size=10&keyword=ERR401`)
  await expect(page).toHaveURL((url) =>
    url.pathname === '/login' && (url.searchParams.get('redirect') ?? '').includes('/projects'),
  )
  await expect(page.getByRole('heading', { name: '欢迎登录', exact: true })).toBeVisible()
})

test('desktop, tablet and 390px layouts pass keyboard and basic accessibility checks', async ({ page }) => {
  const runtime = runtimeManifest()
  await login(page, runtime.privateBaseUrl)

  for (const viewport of [
    { width: 1280, height: 800 },
    { width: 768, height: 1024 },
    { width: 390, height: 844 },
  ]) {
    await page.setViewportSize(viewport)
    await page.goto(`${runtime.privateBaseUrl}/projects?page=1&size=10`)
    await expect(page.getByRole('heading', { name: '项目示例', exact: true })).toBeVisible()
    await expect(page.locator('main')).toBeVisible()

    const documentQuality = await page.evaluate(() => {
      const visible = (element: Element): boolean => {
        const rectangle = element.getBoundingClientRect()
        const style = getComputedStyle(element)
        return rectangle.width > 0 && rectangle.height > 0
          && style.visibility !== 'hidden' && style.display !== 'none'
      }
      const ids = Array.from(document.querySelectorAll<HTMLElement>('[id]'))
        .map((element) => element.id)
        .filter(Boolean)
      const duplicateIds = ids.filter((id, index) => ids.indexOf(id) !== index)
      const unnamed = Array.from(
        document.querySelectorAll<HTMLElement>('button, a[href], input, select, textarea'),
      ).filter((element) => {
        if (!visible(element) || element.hasAttribute('disabled')) return false
        const labelledBy = element.getAttribute('aria-labelledby')
        const labelledText = labelledBy
          ? labelledBy.split(/\s+/).map((id) => document.getElementById(id)?.textContent ?? '').join(' ')
          : ''
        return ![
          element.getAttribute('aria-label'),
          labelledText,
          element.getAttribute('title'),
          element.getAttribute('placeholder'),
          element.textContent,
        ].some((value) => value?.trim())
      })
      return {
        duplicateIds,
        imagesWithoutAlt: document.querySelectorAll('img:not([alt])').length,
        unnamedInteractiveElements: unnamed.length,
        horizontalOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      }
    })
    expect(documentQuality.duplicateIds).toEqual([])
    expect(documentQuality.imagesWithoutAlt).toBe(0)
    expect(documentQuality.unnamedInteractiveElements).toBe(0)
    expect(documentQuality.horizontalOverflow).toBeLessThanOrEqual(0)

    await page.keyboard.press(process.platform === 'darwin' ? 'Meta+K' : 'Control+K')
    const commandDialog = page.getByRole('dialog', { name: '搜索功能' })
    await expect(commandDialog).toBeVisible()
    await expect(commandDialog.getByRole('textbox', { name: '搜索可访问页面' })).toBeFocused()
    await page.keyboard.press('Escape')
    await expect(commandDialog).toBeHidden()

    await page.locator('body').click({ position: { x: 2, y: 2 } })
    let focusEvidence: { interactive: boolean; visibleIndicator: boolean } | null = null
    for (let attempt = 0; attempt < 12; attempt += 1) {
      await page.keyboard.press('Tab')
      focusEvidence = await page.evaluate(() => {
        const element = document.activeElement
        if (!(element instanceof HTMLElement)) return { interactive: false, visibleIndicator: false }
        const style = getComputedStyle(element)
        return {
          interactive: element.matches('a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])'),
          visibleIndicator: style.outlineStyle !== 'none'
            && Number.parseFloat(style.outlineWidth || '0') > 0,
        }
      })
      if (focusEvidence.interactive) break
    }
    expect(focusEvidence?.interactive).toBe(true)
    expect(focusEvidence?.visibleIndicator).toBe(true)

    const mobileMenu = page.getByRole('button', { name: '打开主导航' })
    if (viewport.width <= 900) {
      await expect(mobileMenu).toBeVisible()
      await mobileMenu.click()
      await expect(page.getByRole('navigation', { name: '主导航' })).toBeVisible()
      await page.keyboard.press('Escape')
    } else {
      await expect(mobileMenu).toBeHidden()
    }
  }

  for (const path of [
    '/v3/api-docs',
    '/api-docs',
    '/openapi.json',
    '/swagger-ui.html',
    '/swagger-ui/index.html',
  ]) {
    const response = await page.goto(new URL(path, runtime.publicBaseUrl).toString(), {
      waitUntil: 'domcontentloaded',
    })
    expect(response?.status(), `public MCP ingress must hide ${path}`).toBe(404)
  }
})

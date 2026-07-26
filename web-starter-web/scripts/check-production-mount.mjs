import console from 'node:console'
import { Buffer } from 'node:buffer'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { clearTimeout as cancelTimer, setTimeout as scheduleTimer } from 'node:timers'
import { pathToFileURL, URL } from 'node:url'
import { JSDOM } from 'jsdom'

const FetchRequest = globalThis.Request
const FetchResponse = globalThis.Response

class UnauthorizedXmlHttpRequest {
  readyState = 0
  status = 0
  statusText = ''
  responseText = ''
  response = null
  responseURL = ''
  timeout = 0
  withCredentials = false
  onloadend = null
  onreadystatechange = null
  onabort = null
  onerror = null
  ontimeout = null
  upload = { addEventListener() {} }

  open(_method, url) {
    this.responseURL = new URL(url, 'http://localhost').toString()
    this.readyState = 1
  }

  setRequestHeader() {}
  addEventListener() {}
  removeEventListener() {}
  abort() {
    this.onabort?.()
  }

  getAllResponseHeaders() {
    return 'content-type: application/json\r\n'
  }

  send() {
    void Promise.resolve().then(() => {
      this.status = 401
      this.statusText = 'Unauthorized'
      this.responseText = JSON.stringify({
        code: 4001,
        message: 'Authentication required',
        data: null,
        traceId: 'production-mount-smoke',
      })
      this.response = this.responseText
      this.readyState = 4
      this.onreadystatechange?.()
      this.onloadend?.()
    })
  }
}

function installBrowserGlobals(dom) {
  const { window } = dom
  const smokeFetch = async (input) => {
    const url = String(input instanceof FetchRequest ? input.url : input)
    if (url.includes('/api/')) {
      return new FetchResponse(
        JSON.stringify({
          code: 4001,
          message: 'Authentication required',
          data: null,
          traceId: 'production-mount-smoke',
        }),
        { status: 401, headers: { 'content-type': 'application/json' } },
      )
    }
    return new FetchResponse('', { status: 200 })
  }
  const values = {
    window,
    document: window.document,
    navigator: window.navigator,
    location: window.location,
    history: window.history,
    localStorage: window.localStorage,
    sessionStorage: window.sessionStorage,
    Node: window.Node,
    Element: window.Element,
    HTMLElement: window.HTMLElement,
    SVGElement: window.SVGElement,
    ShadowRoot: window.ShadowRoot,
    Event: window.Event,
    CustomEvent: window.CustomEvent,
    MutationObserver: window.MutationObserver,
    getComputedStyle: window.getComputedStyle.bind(window),
    XMLHttpRequest: UnauthorizedXmlHttpRequest,
    fetch: smokeFetch,
  }
  for (const [name, value] of Object.entries(values)) {
    Object.defineProperty(globalThis, name, { configurable: true, value, writable: true })
  }
  const matchMedia = () => ({
    matches: false,
    media: '',
    onchange: null,
    addEventListener() {},
    removeEventListener() {},
    addListener() {},
    removeListener() {},
    dispatchEvent() { return true },
  })
  window.matchMedia = matchMedia
  window.fetch = smokeFetch
  globalThis.matchMedia = matchMedia
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  globalThis.requestAnimationFrame = (callback) => scheduleTimer(() => callback(Date.now()), 0)
  globalThis.cancelAnimationFrame = (handle) => cancelTimer(handle)
  if (!globalThis.CSS) globalThis.CSS = { supports: () => false }
}

async function waitForMount(root, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (root.querySelector('[data-web-starter-mounted]')) return
    await new Promise((resolve) => scheduleTimer(resolve, 20))
  }
  throw new Error(`production entry did not mount the application root; html=${root.innerHTML.slice(0, 120)}`)
}

export async function checkProductionMount(rootDirectory) {
  const dist = path.join(rootDirectory, 'dist')
  const manifest = JSON.parse(await readFile(path.join(dist, '.vite/manifest.json'), 'utf8'))
  const entries = Object.values(manifest).filter((record) => record?.isEntry === true)
  if (entries.length !== 1 || typeof entries[0]?.file !== 'string') {
    throw new Error(`expected exactly one production entry, found ${entries.length}`)
  }

  const dom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', {
    url: 'http://localhost/login',
    pretendToBeVisual: true,
  })
  installBrowserGlobals(dom)
  const entryUrl = pathToFileURL(path.join(dist, entries[0].file)).href
  await import(`${entryUrl}?mount-smoke=${Date.now()}`)
  const root = dom.window.document.querySelector('#app')
  if (!root) throw new Error('production smoke DOM is missing #app')
  await waitForMount(root)
  const htmlBytes = Buffer.byteLength(root.innerHTML)
  dom.window.close()
  return { entry: entries[0].file, htmlBytes }
}

const scriptPath = path.resolve(process.argv[1] ?? '')
if (scriptPath.endsWith('check-production-mount.mjs')) {
  const root = path.resolve(path.dirname(scriptPath), '..')
  checkProductionMount(root)
    .then(({ entry, htmlBytes }) => console.log(`production-mount PASS entry=${entry} app-html-bytes=${htmlBytes}`))
    .catch((error) => {
      console.error(`production-mount FAIL ${error instanceof Error ? error.stack ?? error.message : String(error)}`)
      process.exitCode = 1
    })
}

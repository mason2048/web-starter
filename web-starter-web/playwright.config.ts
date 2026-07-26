import { tmpdir } from 'node:os'
import { isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig, devices } from '@playwright/test'

const acceptanceAliases = (process.env.WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS ?? '')
  .split(',')
  .map((host) => host.trim().toLowerCase())
  .filter(Boolean)

for (const host of acceptanceAliases) {
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+test$/.test(host)) {
    throw new Error('Acceptance hostname aliases must be reserved lowercase .test DNS names')
  }
}

const diagnosticsEnabled = process.env.WEB_STARTER_PLAYWRIGHT_DIAGNOSTICS === 'true'
const repositoryRoot = resolve(fileURLToPath(new URL('..', import.meta.url)))
const configuredOutput = process.env.WEB_STARTER_PLAYWRIGHT_OUTPUT_DIR?.trim()
const outputDir = resolve(
  configuredOutput || join(tmpdir(), `web-starter-playwright-${process.pid}`),
)
const outputRelativeToRepository = relative(repositoryRoot, outputDir)
if (outputRelativeToRepository === ''
  || (!outputRelativeToRepository.startsWith('..') && !isAbsolute(outputRelativeToRepository))) {
  throw new Error('Playwright output must stay outside the repository because traces may contain credentials')
}
if (diagnosticsEnabled && !configuredOutput) {
  throw new Error('Explicit diagnostics require WEB_STARTER_PLAYWRIGHT_OUTPUT_DIR outside the repository')
}

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: 'line',
  outputDir,
  use: {
    ...devices['Desktop Chrome'],
    channel: 'chromium',
    ignoreHTTPSErrors: process.env.WEB_STARTER_ACCEPTANCE_INSECURE_TLS === 'true',
    launchOptions: acceptanceAliases.length > 0
      ? {
          args: [
            '--proxy-server=direct://',
            '--proxy-bypass-list=*',
            `--host-resolver-rules=${acceptanceAliases
              .map((host) => `MAP ${host} 127.0.0.1`)
              .join(',')}`,
          ],
        }
      : undefined,
    screenshot: diagnosticsEnabled ? 'only-on-failure' : 'off',
    trace: diagnosticsEnabled ? 'retain-on-failure' : 'off',
    video: 'off',
  },
})

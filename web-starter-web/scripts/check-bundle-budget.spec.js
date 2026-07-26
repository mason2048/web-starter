import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { checkBundleBudget } from './check-bundle-budget.mjs'

const budget = {
  maxEntryJavaScriptBytes: 10,
  maxJavaScriptChunkBytes: 20,
  maxStylesheetBytes: 30,
  maxOtherAssetBytes: 40,
  maxTotalProductionBytes: 70,
}

async function fixture(entryContents = '12345') {
  const root = await mkdtemp(path.join(tmpdir(), 'web-starter-budget-'))
  await mkdir(path.join(root, 'dist/.vite'), { recursive: true })
  await mkdir(path.join(root, 'dist/assets'), { recursive: true })
  await writeFile(path.join(root, 'bundle-budget.json'), JSON.stringify(budget))
  await writeFile(
    path.join(root, 'dist/.vite/manifest.json'),
    JSON.stringify({ 'index.html': { file: 'assets/app.js', isEntry: true } }),
  )
  await writeFile(path.join(root, 'dist/index.html'), '<main></main>')
  await writeFile(path.join(root, 'dist/assets/app.js'), entryContents)
  return root
}

describe('fail-closed bundle budget', () => {
  it('accepts a complete bundle within every explicit limit', async () => {
    const result = await checkBundleBudget(await fixture())
    expect(result.measurements.find((item) => item.file === 'assets/app.js')).toMatchObject({ bytes: 5, limit: 10 })
  })

  it('fails when an entry exceeds its limit', async () => {
    await expect(checkBundleBudget(await fixture('12345678901'))).rejects.toThrow('assets/app.js: 11 > 10 bytes')
  })

  it('fails closed when the manifest is missing', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'web-starter-budget-missing-'))
    await writeFile(path.join(root, 'bundle-budget.json'), JSON.stringify(budget))
    await expect(checkBundleBudget(root)).rejects.toThrow()
  })
})

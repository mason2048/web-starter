import { readFile, readdir, stat } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import console from 'node:console'
import process from 'node:process'

const REQUIRED_LIMITS = [
  'maxEntryJavaScriptBytes',
  'maxJavaScriptChunkBytes',
  'maxStylesheetBytes',
  'maxOtherAssetBytes',
  'maxTotalProductionBytes',
]

async function readJson(file) {
  return JSON.parse(await readFile(file, 'utf8'))
}

async function filesUnder(root, directory = root) {
  const entries = await readdir(directory, { withFileTypes: true })
  const files = []
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name)
    if (entry.isDirectory()) files.push(...(await filesUnder(root, absolute)))
    else if (entry.isFile()) files.push(path.relative(root, absolute).split(path.sep).join('/'))
  }
  return files
}

function validateBudget(budget) {
  for (const key of REQUIRED_LIMITS) {
    if (!Number.isSafeInteger(budget[key]) || budget[key] <= 0) {
      throw new Error(`bundle budget ${key} must be a positive integer`)
    }
  }
}

export async function checkBundleBudget(rootDirectory) {
  const budgetPath = path.join(rootDirectory, 'bundle-budget.json')
  const distDirectory = path.join(rootDirectory, 'dist')
  const manifestPath = path.join(distDirectory, '.vite', 'manifest.json')
  const [budget, manifest] = await Promise.all([readJson(budgetPath), readJson(manifestPath)])
  validateBudget(budget)

  const entryFiles = new Set(
    Object.values(manifest)
      .filter((record) => record && record.isEntry === true && typeof record.file === 'string')
      .map((record) => record.file),
  )
  if (entryFiles.size === 0) throw new Error('Vite manifest does not contain a production entry')

  const productionFiles = (await filesUnder(distDirectory)).filter((file) => file !== '.vite/manifest.json')
  if (productionFiles.length === 0) throw new Error('production bundle is empty')

  const violations = []
  let total = 0
  const measurements = []
  for (const file of productionFiles) {
    const bytes = (await stat(path.join(distDirectory, file))).size
    total += bytes
    let limit = budget.maxOtherAssetBytes
    if (file.endsWith('.js')) {
      limit = entryFiles.has(file) ? budget.maxEntryJavaScriptBytes : budget.maxJavaScriptChunkBytes
    } else if (file.endsWith('.css')) {
      limit = budget.maxStylesheetBytes
    }
    measurements.push({ file, bytes, limit })
    if (bytes > limit) violations.push(`${file}: ${bytes} > ${limit} bytes`)
  }
  if (total > budget.maxTotalProductionBytes) {
    violations.push(`total production bundle: ${total} > ${budget.maxTotalProductionBytes} bytes`)
  }
  if (violations.length > 0) {
    throw new Error(`bundle budget exceeded\n${violations.map((value) => `- ${value}`).join('\n')}`)
  }
  return { total, measurements }
}

const invokedFile = process.argv[1] ? path.resolve(process.argv[1]) : ''
if (invokedFile === fileURLToPath(import.meta.url)) {
  const rootDirectory = process.argv[2] ? path.resolve(process.argv[2]) : path.resolve(path.dirname(invokedFile), '..')
  checkBundleBudget(rootDirectory)
    .then(({ total, measurements }) => {
      const largest = [...measurements]
        .sort((left, right) => right.bytes - left.bytes)
        .slice(0, 3)
        .map((measurement) => `${measurement.file}=${measurement.bytes}/${measurement.limit}`)
        .join(',')
      console.log(`bundle-budget PASS files=${measurements.length} total=${total} largest=${largest}`)
    })
    .catch((error) => {
      console.error(`bundle-budget FAIL ${error instanceof Error ? error.message : String(error)}`)
      process.exitCode = 1
    })
}

import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import console from 'node:console'
import { writePrivateApiContract } from './check-private-api-contract.mjs'

const root = path.resolve(path.dirname(path.resolve(process.argv[1] ?? '')), '..')
const target = path.join(root, 'src/api/generated/privateApiContract.ts')

writePrivateApiContract(root)
  .then(async (content) => {
    await mkdir(path.dirname(target), { recursive: true })
    await writeFile(target, content)
    console.log(`private-api-contract WROTE ${path.relative(root, target)}`)
  })
  .catch((error) => {
    console.error(`private-api-contract WRITE FAILED ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  })

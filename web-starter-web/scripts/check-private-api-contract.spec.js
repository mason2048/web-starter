import { readFile } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { describe, expect, it } from 'vitest'
import { checkPrivateApiContract, renderPrivateApiTypes } from './check-private-api-contract.mjs'

describe('private OpenAPI drift gate', () => {
  it('keeps the checked-in TypeScript operation types synchronized with OpenAPI 3.1', async () => {
    const result = await checkPrivateApiContract(process.cwd())
    expect(result.operations).toBe(3)
  })

  it('fails closed when an operation omits a TypeScript request or response binding', async () => {
    const source = await readFile(path.join(process.cwd(), 'contracts/private-api.openapi.json'))
    const contract = JSON.parse(source.toString('utf8'))
    delete contract.paths['/projects'].get['x-web-starter-response-type']

    expect(() => renderPrivateApiTypes(contract, source)).toThrow('missing typed contract extensions')
  })
})

import { describe, expect, it } from 'vitest'
import { isValidProjectCode } from './validators'

describe('isValidProjectCode', () => {
  it('accepts stable machine-readable project codes', () => {
    expect(isValidProjectCode('PRJ-2026_001')).toBe(true)
  })

  it('rejects spaces and punctuation', () => {
    expect(isValidProjectCode('project 001')).toBe(false)
    expect(isValidProjectCode('project/001')).toBe(false)
    expect(isValidProjectCode('1-project')).toBe(false)
  })
})

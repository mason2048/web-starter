import { describe, expect, it } from 'vitest'
import { httpClientDefaults } from './http'

describe('HTTP security defaults', () => {
  it('keeps Axios from overwriting Spring Security masked CSRF headers', () => {
    expect(httpClientDefaults.withCredentials).toBe(true)
    expect(httpClientDefaults.withXSRFToken).toBe(false)
  })
})

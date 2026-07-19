import { describe, expect, it } from 'vitest'
import { isOAuthAuthorizationRedirect, safeInternalRedirect } from './redirect'

describe('safeInternalRedirect', () => {
  it('accepts same-origin application and OAuth paths', () => {
    expect(safeInternalRedirect('/projects?page=2')).toBe('/projects?page=2')
    expect(safeInternalRedirect('/oauth2/authorize?client_id=agent')).toBe('/oauth2/authorize?client_id=agent')
  })

  it('rejects absolute, protocol-relative and backslash redirects', () => {
    expect(safeInternalRedirect('https://example.com')).toBe('/overview')
    expect(safeInternalRedirect('//example.com/path')).toBe('/overview')
    expect(safeInternalRedirect('/\\example.com/path')).toBe('/overview')
  })
})

describe('isOAuthAuthorizationRedirect', () => {
  it('only marks the OAuth and connect endpoint namespaces for full navigation', () => {
    expect(isOAuthAuthorizationRedirect('/oauth2/authorize')).toBe(true)
    expect(isOAuthAuthorizationRedirect('/connect/logout')).toBe(true)
    expect(isOAuthAuthorizationRedirect('/projects')).toBe(false)
  })
})

import { describe, expect, it } from 'vitest'
import type { TokenSummary } from '@/types/models'
import {
  credentialNotices,
  credentialStatus,
  isExpiringSoon,
  isLongUnused,
  matchesCredentialLifecycle,
} from './credentials'

const NOW = new Date('2026-07-19T00:00:00.000Z').getTime()

function token(overrides: Partial<TokenSummary> = {}): TokenSummary {
  return {
    id: '1',
    type: 'PERSONAL_ACCESS_TOKEN',
    name: 'Agent token',
    tokenHint: 'ws_pat_abcd',
    scopes: ['project:list'],
    allowedIpCidrs: [],
    createdAt: '2026-07-01T00:00:00.000Z',
    ...overrides,
  }
}

describe('credential lifecycle filters', () => {
  it('separates active, expiring, expired and revoked credentials', () => {
    const expiring = token({ expiresAt: '2026-08-01T00:00:00.000Z' })
    const expired = token({ expiresAt: '2026-07-18T23:59:59.000Z' })
    const revoked = token({ revokedAt: '2026-07-10T00:00:00.000Z' })

    expect(credentialStatus(expiring, NOW).key).toBe('ACTIVE')
    expect(isExpiringSoon(expiring, NOW)).toBe(true)
    expect(matchesCredentialLifecycle(expiring, 'EXPIRING_SOON', NOW)).toBe(true)
    expect(credentialStatus(expired, NOW).key).toBe('EXPIRED')
    expect(matchesCredentialLifecycle(expired, 'EXPIRED', NOW)).toBe(true)
    expect(credentialStatus(revoked, NOW).key).toBe('REVOKED')
    expect(matchesCredentialLifecycle(revoked, 'REVOKED', NOW)).toBe(true)
  })

  it('treats an active credential with no use after 90 days as long unused', () => {
    const neverUsed = token({ createdAt: '2026-03-01T00:00:00.000Z' })
    const recentlyUsed = token({
      createdAt: '2026-03-01T00:00:00.000Z',
      lastUsedAt: '2026-07-18T00:00:00.000Z',
    })

    expect(isLongUnused(neverUsed, NOW)).toBe(true)
    expect(matchesCredentialLifecycle(neverUsed, 'LONG_UNUSED', NOW)).toBe(true)
    expect(isLongUnused(recentlyUsed, NOW)).toBe(false)
  })

  it('filters IP-restricted credentials and emits actionable notices without exposing secrets', () => {
    const restricted = token({
      allowedIpCidrs: ['10.0.0.0/8'],
      expiresAt: '2026-08-01T00:00:00.000Z',
    })

    expect(matchesCredentialLifecycle(restricted, 'IP_RESTRICTED', NOW)).toBe(true)
    expect(credentialNotices(restricted, NOW)).toEqual(['30 天内到期', '受 IP 限制'])
    expect(Object.keys(restricted)).not.toContain('token')
  })
})

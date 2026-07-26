import type { TokenSummary } from '@/types/models'

const DAY_MS = 24 * 60 * 60 * 1000

export const EXPIRING_SOON_DAYS = 30
export const LONG_UNUSED_DAYS = 90

export type CredentialLifecycleFilter =
  | ''
  | 'ACTIVE'
  | 'EXPIRING_SOON'
  | 'LONG_UNUSED'
  | 'EXPIRED'
  | 'REVOKED'
  | 'IP_RESTRICTED'

export type CredentialStatusKey = 'ACTIVE' | 'EXPIRED' | 'REVOKED'

export interface CredentialStatus {
  key: CredentialStatusKey
  label: string
  type: 'success' | 'warning' | 'danger'
}

export const credentialLifecycleOptions: ReadonlyArray<{
  value: CredentialLifecycleFilter
  label: string
}> = [
  { value: '', label: '全部凭据' },
  { value: 'ACTIVE', label: '当前有效' },
  { value: 'EXPIRING_SOON', label: `${EXPIRING_SOON_DAYS} 天内到期` },
  { value: 'LONG_UNUSED', label: `${LONG_UNUSED_DAYS} 天未使用` },
  { value: 'EXPIRED', label: '已过期' },
  { value: 'REVOKED', label: '已吊销' },
  { value: 'IP_RESTRICTED', label: '受 IP 限制' },
]

function timestamp(value?: string): number | undefined {
  if (!value) return undefined
  const parsed = new Date(value).getTime()
  return Number.isNaN(parsed) ? undefined : parsed
}

export function credentialStatus(token: TokenSummary, now = Date.now()): CredentialStatus {
  if (token.revokedAt) return { key: 'REVOKED', label: '已吊销', type: 'danger' }
  const expiresAt = timestamp(token.expiresAt)
  if (expiresAt !== undefined && expiresAt <= now) {
    return { key: 'EXPIRED', label: '已过期', type: 'warning' }
  }
  return { key: 'ACTIVE', label: '有效', type: 'success' }
}

export function isExpiringSoon(token: TokenSummary, now = Date.now()): boolean {
  if (credentialStatus(token, now).key !== 'ACTIVE') return false
  const expiresAt = timestamp(token.expiresAt)
  return expiresAt !== undefined && expiresAt <= now + EXPIRING_SOON_DAYS * DAY_MS
}

export function isLongUnused(token: TokenSummary, now = Date.now()): boolean {
  if (credentialStatus(token, now).key !== 'ACTIVE') return false
  const activityAt = timestamp(token.lastUsedAt) ?? timestamp(token.createdAt)
  return activityAt !== undefined && activityAt <= now - LONG_UNUSED_DAYS * DAY_MS
}

export function matchesCredentialLifecycle(
  token: TokenSummary,
  filter: CredentialLifecycleFilter,
  now = Date.now(),
): boolean {
  if (!filter) return true
  if (filter === 'EXPIRING_SOON') return isExpiringSoon(token, now)
  if (filter === 'LONG_UNUSED') return isLongUnused(token, now)
  if (filter === 'IP_RESTRICTED') return Boolean(token.allowedIpCidrs?.length)
  return credentialStatus(token, now).key === filter
}

export function credentialNotices(token: TokenSummary, now = Date.now()): string[] {
  const notices: string[] = []
  if (isExpiringSoon(token, now)) notices.push(`${EXPIRING_SOON_DAYS} 天内到期`)
  if (isLongUnused(token, now)) notices.push(`${LONG_UNUSED_DAYS} 天未使用`)
  if (token.allowedIpCidrs?.length) notices.push('受 IP 限制')
  return notices
}

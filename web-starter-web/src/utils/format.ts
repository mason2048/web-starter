export function formatDateTime(value?: string): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date)
}

export function displayError(error: unknown): string {
  if (error instanceof Error) return error.message
  return '请求失败，请稍后重试'
}

export function normalizeEnabled(record: { enabled?: boolean; status?: EnableStatus }): boolean {
  if (typeof record.enabled === 'boolean') return record.enabled
  return record.status !== 'DISABLED'
}

import type { EnableStatus } from '@/types/models'

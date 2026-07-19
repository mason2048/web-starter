import type { CurrentUser } from '@/types/models'
import { hasAccess } from '@/utils/access'

export interface RouteAccessMeta {
  permission?: unknown
  menuId?: unknown
}

export function canAccessRoute(user: CurrentUser | null | undefined, meta: RouteAccessMeta): boolean {
  const permission = typeof meta.permission === 'string' ? meta.permission : undefined
  const menuId = typeof meta.menuId === 'string' ? meta.menuId : undefined
  if (!permission && menuId === undefined) return true
  return hasAccess(user, { permission, menuId })
}

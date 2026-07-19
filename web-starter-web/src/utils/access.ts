import type { CurrentUser } from '@/types/models'

export interface AccessRequirement {
  permission?: string
  menuId?: string
}

/**
 * Runtime access always intersects API permission and assigned menu visibility.
 * Directory-only menu IDs are intentionally not required by leaf routes.
 */
export function hasAccess(
  user: Pick<CurrentUser, 'permissions' | 'menuIds'> | null | undefined,
  requirement: AccessRequirement,
): boolean {
  if (!user) return false

  if (requirement.permission && !user.permissions?.includes(requirement.permission)) {
    return false
  }

  if (requirement.menuId !== undefined) {
    const hasMenu = user.menuIds?.includes(requirement.menuId) ?? false
    if (!hasMenu) return false
  }

  return true
}

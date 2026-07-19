import { useAuthStore } from '@/stores/auth'
import { hasAccess } from '@/utils/access'

export function usePermission(): {
  can: (permission: string) => boolean
  canAccess: (permission: string | undefined, menuId: string | undefined) => boolean
} {
  const auth = useAuthStore()
  return {
    can: (permission: string) => hasAccess(auth.currentUser, { permission }),
    canAccess: (permission: string | undefined, menuId: string | undefined) =>
      hasAccess(auth.currentUser, { permission, menuId }),
  }
}

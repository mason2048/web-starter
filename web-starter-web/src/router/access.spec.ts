import { describe, expect, it } from 'vitest'
import { canAccessRoute } from './access'

describe('canAccessRoute', () => {
  const currentUser = {
    subjectId: '1',
    username: 'admin',
    permissions: ['security:personal-token:list'],
    menuIds: ['2031'],
  }

  it('allows a protected route only when permission and menu are both assigned', () => {
    expect(
      canAccessRoute(currentUser, {
        permission: 'security:personal-token:list',
        menuId: '2031',
      }),
    ).toBe(true)
    expect(
      canAccessRoute(currentUser, {
        permission: 'security:personal-token:list',
        menuId: '2032',
      }),
    ).toBe(false)
  })

  it('allows an unprotected route and rejects a protected route without a user', () => {
    expect(canAccessRoute(null, {})).toBe(true)
    expect(canAccessRoute(null, { menuId: '2001' })).toBe(false)
  })
})

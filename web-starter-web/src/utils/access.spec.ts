import { describe, expect, it } from 'vitest'
import { hasAccess } from './access'

describe('hasAccess', () => {
  const user = {
    permissions: ['project:list', 'security:personal-token:list'],
    menuIds: ['2001', '2002', '2031'],
  }

  it('requires both permission and leaf menu assignment', () => {
    expect(hasAccess(user, { permission: 'project:list', menuId: '2002' })).toBe(true)
    expect(hasAccess(user, { permission: 'project:list', menuId: '2011' })).toBe(false)
    expect(hasAccess(user, { permission: 'project:create', menuId: '2002' })).toBe(false)
  })

  it('supports a menu-only overview and denies missing menu data', () => {
    expect(hasAccess(user, { menuId: '2001' })).toBe(true)
    expect(hasAccess({ permissions: ['project:list'] }, { permission: 'project:list', menuId: '2002' })).toBe(false)
  })

  it('applies security leaf menu IDs in addition to security permissions', () => {
    expect(hasAccess(user, { permission: 'security:personal-token:list', menuId: '2031' })).toBe(true)
    expect(hasAccess(user, { permission: 'security:personal-token:list', menuId: '2032' })).toBe(false)
  })
})

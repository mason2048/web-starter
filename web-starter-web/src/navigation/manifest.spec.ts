import { describe, expect, it } from 'vitest'
import {
  APP_NAVIGATION,
  applicationRoutes,
  commandNavigation,
  findNavigationItem,
  sidebarNavigation,
} from './manifest'

describe('typed application navigation manifest', () => {
  it('is the single source for routes, sidebar, breadcrumbs and command search', () => {
    const routes = applicationRoutes()

    expect(routes).toHaveLength(APP_NAVIGATION.length)
    expect(routes.map((route) => `/${route.path}`)).toEqual(APP_NAVIGATION.map((item) => item.path))
    expect(sidebarNavigation).toEqual(APP_NAVIGATION.filter((item) => item.sidebar))
    expect(commandNavigation).toEqual(APP_NAVIGATION.filter((item) => item.command))

    for (const item of APP_NAVIGATION) {
      expect(findNavigationItem(item.path)).toBe(item)
      expect(routes.find((route) => route.name === item.name)?.meta).toMatchObject({
        title: item.title,
        permission: item.permission,
        menuId: item.menuId,
      })
    }
  })

  it('rejects drift-prone duplicate route names and paths by contract', () => {
    expect(new Set(APP_NAVIGATION.map((item) => item.path)).size).toBe(APP_NAVIGATION.length)
    expect(new Set(APP_NAVIGATION.map((item) => item.name)).size).toBe(APP_NAVIGATION.length)
  })
})

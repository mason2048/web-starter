import type { Component } from 'vue'
import type { RouteRecordRaw } from 'vue-router'
import {
  Aim,
  Avatar,
  Collection,
  Connection,
  DataAnalysis,
  Document,
  Files,
  Key,
  Link as LinkIcon,
  Lock,
  Setting,
  User,
} from '@element-plus/icons-vue'
import { MENU_IDS } from '@/constants/menu'

export interface NavigationItem {
  readonly path: `/${string}`
  readonly name: string
  readonly label: string
  readonly title: string
  readonly icon: Component
  readonly component: NonNullable<RouteRecordRaw['component']>
  readonly permission?: string
  readonly menuId?: string
  readonly sidebar?: boolean
  readonly command?: boolean
}

/**
 * The only application-page navigation manifest.
 *
 * Router records, sidebar entries, breadcrumbs and command search are projections
 * of this list. A generated module adds exactly one item here instead of patching
 * four independent navigation surfaces.
 */
export const APP_NAVIGATION: readonly NavigationItem[] = [
  {
    path: '/overview',
    name: 'overview',
    label: '概览',
    title: '概览',
    icon: DataAnalysis,
    component: () => import('@/views/OverviewView.vue'),
    menuId: MENU_IDS.OVERVIEW,
    sidebar: true,
    command: true,
  },
  {
    path: '/projects',
    name: 'projects',
    label: '项目示例',
    title: '项目示例',
    icon: Files,
    component: () => import('@/views/ProjectsView.vue'),
    permission: 'project:list',
    menuId: MENU_IDS.PROJECTS,
    sidebar: true,
    command: true,
  },
  {
    path: '/users',
    name: 'users',
    label: '用户管理',
    title: '用户管理',
    icon: User,
    component: () => import('@/views/UsersView.vue'),
    permission: 'system:user:list',
    menuId: MENU_IDS.USERS,
    sidebar: true,
    command: true,
  },
  {
    path: '/roles',
    name: 'roles',
    label: '角色权限',
    title: '角色权限',
    icon: Key,
    component: () => import('@/views/RolesView.vue'),
    permission: 'system:role:list',
    menuId: MENU_IDS.ROLES,
    sidebar: true,
    command: true,
  },
  {
    path: '/menus',
    name: 'menus',
    label: '菜单权限',
    title: '菜单权限',
    icon: Collection,
    component: () => import('@/views/MenusView.vue'),
    permission: 'system:menu:list',
    menuId: MENU_IDS.MENUS,
    sidebar: true,
    command: true,
  },
  {
    path: '/configs',
    name: 'configs',
    label: '系统配置',
    title: '系统配置',
    icon: Setting,
    component: () => import('@/views/ConfigsView.vue'),
    permission: 'system:config:list',
    menuId: MENU_IDS.CONFIGS,
    sidebar: true,
    command: true,
  },
  {
    path: '/logs/login',
    name: 'login-logs',
    label: '登录日志',
    title: '登录日志',
    icon: Document,
    component: () => import('@/views/logs/LoginLogsView.vue'),
    permission: 'audit:list',
    menuId: MENU_IDS.LOGIN_LOGS,
    sidebar: true,
    command: true,
  },
  {
    path: '/logs/operation',
    name: 'operation-logs',
    label: '操作审计',
    title: '操作审计',
    icon: Aim,
    component: () => import('@/views/logs/OperationLogsView.vue'),
    permission: 'audit:list',
    menuId: MENU_IDS.OPERATION_LOGS,
    sidebar: true,
    command: true,
  },
  {
    path: '/logs/mcp',
    name: 'mcp-logs',
    label: 'MCP 调用日志',
    title: 'MCP 调用日志',
    icon: Connection,
    component: () => import('@/views/logs/McpLogsView.vue'),
    permission: 'audit:list',
    menuId: MENU_IDS.MCP_LOGS,
    sidebar: true,
    command: true,
  },
  {
    path: '/security/account',
    name: 'account-security',
    label: '个人安全',
    title: '个人安全',
    icon: Lock,
    component: () => import('@/views/security/AccountSecurityView.vue'),
    command: true,
  },
  {
    path: '/security/personal-tokens',
    name: 'personal-tokens',
    label: '个人访问令牌',
    title: '个人访问令牌',
    icon: Key,
    component: () => import('@/views/security/PersonalTokensView.vue'),
    permission: 'security:personal-token:list',
    menuId: MENU_IDS.PERSONAL_TOKENS,
    sidebar: true,
    command: true,
  },
  {
    path: '/security/service-accounts',
    name: 'service-accounts',
    label: '服务账号',
    title: '服务账号',
    icon: Avatar,
    component: () => import('@/views/security/ServiceAccountsView.vue'),
    permission: 'security:service-account:manage',
    menuId: MENU_IDS.SERVICE_ACCOUNTS,
    sidebar: true,
    command: true,
  },
  {
    path: '/security/oauth-clients',
    name: 'oauth-clients',
    label: 'OAuth 客户端',
    title: 'OAuth 客户端',
    icon: LinkIcon,
    component: () => import('@/views/security/OAuthClientsView.vue'),
    permission: 'security:oauth-client:manage',
    menuId: MENU_IDS.OAUTH_CLIENTS,
    sidebar: true,
    command: true,
  },
  // @web-starter-module-navigation
]

export const sidebarNavigation = APP_NAVIGATION.filter((item) => item.sidebar)
export const commandNavigation = APP_NAVIGATION.filter((item) => item.command)

export function applicationRoutes(): RouteRecordRaw[] {
  return APP_NAVIGATION.map((item) => ({
    path: item.path.slice(1),
    name: item.name,
    component: item.component,
    meta: {
      title: item.title,
      permission: item.permission,
      menuId: item.menuId,
    },
  }))
}

export function findNavigationItem(path: string): NavigationItem | undefined {
  return APP_NAVIGATION.find((item) => item.path === path)
}

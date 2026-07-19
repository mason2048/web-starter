import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { MENU_IDS } from '@/constants/menu'
import { canAccessRoute } from '@/router/access'
import { useAuthStore } from '@/stores/auth'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue'),
    meta: { public: true, title: '登录' },
  },
  {
    path: '/',
    component: () => import('@/layouts/AppLayout.vue'),
    redirect: '/overview',
    children: [
      {
        path: 'overview',
        name: 'overview',
        component: () => import('@/views/OverviewView.vue'),
        meta: { title: '概览', menuId: MENU_IDS.OVERVIEW },
      },
      {
        path: 'projects',
        name: 'projects',
        component: () => import('@/views/ProjectsView.vue'),
        meta: { title: '项目示例', permission: 'project:list', menuId: MENU_IDS.PROJECTS },
      },
      {
        path: 'users',
        name: 'users',
        component: () => import('@/views/UsersView.vue'),
        meta: { title: '用户管理', permission: 'system:user:list', menuId: MENU_IDS.USERS },
      },
      {
        path: 'roles',
        name: 'roles',
        component: () => import('@/views/RolesView.vue'),
        meta: { title: '角色权限', permission: 'system:role:list', menuId: MENU_IDS.ROLES },
      },
      {
        path: 'menus',
        name: 'menus',
        component: () => import('@/views/MenusView.vue'),
        meta: { title: '菜单权限', permission: 'system:menu:list', menuId: MENU_IDS.MENUS },
      },
      {
        path: 'configs',
        name: 'configs',
        component: () => import('@/views/ConfigsView.vue'),
        meta: { title: '系统配置', permission: 'system:config:list', menuId: MENU_IDS.CONFIGS },
      },
      {
        path: 'logs/login',
        name: 'login-logs',
        component: () => import('@/views/logs/LoginLogsView.vue'),
        meta: { title: '登录日志', permission: 'audit:list', menuId: MENU_IDS.LOGIN_LOGS },
      },
      {
        path: 'logs/operation',
        name: 'operation-logs',
        component: () => import('@/views/logs/OperationLogsView.vue'),
        meta: { title: '操作审计', permission: 'audit:list', menuId: MENU_IDS.OPERATION_LOGS },
      },
      {
        path: 'logs/mcp',
        name: 'mcp-logs',
        component: () => import('@/views/logs/McpLogsView.vue'),
        meta: { title: 'MCP 调用日志', permission: 'audit:list', menuId: MENU_IDS.MCP_LOGS },
      },
      {
        path: 'security/personal-tokens',
        name: 'personal-tokens',
        component: () => import('@/views/security/PersonalTokensView.vue'),
        meta: {
          title: '个人访问令牌',
          permission: 'security:personal-token:list',
          menuId: MENU_IDS.PERSONAL_TOKENS,
        },
      },
      {
        path: 'security/service-accounts',
        name: 'service-accounts',
        component: () => import('@/views/security/ServiceAccountsView.vue'),
        meta: {
          title: '服务账号',
          permission: 'security:service-account:manage',
          menuId: MENU_IDS.SERVICE_ACCOUNTS,
        },
      },
      {
        path: 'security/oauth-clients',
        name: 'oauth-clients',
        component: () => import('@/views/security/OAuthClientsView.vue'),
        meta: {
          title: 'OAuth 客户端',
          permission: 'security:oauth-client:manage',
          menuId: MENU_IDS.OAUTH_CLIENTS,
        },
      },
      {
        path: 'forbidden',
        name: 'forbidden',
        component: () => import('@/views/ForbiddenView.vue'),
        meta: { title: '无权访问' },
      },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/overview' },
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  const authenticated = await auth.initialize()

  if (to.meta.public) {
    if (to.name === 'login' && authenticated) return { name: 'overview' }
    return true
  }

  if (!authenticated) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }

  if (!canAccessRoute(auth.currentUser, to.meta)) {
    return { name: 'forbidden' }
  }

  return true
})

router.afterEach((to) => {
  document.title = `${String(to.meta.title || '管理端')} · 启程 Web Starter`
})

export default router

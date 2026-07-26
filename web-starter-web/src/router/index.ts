import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { applicationRoutes } from '@/navigation/manifest'
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
      ...applicationRoutes(),
      {
        path: 'forbidden',
        name: 'forbidden',
        component: () => import('@/views/ForbiddenView.vue'),
        meta: { title: '无权访问' },
      },
      {
        path: ':pathMatch(.*)*',
        name: 'not-found',
        component: () => import('@/views/NotFoundView.vue'),
        meta: { title: '页面不存在' },
      },
    ],
  },
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

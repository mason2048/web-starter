<template>
  <nav class="sidebar-nav" aria-label="主导航">
    <div class="sidebar-brand">
      <BrandLogo />
    </div>
    <el-menu
      :default-active="route.path"
      router
      class="sidebar-menu"
      background-color="transparent"
      text-color="#dce9f6"
      active-text-color="#ffffff"
      @select="$emit('navigate')"
    >
      <el-menu-item v-for="item in visibleNavItems" :key="item.path" :index="item.path">
        <el-icon><component :is="item.icon" /></el-icon>
        <span>{{ item.label }}</span>
      </el-menu-item>
    </el-menu>
  </nav>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
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
  Setting,
  User,
} from '@element-plus/icons-vue'
import BrandLogo from './BrandLogo.vue'
import { MENU_IDS } from '@/constants/menu'
import { useAuthStore } from '@/stores/auth'
import { hasAccess } from '@/utils/access'

defineEmits<{ navigate: [] }>()
const route = useRoute()
const auth = useAuthStore()

const navItems = [
  { path: '/overview', label: '概览', icon: DataAnalysis, menuId: MENU_IDS.OVERVIEW },
  { path: '/projects', label: '项目示例', icon: Files, permission: 'project:list', menuId: MENU_IDS.PROJECTS },
  { path: '/users', label: '用户管理', icon: User, permission: 'system:user:list', menuId: MENU_IDS.USERS },
  { path: '/roles', label: '角色权限', icon: Key, permission: 'system:role:list', menuId: MENU_IDS.ROLES },
  { path: '/menus', label: '菜单权限', icon: Collection, permission: 'system:menu:list', menuId: MENU_IDS.MENUS },
  { path: '/configs', label: '系统配置', icon: Setting, permission: 'system:config:list', menuId: MENU_IDS.CONFIGS },
  { path: '/logs/login', label: '登录日志', icon: Document, permission: 'audit:list', menuId: MENU_IDS.LOGIN_LOGS },
  { path: '/logs/operation', label: '操作审计', icon: Aim, permission: 'audit:list', menuId: MENU_IDS.OPERATION_LOGS },
  { path: '/logs/mcp', label: 'MCP 调用日志', icon: Connection, permission: 'audit:list', menuId: MENU_IDS.MCP_LOGS },
  {
    path: '/security/personal-tokens',
    label: '个人访问令牌',
    icon: Key,
    permission: 'security:personal-token:list',
    menuId: MENU_IDS.PERSONAL_TOKENS,
  },
  {
    path: '/security/service-accounts',
    label: '服务账号',
    icon: Avatar,
    permission: 'security:service-account:manage',
    menuId: MENU_IDS.SERVICE_ACCOUNTS,
  },
  {
    path: '/security/oauth-clients',
    label: 'OAuth 客户端',
    icon: LinkIcon,
    permission: 'security:oauth-client:manage',
    menuId: MENU_IDS.OAUTH_CLIENTS,
  },
]

const visibleNavItems = computed(() =>
  navItems.filter((item) => hasAccess(auth.currentUser, { permission: item.permission, menuId: item.menuId })),
)
</script>

<style scoped>
.sidebar-nav {
  width: 100%;
  height: 100%;
  overflow-y: auto;
  background:
    radial-gradient(circle at 20% 12%, rgb(0 164 157 / 9%), transparent 30%),
    linear-gradient(180deg, var(--ws-navy-900), var(--ws-navy-950));
}

.sidebar-brand {
  display: flex;
  height: 70px;
  padding: 0 16px;
  align-items: center;
  border-bottom: 1px solid rgb(255 255 255 / 8%);
}

.sidebar-menu {
  padding: 14px 9px;
  border-right: 0;
}

.sidebar-menu .el-menu-item {
  height: 54px;
  padding: 0 15px !important;
  margin: 3px 0;
  border-radius: 5px;
  font-size: 15px;
}

.sidebar-menu .el-menu-item .el-icon {
  width: 22px;
  margin-right: 13px;
  font-size: 21px;
}

.sidebar-menu .el-menu-item:hover {
  background: rgb(255 255 255 / 7%);
}

.sidebar-menu .el-menu-item.is-active {
  background: linear-gradient(90deg, #008b86, #079f98);
  box-shadow: 0 6px 18px rgb(0 0 0 / 14%);
}
</style>

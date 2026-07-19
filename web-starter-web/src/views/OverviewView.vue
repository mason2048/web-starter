<template>
  <div class="page-content overview-page">
    <PageHeader title="概览" description="查看系统状态并快速进入常用管理功能" />

    <RequestError :message="errorMessage" />

    <section class="welcome-band">
      <div>
        <p class="welcome-greeting">你好，{{ auth.displayName }}</p>
        <h2>欢迎回到启程 Web Starter</h2>
        <p>Web 管理端与 MCP Server 共用业务服务、权限与审计链路。</p>
      </div>
      <img :src="logoUrl" alt="" />
    </section>

    <section v-if="metrics.length" class="metrics" aria-label="系统统计">
      <article v-for="metric in metrics" :key="metric.label" class="metric-item">
        <div class="metric-icon" :class="metric.tone">
          <el-icon><component :is="metric.icon" /></el-icon>
        </div>
        <div>
          <span>{{ metric.label }}</span>
          <strong>{{ metric.value ?? '—' }}</strong>
        </div>
      </article>
    </section>

    <div class="overview-grid">
      <section v-if="quickLinks.length" class="overview-section">
        <header><h3>快捷入口</h3></header>
        <div class="quick-links">
          <RouterLink v-for="link in quickLinks" :key="link.to" :to="link.to" class="quick-link">
            <span class="quick-icon"><el-icon><component :is="link.icon" /></el-icon></span>
            <span>
              <strong>{{ link.title }}</strong>
              <small>{{ link.description }}</small>
            </span>
            <el-icon class="quick-arrow"><ArrowRight /></el-icon>
          </RouterLink>
        </div>
      </section>

      <section v-if="canSeeMcpLogs" class="overview-section">
        <header>
          <h3>最近 MCP 调用</h3>
          <RouterLink to="/logs/mcp">查看全部</RouterLink>
        </header>
        <el-table v-if="recentMcpCalls.length" :data="recentMcpCalls" size="small">
          <el-table-column prop="toolName" label="工具" min-width="130" />
          <el-table-column label="结果" width="78">
            <template #default="{ row }"><StatusTag :value="row.result === 'SUCCESS' ? 'SUCCESS' : 'FAILED'" /></template>
          </el-table-column>
          <el-table-column label="时间" width="150">
            <template #default="{ row }">{{ formatDateTime(row.createdAt) }}</template>
          </el-table-column>
        </el-table>
        <el-empty v-else description="暂无调用记录" :image-size="72" />
      </section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { ArrowRight, Connection, Files, Key, Setting, User } from '@element-plus/icons-vue'
import logoUrl from '@/assets/logo.svg'
import { logsApi, rolesApi, usersApi } from '@/api/admin'
import { listProjects } from '@/api/projects'
import PageHeader from '@/components/PageHeader.vue'
import RequestError from '@/components/RequestError.vue'
import StatusTag from '@/components/StatusTag.vue'
import { useAuthStore } from '@/stores/auth'
import { MENU_IDS } from '@/constants/menu'
import type { McpCallLog } from '@/types/models'
import { hasAccess } from '@/utils/access'
import { formatDateTime } from '@/utils/format'

const auth = useAuthStore()
const loading = ref(false)
const errorMessage = ref('')
const counts = ref<{ projects: number | null; users: number | null; roles: number | null; mcp: number | null }>({
  projects: null,
  users: null,
  roles: null,
  mcp: null,
})
const recentMcpCalls = ref<McpCallLog[]>([])

const canSeeProjects = computed(() => hasAccess(auth.currentUser, { permission: 'project:list', menuId: MENU_IDS.PROJECTS }))
const canSeeUsers = computed(() => hasAccess(auth.currentUser, { permission: 'system:user:list', menuId: MENU_IDS.USERS }))
const canSeeRoles = computed(() => hasAccess(auth.currentUser, { permission: 'system:role:list', menuId: MENU_IDS.ROLES }))
const canSeeMcpLogs = computed(() => hasAccess(auth.currentUser, { permission: 'audit:list', menuId: MENU_IDS.MCP_LOGS }))

const metrics = computed(() =>
  [
    { label: '项目总数', value: counts.value.projects, icon: Files, tone: 'teal', allowed: canSeeProjects.value },
    { label: '系统用户', value: counts.value.users, icon: User, tone: 'blue', allowed: canSeeUsers.value },
    { label: '角色数量', value: counts.value.roles, icon: Key, tone: 'purple', allowed: canSeeRoles.value },
    { label: 'MCP 调用', value: counts.value.mcp, icon: Connection, tone: 'orange', allowed: canSeeMcpLogs.value },
  ].filter((metric) => metric.allowed),
)

const quickLinks = computed(() => [
  { to: '/projects', title: '项目示例', description: '体验完整业务 CRUD', icon: Files, permission: 'project:list', menuId: MENU_IDS.PROJECTS },
  { to: '/users', title: '用户管理', description: '维护账号与角色', icon: User, permission: 'system:user:list', menuId: MENU_IDS.USERS },
  { to: '/roles', title: '角色权限', description: '配置 RBAC 权限', icon: Key, permission: 'system:role:list', menuId: MENU_IDS.ROLES },
  { to: '/configs', title: '系统配置', description: '维护运行参数', icon: Setting, permission: 'system:config:list', menuId: MENU_IDS.CONFIGS },
].filter((link) => hasAccess(auth.currentUser, link)))

async function loadOverview(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  const query = { page: 1, size: 5 }
  const [projects, users, roles, mcp] = await Promise.allSettled([
    canSeeProjects.value ? listProjects(query) : Promise.resolve(null),
    canSeeUsers.value ? usersApi.list(query) : Promise.resolve(null),
    canSeeRoles.value ? rolesApi.list(query) : Promise.resolve(null),
    canSeeMcpLogs.value ? logsApi.mcp(query) : Promise.resolve(null),
  ])

  if (projects.status === 'fulfilled' && projects.value) counts.value.projects = projects.value.total
  if (users.status === 'fulfilled' && users.value) counts.value.users = users.value.total
  if (roles.status === 'fulfilled' && roles.value) counts.value.roles = roles.value.total
  if (mcp.status === 'fulfilled' && mcp.value) {
    counts.value.mcp = mcp.value.total
    recentMcpCalls.value = mcp.value.records
  }

  if ([projects, users, roles, mcp].some((item) => item.status === 'rejected')) {
    errorMessage.value = '部分概览数据加载失败，请确认后端服务和当前账号权限。'
  }
  loading.value = false
}

onMounted(loadOverview)
</script>

<style scoped>
.welcome-band {
  position: relative;
  display: flex;
  min-height: 176px;
  padding: 34px 40px;
  overflow: hidden;
  color: #fff;
  background:
    radial-gradient(circle at 82% 50%, rgb(0 195 185 / 25%), transparent 22%),
    linear-gradient(115deg, #062544 0%, #07345b 70%, #075d69 100%);
  border-radius: 10px;
  align-items: center;
  justify-content: space-between;
}

.welcome-band h2 {
  margin: 3px 0 8px;
  font-size: 26px;
}

.welcome-band p {
  margin: 0;
  color: #d7e5ef;
}

.welcome-band .welcome-greeting {
  color: #5ee4de;
  font-size: 14px;
  font-weight: 600;
}

.welcome-band img {
  width: 106px;
  height: 106px;
  margin-right: 9%;
  opacity: 0.94;
}

.metrics {
  display: grid;
  margin: 24px 0;
  background: #fff;
  border: 1px solid var(--ws-border);
  border-radius: 8px;
  grid-template-columns: repeat(4, 1fr);
}

.metric-item {
  display: flex;
  gap: 16px;
  min-height: 112px;
  padding: 24px 28px;
  align-items: center;
}

.metric-item + .metric-item {
  border-left: 1px solid var(--ws-border);
}

.metric-icon {
  display: inline-flex;
  width: 48px;
  height: 48px;
  color: #008f88;
  background: #e3f6f4;
  border-radius: 10px;
  align-items: center;
  justify-content: center;
}

.metric-icon .el-icon {
  font-size: 24px;
}

.metric-icon.blue { color: #2677c9; background: #eaf3fc; }
.metric-icon.purple { color: #7856c7; background: #f1edfb; }
.metric-icon.orange { color: #bd6b18; background: #fdf2e5; }

.metric-item span {
  display: block;
  margin-bottom: 5px;
  color: var(--ws-text-secondary);
  font-size: 13px;
}

.metric-item strong {
  font-size: 27px;
  line-height: 1;
}

.overview-grid {
  display: grid;
  gap: 24px;
  grid-template-columns: minmax(360px, 0.9fr) minmax(500px, 1.3fr);
}

.overview-section {
  min-width: 0;
  padding: 24px;
  border: 1px solid var(--ws-border);
  border-radius: 8px;
}

.overview-section > header {
  display: flex;
  margin-bottom: 19px;
  align-items: center;
  justify-content: space-between;
}

.overview-section h3 {
  margin: 0;
  font-size: 18px;
}

.overview-section > header a {
  color: var(--ws-teal-600);
  font-size: 13px;
}

.quick-links {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.quick-link {
  display: flex;
  gap: 12px;
  min-height: 84px;
  padding: 16px;
  border-bottom: 1px solid var(--ws-border);
  align-items: center;
}

.quick-link:nth-child(odd) { border-right: 1px solid var(--ws-border); }
.quick-link:nth-child(n + 3) { border-bottom: 0; }
.quick-link:hover { background: #f7fbfb; }

.quick-icon {
  display: inline-flex;
  width: 38px;
  height: 38px;
  color: var(--ws-teal-600);
  background: var(--ws-teal-100);
  border-radius: 8px;
  align-items: center;
  justify-content: center;
}

.quick-link strong,
.quick-link small {
  display: block;
}

.quick-link strong { margin-bottom: 4px; font-size: 14px; }
.quick-link small { color: var(--ws-text-secondary); font-size: 12px; }
.quick-arrow { margin-left: auto; color: #aeb7c3; }

@media (max-width: 1120px) {
  .overview-grid { grid-template-columns: 1fr; }
  .metrics { grid-template-columns: repeat(2, 1fr); }
  .metric-item:nth-child(3) { border-left: 0; border-top: 1px solid var(--ws-border); }
  .metric-item:nth-child(4) { border-top: 1px solid var(--ws-border); }
}

@media (max-width: 600px) {
  .welcome-band { min-height: 160px; padding: 28px 24px; }
  .welcome-band img { position: absolute; right: -10px; width: 100px; height: 100px; margin: 0; opacity: 0.22; }
  .welcome-band h2 { font-size: 21px; }
  .welcome-band > div { position: relative; z-index: 1; }
  .metrics { grid-template-columns: 1fr 1fr; }
  .metric-item { gap: 10px; min-height: 98px; padding: 18px 14px; }
  .metric-icon { width: 38px; height: 38px; }
  .metric-item strong { font-size: 22px; }
  .quick-links { grid-template-columns: 1fr; }
  .quick-link:nth-child(odd) { border-right: 0; }
  .quick-link:nth-child(3) { border-bottom: 1px solid var(--ws-border); }
}
</style>

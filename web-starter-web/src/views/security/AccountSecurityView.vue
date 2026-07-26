<template>
  <div class="page-content">
    <PageHeader title="个人安全" description="修改本人密码、管理 Web Session，并在凭据疑似泄露时执行安全注销" />

    <el-alert
      class="security-notice"
      type="info"
      title="此页面只管理本人安全状态，不提供角色、菜单或权限变更能力。普通退出只结束当前 Session；安全注销会使全部现有凭据失效。"
      :closable="false"
      show-icon
    />

    <div class="security-layout">
      <section class="security-panel" aria-labelledby="password-heading">
        <header class="panel-heading">
          <div>
            <h2 id="password-heading">修改登录密码</h2>
            <p>需要验证当前密码。修改成功后，本次登录将失效，请使用新密码重新登录。</p>
          </div>
          <span class="panel-icon"><el-icon><Lock /></el-icon></span>
        </header>

        <RequestError :message="passwordError" />
        <el-form
          ref="passwordFormRef"
          class="password-form"
          :model="passwordForm"
          :rules="passwordRules"
          label-position="top"
          @submit.prevent="changePassword"
        >
          <el-form-item label="当前密码" prop="currentPassword">
            <el-input
              v-model="passwordForm.currentPassword"
              type="password"
              autocomplete="current-password"
              show-password
              maxlength="128"
              data-testid="current-password"
            />
          </el-form-item>
          <el-form-item label="新密码" prop="newPassword">
            <el-input
              v-model="passwordForm.newPassword"
              type="password"
              autocomplete="new-password"
              show-password
              maxlength="128"
              data-testid="new-password"
            />
            <p class="form-help">长度 12 至 128 位，且不能与当前密码相同。</p>
          </el-form-item>
          <el-form-item label="确认新密码" prop="confirmPassword">
            <el-input
              v-model="passwordForm.confirmPassword"
              type="password"
              autocomplete="new-password"
              show-password
              maxlength="128"
              data-testid="confirm-password"
            />
          </el-form-item>
          <el-button
            type="primary"
            native-type="submit"
            :loading="changingPassword"
            data-testid="change-password"
          >
            验证并修改密码
          </el-button>
        </el-form>
      </section>

      <section class="security-panel sessions-panel" aria-labelledby="sessions-heading">
        <header class="panel-heading sessions-heading">
          <div>
            <h2 id="sessions-heading">活动 Session</h2>
            <p>Session 引用为不可逆标识，不展示 Redis 中的原始 Session ID。</p>
          </div>
          <div class="session-actions">
            <el-button :icon="Refresh" :loading="sessionsLoading" @click="loadSessions">刷新</el-button>
            <el-button
              type="warning"
              :disabled="otherSessionCount === 0"
              data-testid="revoke-other-sessions"
              @click="revokeOtherSessions"
            >
              退出其他设备{{ otherSessionCount ? ` (${otherSessionCount})` : '' }}
            </el-button>
          </div>
        </header>

        <RequestError :message="sessionsError" />
        <div v-loading="sessionsLoading" class="session-list" aria-live="polite">
          <el-empty v-if="!sessionsLoading && sessions.length === 0" description="没有可用的活动 Session" />
          <article
            v-for="session in orderedSessions"
            :key="session.reference"
            class="session-row"
            :data-testid="`session-${session.reference}`"
          >
            <div class="session-marker"><el-icon><Monitor /></el-icon></div>
            <div class="session-main">
              <div class="session-title">
                <strong>{{ deviceLabel(session.userAgent) }}</strong>
                <el-tag v-if="session.current" size="small" type="success">当前会话</el-tag>
              </div>
              <dl class="session-details">
                <div>
                  <dt>来源 IP</dt>
                  <dd class="mono">{{ session.ipAddress || '未记录' }}</dd>
                </div>
                <div>
                  <dt>最后活动</dt>
                  <dd>{{ formatDateTime(session.lastAccessedAt) }}</dd>
                </div>
                <div>
                  <dt>预计过期</dt>
                  <dd>{{ formatDateTime(session.expiresAt) }}</dd>
                </div>
              </dl>
              <p class="user-agent" :title="session.userAgent || ''">{{ session.userAgent || '未记录 User-Agent' }}</p>
            </div>
            <el-button
              link
              type="danger"
              :data-testid="`revoke-session-${session.reference}`"
              @click="revokeSession(session)"
            >
              {{ session.current ? '退出当前会话' : '撤销' }}
            </el-button>
          </article>
        </div>
      </section>

      <section class="security-panel security-logout-panel" aria-labelledby="security-logout-heading">
        <header class="panel-heading">
          <div>
            <h2 id="security-logout-heading">安全注销</h2>
            <p>当账号或令牌可能泄露时使用。所有 Web Session、OAuth access/refresh token，以及本账号签发的个人访问令牌都会在下一次请求时失效。</p>
          </div>
          <span class="panel-icon danger-icon"><el-icon><WarningFilled /></el-icon></span>
        </header>

        <RequestError :message="securityLogoutError" />
        <el-button
          type="danger"
          plain
          :loading="securityLogoutLoading"
          data-testid="security-logout"
          @click="securityLogout"
        >
          使全部现有凭据失效并退出
        </el-button>
      </section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Lock, Monitor, Refresh, WarningFilled } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import { accountSecurityApi } from '@/api/security'
import PageHeader from '@/components/PageHeader.vue'
import RequestError from '@/components/RequestError.vue'
import { useAuthStore } from '@/stores/auth'
import type { WebSessionSummary } from '@/types/models'
import { displayError, formatDateTime } from '@/utils/format'

interface PasswordForm {
  currentPassword: string
  newPassword: string
  confirmPassword: string
}

const auth = useAuthStore()
const router = useRouter()
const passwordFormRef = ref<FormInstance>()
const passwordForm = reactive<PasswordForm>({ currentPassword: '', newPassword: '', confirmPassword: '' })
const changingPassword = ref(false)
const passwordError = ref('')
const sessions = ref<WebSessionSummary[]>([])
const sessionsLoading = ref(false)
const sessionsError = ref('')
const securityLogoutLoading = ref(false)
const securityLogoutError = ref('')

const passwordRules: FormRules<PasswordForm> = {
  currentPassword: [{ required: true, message: '请输入当前密码', trigger: 'blur' }],
  newPassword: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 12, max: 128, message: '新密码长度应为 12 至 128 个字符', trigger: 'blur' },
    {
      validator: (_rule, value: string, callback) => {
        if (value && value === passwordForm.currentPassword) callback(new Error('新密码不能与当前密码相同'))
        else callback()
      },
      trigger: 'blur',
    },
  ],
  confirmPassword: [
    { required: true, message: '请再次输入新密码', trigger: 'blur' },
    {
      validator: (_rule, value: string, callback) => {
        if (value !== passwordForm.newPassword) callback(new Error('两次输入的新密码不一致'))
        else callback()
      },
      trigger: 'blur',
    },
  ],
}

const orderedSessions = computed(() =>
  [...sessions.value].sort((left, right) => Number(right.current) - Number(left.current)),
)
const otherSessionCount = computed(() => sessions.value.filter((session) => !session.current).length)

async function changePassword(): Promise<void> {
  if (!passwordFormRef.value || !(await passwordFormRef.value.validate().catch(() => false))) return
  changingPassword.value = true
  passwordError.value = ''
  try {
    await accountSecurityApi.changePassword({
      currentPassword: passwordForm.currentPassword,
      newPassword: passwordForm.newPassword,
    })
    auth.clearSession()
    ElMessage.success('密码已修改，请使用新密码重新登录')
    await router.replace({ name: 'login', query: { reason: 'password-changed' } })
  } catch (error: unknown) {
    passwordError.value = displayError(error)
  } finally {
    changingPassword.value = false
  }
}

async function loadSessions(): Promise<void> {
  sessionsLoading.value = true
  sessionsError.value = ''
  try {
    sessions.value = await accountSecurityApi.listSessions()
  } catch (error: unknown) {
    sessions.value = []
    sessionsError.value = displayError(error)
  } finally {
    sessionsLoading.value = false
  }
}

async function revokeSession(session: WebSessionSummary): Promise<void> {
  const action = session.current ? '退出当前会话' : '撤销此 Session'
  try {
    await ElMessageBox.confirm(
      session.current
        ? '退出当前会话后需要重新登录，是否继续？'
        : `确定撤销来自 ${session.ipAddress || '未知地址'} 的 Session 吗？`,
      action,
      { type: 'warning', confirmButtonText: action },
    )
    await accountSecurityApi.revokeSession(session.reference)
    if (session.current) {
      auth.clearSession()
      await router.replace({ name: 'login', query: { reason: 'session-revoked' } })
      return
    }
    ElMessage.success('Session 已撤销')
    await loadSessions()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    sessionsError.value = displayError(error)
  }
}

async function revokeOtherSessions(): Promise<void> {
  if (otherSessionCount.value === 0) return
  try {
    await ElMessageBox.confirm(
      `将退出另外 ${otherSessionCount.value} 个设备上的登录，会保留当前会话。是否继续？`,
      '退出其他设备',
      { type: 'warning', confirmButtonText: '确认退出其他设备' },
    )
    const result = await accountSecurityApi.revokeOtherSessions()
    ElMessage.success(`已退出 ${result.revoked} 个其他 Session`)
    await loadSessions()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    sessionsError.value = displayError(error)
  }
}

async function securityLogout(): Promise<void> {
  try {
    await ElMessageBox.confirm(
      '此操作会退出所有设备，并立即使现有 OAuth 令牌和个人访问令牌失效。之后需要重新登录并重新签发所需凭据，是否继续？',
      '安全注销全部凭据',
      { type: 'error', confirmButtonText: '确认安全注销' },
    )
    securityLogoutLoading.value = true
    securityLogoutError.value = ''
    await accountSecurityApi.securityLogout()
    auth.clearSession()
    ElMessage.success('安全注销已完成，全部现有凭据均已失效')
    await router.replace({ name: 'login', query: { reason: 'security-logout' } })
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    securityLogoutError.value = displayError(error)
  } finally {
    securityLogoutLoading.value = false
  }
}

function deviceLabel(userAgent?: string): string {
  if (!userAgent) return '未知客户端'
  const browser = userAgent.includes('Edg/')
    ? 'Edge'
    : userAgent.includes('Firefox/')
      ? 'Firefox'
      : userAgent.includes('Chrome/')
        ? 'Chrome'
        : userAgent.includes('Safari/')
          ? 'Safari'
          : '浏览器'
  const platform = userAgent.includes('iPhone')
    ? 'iPhone'
    : userAgent.includes('Android')
      ? 'Android'
      : userAgent.includes('Mac OS')
        ? 'macOS'
        : userAgent.includes('Windows')
          ? 'Windows'
          : userAgent.includes('Linux')
            ? 'Linux'
            : '未知设备'
  return `${browser} · ${platform}`
}

onMounted(loadSessions)
</script>

<style scoped>
.security-notice {
  margin-bottom: 20px;
}

.security-layout {
  display: grid;
  gap: 20px;
  grid-template-columns: minmax(300px, 0.72fr) minmax(520px, 1.28fr);
  align-items: start;
}

.security-panel {
  padding: 24px;
  background: var(--ws-surface);
  border: 1px solid var(--ws-border);
  border-radius: 8px;
}

.panel-heading {
  display: flex;
  gap: 18px;
  margin-bottom: 24px;
  align-items: flex-start;
  justify-content: space-between;
}

.panel-heading h2 {
  margin: 0 0 7px;
  color: var(--ws-text);
  font-size: 20px;
}

.panel-heading p {
  margin: 0;
  color: var(--ws-text-secondary);
  font-size: 13px;
  line-height: 1.6;
}

.panel-icon,
.session-marker {
  display: inline-flex;
  width: 42px;
  height: 42px;
  flex: 0 0 42px;
  color: var(--ws-teal-600);
  background: var(--ws-teal-100);
  border-radius: 50%;
  align-items: center;
  justify-content: center;
}

.danger-icon {
  color: var(--el-color-danger);
  background: var(--el-color-danger-light-9);
}

.security-logout-panel {
  grid-column: 1 / -1;
  border-color: var(--el-color-danger-light-7);
}

.password-form :deep(.el-form-item) {
  margin-bottom: 22px;
}

.password-form > .el-button {
  width: 100%;
  margin-top: 2px;
}

.form-help {
  margin: 6px 0 0;
  color: var(--ws-text-secondary);
  font-size: 12px;
  line-height: 1.5;
}

.sessions-heading {
  gap: 20px;
}

.session-actions {
  display: flex;
  flex: 0 0 auto;
  gap: 10px;
}

.session-list {
  min-height: 150px;
}

.session-row {
  display: grid;
  gap: 16px;
  padding: 18px 0;
  border-top: 1px solid var(--ws-border);
  grid-template-columns: 42px minmax(0, 1fr) auto;
  align-items: start;
}

.session-row:first-child {
  padding-top: 0;
  border-top: 0;
}

.session-title {
  display: flex;
  flex-wrap: wrap;
  gap: 9px;
  align-items: center;
}

.session-details {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 28px;
  margin: 14px 0 0;
}

.session-details div {
  display: grid;
  gap: 3px;
}

.session-details dt {
  color: var(--ws-text-secondary);
  font-size: 12px;
}

.session-details dd {
  margin: 0;
  color: #354258;
  font-size: 13px;
}

.user-agent {
  margin: 12px 0 0;
  overflow: hidden;
  color: var(--ws-text-secondary);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@media (max-width: 1160px) {
  .security-layout {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 680px) {
  .security-panel {
    padding: 20px 16px;
  }

  .sessions-heading,
  .session-actions {
    flex-direction: column;
  }

  .session-actions,
  .session-actions .el-button {
    width: 100%;
  }

  .session-actions .el-button {
    margin-left: 0;
  }

  .session-row {
    grid-template-columns: 36px minmax(0, 1fr);
  }

  .session-marker {
    width: 36px;
    height: 36px;
    flex-basis: 36px;
  }

  .session-row > .el-button {
    grid-column: 2;
    justify-self: start;
    margin-left: 0;
  }
}
</style>

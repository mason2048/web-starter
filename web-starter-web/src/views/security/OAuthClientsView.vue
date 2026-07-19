<template>
  <div class="page-content">
    <PageHeader title="OAuth 客户端" description="为内网或外网 Agent 注册标准 OAuth 客户端并管理客户端密钥">
      <template #actions>
        <el-button type="primary" :icon="Plus" @click="openCreate">注册 OAuth 客户端</el-button>
      </template>
    </PageHeader>

    <el-alert
      class="security-notice"
      type="info"
      title="授权码模式强制启用 PKCE；客户端凭据模式必须绑定服务账号。密钥轮换后旧密钥立即失效。"
      :closable="false"
      show-icon
    />
    <RequestError :message="errorMessage" />

    <div class="filter-row">
      <el-input
        v-model.trim="keyword"
        class="filter-input"
        placeholder="搜索客户端名称或 Client ID"
        clearable
        :prefix-icon="Search"
      />
      <el-select v-model="flowFilter" class="flow-filter" placeholder="全部授权模式">
        <el-option label="全部授权模式" value="" />
        <el-option label="授权码 + PKCE" value="authorization_code" />
        <el-option label="客户端凭据" value="client_credentials" />
      </el-select>
      <el-button :icon="Refresh" :loading="loading" @click="loadClients">刷新</el-button>
    </div>

    <div class="table-panel">
      <el-table v-loading="loading" :data="filteredClients" row-key="id" empty-text="暂无 OAuth 客户端">
        <el-table-column prop="clientName" label="客户端名称" min-width="180" />
        <el-table-column label="Client ID" min-width="190">
          <template #default="{ row }"><span class="mono">{{ row.clientId }}</span></template>
        </el-table-column>
        <el-table-column label="授权模式" min-width="190">
          <template #default="{ row }">{{ grantLabel(row.grantTypes) }}</template>
        </el-table-column>
        <el-table-column label="认证方式" min-width="175">
          <template #default="{ row }"><span class="mono">{{ row.authenticationMethods.join(', ') }}</span></template>
        </el-table-column>
        <el-table-column label="Scope" min-width="230" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ row.scopes.join(', ') }}</span></template>
        </el-table-column>
        <el-table-column label="服务账号" min-width="170">
          <template #default="{ row }">{{ serviceAccountLabel(row.serviceAccountId) }}</template>
        </el-table-column>
        <el-table-column label="安全策略" min-width="165">
          <template #default="{ row }">
            <div class="policy-tags">
              <el-tag v-if="row.grantTypes.includes('authorization_code') && row.requirePkce" size="small" effect="plain">PKCE</el-tag>
              <el-tag v-if="row.requireConsent" size="small" type="info" effect="plain">需确认授权</el-tag>
              <el-tag v-if="row.grantTypes.includes('client_credentials')" size="small" type="info" effect="plain">服务身份</el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }"><StatusTag :value="row.enabled" /></template>
        </el-table-column>
        <el-table-column label="更新时间" min-width="175">
          <template #default="{ row }">{{ formatDateTime(row.updatedAt || row.createdAt) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="240" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button v-if="!isPublicClient(row)" link type="primary" @click="confirmRotate(row)">轮换密钥</el-button>
            <el-button link :type="row.enabled ? 'danger' : 'success'" @click="confirmToggle(row)">
              {{ row.enabled ? '停用' : '启用' }}
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-drawer
      v-model="drawerOpen"
      :title="editingId === null ? '注册 OAuth 客户端' : '编辑 OAuth 客户端'"
      size="540px"
      :modal="false"
      destroy-on-close
    >
      <RequestError :message="drawerError" />
      <el-form ref="formRef" class="drawer-form" :model="form" :rules="rules" label-position="top">
        <el-form-item label="客户端名称" prop="clientName">
          <el-input v-model.trim="form.clientName" maxlength="100" show-word-limit placeholder="例如：外部数据 Agent" />
        </el-form-item>
        <el-form-item label="Client ID" prop="clientId">
          <el-input
            v-model.trim="form.clientId"
            maxlength="128"
            :disabled="editingId !== null"
            placeholder="例如 external-data-agent"
          />
        </el-form-item>
        <el-form-item label="授权模式" prop="flow">
          <el-radio-group v-model="form.flow" @change="handleFlowChange">
            <el-radio-button value="AUTHORIZATION_CODE">授权码 + PKCE</el-radio-button>
            <el-radio-button value="CLIENT_CREDENTIALS" :disabled="editingId !== null && editingWasPublic">
              客户端凭据
            </el-radio-button>
          </el-radio-group>
          <p class="form-help">
            授权码适合代表具体用户的 Agent；客户端凭据适合固定自动化任务。
          </p>
        </el-form-item>
        <el-form-item label="客户端认证" prop="authenticationMethod">
          <el-select v-model="form.authenticationMethod">
            <el-option v-if="editingId === null || !editingWasPublic" label="Client Secret Basic（推荐）" value="client_secret_basic" />
            <el-option v-if="editingId === null || !editingWasPublic" label="Client Secret Post" value="client_secret_post" />
            <el-option
              v-if="form.flow === 'AUTHORIZATION_CODE' && (editingId === null || editingWasPublic)"
              label="公开客户端（无密钥）"
              value="none"
            />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.flow === 'AUTHORIZATION_CODE'" label="回调地址" prop="redirectUris">
          <el-select
            v-model="form.redirectUris"
            multiple
            filterable
            allow-create
            default-first-option
            placeholder="输入完整 URI 后按回车"
          />
          <p class="form-help">生产环境仅允许 HTTPS；本机开发可使用 localhost、127.0.0.0/8 或 ::1 的 HTTP 地址。</p>
        </el-form-item>
        <el-form-item label="授权范围（Scope）" prop="scopes">
          <el-select
            v-model="form.scopes"
            multiple
            filterable
            allow-create
            default-first-option
            collapse-tags
            collapse-tags-tooltip
            placeholder="选择或输入权限编码"
          >
            <el-option v-for="scope in scopeOptions" :key="scope" :label="scope" :value="scope" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.flow === 'CLIENT_CREDENTIALS'" label="绑定服务账号" prop="serviceAccountId">
          <el-select
            v-model="form.serviceAccountId"
            filterable
            allow-create
            default-first-option
            :loading="accountsLoading"
            placeholder="选择服务账号，或输入账号 ID"
          >
            <el-option
              v-for="account in enabledServiceAccounts"
              :key="account.id"
              :label="`${account.displayName} (${account.code})`"
              :value="account.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.flow === 'AUTHORIZATION_CODE'" label="授权设置">
          <div class="switch-list">
            <label>
              <span>
                <strong>签发刷新令牌</strong>
                <small>允许 Agent 在用户离线时续期访问</small>
              </span>
              <el-switch v-model="form.includeRefreshToken" />
            </label>
            <label>
              <span>
                <strong>要求用户确认授权</strong>
                <small>首次授权时显示 Scope 确认页</small>
              </span>
              <el-switch v-model="form.requireConsent" />
            </label>
          </div>
        </el-form-item>
        <el-form-item v-if="editingId !== null" label="客户端状态">
          <el-switch v-model="form.enabled" inline-prompt active-text="启" inactive-text="停" />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="drawer-footer">
          <el-button @click="drawerOpen = false">取消</el-button>
          <el-button type="primary" :loading="saving" @click="saveClient">
            {{ editingId === null ? '注册客户端' : '保存修改' }}
          </el-button>
        </div>
      </template>
    </el-drawer>

    <OneTimeSecretDialog
      v-model="secretOpen"
      :secret="rawSecret"
      :title="secretTitle"
      label="Client Secret"
      @consumed="clearSecret"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import { oauthClientsApi, serviceAccountsApi } from '@/api/security'
import OneTimeSecretDialog from '@/components/OneTimeSecretDialog.vue'
import PageHeader from '@/components/PageHeader.vue'
import RequestError from '@/components/RequestError.vue'
import StatusTag from '@/components/StatusTag.vue'
import { usePermission } from '@/composables/usePermission'
import { useAuthStore } from '@/stores/auth'
import type { OAuthClient, ServiceAccount } from '@/types/models'
import { displayError, formatDateTime } from '@/utils/format'

type OAuthFlow = 'AUTHORIZATION_CODE' | 'CLIENT_CREDENTIALS'

interface OAuthClientForm {
  clientId: string
  clientName: string
  flow: OAuthFlow
  authenticationMethod: 'client_secret_basic' | 'client_secret_post' | 'none'
  redirectUris: string[]
  scopes: string[]
  requireConsent: boolean
  includeRefreshToken: boolean
  serviceAccountId?: string
  enabled: boolean
}

const auth = useAuthStore()
const { can } = usePermission()
const clients = ref<OAuthClient[]>([])
const serviceAccounts = ref<ServiceAccount[]>([])
const loading = ref(false)
const accountsLoading = ref(false)
const saving = ref(false)
const errorMessage = ref('')
const drawerError = ref('')
const drawerOpen = ref(false)
const editingId = ref<string | null>(null)
const editingWasPublic = ref(false)
const secretOpen = ref(false)
const rawSecret = ref('')
const secretTitle = ref('OAuth 客户端密钥已生成')
const keyword = ref('')
const flowFilter = ref('')
const formRef = ref<FormInstance>()
const form = reactive<OAuthClientForm>({
  clientId: '',
  clientName: '',
  flow: 'AUTHORIZATION_CODE',
  authenticationMethod: 'client_secret_basic',
  redirectUris: [],
  scopes: [],
  requireConsent: true,
  includeRefreshToken: true,
  serviceAccountId: undefined,
  enabled: true,
})

const scopeOptions = computed(() => [...new Set(auth.currentUser?.permissions || [])].sort())
const enabledServiceAccounts = computed(() => serviceAccounts.value.filter((account) => account.enabled))
const filteredClients = computed(() => {
  const search = keyword.value.toLowerCase()
  return clients.value.filter((client) => {
    const matchesSearch = !search || `${client.clientName} ${client.clientId}`.toLowerCase().includes(search)
    const matchesFlow = !flowFilter.value || client.grantTypes.includes(flowFilter.value)
    return matchesSearch && matchesFlow
  })
})

const rules: FormRules<OAuthClientForm> = {
  clientName: [{ required: true, message: '请输入客户端名称', trigger: 'blur' }],
  clientId: [
    { required: true, message: '请输入 Client ID', trigger: 'blur' },
    {
      pattern: /^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/,
      message: '长度 3 至 128 位，仅含字母、数字、点、连字符和下划线',
      trigger: 'blur',
    },
  ],
  flow: [{ required: true, message: '请选择授权模式', trigger: 'change' }],
  authenticationMethod: [{ required: true, message: '请选择客户端认证方式', trigger: 'change' }],
  redirectUris: [
    {
      validator: (_rule, values: string[], callback) => {
        if (form.flow !== 'AUTHORIZATION_CODE') return callback()
        if (!values.length) return callback(new Error('授权码模式至少需要一个回调地址'))
        const invalid = values.find((uri) => !isAllowedRedirectUri(uri))
        if (invalid) return callback(new Error(`回调地址不符合 HTTPS / 本机 HTTP 规则：${invalid}`))
        callback()
      },
      trigger: 'change',
    },
  ],
  scopes: [{ type: 'array', required: true, min: 1, message: '请至少选择一个 Scope', trigger: 'change' }],
  serviceAccountId: [
    {
      validator: (_rule, value: string | undefined, callback) => {
        if (form.flow !== 'CLIENT_CREDENTIALS') return callback()
        if (/^[1-9][0-9]*$/.test(value ?? '')) callback()
        else callback(new Error('请选择或输入有效的服务账号 ID'))
      },
      trigger: 'change',
    },
  ],
}

function isAllowedRedirectUri(value: string): boolean {
  try {
    const uri = new URL(value)
    if (uri.username || uri.password || uri.hash) return false
    if (uri.protocol === 'https:') return true
    const host = uri.hostname.replace(/^\[|\]$/g, '').toLowerCase()
    return uri.protocol === 'http:' && (host === 'localhost' || host === '::1' || /^127\.(\d{1,3}\.){2}\d{1,3}$/.test(host))
  } catch {
    return false
  }
}

function grantLabel(grants: string[]): string {
  if (grants.includes('client_credentials')) return '客户端凭据'
  return grants.includes('refresh_token') ? '授权码 + 刷新令牌' : '授权码 + PKCE'
}

function serviceAccountLabel(id?: string): string {
  if (!id) return '—'
  const account = serviceAccounts.value.find((item) => item.id === id)
  return account ? account.displayName : `服务账号 #${id}`
}

function isPublicClient(client: OAuthClient): boolean {
  return client.authenticationMethods.includes('none')
}

async function loadClients(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    clients.value = await oauthClientsApi.list()
  } catch (error: unknown) {
    clients.value = []
    errorMessage.value = displayError(error)
  } finally {
    loading.value = false
  }
}

async function loadServiceAccounts(): Promise<void> {
  if (!can('security:service-account:manage')) return
  accountsLoading.value = true
  try {
    serviceAccounts.value = await serviceAccountsApi.list()
  } catch (error: unknown) {
    serviceAccounts.value = []
    drawerError.value = `服务账号列表加载失败，可直接输入账号 ID：${displayError(error)}`
  } finally {
    accountsLoading.value = false
  }
}

function resetForm(): void {
  editingId.value = null
  editingWasPublic.value = false
  drawerError.value = ''
  Object.assign(form, {
    clientId: '',
    clientName: '',
    flow: 'AUTHORIZATION_CODE',
    authenticationMethod: 'client_secret_basic',
    redirectUris: [],
    scopes: [],
    requireConsent: true,
    includeRefreshToken: true,
    serviceAccountId: undefined,
    enabled: true,
  })
  formRef.value?.clearValidate()
}

function openCreate(): void {
  resetForm()
  drawerOpen.value = true
  void loadServiceAccounts()
}

function openEdit(client: OAuthClient): void {
  resetForm()
  editingId.value = client.id
  editingWasPublic.value = isPublicClient(client)
  const clientCredentials = client.grantTypes.includes('client_credentials')
  Object.assign(form, {
    clientId: client.clientId,
    clientName: client.clientName,
    flow: clientCredentials ? 'CLIENT_CREDENTIALS' : 'AUTHORIZATION_CODE',
    authenticationMethod: client.authenticationMethods[0] || (clientCredentials ? 'client_secret_basic' : 'none'),
    redirectUris: [...client.redirectUris],
    scopes: [...client.scopes],
    requireConsent: client.requireConsent,
    includeRefreshToken: client.grantTypes.includes('refresh_token'),
    serviceAccountId: client.serviceAccountId,
    enabled: client.enabled,
  })
  drawerOpen.value = true
  void loadServiceAccounts()
}

function handleFlowChange(): void {
  if (form.flow === 'CLIENT_CREDENTIALS') {
    if (form.authenticationMethod === 'none') form.authenticationMethod = 'client_secret_basic'
    form.redirectUris = []
    form.includeRefreshToken = false
    form.requireConsent = false
  } else {
    form.serviceAccountId = undefined
    form.includeRefreshToken = true
    form.requireConsent = true
  }
  formRef.value?.clearValidate(['authenticationMethod', 'redirectUris', 'serviceAccountId'])
}

async function saveClient(): Promise<void> {
  if (!formRef.value || !(await formRef.value.validate().catch(() => false))) return
  saving.value = true
  drawerError.value = ''
  try {
    const clientCredentials = form.flow === 'CLIENT_CREDENTIALS'
    const payload = {
      clientName: form.clientName,
      authenticationMethods: [form.authenticationMethod],
      grantTypes: clientCredentials
        ? ['client_credentials']
        : ['authorization_code', ...(form.includeRefreshToken ? ['refresh_token'] : [])],
      redirectUris: clientCredentials ? [] : [...new Set(form.redirectUris.map((uri) => uri.trim()))],
      scopes: [...new Set(form.scopes.map((scope) => scope.trim()).filter(Boolean))],
      requireConsent: clientCredentials ? false : form.requireConsent,
      serviceAccountId: clientCredentials ? form.serviceAccountId : undefined,
    }
    if (editingId.value !== null) {
      await oauthClientsApi.update(editingId.value, { ...payload, enabled: form.enabled })
      drawerOpen.value = false
      ElMessage.success('OAuth 客户端已更新')
      void loadClients()
      return
    }
    const created = await oauthClientsApi.create({ clientId: form.clientId, ...payload })
    drawerOpen.value = false
    if (created.clientSecret) {
      rawSecret.value = created.clientSecret
      secretTitle.value = 'OAuth 客户端密钥已生成'
      secretOpen.value = true
    } else {
      ElMessage.success('公开 OAuth 客户端已注册，无客户端密钥')
    }
    void loadClients()
  } catch (error: unknown) {
    drawerError.value = displayError(error)
  } finally {
    saving.value = false
  }
}

function updatePayload(client: OAuthClient, enabled: boolean) {
  return {
    clientName: client.clientName,
    authenticationMethods: [...client.authenticationMethods],
    grantTypes: [...client.grantTypes],
    redirectUris: [...client.redirectUris],
    scopes: [...client.scopes],
    requireConsent: client.requireConsent,
    serviceAccountId: client.serviceAccountId,
    enabled,
  }
}

async function confirmToggle(client: OAuthClient): Promise<void> {
  const nextEnabled = !client.enabled
  const action = nextEnabled ? '启用' : '停用'
  try {
    await ElMessageBox.confirm(
      `确定${action}“${client.clientName}”吗？${nextEnabled ? '' : '已有授权与后续换取令牌将立即被拒绝。'}`,
      `${action} OAuth 客户端`,
      { type: nextEnabled ? 'info' : 'warning', confirmButtonText: `确认${action}` },
    )
    await oauthClientsApi.update(client.id, updatePayload(client, nextEnabled))
    ElMessage.success(`OAuth 客户端已${action}`)
    await loadClients()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    errorMessage.value = displayError(error)
  }
}

async function confirmRotate(client: OAuthClient): Promise<void> {
  try {
    await ElMessageBox.confirm(
      `确定轮换“${client.clientName}”的客户端密钥吗？旧密钥将立即失效。`,
      '轮换 OAuth 客户端密钥',
      { type: 'warning', confirmButtonText: '确认轮换' },
    )
    const rotated = await oauthClientsApi.rotateSecret(client.id)
    if (!rotated.clientSecret) throw new Error('服务端未返回一次性客户端密钥')
    rawSecret.value = rotated.clientSecret
    secretTitle.value = 'OAuth 客户端密钥已轮换'
    secretOpen.value = true
    void loadClients()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    errorMessage.value = displayError(error)
  }
}

function clearSecret(): void {
  rawSecret.value = ''
}

onMounted(() => {
  void Promise.all([loadClients(), loadServiceAccounts()])
})
</script>

<style scoped>
.security-notice {
  margin-bottom: 20px;
}

.flow-filter {
  width: 168px;
}

.policy-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.form-help {
  margin: 7px 0 0;
  color: var(--ws-text-secondary);
  font-size: 12px;
  line-height: 1.55;
}

.switch-list {
  display: grid;
  width: 100%;
  border: 1px solid var(--ws-border);
  border-radius: 6px;
}

.switch-list label {
  display: flex;
  gap: 18px;
  padding: 14px;
  align-items: center;
  justify-content: space-between;
}

.switch-list label + label {
  border-top: 1px solid var(--ws-border);
}

.switch-list span {
  display: grid;
  gap: 4px;
}

.switch-list small {
  color: var(--ws-text-secondary);
  line-height: 1.45;
}
</style>

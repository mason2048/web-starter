<template>
  <div class="page-content">
    <PageHeader title="服务账号" description="为固定 Agent 与自动化任务建立非人员身份，并独立管理角色和令牌">
      <template #actions>
        <el-button type="primary" :icon="Plus" @click="openCreate">新建服务账号</el-button>
      </template>
    </PageHeader>

    <el-alert
      class="security-notice"
      type="info"
      title="服务账号不具备浏览器登录能力。令牌 Scope 与账号角色权限实时取交集，可单独吊销。"
      :closable="false"
      show-icon
    />
    <RequestError :message="errorMessage" />

    <div class="filter-row">
      <el-input
        v-model.trim="keyword"
        class="filter-input"
        placeholder="搜索账号名称或编码"
        clearable
        :prefix-icon="Search"
      />
      <el-select v-model="enabledFilter" class="status-filter" placeholder="全部状态">
        <el-option label="全部状态" value="" />
        <el-option label="启用" value="ENABLED" />
        <el-option label="停用" value="DISABLED" />
      </el-select>
      <el-button :icon="Refresh" :loading="loading" @click="loadAccounts">刷新</el-button>
    </div>

    <div class="table-panel">
      <el-table v-loading="loading" :data="filteredAccounts" row-key="id" empty-text="暂无服务账号">
        <el-table-column prop="displayName" label="显示名称" min-width="170" />
        <el-table-column label="账号编码" min-width="170">
          <template #default="{ row }"><span class="mono">{{ row.code }}</span></template>
        </el-table-column>
        <el-table-column prop="description" label="说明" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">{{ row.description || '—' }}</template>
        </el-table-column>
        <el-table-column label="绑定角色" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">{{ roleSummary(row.roleIds) }}</template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }"><StatusTag :value="row.enabled" /></template>
        </el-table-column>
        <el-table-column label="更新时间" min-width="175">
          <template #default="{ row }">{{ formatDateTime(row.updatedAt || row.createdAt) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="210" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openTokens(row)">令牌</el-button>
            <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button v-if="row.enabled" link type="danger" @click="confirmDisable(row)">停用</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-drawer
      v-model="accountDrawerOpen"
      :title="editingId === null ? '新建服务账号' : '编辑服务账号'"
      size="470px"
      :modal="false"
      destroy-on-close
    >
      <RequestError :message="accountError" />
      <el-form ref="accountFormRef" class="drawer-form" :model="accountForm" :rules="accountRules" label-position="top">
        <el-form-item label="账号编码" prop="code">
          <el-input
            v-model.trim="accountForm.code"
            maxlength="64"
            :disabled="editingId !== null"
            placeholder="例如 report_agent"
          />
        </el-form-item>
        <el-form-item label="显示名称" prop="displayName">
          <el-input v-model.trim="accountForm.displayName" maxlength="100" show-word-limit placeholder="例如：报表同步 Agent" />
        </el-form-item>
        <el-form-item label="说明">
          <el-input v-model="accountForm.description" type="textarea" :rows="3" maxlength="500" show-word-limit />
        </el-form-item>
        <el-form-item label="绑定角色" prop="roleIds">
          <el-select
            v-model="accountForm.roleIds"
            multiple
            filterable
            allow-create
            default-first-option
            collapse-tags
            collapse-tags-tooltip
            :loading="rolesLoading"
            placeholder="选择角色，或输入角色 ID"
          >
            <el-option
              v-for="role in roleOptions"
              :key="role.id"
              :label="`${role.name} (${role.code})`"
              :value="role.id"
            />
          </el-select>
          <p class="form-help">服务账号的权限来自所选角色；输入角色 ID 后按回车添加。</p>
        </el-form-item>
        <el-form-item v-if="editingId !== null" label="账号状态">
          <el-switch v-model="accountForm.enabled" inline-prompt active-text="启" inactive-text="停" />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="drawer-footer">
          <el-button @click="accountDrawerOpen = false">取消</el-button>
          <el-button type="primary" :loading="saving" @click="saveAccount">保存</el-button>
        </div>
      </template>
    </el-drawer>

    <el-drawer
      v-model="tokenDrawerOpen"
      :title="selectedAccount ? `${selectedAccount.displayName} · 令牌` : '服务账号令牌'"
      size="720px"
      :modal="false"
      destroy-on-close
    >
      <div class="token-toolbar">
        <div>
          <span class="text-muted">账号编码</span>
          <strong class="mono">{{ selectedAccount?.code }}</strong>
        </div>
        <el-button
          v-if="selectedAccount?.enabled"
          type="primary"
          :icon="Plus"
          @click="openTokenIssue"
        >
          签发服务令牌
        </el-button>
      </div>
      <el-alert
        class="token-secret-notice"
        type="info"
        title="列表只返回令牌标识；完整明文仅在签发成功时展示一次，关闭后不能再次读取。"
        :closable="false"
        show-icon
      />
      <RequestError :message="tokenError" />
      <div class="token-filter-row">
        <el-select
          v-model="tokenCredentialFilter"
          placeholder="全部凭据"
          data-testid="service-token-filter"
        >
          <el-option
            v-for="option in credentialLifecycleOptions"
            :key="option.value || 'ALL'"
            :label="option.label"
            :value="option.value"
          />
        </el-select>
        <span>筛选仅作用于当前服务账号已加载的令牌。</span>
      </div>
      <div class="table-panel token-table">
        <el-table
          v-loading="tokensLoading"
          :data="filteredAccountTokens"
          row-key="id"
          empty-text="没有符合筛选条件的服务账号令牌"
        >
          <el-table-column prop="name" label="名称" min-width="150" />
          <el-table-column label="令牌标识" min-width="145">
            <template #default="{ row }"><span class="mono">{{ row.tokenHint }}</span></template>
          </el-table-column>
          <el-table-column label="Scope" min-width="200" show-overflow-tooltip>
            <template #default="{ row }"><span class="mono">{{ row.scopes?.join(', ') || '—' }}</span></template>
          </el-table-column>
          <el-table-column label="状态" width="96">
            <template #default="{ row }">
              <el-tag :type="credentialStatus(row).type" size="small">{{ credentialStatus(row).label }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="IP 限制" min-width="160" show-overflow-tooltip>
            <template #default="{ row }">
              {{ row.allowedIpCidrs?.length ? row.allowedIpCidrs.join(', ') : '不限' }}
            </template>
          </el-table-column>
          <el-table-column label="安全提示" min-width="175" show-overflow-tooltip>
            <template #default="{ row }">{{ credentialNotices(row).join('、') || '—' }}</template>
          </el-table-column>
          <el-table-column label="最后使用" min-width="170">
            <template #default="{ row }">{{ formatDateTime(row.lastUsedAt) }}</template>
          </el-table-column>
          <el-table-column label="有效期" min-width="170">
            <template #default="{ row }">{{ row.expiresAt ? formatDateTime(row.expiresAt) : '长期有效' }}</template>
          </el-table-column>
          <el-table-column label="操作" width="84" fixed="right">
            <template #default="{ row }">
              <el-button
                v-if="credentialStatus(row).key === 'ACTIVE'"
                link
                type="danger"
                @click="confirmRevokeToken(row)"
              >
                吊销
              </el-button>
              <span v-else class="text-muted">—</span>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-drawer>

    <TokenIssueDialog
      v-model="tokenIssueOpen"
      title="签发服务账号令牌"
      :submitting="issuingToken"
      :error="tokenIssueError"
      :scope-options="scopeOptions"
      @submit="issueServiceToken"
    />
    <OneTimeSecretDialog
      v-model="secretOpen"
      :secret="rawToken"
      title="服务账号令牌已签发"
      label="服务账号令牌"
      @consumed="clearSecret"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import { rolesApi } from '@/api/admin'
import { serviceAccountsApi } from '@/api/security'
import OneTimeSecretDialog from '@/components/OneTimeSecretDialog.vue'
import PageHeader from '@/components/PageHeader.vue'
import RequestError from '@/components/RequestError.vue'
import StatusTag from '@/components/StatusTag.vue'
import TokenIssueDialog from '@/components/TokenIssueDialog.vue'
import { usePermission } from '@/composables/usePermission'
import { useAuthStore } from '@/stores/auth'
import type { IssueTokenPayload, RoleRecord, ServiceAccount, TokenSummary } from '@/types/models'
import {
  credentialLifecycleOptions,
  credentialNotices,
  credentialStatus,
  matchesCredentialLifecycle,
  type CredentialLifecycleFilter,
} from '@/utils/credentials'
import { displayError, formatDateTime } from '@/utils/format'
type EnabledFilter = '' | 'ENABLED' | 'DISABLED'

interface AccountForm {
  code: string
  displayName: string
  description: string
  enabled: boolean
  roleIds: string[]
}

const auth = useAuthStore()
const { can } = usePermission()
const accounts = ref<ServiceAccount[]>([])
const roleOptions = ref<RoleRecord[]>([])
const accountTokens = ref<TokenSummary[]>([])
const selectedAccount = ref<ServiceAccount | null>(null)
const loading = ref(false)
const rolesLoading = ref(false)
const saving = ref(false)
const tokensLoading = ref(false)
const issuingToken = ref(false)
const errorMessage = ref('')
const accountError = ref('')
const tokenError = ref('')
const tokenIssueError = ref('')
const accountDrawerOpen = ref(false)
const tokenDrawerOpen = ref(false)
const tokenIssueOpen = ref(false)
const secretOpen = ref(false)
const rawToken = ref('')
const editingId = ref<string | null>(null)
const keyword = ref('')
const enabledFilter = ref<EnabledFilter>('')
const tokenCredentialFilter = ref<CredentialLifecycleFilter>('')
const accountFormRef = ref<FormInstance>()
const accountForm = reactive<AccountForm>({ code: '', displayName: '', description: '', enabled: true, roleIds: [] })

const scopeOptions = computed(() => [...new Set(auth.currentUser?.permissions || [])].sort())
const filteredAccounts = computed(() => {
  const search = keyword.value.toLowerCase()
  return accounts.value.filter((account) => {
    const matchesSearch = !search || `${account.displayName} ${account.code}`.toLowerCase().includes(search)
    const matchesStatus = !enabledFilter.value || account.enabled === (enabledFilter.value === 'ENABLED')
    return matchesSearch && matchesStatus
  })
})
const filteredAccountTokens = computed(() =>
  accountTokens.value.filter((token) => matchesCredentialLifecycle(token, tokenCredentialFilter.value)),
)

const accountRules: FormRules<AccountForm> = {
  code: [
    { required: true, message: '请输入账号编码', trigger: 'blur' },
    {
      pattern: /^[A-Za-z][A-Za-z0-9_-]{2,63}$/,
      message: '编码长度 3 至 64 位，须以字母开头，仅含字母、数字、连字符和下划线',
      trigger: 'blur',
    },
  ],
  displayName: [{ required: true, message: '请输入显示名称', trigger: 'blur' }],
  roleIds: [
    {
      validator: (_rule, values: string[], callback) => {
        if (values.every((value) => /^[1-9][0-9]*$/.test(value))) callback()
        else callback(new Error('角色 ID 必须为正整数'))
      },
      trigger: 'change',
    },
  ],
}

function roleSummary(roleIds: string[]): string {
  if (!roleIds?.length) return '未绑定角色'
  return roleIds
    .map((id) => roleOptions.value.find((role) => role.id === id)?.name || `角色 #${id}`)
    .join('、')
}

async function loadAccounts(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    accounts.value = await serviceAccountsApi.list()
  } catch (error: unknown) {
    accounts.value = []
    errorMessage.value = displayError(error)
  } finally {
    loading.value = false
  }
}

async function loadRoles(): Promise<void> {
  if (!can('system:role:list')) return
  rolesLoading.value = true
  try {
    const data = await rolesApi.list({ page: 1, size: 100 })
    roleOptions.value = data.records
  } catch (error: unknown) {
    roleOptions.value = []
    accountError.value = `角色列表加载失败，可直接输入角色 ID：${displayError(error)}`
  } finally {
    rolesLoading.value = false
  }
}

function resetAccountForm(): void {
  editingId.value = null
  accountError.value = ''
  Object.assign(accountForm, { code: '', displayName: '', description: '', enabled: true, roleIds: [] })
  accountFormRef.value?.clearValidate()
}

function openCreate(): void {
  resetAccountForm()
  accountDrawerOpen.value = true
  void loadRoles()
}

function openEdit(account: ServiceAccount): void {
  resetAccountForm()
  editingId.value = account.id
  Object.assign(accountForm, {
    code: account.code,
    displayName: account.displayName,
    description: account.description || '',
    enabled: account.enabled,
    roleIds: [...(account.roleIds || [])],
  })
  accountDrawerOpen.value = true
  void loadRoles()
}

async function saveAccount(): Promise<void> {
  if (!accountFormRef.value || !(await accountFormRef.value.validate().catch(() => false))) return
  saving.value = true
  accountError.value = ''
  const roleIds = [...new Set(accountForm.roleIds)]
  try {
    if (editingId.value === null) {
      await serviceAccountsApi.create({
        code: accountForm.code,
        displayName: accountForm.displayName,
        description: accountForm.description || undefined,
        roleIds,
      })
      ElMessage.success('服务账号创建成功')
    } else {
      await serviceAccountsApi.update(editingId.value, {
        displayName: accountForm.displayName,
        description: accountForm.description || undefined,
        enabled: accountForm.enabled,
        roleIds,
      })
      ElMessage.success('服务账号更新成功')
    }
    accountDrawerOpen.value = false
    await loadAccounts()
  } catch (error: unknown) {
    accountError.value = displayError(error)
  } finally {
    saving.value = false
  }
}

async function confirmDisable(account: ServiceAccount): Promise<void> {
  try {
    await ElMessageBox.confirm(
      `确定停用“${account.displayName}”吗？其所有令牌将无法再通过身份校验。`,
      '停用服务账号',
      { type: 'warning', confirmButtonText: '确认停用' },
    )
    await serviceAccountsApi.disable(account.id)
    ElMessage.success('服务账号已停用')
    await loadAccounts()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    errorMessage.value = displayError(error)
  }
}

async function openTokens(account: ServiceAccount): Promise<void> {
  selectedAccount.value = account
  accountTokens.value = []
  tokenCredentialFilter.value = ''
  tokenError.value = ''
  tokenDrawerOpen.value = true
  await loadAccountTokens()
}

async function loadAccountTokens(): Promise<void> {
  if (!selectedAccount.value) return
  tokensLoading.value = true
  tokenError.value = ''
  try {
    accountTokens.value = await serviceAccountsApi.listTokens(selectedAccount.value.id)
  } catch (error: unknown) {
    accountTokens.value = []
    tokenError.value = displayError(error)
  } finally {
    tokensLoading.value = false
  }
}

function openTokenIssue(): void {
  tokenIssueError.value = ''
  tokenIssueOpen.value = true
}

async function issueServiceToken(payload: IssueTokenPayload): Promise<void> {
  if (!selectedAccount.value) return
  issuingToken.value = true
  tokenIssueError.value = ''
  try {
    const issued = await serviceAccountsApi.issueToken(selectedAccount.value.id, payload)
    if (!issued.token) throw new Error('服务端未返回一次性令牌明文')
    tokenIssueOpen.value = false
    rawToken.value = issued.token
    secretOpen.value = true
    void loadAccountTokens()
  } catch (error: unknown) {
    tokenIssueError.value = displayError(error)
  } finally {
    issuingToken.value = false
  }
}

async function confirmRevokeToken(token: TokenSummary): Promise<void> {
  if (!selectedAccount.value) return
  try {
    await ElMessageBox.confirm(`确定吊销服务令牌“${token.name}”吗？`, '吊销服务账号令牌', {
      type: 'warning',
      confirmButtonText: '确认吊销',
    })
    await serviceAccountsApi.revokeToken(selectedAccount.value.id, token.id)
    ElMessage.success('服务账号令牌已吊销')
    await loadAccountTokens()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    tokenError.value = displayError(error)
  }
}

function clearSecret(): void {
  rawToken.value = ''
}

onMounted(() => {
  void Promise.all([loadAccounts(), loadRoles()])
})
</script>

<style scoped>
.security-notice {
  margin-bottom: 20px;
}

.status-filter {
  width: 142px;
}

.form-help {
  margin: 7px 0 0;
  color: var(--ws-text-secondary);
  font-size: 12px;
  line-height: 1.55;
}

.token-toolbar {
  display: flex;
  gap: 18px;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
}

.token-toolbar > div {
  display: grid;
  gap: 5px;
}

.token-table {
  overflow-x: auto;
}

.token-secret-notice {
  margin-bottom: 16px;
}

.token-filter-row {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
  color: var(--ws-text-secondary);
  font-size: 12px;
  align-items: center;
}

.token-filter-row .el-select {
  width: 172px;
}

@media (max-width: 680px) {
  .token-filter-row {
    align-items: stretch;
    flex-direction: column;
  }

  .token-filter-row .el-select {
    width: 100%;
  }
}
</style>

<template>
  <div class="page-content">
    <PageHeader title="个人访问令牌" description="为当前用户签发独立于浏览器会话的 Agent 访问凭据">
      <template #actions>
        <el-button v-if="can('security:personal-token:create')" type="primary" :icon="Plus" @click="openIssue">
          签发个人令牌
        </el-button>
      </template>
    </PageHeader>

    <el-alert
      class="security-notice"
      type="info"
      title="个人令牌权限由 Scope 与实时 RBAC 取交集。列表只返回令牌标识，完整明文仅在签发成功时展示一次，关闭后不能再次读取。"
      :closable="false"
      show-icon
    />
    <RequestError :message="errorMessage" />

    <div class="filter-row">
      <el-input
        v-model.trim="keyword"
        class="filter-input"
        placeholder="搜索名称或令牌标识"
        clearable
        :prefix-icon="Search"
      />
      <el-select
        v-model="credentialFilter"
        class="lifecycle-filter"
        placeholder="全部凭据"
        data-testid="personal-token-filter"
      >
        <el-option
          v-for="option in credentialLifecycleOptions"
          :key="option.value || 'ALL'"
          :label="option.label"
          :value="option.value"
        />
      </el-select>
      <el-button :icon="Refresh" :loading="loading" @click="loadTokens">刷新</el-button>
    </div>

    <div class="table-panel">
      <el-table v-loading="loading" :data="filteredTokens" row-key="id" empty-text="暂无个人访问令牌">
        <el-table-column prop="name" label="名称" min-width="170" />
        <el-table-column label="令牌标识" min-width="150">
          <template #default="{ row }"><span class="mono">{{ row.tokenHint }}</span></template>
        </el-table-column>
        <el-table-column label="Scope" min-width="230" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ formatScopes(row.scopes) }}</span></template>
        </el-table-column>
        <el-table-column label="IP 限制" min-width="160" show-overflow-tooltip>
          <template #default="{ row }">{{ row.allowedIpCidrs?.length ? row.allowedIpCidrs.join(', ') : '不限' }}</template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="credentialStatus(row).type" size="small" effect="light">
              {{ credentialStatus(row).label }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="安全提示" min-width="180" show-overflow-tooltip>
          <template #default="{ row }">{{ credentialNotices(row).join('、') || '—' }}</template>
        </el-table-column>
        <el-table-column label="有效期" min-width="175">
          <template #default="{ row }">{{ row.expiresAt ? formatDateTime(row.expiresAt) : '长期有效' }}</template>
        </el-table-column>
        <el-table-column label="最后使用" min-width="175">
          <template #default="{ row }">{{ formatDateTime(row.lastUsedAt) }}</template>
        </el-table-column>
        <el-table-column label="创建时间" min-width="175">
          <template #default="{ row }">{{ formatDateTime(row.createdAt) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="90" fixed="right">
          <template #default="{ row }">
            <el-button
              v-if="can('security:personal-token:revoke') && credentialStatus(row).key === 'ACTIVE'"
              link
              type="danger"
              @click="confirmRevoke(row)"
            >
              吊销
            </el-button>
            <span v-else class="text-muted">—</span>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <TokenIssueDialog
      v-model="issueOpen"
      title="签发个人访问令牌"
      :submitting="issuing"
      :error="issueError"
      :scope-options="scopeOptions"
      @submit="issueToken"
    />
    <OneTimeSecretDialog
      v-model="secretOpen"
      :secret="rawToken"
      title="个人访问令牌已签发"
      label="个人访问令牌"
      @consumed="clearSecret"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { personalTokensApi } from '@/api/security'
import OneTimeSecretDialog from '@/components/OneTimeSecretDialog.vue'
import PageHeader from '@/components/PageHeader.vue'
import RequestError from '@/components/RequestError.vue'
import TokenIssueDialog from '@/components/TokenIssueDialog.vue'
import { usePermission } from '@/composables/usePermission'
import { useAuthStore } from '@/stores/auth'
import type { IssueTokenPayload, TokenSummary } from '@/types/models'
import {
  credentialLifecycleOptions,
  credentialNotices,
  credentialStatus,
  matchesCredentialLifecycle,
  type CredentialLifecycleFilter,
} from '@/utils/credentials'
import { displayError, formatDateTime } from '@/utils/format'

const auth = useAuthStore()
const { can } = usePermission()
const tokens = ref<TokenSummary[]>([])
const loading = ref(false)
const issuing = ref(false)
const errorMessage = ref('')
const issueError = ref('')
const issueOpen = ref(false)
const secretOpen = ref(false)
const rawToken = ref('')
const keyword = ref('')
const credentialFilter = ref<CredentialLifecycleFilter>('')

const scopeOptions = computed(() => [...new Set(auth.currentUser?.permissions || [])].sort())
const filteredTokens = computed(() => {
  const search = keyword.value.toLowerCase()
  return tokens.value.filter((token) => {
    const matchesSearch = !search || `${token.name} ${token.tokenHint}`.toLowerCase().includes(search)
    return matchesSearch && matchesCredentialLifecycle(token, credentialFilter.value)
  })
})

function formatScopes(scopes: string[]): string {
  return scopes?.length ? scopes.join(', ') : '—'
}

async function loadTokens(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    tokens.value = await personalTokensApi.list()
  } catch (error: unknown) {
    tokens.value = []
    errorMessage.value = displayError(error)
  } finally {
    loading.value = false
  }
}

function openIssue(): void {
  issueError.value = ''
  issueOpen.value = true
}

async function issueToken(payload: IssueTokenPayload): Promise<void> {
  issuing.value = true
  issueError.value = ''
  try {
    const issued = await personalTokensApi.issue(payload)
    if (!issued.token) throw new Error('服务端未返回一次性令牌明文')
    issueOpen.value = false
    rawToken.value = issued.token
    secretOpen.value = true
    void loadTokens()
  } catch (error: unknown) {
    issueError.value = displayError(error)
  } finally {
    issuing.value = false
  }
}

async function confirmRevoke(token: TokenSummary): Promise<void> {
  try {
    await ElMessageBox.confirm(
      `确定吊销“${token.name}”吗？吊销后使用该令牌的 Agent 将立即无法访问。`,
      '吊销个人访问令牌',
      { type: 'warning', confirmButtonText: '确认吊销' },
    )
    await personalTokensApi.revoke(token.id)
    ElMessage.success('个人访问令牌已吊销')
    await loadTokens()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    errorMessage.value = displayError(error)
  }
}

function clearSecret(): void {
  rawToken.value = ''
}

onMounted(loadTokens)
</script>

<style scoped>
.security-notice {
  margin-bottom: 20px;
}

.lifecycle-filter {
  width: 172px;
}
</style>

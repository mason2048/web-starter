<template>
  <el-dialog
    :model-value="modelValue"
    title="Trace 调用链"
    width="min(760px, 94vw)"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <RequestError :message="errorMessage" />
    <el-descriptions v-if="trace" :column="1" border size="small">
      <el-descriptions-item label="Trace ID"><span class="mono">{{ trace.traceId }}</span></el-descriptions-item>
      <el-descriptions-item label="记录数">{{ entries.length }}{{ trace.truncated ? '（已截断）' : '' }}</el-descriptions-item>
      <el-descriptions-item label="关联类型">
        <span data-testid="trace-login-count">登录 {{ trace.loginLogs.length }}</span>
        <span class="type-count" data-testid="trace-operation-count">操作 {{ trace.operationLogs.length }}</span>
        <span class="type-count" data-testid="trace-mcp-count">MCP {{ trace.mcpCalls.length }}</span>
      </el-descriptions-item>
    </el-descriptions>
    <el-empty v-if="!loading && trace && entries.length === 0" description="该 Trace 暂无关联审计记录" />
    <el-timeline v-else-if="trace" class="trace-timeline">
      <el-timeline-item
        v-for="entry in entries"
        :key="entry.key"
        :data-testid="`trace-entry-${entry.kindCode}-${entry.id}`"
        :timestamp="formatDateTime(entry.createdAt)"
        placement="top"
      >
        <div class="entry-title">{{ entry.kind }} · {{ entry.action }}</div>
        <div class="entry-detail">{{ entry.detail }}</div>
        <el-tag size="small" :type="resultType(entry.result)">{{ resultLabel(entry.result) }}</el-tag>
      </el-timeline-item>
    </el-timeline>
    <el-skeleton v-if="loading" :rows="4" animated />
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { logsApi } from '@/api/admin'
import RequestError from '@/components/RequestError.vue'
import type { McpCallLog, OperationLog, TraceAudit } from '@/types/models'
import { displayError, formatDateTime } from '@/utils/format'

const props = defineProps<{ modelValue: boolean; traceId: string }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
const loading = ref(false)
const errorMessage = ref('')
const trace = ref<TraceAudit | null>(null)
let requestSequence = 0

type Entry = {
  key: string
  id: string
  kindCode: 'login' | 'operation' | 'mcp'
  kind: string
  action: string
  detail: string
  result?: string
  createdAt?: string
}
const entries = computed<Entry[]>(() => {
  if (!trace.value) return []
  const login: Entry[] = trace.value.loginLogs.map((item) => ({
    key: `login-${item.id}`,
    id: item.id,
    kindCode: 'login',
    kind: '登录',
    action: item.username || '未知用户',
    detail: `来源 ${item.ipAddress || '—'}`,
    result: item.result,
    createdAt: item.createdAt,
  }))
  const operation: Entry[] = trace.value.operationLogs.map((item: OperationLog) => ({
    key: `operation-${item.id}`,
    id: item.id,
    kindCode: 'operation',
    kind: '操作',
    action: `${item.module || '系统'} · ${item.action || '—'}`,
    detail: `${item.actorName || '未知主体'} · 资源 ${item.resourceType || '—'} ${item.resourceId || ''}`.trim(),
    result: item.result,
    createdAt: item.createdAt,
  }))
  const mcp: Entry[] = trace.value.mcpCalls.map((item: McpCallLog) => ({
    key: `mcp-${item.id}`,
    id: item.id,
    kindCode: 'mcp',
    kind: 'MCP',
    action: item.toolName || '—',
    // Credential record identifiers are intentionally not rendered in this
    // operator view. Client IDs are public identifiers; bearer material and
    // request/response payloads are never part of the Trace DTO.
    detail: `${item.actorName || '未知主体'} · ${item.clientId ? `客户端 ${item.clientId}` : '凭据已脱敏'}`,
    result: item.result,
    createdAt: item.createdAt,
  }))
  return [...login, ...operation, ...mcp].sort((a, b) => {
    const byTime = String(a.createdAt || '').localeCompare(String(b.createdAt || ''))
    return byTime || a.key.localeCompare(b.key)
  })
})

function resultLabel(result?: string): string {
  if (result === 'SUCCESS') return '成功'
  if (result === 'FAILURE' || result === 'FAILED') return '失败'
  return result || '未知'
}

function resultType(result?: string): 'success' | 'danger' | 'info' {
  if (result === 'SUCCESS') return 'success'
  if (result === 'FAILURE' || result === 'FAILED') return 'danger'
  return 'info'
}

watch(() => [props.modelValue, props.traceId] as const, ([open, traceId]) => {
  const sequence = ++requestSequence
  if (!open || !traceId) {
    loading.value = false
    return
  }
  loading.value = true
  errorMessage.value = ''
  trace.value = null
  void logsApi.trace(traceId).then((data) => {
    if (sequence !== requestSequence) return
    if (data.traceId !== traceId) throw new Error('Trace response does not match the requested identifier')
    trace.value = data
  }).catch((error: unknown) => {
    if (sequence === requestSequence) errorMessage.value = displayError(error)
  }).finally(() => {
    if (sequence === requestSequence) loading.value = false
  })
}, { immediate: true })
</script>

<style scoped>
.trace-timeline { margin: 18px 4px 0; max-height: 48vh; overflow: auto; }
.type-count { margin-left: 14px; }
.entry-title { font-weight: 600; color: var(--ws-text); }
.entry-detail { margin: 4px 0 8px; color: var(--ws-text-secondary); }
</style>

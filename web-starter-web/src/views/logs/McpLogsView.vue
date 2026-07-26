<template>
  <div class="page-content">
    <PageHeader title="MCP 调用日志" description="审计内外网 Agent 的工具调用、身份、耗时与 Trace ID" />
    <RequestError :message="errorMessage" />
    <div class="filter-row">
      <el-input v-model.trim="query.keyword" class="filter-input" placeholder="搜索调用者" clearable :prefix-icon="Search" @keyup.enter="search" @clear="search" />
      <el-input v-model.trim="query.toolName" style="width: 210px" placeholder="搜索工具名称" clearable @keyup.enter="search" @clear="search" />
      <el-input v-model.trim="query.traceId" class="filter-input" placeholder="Trace ID" clearable @keyup.enter="search" @clear="search" />
      <el-date-picker v-model="query.occurredRange" type="datetimerange" value-format="YYYY-MM-DDTHH:mm:ss" range-separator="至" start-placeholder="开始时间" end-placeholder="结束时间" @change="search" />
      <el-select v-model="query.success" clearable placeholder="全部结果" aria-label="调用结果" style="width: 150px" @change="search"><el-option label="成功" :value="true" /><el-option label="失败" :value="false" /></el-select>
      <el-button :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
    </div>
    <div class="table-panel">
      <el-table v-loading="loading" :data="records" row-key="id" empty-text="暂无 MCP 调用日志">
        <el-table-column prop="actorName" label="调用者" min-width="130"><template #default="{ row }">{{ row.actorName || '—' }}</template></el-table-column>
        <el-table-column prop="actorType" label="身份类型" min-width="105"><template #default="{ row }"><el-tag size="small" effect="plain">{{ callerTypeLabel(row.actorType) }}</el-tag></template></el-table-column>
        <el-table-column prop="toolName" label="工具" min-width="160"><template #default="{ row }"><span class="mono">{{ row.toolName || '—' }}</span></template></el-table-column>
        <el-table-column label="结果" width="82"><template #default="{ row }"><el-tag :type="row.result === 'SUCCESS' ? 'success' : 'danger'" size="small">{{ row.result === 'SUCCESS' ? '成功' : '失败' }}</el-tag></template></el-table-column>
        <el-table-column label="幂等" width="92"><template #default="{ row }"><el-tag v-if="row.replayed" type="warning" size="small">已重放</el-tag><span v-else-if="row.idempotencyKeyHash" class="muted">首次</span><span v-else>—</span></template></el-table-column>
        <el-table-column label="耗时" width="90"><template #default="{ row }">{{ row.durationMs ?? '—' }}<span v-if="row.durationMs !== undefined"> ms</span></template></el-table-column>
        <el-table-column prop="ipAddress" label="来源 IP" min-width="135"><template #default="{ row }"><span class="mono">{{ row.ipAddress || '—' }}</span></template></el-table-column>
        <el-table-column prop="traceId" label="Trace ID" min-width="170" show-overflow-tooltip><template #default="{ row }"><el-button v-if="row.traceId" link type="primary" @click="openTrace(row.traceId)">{{ row.traceId }}</el-button><span v-else>—</span></template></el-table-column>
        <el-table-column label="发生时间" min-width="175"><template #default="{ row }">{{ formatDateTime(row.createdAt) }}</template></el-table-column>
      </el-table>
    </div>
    <div class="pagination-row"><span>共 {{ total }} 条</span><el-pagination v-model:current-page="query.page" v-model:page-size="query.size" background layout="sizes, prev, pager, next" :page-sizes="[10, 20, 50]" :total="total" @current-change="load" @size-change="resize" /></div>
    <TraceAuditDialog v-model="traceOpen" :trace-id="selectedTrace" />
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { Refresh, Search } from '@element-plus/icons-vue'
import { logsApi } from '@/api/admin'
import PageHeader from '@/components/PageHeader.vue'
import RequestError from '@/components/RequestError.vue'
import TraceAuditDialog from '@/components/TraceAuditDialog.vue'
import type { McpCallLog } from '@/types/models'
import { displayError, formatDateTime } from '@/utils/format'

const records = ref<McpCallLog[]>([])
const total = ref(0)
const loading = ref(false)
const errorMessage = ref('')
const query = reactive<{ page: number; size: number; keyword: string; toolName: string; traceId: string; occurredRange: string[]; success: boolean | '' }>({ page: 1, size: 10, keyword: '', toolName: '', traceId: '', occurredRange: [], success: '' })
const traceOpen = ref(false)
const selectedTrace = ref('')
function callerTypeLabel(value?: string): string { return ({ USER: '个人', SERVICE_ACCOUNT: '服务账号', OAUTH_CLIENT: 'OAuth Client' } as Record<string, string>)[value || ''] || value || '未知' }
async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const data = await logsApi.mcp({
      page: query.page,
      size: query.size,
      actorName: query.keyword || undefined,
      toolName: query.toolName || undefined,
      traceId: query.traceId || undefined,
      occurredFrom: query.occurredRange[0] || undefined,
      occurredTo: query.occurredRange[1] || undefined,
      result: query.success === '' ? undefined : query.success ? 'SUCCESS' : 'FAILED',
    })
    records.value = data.records
    total.value = data.total
  } catch (error: unknown) { records.value = []; total.value = 0; errorMessage.value = displayError(error) }
  finally { loading.value = false }
}
function openTrace(traceId: string): void { selectedTrace.value = traceId; traceOpen.value = true }
function search(): void { query.page = 1; void load() }
function resize(): void { query.page = 1; void load() }
onMounted(load)
</script>

<template>
  <div class="page-content">
    <PageHeader title="操作审计" description="记录关键管理操作、执行结果、耗时与 Trace ID" />
    <RequestError :message="errorMessage" />
    <div class="filter-row">
      <el-input v-model.trim="query.keyword" class="filter-input" placeholder="搜索操作人" clearable :prefix-icon="Search" @keyup.enter="search" @clear="search" />
      <el-select v-model="query.success" clearable placeholder="全部结果" style="width: 150px" @change="search"><el-option label="成功" :value="true" /><el-option label="失败" :value="false" /></el-select>
      <el-button :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
    </div>
    <div class="table-panel">
      <el-table v-loading="loading" :data="records" row-key="id" empty-text="暂无操作审计日志">
        <el-table-column prop="actorName" label="操作人" min-width="115"><template #default="{ row }">{{ row.actorName || '—' }}</template></el-table-column>
        <el-table-column prop="module" label="模块" min-width="110"><template #default="{ row }">{{ row.module || '—' }}</template></el-table-column>
        <el-table-column prop="action" label="操作" min-width="130"><template #default="{ row }">{{ row.action || '—' }}</template></el-table-column>
        <el-table-column label="请求" min-width="220" show-overflow-tooltip><template #default="{ row }"><span class="mono">{{ [row.requestMethod, row.requestPath].filter(Boolean).join(' ') || '—' }}</span></template></el-table-column>
        <el-table-column label="结果" width="82"><template #default="{ row }"><el-tag :type="row.result === 'SUCCESS' ? 'success' : 'danger'" size="small">{{ row.result === 'SUCCESS' ? '成功' : '失败' }}</el-tag></template></el-table-column>
        <el-table-column label="耗时" width="90"><template #default="{ row }">{{ row.durationMs ?? '—' }}<span v-if="row.durationMs !== undefined"> ms</span></template></el-table-column>
        <el-table-column prop="traceId" label="Trace ID" min-width="165" show-overflow-tooltip><template #default="{ row }"><span class="mono">{{ row.traceId || '—' }}</span></template></el-table-column>
        <el-table-column label="发生时间" min-width="175"><template #default="{ row }">{{ formatDateTime(row.createdAt) }}</template></el-table-column>
      </el-table>
    </div>
    <div class="pagination-row"><span>共 {{ total }} 条</span><el-pagination v-model:current-page="query.page" v-model:page-size="query.size" background layout="sizes, prev, pager, next" :page-sizes="[10, 20, 50]" :total="total" @current-change="load" @size-change="resize" /></div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { Refresh, Search } from '@element-plus/icons-vue'
import { logsApi } from '@/api/admin'
import PageHeader from '@/components/PageHeader.vue'
import RequestError from '@/components/RequestError.vue'
import type { OperationLog } from '@/types/models'
import { displayError, formatDateTime } from '@/utils/format'

const records = ref<OperationLog[]>([])
const total = ref(0)
const loading = ref(false)
const errorMessage = ref('')
const query = reactive<{ page: number; size: number; keyword: string; success: boolean | '' }>({ page: 1, size: 10, keyword: '', success: '' })
async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const data = await logsApi.operation({
      page: query.page,
      size: query.size,
      actorName: query.keyword || undefined,
      result: query.success === '' ? undefined : query.success ? 'SUCCESS' : 'FAILURE',
    })
    records.value = data.records
    total.value = data.total
  } catch (error: unknown) { records.value = []; total.value = 0; errorMessage.value = displayError(error) }
  finally { loading.value = false }
}
function search(): void { query.page = 1; void load() }
function resize(): void { query.page = 1; void load() }
onMounted(load)
</script>

<template>
  <div class="page-content">
    <PageHeader title="系统配置" description="集中维护非敏感运行参数，密钥与密码应通过环境变量注入">
      <template #actions><el-button v-if="can('system:config:manage')" type="primary" :icon="Plus" @click="openCreate">新建配置</el-button></template>
    </PageHeader>
    <el-alert
      class="config-notice"
      type="warning"
      title="请勿在系统配置中保存密码、访问令牌或私钥。敏感配置必须通过 WEB_STARTER_ 环境变量注入。"
      :closable="false"
      show-icon
    />
    <RequestError :message="errorMessage" />

    <div class="filter-row">
      <el-input
        v-model.trim="query.keyword"
        class="filter-input"
        placeholder="搜索配置名称或键"
        clearable
        :prefix-icon="Search"
        @keyup.enter="search"
        @clear="search"
      />
      <el-button :icon="Refresh" :loading="loading" @click="loadConfigs">刷新</el-button>
    </div>

    <div class="table-panel">
      <el-table v-loading="loading" :data="records" row-key="id" empty-text="暂无系统配置">
        <el-table-column prop="configKey" label="配置键" min-width="230">
          <template #default="{ row }"><span class="mono">{{ row.configKey }}</span></template>
        </el-table-column>
        <el-table-column prop="configValue" label="配置值" min-width="230" show-overflow-tooltip>
          <template #default="{ row }"><span>{{ maskSensitive(row.configKey, row.configValue) }}</span></template>
        </el-table-column>
        <el-table-column prop="valueType" label="类型" width="90">
          <template #default="{ row }"><el-tag size="small" effect="plain">{{ row.valueType }}</el-tag></template>
        </el-table-column>
        <el-table-column label="来源" width="90">
          <template #default="{ row }"><el-tag :type="row.builtin ? 'info' : 'primary'" size="small">{{ row.builtin ? '内置' : '自定义' }}</el-tag></template>
        </el-table-column>
        <el-table-column label="操作" width="132" fixed="right">
          <template #default="{ row }">
            <el-button v-if="can('system:config:manage')" link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button v-if="can('system:config:manage')" link type="danger" :disabled="row.builtin" @click="confirmRemove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="pagination-row">
      <span>共 {{ total }} 条</span>
      <el-pagination
        v-model:current-page="query.page"
        v-model:page-size="query.size"
        background
        layout="sizes, prev, pager, next"
        :page-sizes="[10, 20, 50]"
        :total="total"
        @current-change="loadConfigs"
        @size-change="handleSizeChange"
      />
    </div>

    <el-drawer v-model="drawerOpen" :title="editingId === null ? '新建配置' : '编辑配置'" size="430px" :modal="false" destroy-on-close>
      <RequestError :message="drawerError" />
      <el-form ref="formRef" class="drawer-form" :model="form" :rules="rules" label-position="top">
        <el-form-item label="配置键" prop="key">
          <el-input v-model.trim="form.key" maxlength="128" :disabled="editingId !== null" placeholder="例如 system.page-size" />
        </el-form-item>
        <el-form-item label="值类型" prop="type">
          <el-select v-model="form.type">
            <el-option v-for="type in configTypes" :key="type" :label="type" :value="type" />
          </el-select>
        </el-form-item>
        <el-form-item label="配置值" prop="value">
          <el-input
            v-if="form.type === 'JSON'"
            v-model="form.value"
            type="textarea"
            :rows="7"
            placeholder="请输入合法 JSON"
          />
          <el-select v-else-if="form.type === 'BOOLEAN'" v-model="form.value">
            <el-option label="true" value="true" />
            <el-option label="false" value="false" />
          </el-select>
          <el-input v-else v-model="form.value" :type="isSensitiveKey(form.key) ? 'password' : 'text'" show-password />
        </el-form-item>
        <el-form-item label="说明">
          <el-input v-model="form.description" type="textarea" :rows="3" maxlength="200" show-word-limit />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="drawer-footer">
          <el-button @click="drawerOpen = false">取消</el-button>
          <el-button type="primary" :loading="saving" @click="save">保存</el-button>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import { configsApi } from '@/api/admin'
import PageHeader from '@/components/PageHeader.vue'
import RequestError from '@/components/RequestError.vue'
import { usePermission } from '@/composables/usePermission'
import type { ConfigRecord } from '@/types/models'
import { displayError } from '@/utils/format'

type ConfigType = 'STRING' | 'NUMBER' | 'BOOLEAN' | 'JSON'
const { can } = usePermission()
interface ConfigForm {
  key: string
  value: string
  type: ConfigType
  description: string
}

const configTypes: ConfigType[] = ['STRING', 'NUMBER', 'BOOLEAN', 'JSON']
const records = ref<ConfigRecord[]>([])
const total = ref(0)
const loading = ref(false)
const saving = ref(false)
const errorMessage = ref('')
const drawerError = ref('')
const drawerOpen = ref(false)
const editingId = ref<ConfigRecord['id'] | null>(null)
const formRef = ref<FormInstance>()
const query = reactive({ page: 1, size: 10, keyword: '' })
const form = reactive<ConfigForm>({ key: '', value: '', type: 'STRING', description: '' })

const rules: FormRules<ConfigForm> = {
  key: [
    { required: true, message: '请输入配置键', trigger: 'blur' },
    { pattern: /^[a-zA-Z][a-zA-Z0-9._-]{1,127}$/, message: '配置键应以字母开头，仅含字母、数字、点、连字符和下划线', trigger: 'blur' },
  ],
  type: [{ required: true, message: '请选择值类型', trigger: 'change' }],
  value: [
    { required: true, message: '请输入配置值', trigger: 'blur' },
    {
      validator: (_rule, value: string, callback) => {
        try {
          if (form.type === 'NUMBER' && !Number.isFinite(Number(value))) throw new Error('请输入有效数字')
          if (form.type === 'JSON') JSON.parse(value)
          callback()
        } catch (error: unknown) {
          callback(new Error(error instanceof Error ? error.message : '配置值格式错误'))
        }
      },
      trigger: 'blur',
    },
  ],
}

function isSensitiveKey(key: string): boolean {
  return /(password|secret|token|private[-_.]?key)/i.test(key)
}

function maskSensitive(key: string, value: string): string {
  return isSensitiveKey(key) ? '••••••••' : value
}

async function loadConfigs(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const data = await configsApi.list({ page: query.page, size: query.size, keyword: query.keyword || undefined })
    records.value = data.records
    total.value = data.total
  } catch (error: unknown) {
    records.value = []
    total.value = 0
    errorMessage.value = displayError(error)
  } finally {
    loading.value = false
  }
}

function resetForm(): void {
  editingId.value = null
  drawerError.value = ''
  Object.assign(form, { key: '', value: '', type: 'STRING', description: '' })
  formRef.value?.clearValidate()
}

function search(): void {
  query.page = 1
  void loadConfigs()
}

function handleSizeChange(): void {
  query.page = 1
  void loadConfigs()
}

function openCreate(): void {
  resetForm()
  drawerOpen.value = true
}

function openEdit(config: ConfigRecord): void {
  resetForm()
  editingId.value = config.id
  Object.assign(form, {
    key: config.configKey,
    value: config.configValue,
    type: config.valueType as ConfigType,
    description: config.description || '',
  })
  drawerOpen.value = true
}

async function save(): Promise<void> {
  if (!formRef.value || !(await formRef.value.validate().catch(() => false))) return
  saving.value = true
  drawerError.value = ''
  try {
    const payload = {
      configKey: form.key,
      configValue: form.value,
      valueType: form.type,
      description: form.description || undefined,
    }
    if (editingId.value === null) await configsApi.create(payload)
    else await configsApi.update(editingId.value, payload)
    ElMessage.success(editingId.value === null ? '配置创建成功' : '配置更新成功')
    drawerOpen.value = false
    await loadConfigs()
  } catch (error: unknown) {
    drawerError.value = displayError(error)
  } finally {
    saving.value = false
  }
}

async function confirmRemove(config: ConfigRecord): Promise<void> {
  try {
    await ElMessageBox.confirm(`确定删除配置“${config.configKey}”吗？`, '删除配置', { type: 'warning' })
    await configsApi.remove(config.id)
    ElMessage.success('配置已删除')
    await loadConfigs()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    errorMessage.value = displayError(error)
  }
}

onMounted(loadConfigs)
</script>

<style scoped>
.config-notice { margin-bottom: 20px; }
</style>

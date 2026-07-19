<template>
  <el-dialog
    :model-value="modelValue"
    :title="title"
    width="min(570px, 92vw)"
    :close-on-click-modal="false"
    destroy-on-close
    @update:model-value="emit('update:modelValue', $event)"
  >
    <RequestError :message="error" />
    <el-alert
      class="scope-notice"
      type="info"
      title="最终可用权限为所选 Scope 与令牌主体 RBAC 权限的交集。"
      :closable="false"
      show-icon
    />
    <el-form ref="formRef" :model="form" :rules="rules" label-position="top">
      <el-form-item label="令牌名称" prop="name">
        <el-input v-model.trim="form.name" maxlength="100" show-word-limit placeholder="例如：数据同步 Agent" />
      </el-form-item>
      <el-form-item label="权限范围（Scope）" prop="scopes">
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
          <el-option v-for="scope in availableScopes" :key="scope" :label="scope" :value="scope" />
        </el-select>
        <p class="form-help">建议按最小权限原则选择精确的读写权限；输入后按回车添加。</p>
      </el-form-item>
      <el-form-item label="允许的 IP / CIDR（可选）">
        <el-input
          v-model="form.allowedIpText"
          type="textarea"
          :rows="3"
          maxlength="1000"
          placeholder="每行一个，例如 10.0.0.0/8 或 192.168.1.10"
        />
        <p class="form-help">留空表示不限制来源地址；外网 Agent 建议配置固定出口 IP。</p>
      </el-form-item>
      <el-form-item label="有效期（可选）" prop="expiresAt">
        <el-date-picker
          v-model="form.expiresAt"
          type="datetime"
          placeholder="不选择则长期有效，建议设置"
          :disabled-date="disablePastDate"
        />
      </el-form-item>
    </el-form>

    <template #footer>
      <div class="dialog-footer">
        <el-button @click="emit('update:modelValue', false)">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="submit">签发令牌</el-button>
      </div>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import type { FormInstance, FormRules } from 'element-plus'
import RequestError from './RequestError.vue'
import type { IssueTokenPayload } from '@/types/models'

interface IssueTokenForm {
  name: string
  scopes: string[]
  allowedIpText: string
  expiresAt: Date | null
}

const props = withDefaults(
  defineProps<{
    modelValue: boolean
    title?: string
    submitting?: boolean
    error?: string
    scopeOptions?: string[]
  }>(),
  {
    title: '签发令牌',
    submitting: false,
    error: '',
    scopeOptions: () => [],
  },
)

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  submit: [payload: IssueTokenPayload]
}>()

const formRef = ref<FormInstance>()
const form = reactive<IssueTokenForm>({ name: '', scopes: [], allowedIpText: '', expiresAt: null })

const availableScopes = computed(() => [...new Set(props.scopeOptions)].sort())

const rules: FormRules<IssueTokenForm> = {
  name: [{ required: true, message: '请输入令牌名称', trigger: 'blur' }],
  scopes: [{ type: 'array', required: true, min: 1, message: '请至少选择一个 Scope', trigger: 'change' }],
  expiresAt: [
    {
      validator: (_rule, value: Date | null, callback) => {
        if (!value || value.getTime() > Date.now()) callback()
        else callback(new Error('有效期必须晚于当前时间'))
      },
      trigger: 'change',
    },
  ],
}

watch(
  () => props.modelValue,
  (open) => {
    if (!open) return
    Object.assign(form, { name: '', scopes: [], allowedIpText: '', expiresAt: null })
    formRef.value?.clearValidate()
  },
)

function disablePastDate(date: Date): boolean {
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  return date.getTime() < today.getTime()
}

function parseIpCidrs(value: string): string[] {
  return [...new Set(value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean))]
}

async function submit(): Promise<void> {
  if (!formRef.value || !(await formRef.value.validate().catch(() => false))) return
  emit('submit', {
    name: form.name,
    scopes: [...new Set(form.scopes.map((scope) => scope.trim()).filter(Boolean))],
    allowedIpCidrs: parseIpCidrs(form.allowedIpText),
    expiresAt: form.expiresAt?.toISOString(),
  })
}
</script>

<style scoped>
.scope-notice {
  margin-bottom: 20px;
}

.form-help {
  margin: 7px 0 0;
  color: var(--ws-text-secondary);
  font-size: 12px;
  line-height: 1.55;
}

.dialog-footer {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
}

:deep(.el-select),
:deep(.el-date-editor) {
  width: 100%;
}
</style>

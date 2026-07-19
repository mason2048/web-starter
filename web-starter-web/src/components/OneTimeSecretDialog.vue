<template>
  <el-dialog
    :model-value="modelValue"
    width="min(620px, 92vw)"
    :show-close="false"
    :close-on-click-modal="false"
    :close-on-press-escape="false"
    :destroy-on-close="true"
    align-center
  >
    <template #header>
      <div class="secret-heading">
        <span class="secret-icon"><el-icon><Lock /></el-icon></span>
        <div>
          <h2>{{ title }}</h2>
          <p>这是系统唯一一次展示完整明文，请立即复制并存入安全的密钥管理工具。</p>
        </div>
      </div>
    </template>

    <el-alert
      type="warning"
      title="关闭后无法再次查看；如有遗失，请吊销或轮换后重新签发。"
      :closable="false"
      show-icon
    />

    <div class="secret-field">
      <span>{{ label }}</span>
      <code data-testid="one-time-secret">{{ visibleSecret }}</code>
    </div>

    <el-checkbox v-model="acknowledged" data-testid="secret-acknowledgement">
      我确认已将明文安全保存，并理解关闭后无法找回
    </el-checkbox>

    <template #footer>
      <div class="secret-actions">
        <el-button :icon="CopyDocument" :disabled="!visibleSecret" data-testid="secret-copy" @click="copySecret">
          复制明文
        </el-button>
        <el-button
          type="primary"
          :disabled="!acknowledged"
          data-testid="secret-confirm"
          @click="consume"
        >
          已安全保存，关闭
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { CopyDocument, Lock } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'

const props = withDefaults(
  defineProps<{
    modelValue: boolean
    secret: string
    title?: string
    label?: string
  }>(),
  {
    title: '凭据签发成功',
    label: '一次性明文',
  },
)

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  consumed: []
}>()

const visibleSecret = ref('')
const acknowledged = ref(false)

watch(
  () => [props.modelValue, props.secret] as const,
  ([open, secret]) => {
    if (open) {
      visibleSecret.value = secret
      acknowledged.value = false
    } else {
      visibleSecret.value = ''
    }
  },
  { immediate: true },
)

async function writeClipboard(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value)
    return
  }

  const textarea = document.createElement('textarea')
  textarea.value = value
  textarea.setAttribute('readonly', '')
  textarea.style.position = 'fixed'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.select()
  const copied = document.execCommand('copy')
  textarea.remove()
  if (!copied) throw new Error('浏览器未授权复制')
}

async function copySecret(): Promise<void> {
  if (!visibleSecret.value) return
  try {
    await writeClipboard(visibleSecret.value)
    ElMessage.success('明文已复制，请立即安全保存')
  } catch {
    ElMessage.error('复制失败，请手动选择明文复制')
  }
}

function consume(): void {
  if (!acknowledged.value) return
  visibleSecret.value = ''
  acknowledged.value = false
  emit('consumed')
  emit('update:modelValue', false)
}
</script>

<style scoped>
.secret-heading {
  display: flex;
  gap: 14px;
  align-items: flex-start;
}

.secret-heading h2 {
  margin: 0 0 5px;
  color: var(--ws-text);
  font-size: 19px;
}

.secret-heading p {
  margin: 0;
  color: var(--ws-text-secondary);
  font-size: 13px;
  line-height: 1.55;
}

.secret-icon {
  display: inline-flex;
  width: 42px;
  height: 42px;
  flex: 0 0 42px;
  color: #007e78;
  background: var(--ws-teal-100);
  border-radius: 50%;
  align-items: center;
  justify-content: center;
}

.secret-field {
  display: grid;
  gap: 9px;
  padding: 20px 0;
}

.secret-field > span {
  color: #465369;
  font-size: 13px;
  font-weight: 600;
}

.secret-field code {
  display: block;
  padding: 16px;
  overflow-wrap: anywhere;
  color: #e8f7f6;
  background: var(--ws-navy-950);
  border: 1px solid #17425f;
  border-radius: 6px;
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 13px;
  line-height: 1.65;
  user-select: all;
}

.secret-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
}

@media (max-width: 560px) {
  .secret-actions {
    flex-direction: column-reverse;
  }

  .secret-actions .el-button {
    width: 100%;
    margin-left: 0;
  }
}
</style>

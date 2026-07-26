<template>
  <el-dialog
    :model-value="modelValue"
    title="搜索功能"
    width="min(560px, 92vw)"
    append-to-body
    @update:model-value="$emit('update:modelValue', $event)"
    @opened="focusInput"
  >
    <el-input
      ref="inputRef"
      v-model.trim="keyword"
      clearable
      :prefix-icon="Search"
      placeholder="输入页面名称、路径或权限"
      aria-label="搜索可访问页面"
    />
    <div class="command-results" role="listbox" aria-label="可访问页面">
      <button
        v-for="item in matches"
        :key="item.path"
        type="button"
        class="command-item"
        role="option"
        @click="navigate(item.path)"
      >
        <el-icon><component :is="item.icon" /></el-icon>
        <span><strong>{{ item.label }}</strong><small>{{ item.path }}</small></span>
      </button>
      <el-empty v-if="matches.length === 0" description="没有匹配的可访问页面" :image-size="72" />
    </div>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, nextTick, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Search } from '@element-plus/icons-vue'
import type { InputInstance } from 'element-plus'
import { commandNavigation } from '@/navigation/manifest'
import { useAuthStore } from '@/stores/auth'
import { hasAccess } from '@/utils/access'

defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
const router = useRouter()
const auth = useAuthStore()
const keyword = ref('')
const inputRef = ref<InputInstance>()

const matches = computed(() => {
  const normalized = keyword.value.toLocaleLowerCase()
  return commandNavigation.filter((item) => {
    if (!hasAccess(auth.currentUser, { permission: item.permission, menuId: item.menuId })) return false
    if (!normalized) return true
    return `${item.label} ${item.path} ${item.permission ?? ''}`.toLocaleLowerCase().includes(normalized)
  })
})

function focusInput(): void {
  void nextTick(() => inputRef.value?.focus())
}

async function navigate(path: string): Promise<void> {
  emit('update:modelValue', false)
  keyword.value = ''
  await router.push(path)
}
</script>

<style scoped>
.command-results {
  display: grid;
  gap: 6px;
  max-height: min(56vh, 480px);
  padding-top: 14px;
  overflow-y: auto;
}

.command-item {
  display: flex;
  gap: 12px;
  width: 100%;
  padding: 12px 14px;
  color: var(--ws-text);
  text-align: left;
  cursor: pointer;
  background: transparent;
  border: 1px solid transparent;
  border-radius: 7px;
  align-items: center;
}

.command-item:hover,
.command-item:focus-visible {
  background: var(--ws-teal-100);
  border-color: #a7deda;
}

.command-item > .el-icon {
  color: var(--ws-teal-600);
  font-size: 20px;
}

.command-item span {
  display: grid;
  gap: 3px;
}

.command-item small {
  color: var(--ws-text-secondary);
  font-family: "SFMono-Regular", Consolas, monospace;
}
</style>

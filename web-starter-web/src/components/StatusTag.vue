<template>
  <el-tag :type="tagType" effect="light" size="small">{{ label }}</el-tag>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ value?: string | boolean }>()

const label = computed(() => {
  if (props.value === 'SUCCESS') return '成功'
  if (props.value === 'FAILED' || props.value === 'FAILURE') return '失败'
  if (props.value === true || props.value === 'ENABLED') return '启用'
  if (props.value === false || props.value === 'DISABLED') return '停用'
  const labels: Record<string, string> = {
    PLANNING: '规划中',
    IN_PROGRESS: '进行中',
    ARCHIVED: '已归档',
  }
  return labels[String(props.value)] ?? String(props.value || '未知')
})

const tagType = computed<'success' | 'info' | 'warning' | 'danger' | 'primary'>(() => {
  if (props.value === true || props.value === 'ENABLED' || props.value === 'SUCCESS') return 'success'
  if (props.value === false || props.value === 'DISABLED' || props.value === 'FAILED') return 'danger'
  if (props.value === 'ARCHIVED') return 'success'
  if (props.value === 'PLANNING') return 'warning'
  return 'primary'
})
</script>

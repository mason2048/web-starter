<template>
  <el-alert
    v-if="presentation.title"
    class="request-error"
    type="error"
    :title="presentation.title"
    :closable="false"
    show-icon
  >
    <template v-if="presentation.message || presentation.traceId" #default>
      <span v-if="presentation.message" class="guidance">{{ presentation.message }}</span>
      <span v-if="presentation.traceId" class="trace">Trace ID：{{ presentation.traceId }}</span>
    </template>
  </el-alert>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { RequestFailure } from '@/api/requestFailure'

const props = defineProps<{ message?: string; traceId?: string; failure?: RequestFailure | null }>()

const presentation = computed(() => ({
  title: props.failure?.title ?? props.message ?? '',
  message: props.failure?.message ?? '',
  traceId: props.failure?.traceId ?? props.traceId,
}))
</script>

<style scoped>
.request-error {
  margin-bottom: 18px;
}

.trace {
  display: block;
  margin-top: 5px;
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
}

.guidance {
  display: block;
}
</style>

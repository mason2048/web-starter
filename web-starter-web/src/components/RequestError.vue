<template>
  <el-alert
    v-if="message"
    class="request-error"
    type="error"
    :title="message"
    :closable="false"
    show-icon
  >
    <template v-if="traceId" #default>
      <span class="trace">Trace ID：{{ traceId }}</span>
    </template>
  </el-alert>
</template>

<script setup lang="ts">
defineProps<{ message?: string; traceId?: string }>()
</script>

<style scoped>
.request-error {
  margin-bottom: 18px;
}

.trace {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
}
</style>

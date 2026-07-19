<template>
  <div class="brand" :class="{ compact }">
    <img src="/src/assets/logo.svg" alt="" class="brand-logo" />
    <span v-if="!compact" class="brand-name">启程 Web Starter</span>
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ compact?: boolean }>(), { compact: false })
</script>

<style scoped>
.brand {
  display: flex;
  gap: 10px;
  align-items: center;
  min-width: 0;
}

.brand-logo {
  width: 40px;
  height: 40px;
  flex: 0 0 auto;
}

.brand-name {
  overflow: hidden;
  color: #fff;
  font-size: 18px;
  font-weight: 700;
  letter-spacing: -0.2px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.compact .brand-logo {
  width: 34px;
  height: 34px;
}
</style>

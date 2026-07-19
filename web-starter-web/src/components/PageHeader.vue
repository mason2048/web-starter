<template>
  <div class="page-header">
    <div>
      <h1>{{ title }}</h1>
      <p v-if="description">{{ description }}</p>
    </div>
    <div v-if="$slots.actions" class="page-actions">
      <slot name="actions" />
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{ title: string; description?: string }>()
</script>

<style scoped>
.page-header {
  display: flex;
  gap: 24px;
  align-items: flex-start;
  justify-content: space-between;
  padding-bottom: 20px;
  margin-bottom: 24px;
  border-bottom: 1px solid var(--ws-border);
}

h1 {
  margin: 0 0 7px;
  color: #11243d;
  font-size: 30px;
  line-height: 1.25;
  letter-spacing: -0.6px;
}

p {
  margin: 0;
  color: var(--ws-text-secondary);
  font-size: 14px;
  line-height: 1.6;
}

.page-actions {
  flex: 0 0 auto;
}

@media (max-width: 640px) {
  .page-header {
    align-items: center;
  }

  h1 {
    font-size: 24px;
  }

  p {
    font-size: 13px;
  }
}
</style>

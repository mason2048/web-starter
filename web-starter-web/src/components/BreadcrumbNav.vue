<template>
  <nav class="breadcrumbs" aria-label="面包屑">
    <RouterLink to="/overview">启程 Web Starter</RouterLink>
    <span aria-hidden="true">/</span>
    <span aria-current="page">{{ current?.label ?? String(route.meta.title || '当前页面') }}</span>
  </nav>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { findNavigationItem } from '@/navigation/manifest'

const route = useRoute()
const current = computed(() => findNavigationItem(route.path))
</script>

<style scoped>
.breadcrumbs {
  display: flex;
  gap: 8px;
  min-width: 0;
  color: var(--ws-text-secondary);
  font-size: 13px;
  align-items: center;
}

.breadcrumbs a:hover,
.breadcrumbs a:focus-visible {
  color: var(--ws-teal-600);
}

.breadcrumbs [aria-current='page'] {
  overflow: hidden;
  color: var(--ws-text);
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>

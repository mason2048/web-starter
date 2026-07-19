<template>
  <RouterView />
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted } from 'vue'
import { RouterView, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const auth = useAuthStore()

function handleUnauthorized(): void {
  auth.clearSession()
  if (router.currentRoute.value.name !== 'login') {
    void router.replace({ name: 'login', query: { redirect: router.currentRoute.value.fullPath } })
  }
}

onMounted(() => window.addEventListener('auth:unauthorized', handleUnauthorized))
onBeforeUnmount(() => window.removeEventListener('auth:unauthorized', handleUnauthorized))
</script>

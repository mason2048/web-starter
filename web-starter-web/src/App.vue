<template>
  <div class="app-root" data-web-starter-mounted>
    <RouterView />
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted } from 'vue'
import { RouterView, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const auth = useAuthStore()

function browserIsAtLogin(): boolean {
  const loginHref = router.resolve({ name: 'login' }).href
  const loginPath = new URL(loginHref, window.location.origin).pathname
  return window.location.pathname === loginPath
}

function handleUnauthorized(): void {
  auth.clearSession()
  // During the first /auth/me probe, Vue Router can still expose its start
  // location even though the browser has already reached /login. Preserve the
  // server-provided OAuth return target instead of replacing it with "/".
  if (router.currentRoute.value.name !== 'login' && !browserIsAtLogin()) {
    void router.replace({ name: 'login', query: { redirect: router.currentRoute.value.fullPath } })
  }
}

onMounted(() => window.addEventListener('auth:unauthorized', handleUnauthorized))
onBeforeUnmount(() => window.removeEventListener('auth:unauthorized', handleUnauthorized))
</script>

<style scoped>
.app-root {
  height: 100%;
}
</style>

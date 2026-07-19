import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import * as authApi from '@/api/auth'
import type { CurrentUser } from '@/types/models'

const REMEMBERED_USERNAME_KEY = 'web-starter.remembered-username'

export const useAuthStore = defineStore('auth', () => {
  const currentUser = ref<CurrentUser | null>(null)
  const initialized = ref(false)
  const loading = ref(false)

  const isAuthenticated = computed(() => currentUser.value !== null)
  const displayName = computed(
    () => currentUser.value?.displayName || currentUser.value?.username || '管理员',
  )

  async function initialize(force = false): Promise<boolean> {
    if (initialized.value && !force) return isAuthenticated.value
    try {
      currentUser.value = await authApi.getCurrentUser()
    } catch {
      currentUser.value = null
    } finally {
      initialized.value = true
    }
    return isAuthenticated.value
  }

  async function signIn(username: string, password: string, rememberUsername: boolean): Promise<void> {
    loading.value = true
    try {
      const user = await authApi.login({ username, password })
      currentUser.value = user ?? (await authApi.getCurrentUser())
      initialized.value = true
      if (rememberUsername) localStorage.setItem(REMEMBERED_USERNAME_KEY, username)
      else localStorage.removeItem(REMEMBERED_USERNAME_KEY)
    } finally {
      loading.value = false
    }
  }

  async function signOut(): Promise<void> {
    loading.value = true
    try {
      await authApi.logout()
    } finally {
      currentUser.value = null
      initialized.value = true
      loading.value = false
    }
  }

  function clearSession(): void {
    currentUser.value = null
    initialized.value = true
  }

  function getRememberedUsername(): string {
    return localStorage.getItem(REMEMBERED_USERNAME_KEY) ?? ''
  }

  return {
    currentUser,
    initialized,
    loading,
    isAuthenticated,
    displayName,
    initialize,
    signIn,
    signOut,
    clearSession,
    getRememberedUsername,
  }
})

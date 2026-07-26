<template>
  <div class="app-shell">
    <aside class="desktop-sidebar">
      <SidebarNav />
    </aside>

    <div class="app-column">
      <header class="topbar">
        <div class="mobile-brand">
          <button class="menu-trigger" type="button" aria-label="打开主导航" @click="mobileNavOpen = true">
            <el-icon><Menu /></el-icon>
          </button>
          <BrandLogo compact />
          <span>启程 Web Starter</span>
        </div>
        <div class="topbar-spacer" />
        <el-tooltip content="搜索功能（⌘/Ctrl + K）" placement="bottom">
          <button class="topbar-icon search-trigger" type="button" aria-label="搜索功能" @click="commandOpen = true">
            <el-icon><Search /></el-icon>
          </button>
        </el-tooltip>
        <el-tooltip content="暂无新通知" placement="bottom">
          <button class="topbar-icon" type="button" aria-label="通知">
            <el-icon><Bell /></el-icon>
          </button>
        </el-tooltip>
        <span class="topbar-divider" />
        <el-dropdown trigger="click" @command="handleCommand">
          <button class="user-menu" type="button">
            <span class="avatar"><el-icon><User /></el-icon></span>
            <span class="user-name">{{ auth.displayName }}</span>
            <el-icon class="chevron"><ArrowDown /></el-icon>
          </button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item disabled>{{ auth.currentUser?.username }}</el-dropdown-item>
              <el-dropdown-item command="account-security">个人安全</el-dropdown-item>
              <el-dropdown-item divided command="logout">退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </header>

      <div class="contextbar">
        <BreadcrumbNav />
      </div>

      <main class="main-content">
        <RouterView v-slot="{ Component }">
          <Transition name="page" mode="out-in">
            <component :is="Component" />
          </Transition>
        </RouterView>
      </main>
    </div>

    <el-drawer v-model="mobileNavOpen" direction="ltr" :with-header="false" size="248px" class="nav-drawer">
      <SidebarNav @navigate="mobileNavOpen = false" />
    </el-drawer>
    <CommandSearch v-model="commandOpen" />
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter, RouterView } from 'vue-router'
import { ArrowDown, Bell, Menu, Search, User } from '@element-plus/icons-vue'
import { ElMessageBox } from 'element-plus'
import BrandLogo from '@/components/BrandLogo.vue'
import BreadcrumbNav from '@/components/BreadcrumbNav.vue'
import CommandSearch from '@/components/CommandSearch.vue'
import SidebarNav from '@/components/SidebarNav.vue'
import { useAuthStore } from '@/stores/auth'
import { displayError } from '@/utils/format'

const auth = useAuthStore()
const router = useRouter()
const mobileNavOpen = ref(false)
const commandOpen = ref(false)

function handleGlobalShortcut(event: KeyboardEvent): void {
  if ((event.metaKey || event.ctrlKey) && event.key.toLocaleLowerCase() === 'k') {
    event.preventDefault()
    commandOpen.value = true
  }
}

onMounted(() => window.addEventListener('keydown', handleGlobalShortcut))
onBeforeUnmount(() => window.removeEventListener('keydown', handleGlobalShortcut))

async function handleCommand(command: string): Promise<void> {
  if (command === 'account-security') {
    await router.push({ name: 'account-security' })
    return
  }
  if (command !== 'logout') return
  try {
    await auth.signOut()
    await router.replace({ name: 'login' })
  } catch (error: unknown) {
    await ElMessageBox.alert(displayError(error), '退出失败', { type: 'error' })
  }
}
</script>

<style scoped>
.app-shell {
  display: flex;
  min-height: 100%;
  background: #fff;
}

.desktop-sidebar {
  position: fixed;
  z-index: 20;
  inset: 0 auto 0 0;
  width: 232px;
}

.app-column {
  width: calc(100% - 232px);
  min-width: 0;
  min-height: 100vh;
  margin-left: 232px;
  background: #fff;
}

.topbar {
  position: sticky;
  z-index: 15;
  top: 0;
  display: flex;
  height: 70px;
  padding: 0 28px;
  align-items: center;
  background: rgb(255 255 255 / 96%);
  border-bottom: 1px solid var(--ws-border);
  backdrop-filter: blur(12px);
}

.topbar-spacer {
  flex: 1;
}

.topbar-icon,
.menu-trigger,
.user-menu {
  display: inline-flex;
  padding: 0;
  color: #14253c;
  cursor: pointer;
  background: transparent;
  border: 0;
  align-items: center;
  justify-content: center;
}

.topbar-icon {
  width: 42px;
  height: 42px;
  border-radius: 50%;
  font-size: 21px;
}

.topbar-icon:hover {
  color: var(--ws-teal-600);
  background: #f2f7f7;
}

.topbar-divider {
  width: 1px;
  height: 25px;
  margin: 0 14px;
  background: var(--ws-border);
}

.user-menu {
  gap: 10px;
  height: 46px;
}

.avatar {
  display: inline-flex;
  width: 34px;
  height: 34px;
  color: #a7b2c0;
  background: #f3f5f7;
  border: 1px solid #d8dee6;
  border-radius: 50%;
  align-items: center;
  justify-content: center;
}

.avatar .el-icon {
  font-size: 20px;
}

.user-name {
  max-width: 120px;
  overflow: hidden;
  font-size: 15px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.chevron {
  font-size: 12px;
}

.main-content {
  min-height: calc(100vh - 109px);
  background: #fff;
}

.contextbar {
  display: flex;
  min-height: 39px;
  padding: 0 36px;
  border-bottom: 1px solid #edf0f4;
  align-items: center;
}

.mobile-brand {
  display: none;
  gap: 9px;
  color: var(--ws-text);
  font-weight: 700;
  align-items: center;
}

.menu-trigger {
  width: 38px;
  height: 38px;
  margin-right: 2px;
  border-radius: 6px;
  font-size: 23px;
}

.page-enter-active,
.page-leave-active {
  transition: opacity 150ms ease, transform 150ms ease;
}

.page-enter-from,
.page-leave-to {
  opacity: 0;
  transform: translateY(3px);
}

:global(.nav-drawer .el-drawer__body) {
  padding: 0;
}

:global(.nav-drawer.el-drawer) {
  width: 248px !important;
}

@media (max-width: 900px) {
  .desktop-sidebar {
    display: none;
  }

  .app-column {
    width: 100%;
    margin-left: 0;
  }

  .topbar {
    height: 62px;
    padding: 0 14px 0 10px;
  }

  .mobile-brand {
    display: flex;
  }

  .topbar-icon:not(.search-trigger),
  .topbar-divider {
    display: none;
  }

  .search-trigger {
    width: 38px;
    height: 38px;
  }

  .user-menu {
    margin-left: 12px;
  }

  .user-name,
  .chevron {
    display: none;
  }

  .main-content {
    min-height: calc(100vh - 101px);
  }

  .contextbar {
    padding: 0 18px;
  }
}
</style>

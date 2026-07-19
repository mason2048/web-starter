<template>
  <div class="login-page">
    <section class="login-brand-panel" aria-label="产品介绍">
      <div class="brand-panel-content">
        <img :src="logoUrl" class="hero-logo" alt="" />
        <h1>启程 Web Starter</h1>
        <p>面向内部管理系统的通用开发脚手架</p>
        <ul class="feature-list">
          <li>
            <span class="feature-icon"><el-icon><UserFilled /></el-icon></span>
            <span>统一权限</span>
          </li>
          <li>
            <span class="feature-icon"><el-icon><DocumentChecked /></el-icon></span>
            <span>完整审计</span>
          </li>
          <li>
            <span class="feature-icon"><el-icon><Connection /></el-icon></span>
            <span>MCP Server</span>
          </li>
        </ul>
      </div>
    </section>

    <main class="login-form-panel">
      <div class="login-box">
        <header>
          <h2>欢迎登录</h2>
          <p>使用管理员分配的账号进入系统</p>
        </header>

        <RequestError :message="errorMessage" :trace-id="errorTraceId" />

        <el-form
          ref="formRef"
          :model="form"
          :rules="rules"
          label-position="top"
          hide-required-asterisk
          @submit.prevent="submit"
        >
          <el-form-item label="用户名" prop="username">
            <el-input
              v-model.trim="form.username"
              size="large"
              autocomplete="username"
              placeholder="请输入用户名"
              :prefix-icon="User"
              @keyup.enter="focusPassword"
            />
          </el-form-item>
          <el-form-item label="密码" prop="password">
            <el-input
              ref="passwordInput"
              v-model="form.password"
              size="large"
              type="password"
              autocomplete="current-password"
              placeholder="请输入密码"
              :prefix-icon="Lock"
              show-password
              @keyup.enter="submit"
            />
          </el-form-item>

          <div class="login-options">
            <el-checkbox v-model="form.rememberUsername">记住用户名</el-checkbox>
            <el-button link type="primary" @click="showPasswordHelp">忘记密码请联系管理员</el-button>
          </div>

          <el-button class="login-button" type="primary" size="large" :loading="auth.loading" @click="submit">
            登录
          </el-button>
        </el-form>
      </div>
      <footer>启程 Web Starter · 内部系统</footer>
    </main>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Connection, DocumentChecked, Lock, User, UserFilled } from '@element-plus/icons-vue'
import { ElMessage, type FormInstance, type FormRules, type InputInstance } from 'element-plus'
import logoUrl from '@/assets/logo.svg'
import RequestError from '@/components/RequestError.vue'
import { useAuthStore } from '@/stores/auth'
import { ApiError } from '@/types/api'
import { displayError } from '@/utils/format'
import { isOAuthAuthorizationRedirect, safeInternalRedirect } from '@/utils/redirect'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const formRef = ref<FormInstance>()
const passwordInput = ref<InputInstance>()
const errorMessage = ref('')
const errorTraceId = ref('')

const rememberedUsername = auth.getRememberedUsername()
const form = reactive({
  username: rememberedUsername,
  password: '',
  rememberUsername: Boolean(rememberedUsername),
})

const rules: FormRules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { min: 2, max: 64, message: '用户名长度应为 2 至 64 个字符', trigger: 'blur' },
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, max: 128, message: '密码长度应为 6 至 128 个字符', trigger: 'blur' },
  ],
}

function focusPassword(): void {
  passwordInput.value?.focus()
}

function showPasswordHelp(): void {
  ElMessage.info('内部系统不提供自助找回密码，请联系系统管理员重置。')
}

async function submit(): Promise<void> {
  if (!formRef.value || !(await formRef.value.validate().catch(() => false))) return
  errorMessage.value = ''
  errorTraceId.value = ''
  try {
    await auth.signIn(form.username, form.password, form.rememberUsername)
    const redirect = safeInternalRedirect(route.query.redirect)
    if (isOAuthAuthorizationRedirect(redirect)) window.location.assign(redirect)
    else await router.replace(redirect)
  } catch (error: unknown) {
    errorMessage.value = displayError(error)
    if (error instanceof ApiError) errorTraceId.value = error.traceId ?? ''
  }
}
</script>

<style scoped>
.login-page {
  display: grid;
  width: 100%;
  min-height: 100vh;
  grid-template-columns: minmax(480px, 52%) minmax(500px, 48%);
  background: #fff;
}

.login-brand-panel {
  position: relative;
  display: flex;
  min-height: 100vh;
  overflow: hidden;
  color: #fff;
  background:
    radial-gradient(circle at 50% 45%, rgb(0 168 160 / 14%), transparent 35%),
    linear-gradient(145deg, #062846 0%, #041d38 52%, #062746 100%);
  align-items: center;
  justify-content: center;
}

.login-brand-panel::after {
  position: absolute;
  right: -100px;
  bottom: -140px;
  width: 400px;
  height: 400px;
  content: '';
  border: 1px solid rgb(16 208 198 / 8%);
  border-radius: 50%;
}

.brand-panel-content {
  position: relative;
  z-index: 1;
  width: min(520px, 72%);
  transform: translateY(-10px);
}

.hero-logo {
  display: block;
  width: 112px;
  height: 112px;
  margin: 0 auto 16px;
}

.brand-panel-content h1 {
  margin: 0 0 14px;
  font-size: clamp(36px, 3.2vw, 54px);
  font-weight: 700;
  line-height: 1.25;
  letter-spacing: -1px;
  text-align: center;
}

.brand-panel-content > p {
  margin: 0;
  color: #d6e4ef;
  font-size: 21px;
  line-height: 1.6;
  text-align: center;
}

.feature-list {
  display: grid;
  width: 250px;
  padding: 0;
  margin: 54px auto 0;
  list-style: none;
  gap: 25px;
}

.feature-list li {
  display: flex;
  gap: 20px;
  color: #f5f9fc;
  font-size: 20px;
  align-items: center;
}

.feature-icon {
  display: inline-flex;
  width: 46px;
  height: 46px;
  color: #08c2bb;
  border: 1px solid rgb(9 191 184 / 40%);
  border-radius: 12px;
  align-items: center;
  justify-content: center;
}

.feature-icon .el-icon {
  font-size: 27px;
}

.login-form-panel {
  position: relative;
  display: flex;
  min-height: 100vh;
  padding: 70px clamp(40px, 8vw, 130px) 90px;
  align-items: center;
  justify-content: center;
}

.login-box {
  width: min(500px, 100%);
  transform: translateY(-26px);
}

.login-box header {
  margin-bottom: 48px;
  text-align: center;
}

.login-box h2 {
  margin: 0 0 15px;
  color: #0c2949;
  font-size: 38px;
  line-height: 1.25;
  letter-spacing: -0.6px;
}

.login-box header p {
  margin: 0;
  color: #767d87;
  font-size: 17px;
}

.login-box :deep(.el-form-item) {
  margin-bottom: 24px;
}

.login-box :deep(.el-form-item__label) {
  padding-bottom: 9px;
  color: #17304f;
  font-size: 16px;
  font-weight: 600;
  line-height: 1.3;
}

.login-box :deep(.el-input__wrapper) {
  min-height: 56px;
  padding: 1px 17px;
  border-radius: 6px;
  box-shadow: 0 0 0 1px #ccd4de inset;
}

.login-box :deep(.el-input__inner) {
  font-size: 16px;
}

.login-box :deep(.el-input__prefix) {
  margin-right: 9px;
  font-size: 20px;
}

.login-options {
  display: flex;
  margin: 3px 0 32px;
  align-items: center;
  justify-content: space-between;
}

.login-options :deep(.el-checkbox__label),
.login-options .el-button {
  font-size: 14px;
}

.login-button {
  width: 100%;
  height: 58px;
  font-size: 18px;
  font-weight: 700;
  background: linear-gradient(90deg, #00a49c, #05aaa3);
  border: 0;
  box-shadow: 0 8px 22px rgb(0 156 148 / 18%);
}

.login-form-panel footer {
  position: absolute;
  bottom: 38px;
  color: #858c95;
  font-size: 14px;
}

@media (max-width: 960px) {
  .login-page {
    display: block;
  }

  .login-brand-panel {
    min-height: 230px;
    padding: 30px 24px;
  }

  .brand-panel-content {
    width: 100%;
    transform: none;
  }

  .hero-logo {
    width: 70px;
    height: 70px;
    margin-bottom: 4px;
  }

  .brand-panel-content h1 {
    margin-bottom: 3px;
    font-size: 29px;
  }

  .brand-panel-content > p {
    font-size: 15px;
  }

  .feature-list {
    display: none;
  }

  .login-form-panel {
    min-height: calc(100vh - 230px);
    padding: 48px 22px 80px;
    align-items: flex-start;
  }

  .login-box {
    transform: none;
  }

  .login-box header {
    margin-bottom: 34px;
  }

  .login-box h2 {
    font-size: 30px;
  }

  .login-form-panel footer {
    bottom: 24px;
  }
}

@media (max-width: 480px) {
  .login-brand-panel {
    min-height: 205px;
  }

  .login-form-panel {
    min-height: calc(100vh - 205px);
  }

  .login-options {
    gap: 10px;
  }

  .login-options :deep(.el-checkbox__label),
  .login-options .el-button {
    font-size: 12px;
  }
}
</style>

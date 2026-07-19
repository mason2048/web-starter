<template>
  <div class="page-content">
    <PageHeader title="用户管理" description="维护内部账号、状态与角色分配">
      <template #actions><el-button v-if="can('system:user:create')" type="primary" :icon="Plus" @click="openCreate">新建用户</el-button></template>
    </PageHeader>
    <RequestError :message="errorMessage" />

    <div class="filter-row">
      <el-input
        v-model.trim="query.keyword"
        class="filter-input"
        placeholder="搜索用户名、姓名或邮箱"
        clearable
        :prefix-icon="Search"
        @keyup.enter="search"
        @clear="search"
      />
      <el-select v-model="query.enabled" clearable placeholder="全部状态" style="width: 160px" @change="search">
        <el-option label="已启用" :value="true" />
        <el-option label="已停用" :value="false" />
      </el-select>
      <el-button :icon="Refresh" :loading="loading" @click="loadUsers">刷新</el-button>
    </div>

    <div class="table-panel">
      <el-table v-loading="loading" :data="records" row-key="id" empty-text="暂无用户数据">
        <el-table-column prop="username" label="用户名" min-width="130" />
        <el-table-column label="姓名" min-width="130">
          <template #default="{ row }">{{ row.displayName || '—' }}</template>
        </el-table-column>
        <el-table-column label="联系方式" min-width="190">
          <template #default="{ row }">
            <div>{{ row.email || '—' }}</div>
            <small class="text-muted">{{ row.mobile || '' }}</small>
          </template>
        </el-table-column>
        <el-table-column label="角色" min-width="160">
          <template #default="{ row }">
            <span v-if="!row.roleIds?.length">—</span>
            <el-tag v-for="roleId in row.roleIds" v-else :key="roleId" class="role-tag" size="small" effect="plain">
              {{ roleLabel(roleId) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }"><StatusTag :value="normalizeEnabled(row)" /></template>
        </el-table-column>
        <el-table-column label="更新时间" min-width="170">
          <template #default="{ row }">{{ formatDateTime(row.updatedAt || row.createdAt) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="210" fixed="right">
          <template #default="{ row }">
            <el-button v-if="can('system:user:update')" link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button v-if="can('system:user:update')" link type="primary" @click="openPasswordReset(row)">
              重置密码
            </el-button>
            <el-button v-if="can('system:user:remove')" link type="danger" @click="confirmRemove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="pagination-row">
      <span>共 {{ total }} 条</span>
      <el-pagination
        v-model:current-page="query.page"
        v-model:page-size="query.size"
        background
        layout="sizes, prev, pager, next"
        :page-sizes="[10, 20, 50]"
        :total="total"
        @current-change="loadUsers"
        @size-change="handleSizeChange"
      />
    </div>

    <el-drawer v-model="drawerOpen" :title="editingId === null ? '新建用户' : '编辑用户'" size="420px" :modal="false" destroy-on-close>
      <RequestError :message="drawerError" />
      <el-form ref="formRef" class="drawer-form" :model="form" :rules="rules" label-position="top">
        <el-form-item label="用户名" prop="username">
          <el-input v-model.trim="form.username" maxlength="64" :disabled="editingId !== null" placeholder="请输入用户名" />
        </el-form-item>
        <el-form-item v-if="editingId === null" label="初始密码" prop="password">
          <el-input v-model="form.password" type="password" show-password autocomplete="new-password" placeholder="至少 12 个字符" />
        </el-form-item>
        <el-form-item label="姓名" prop="displayName">
          <el-input v-model.trim="form.displayName" maxlength="50" placeholder="请输入姓名" />
        </el-form-item>
        <el-form-item label="邮箱" prop="email">
          <el-input v-model.trim="form.email" maxlength="128" placeholder="name@example.com" />
        </el-form-item>
        <el-form-item label="手机号码" prop="mobile">
          <el-input v-model.trim="form.mobile" maxlength="20" placeholder="请输入手机号码（可选）" />
        </el-form-item>
        <el-form-item label="角色" prop="roleIds">
          <el-select v-model="form.roleIds" multiple filterable placeholder="请选择角色" :loading="rolesLoading">
            <el-option v-for="role in roleOptions" :key="role.id" :label="role.name" :value="role.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="账号状态">
          <el-switch v-model="form.enabled" inline-prompt active-text="启" inactive-text="停" />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="drawer-footer">
          <el-button @click="drawerOpen = false">取消</el-button>
          <el-button type="primary" :loading="saving" @click="save">保存</el-button>
        </div>
      </template>
    </el-drawer>

    <el-dialog
      v-model="passwordDialogOpen"
      title="重置用户密码"
      width="440px"
      :close-on-click-modal="false"
      destroy-on-close
      @closed="clearPasswordForm"
    >
      <p class="password-target">
        正在为 <strong>{{ passwordTarget?.username }}</strong> 设置新密码。密码不会在页面或接口中再次显示。
      </p>
      <RequestError :message="passwordError" />
      <el-form
        ref="passwordFormRef"
        :model="passwordForm"
        :rules="passwordRules"
        label-position="top"
        @submit.prevent
      >
        <el-form-item label="新密码" prop="password">
          <el-input
            v-model="passwordForm.password"
            type="password"
            show-password
            autocomplete="new-password"
            maxlength="128"
            placeholder="12 至 128 个字符"
          />
        </el-form-item>
        <el-form-item label="再次输入新密码" prop="confirmation">
          <el-input
            v-model="passwordForm.confirmation"
            type="password"
            show-password
            autocomplete="new-password"
            maxlength="128"
            placeholder="再次输入以确认"
            @keyup.enter="confirmPasswordReset"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button :disabled="resettingPassword" @click="passwordDialogOpen = false">取消</el-button>
        <el-button type="primary" :loading="resettingPassword" @click="confirmPasswordReset">确认重置</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import { rolesApi, usersApi } from '@/api/admin'
import PageHeader from '@/components/PageHeader.vue'
import RequestError from '@/components/RequestError.vue'
import StatusTag from '@/components/StatusTag.vue'
import { usePermission } from '@/composables/usePermission'
import type { RoleRecord, UserRecord } from '@/types/models'
import { displayError, formatDateTime, normalizeEnabled } from '@/utils/format'

interface UserForm {
  username: string
  password: string
  displayName: string
  email: string
  mobile: string
  roleIds: string[]
  enabled: boolean
}

interface PasswordForm {
  password: string
  confirmation: string
}

const { can } = usePermission()

const records = ref<UserRecord[]>([])
const roleOptions = ref<RoleRecord[]>([])
const total = ref(0)
const loading = ref(false)
const rolesLoading = ref(false)
const saving = ref(false)
const resettingPassword = ref(false)
const errorMessage = ref('')
const drawerError = ref('')
const drawerOpen = ref(false)
const passwordDialogOpen = ref(false)
const passwordTarget = ref<UserRecord | null>(null)
const passwordError = ref('')
const editingId = ref<UserRecord['id'] | null>(null)
const editingVersion = ref<number | null>(null)
const formRef = ref<FormInstance>()
const passwordFormRef = ref<FormInstance>()
const query = reactive<{ page: number; size: number; keyword: string; enabled: boolean | '' }>({
  page: 1,
  size: 10,
  keyword: '',
  enabled: '',
})
const form = reactive<UserForm>({
  username: '',
  password: '',
  displayName: '',
  email: '',
  mobile: '',
  roleIds: [],
  enabled: true,
})
const passwordForm = reactive<PasswordForm>({ password: '', confirmation: '' })

const rules: FormRules<UserForm> = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { min: 2, max: 64, message: '用户名长度应为 2 至 64 个字符', trigger: 'blur' },
  ],
  password: [
    {
      validator: (_rule, value: string, callback) => {
        if (editingId.value !== null || value.length >= 12) callback()
        else callback(new Error('初始密码至少需要 12 个字符'))
      },
      trigger: 'blur',
    },
  ],
  displayName: [{ required: true, message: '请输入姓名', trigger: 'blur' }],
  email: [{ type: 'email', message: '请输入有效的邮箱地址', trigger: 'blur' }],
}

const passwordRules: FormRules<PasswordForm> = {
  password: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 12, max: 128, message: '密码长度应为 12 至 128 个字符', trigger: 'blur' },
  ],
  confirmation: [
    { required: true, message: '请再次输入新密码', trigger: 'blur' },
    {
      validator: (_rule, value: string, callback) => {
        if (value === passwordForm.password) callback()
        else callback(new Error('两次输入的密码不一致'))
      },
      trigger: ['blur', 'change'],
    },
  ],
}

function resetForm(): void {
  editingId.value = null
  editingVersion.value = null
  drawerError.value = ''
  Object.assign(form, {
    username: '',
    password: '',
    displayName: '',
    email: '',
    mobile: '',
    roleIds: [],
    enabled: true,
  })
  formRef.value?.clearValidate()
}

async function loadUsers(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const data = await usersApi.list({
      page: query.page,
      size: query.size,
      keyword: query.keyword || undefined,
      status: query.enabled === '' ? undefined : query.enabled ? 'ENABLED' : 'DISABLED',
    })
    records.value = data.records
    total.value = data.total
  } catch (error: unknown) {
    records.value = []
    total.value = 0
    errorMessage.value = displayError(error)
  } finally {
    loading.value = false
  }
}

async function loadRoles(): Promise<void> {
  rolesLoading.value = true
  try {
    roleOptions.value = (await rolesApi.list({ page: 1, size: 100 })).records
  } catch (error: unknown) {
    roleOptions.value = []
    drawerError.value = `角色列表加载失败：${displayError(error)}`
  } finally {
    rolesLoading.value = false
  }
}

function search(): void {
  query.page = 1
  void loadUsers()
}

function handleSizeChange(): void {
  query.page = 1
  void loadUsers()
}

function openCreate(): void {
  resetForm()
  drawerOpen.value = true
  void loadRoles()
}

function openEdit(user: UserRecord): void {
  resetForm()
  editingId.value = user.id
  editingVersion.value = user.version
  Object.assign(form, {
    username: user.username,
    displayName: user.displayName || '',
    email: user.email || '',
    mobile: user.mobile || '',
    roleIds: user.roleIds || [],
    enabled: normalizeEnabled(user),
  })
  drawerOpen.value = true
  void loadRoles()
}

function openPasswordReset(user: UserRecord): void {
  clearPasswordForm()
  passwordTarget.value = user
  passwordDialogOpen.value = true
}

function clearPasswordForm(): void {
  passwordForm.password = ''
  passwordForm.confirmation = ''
  passwordError.value = ''
  passwordTarget.value = null
  passwordFormRef.value?.clearValidate()
}

async function confirmPasswordReset(): Promise<void> {
  if (!passwordTarget.value || !passwordFormRef.value) return
  if (!(await passwordFormRef.value.validate().catch(() => false))) return
  const target = passwordTarget.value
  try {
    await ElMessageBox.confirm(
      `确认重置用户“${target.username}”的密码吗？`,
      '确认密码重置',
      { type: 'warning', confirmButtonText: '确认重置' },
    )
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    passwordError.value = displayError(error)
    return
  }

  resettingPassword.value = true
  passwordError.value = ''
  try {
    await usersApi.resetPassword(target.id, { password: passwordForm.password })
    ElMessage.success('用户密码已重置')
    passwordDialogOpen.value = false
    clearPasswordForm()
  } catch (error: unknown) {
    passwordError.value = displayError(error)
  } finally {
    resettingPassword.value = false
  }
}

async function save(): Promise<void> {
  if (!formRef.value || !(await formRef.value.validate().catch(() => false))) return
  saving.value = true
  drawerError.value = ''
  try {
    if (editingId.value === null) {
      await usersApi.create({
        username: form.username,
        displayName: form.displayName,
        password: form.password,
        email: form.email || undefined,
        mobile: form.mobile || undefined,
        status: form.enabled ? 'ENABLED' : 'DISABLED',
        roleIds: form.roleIds,
      })
    } else if (editingVersion.value !== null) {
      await usersApi.update(editingId.value, {
        displayName: form.displayName,
        email: form.email || undefined,
        mobile: form.mobile || undefined,
        status: form.enabled ? 'ENABLED' : 'DISABLED',
        version: editingVersion.value,
        roleIds: form.roleIds,
      })
    }
    ElMessage.success(editingId.value === null ? '用户创建成功' : '用户更新成功')
    drawerOpen.value = false
    await loadUsers()
  } catch (error: unknown) {
    drawerError.value = displayError(error)
  } finally {
    saving.value = false
  }
}

async function confirmRemove(user: UserRecord): Promise<void> {
  try {
    await ElMessageBox.confirm(`确定删除用户“${user.username}”吗？`, '删除用户', { type: 'warning' })
    await usersApi.remove(user.id)
    ElMessage.success('用户已删除')
    await loadUsers()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    errorMessage.value = displayError(error)
  }
}

onMounted(loadUsers)

function roleLabel(roleId: string): string {
  return roleOptions.value.find((role) => role.id === roleId)?.name || `角色 #${roleId}`
}

onMounted(loadRoles)
</script>

<style scoped>
.role-tag + .role-tag { margin-left: 5px; }

.password-target {
  margin: 0 0 18px;
  color: var(--ws-text-secondary);
  line-height: 1.6;
}
</style>

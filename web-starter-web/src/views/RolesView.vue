<template>
  <div class="page-content">
    <PageHeader title="角色权限" description="通过角色统一分配菜单、按钮与 MCP 工具权限">
      <template #actions><el-button v-if="can('system:role:create')" type="primary" :icon="Plus" @click="openCreate">新建角色</el-button></template>
    </PageHeader>
    <RequestError :message="errorMessage" />

    <div class="filter-row">
      <el-input
        v-model.trim="query.keyword"
        class="filter-input"
        placeholder="搜索角色名称或编码"
        clearable
        :prefix-icon="Search"
        @keyup.enter="search"
        @clear="search"
      />
      <el-button :icon="Refresh" :loading="loading" @click="loadRoles">刷新</el-button>
    </div>

    <div class="table-panel">
      <el-table v-loading="loading" :data="records" row-key="id" empty-text="暂无角色数据">
        <el-table-column prop="name" label="角色名称" min-width="150" />
        <el-table-column prop="code" label="角色编码" min-width="160">
          <template #default="{ row }"><span class="mono">{{ row.code }}</span></template>
        </el-table-column>
        <el-table-column prop="description" label="说明" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">{{ row.description || '—' }}</template>
        </el-table-column>
        <el-table-column label="权限数量" width="105">
          <template #default="{ row }">{{ (row.permissionIds?.length || 0) + (row.menuIds?.length || 0) }}</template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }"><StatusTag :value="normalizeEnabled(row)" /></template>
        </el-table-column>
        <el-table-column label="更新时间" min-width="170">
          <template #default="{ row }">{{ formatDateTime(row.updatedAt || row.createdAt) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="132" fixed="right">
          <template #default="{ row }">
            <el-button v-if="can('system:role:update')" link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button v-if="can('system:role:remove')" link type="danger" @click="confirmRemove(row)">删除</el-button>
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
        @current-change="loadRoles"
        @size-change="handleSizeChange"
      />
    </div>

    <el-drawer v-model="drawerOpen" :title="editingId === null ? '新建角色' : '编辑角色'" size="470px" :modal="false" destroy-on-close>
      <RequestError :message="drawerError" />
      <el-form ref="formRef" class="drawer-form" :model="form" :rules="rules" label-position="top">
        <el-form-item label="角色名称" prop="name">
          <el-input v-model.trim="form.name" maxlength="50" placeholder="请输入角色名称" />
        </el-form-item>
        <el-form-item label="角色编码" prop="code">
          <el-input
            v-model.trim="form.code"
            maxlength="64"
            :disabled="editingId !== null"
            placeholder="例如 PROJECT_MANAGER"
            @input="normalizeRoleCode"
          />
        </el-form-item>
        <el-form-item label="角色说明">
          <el-input v-model="form.description" type="textarea" :rows="3" maxlength="200" show-word-limit />
        </el-form-item>
        <el-form-item label="角色状态">
          <el-switch v-model="form.enabled" inline-prompt active-text="启" inactive-text="停" />
        </el-form-item>
        <el-form-item label="菜单与按钮权限">
          <div v-loading="menusLoading" class="permission-tree">
            <el-tree
              ref="treeRef"
              :data="menuTree"
              node-key="id"
              show-checkbox
              default-expand-all
              check-strictly
              :props="{ label: 'name', children: 'children' }"
              empty-text="暂无可分配权限"
            >
              <template #default="{ data }">
                <span class="tree-node">
                  <span>{{ data.name }}</span>
                  <code v-if="data.permissionCode">{{ data.permissionCode }}</code>
                </span>
              </template>
            </el-tree>
          </div>
        </el-form-item>
        <el-form-item label="业务与 MCP 权限">
          <div v-loading="permissionsLoading" class="permission-list">
            <el-checkbox-group v-model="checkedPermissionIds">
              <el-checkbox v-for="permission in permissionOptions" :key="permission.id" :value="permission.id">
                <span class="permission-option">
                  <span>{{ permission.name }}</span>
                  <code>{{ permission.code }}</code>
                </span>
              </el-checkbox>
            </el-checkbox-group>
            <el-empty v-if="!permissionsLoading && !permissionOptions.length" description="暂无业务权限" :image-size="60" />
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="drawer-footer">
          <el-button @click="drawerOpen = false">取消</el-button>
          <el-button type="primary" :loading="saving" @click="save">保存</el-button>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { nextTick, onMounted, reactive, ref } from 'vue'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules, type TreeInstance } from 'element-plus'
import { menusApi, permissionsApi, rolesApi } from '@/api/admin'
import PageHeader from '@/components/PageHeader.vue'
import RequestError from '@/components/RequestError.vue'
import StatusTag from '@/components/StatusTag.vue'
import { usePermission } from '@/composables/usePermission'
import type { MenuRecord, PermissionRecord, RoleRecord } from '@/types/models'
import { displayError, formatDateTime, normalizeEnabled } from '@/utils/format'

interface RoleForm {
  name: string
  code: string
  description: string
  enabled: boolean
}

const { can } = usePermission()

const records = ref<RoleRecord[]>([])
const menuTree = ref<MenuRecord[]>([])
const permissionOptions = ref<PermissionRecord[]>([])
const total = ref(0)
const loading = ref(false)
const menusLoading = ref(false)
const permissionsLoading = ref(false)
const saving = ref(false)
const errorMessage = ref('')
const drawerError = ref('')
const drawerOpen = ref(false)
const editingId = ref<RoleRecord['id'] | null>(null)
const checkedMenuIds = ref<string[]>([])
const checkedPermissionIds = ref<string[]>([])
const editingVersion = ref<number | null>(null)
const formRef = ref<FormInstance>()
const treeRef = ref<TreeInstance>()
const query = reactive({ page: 1, size: 10, keyword: '' })
const form = reactive<RoleForm>({ name: '', code: '', description: '', enabled: true })

const rules: FormRules<RoleForm> = {
  name: [{ required: true, message: '请输入角色名称', trigger: 'blur' }],
  code: [
    { required: true, message: '请输入角色编码', trigger: 'blur' },
    { pattern: /^[A-Z][A-Z0-9:_-]{1,63}$/, message: '使用大写字母、数字、冒号、连字符或下划线', trigger: 'blur' },
  ],
}

function normalizeRoleCode(value: string | number): void {
  form.code = String(value).toUpperCase()
}

async function loadRoles(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const data = await rolesApi.list({ page: query.page, size: query.size, keyword: query.keyword || undefined })
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

async function loadMenus(): Promise<void> {
  menusLoading.value = true
  try {
    menuTree.value = buildMenuTree(await menusApi.list())
    await nextTick()
    treeRef.value?.setCheckedKeys(checkedMenuIds.value, false)
  } catch (error: unknown) {
    menuTree.value = []
    drawerError.value = `权限树加载失败：${displayError(error)}`
  } finally {
    menusLoading.value = false
  }
}

function buildMenuTree(records: MenuRecord[]): MenuRecord[] {
  const map = new Map<string, MenuRecord>()
  const roots: MenuRecord[] = []
  records.forEach((record) => map.set(record.id, { ...record, children: [] }))
  map.forEach((record) => {
    const parent = record.parentId ? map.get(record.parentId) : undefined
    if (parent) parent.children?.push(record)
    else roots.push(record)
  })
  return roots
}

async function loadPermissions(): Promise<void> {
  permissionsLoading.value = true
  try {
    permissionOptions.value = await permissionsApi.list({ status: 'ENABLED' })
  } catch (error: unknown) {
    permissionOptions.value = []
    drawerError.value = `业务权限加载失败：${displayError(error)}`
  } finally {
    permissionsLoading.value = false
  }
}

function resetForm(): void {
  editingId.value = null
  checkedMenuIds.value = []
  checkedPermissionIds.value = []
  editingVersion.value = null
  drawerError.value = ''
  Object.assign(form, { name: '', code: '', description: '', enabled: true })
  formRef.value?.clearValidate()
}

function search(): void {
  query.page = 1
  void loadRoles()
}

function handleSizeChange(): void {
  query.page = 1
  void loadRoles()
}

function openCreate(): void {
  resetForm()
  drawerOpen.value = true
  void Promise.all([loadMenus(), loadPermissions()])
}

function openEdit(role: RoleRecord): void {
  resetForm()
  editingId.value = role.id
  editingVersion.value = role.version
  checkedMenuIds.value = role.menuIds || []
  checkedPermissionIds.value = role.permissionIds || []
  Object.assign(form, {
    name: role.name,
    code: role.code,
    description: role.description || '',
    enabled: normalizeEnabled(role),
  })
  drawerOpen.value = true
  void Promise.all([loadMenus(), loadPermissions()])
}

async function save(): Promise<void> {
  if (!formRef.value || !(await formRef.value.validate().catch(() => false))) return
  saving.value = true
  drawerError.value = ''
  const menuIds = (treeRef.value?.getCheckedKeys(false) || []) as string[]
  try {
    if (editingId.value === null) {
      await rolesApi.create({
        code: form.code,
        name: form.name,
        description: form.description || undefined,
        status: form.enabled ? 'ENABLED' : 'DISABLED',
        permissionIds: checkedPermissionIds.value,
        menuIds,
      })
    } else if (editingVersion.value !== null) {
      await rolesApi.update(editingId.value, {
        name: form.name,
        description: form.description || undefined,
        status: form.enabled ? 'ENABLED' : 'DISABLED',
        version: editingVersion.value,
        permissionIds: checkedPermissionIds.value,
        menuIds,
      })
    }
    ElMessage.success(editingId.value === null ? '角色创建成功' : '角色更新成功')
    drawerOpen.value = false
    await loadRoles()
  } catch (error: unknown) {
    drawerError.value = displayError(error)
  } finally {
    saving.value = false
  }
}

async function confirmRemove(role: RoleRecord): Promise<void> {
  try {
    await ElMessageBox.confirm(`确定删除角色“${role.name}”吗？`, '删除角色', { type: 'warning' })
    await rolesApi.remove(role.id)
    ElMessage.success('角色已删除')
    await loadRoles()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    errorMessage.value = displayError(error)
  }
}

onMounted(loadRoles)
</script>

<style scoped>
.permission-tree {
  width: 100%;
  min-height: 180px;
  max-height: 340px;
  padding: 12px;
  overflow: auto;
  border: 1px solid var(--ws-border);
  border-radius: 6px;
}

.permission-list {
  width: 100%;
  min-height: 120px;
  max-height: 260px;
  padding: 12px 16px;
  overflow: auto;
  border: 1px solid var(--ws-border);
  border-radius: 6px;
}

.permission-list :deep(.el-checkbox-group),
.permission-list :deep(.el-checkbox) {
  display: flex;
  width: 100%;
  height: auto;
}

.permission-list :deep(.el-checkbox) {
  padding: 7px 0;
  align-items: flex-start;
}

.permission-option span,
.permission-option code {
  display: block;
}

.permission-option code {
  margin-top: 2px;
  color: var(--ws-text-secondary);
  font-size: 11px;
}

.tree-node {
  display: flex;
  width: 100%;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
}

.tree-node code {
  color: var(--ws-text-secondary);
  font-size: 11px;
}
</style>

<template>
  <div class="page-content">
    <PageHeader title="菜单权限" description="维护导航结构与按钮级权限标识">
      <template #actions><el-button v-if="can('system:menu:manage')" type="primary" :icon="Plus" @click="openCreate">新建菜单</el-button></template>
    </PageHeader>
    <RequestError :message="errorMessage" />

    <div class="filter-row">
      <el-input
        v-model.trim="keyword"
        class="filter-input"
        placeholder="搜索菜单名称或权限标识"
        clearable
        :prefix-icon="Search"
        @keyup.enter="loadMenus"
        @clear="loadMenus"
      />
      <el-button :icon="Refresh" :loading="loading" @click="loadMenus">刷新</el-button>
    </div>

    <div class="table-panel">
      <el-table
        v-loading="loading"
        :data="menuTree"
        row-key="id"
        default-expand-all
        :tree-props="{ children: 'children' }"
        empty-text="暂无菜单数据"
      >
        <el-table-column prop="name" label="菜单名称" min-width="180" />
        <el-table-column label="类型" width="92">
          <template #default="{ row }"><el-tag size="small" effect="plain">{{ typeLabel(resolveMenuType(row)) }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="path" label="路由" min-width="150">
          <template #default="{ row }"><span class="mono">{{ row.path || '—' }}</span></template>
        </el-table-column>
        <el-table-column prop="permissionCode" label="权限标识" min-width="190">
          <template #default="{ row }"><span class="mono">{{ row.permissionCode || '—' }}</span></template>
        </el-table-column>
        <el-table-column prop="sortOrder" label="排序" width="75" />
        <el-table-column label="可见" width="75">
          <template #default="{ row }"><StatusTag :value="row.visible !== false" /></template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="{ row }">
            <el-button v-if="can('system:menu:manage')" link type="primary" @click="openChild(row)">新增下级</el-button>
            <el-button v-if="can('system:menu:manage')" link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button v-if="can('system:menu:manage')" link type="danger" @click="confirmRemove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-drawer v-model="drawerOpen" :title="editingId === null ? '新建菜单权限' : '编辑菜单权限'" size="440px" :modal="false" destroy-on-close>
      <RequestError :message="drawerError" />
      <el-form ref="formRef" class="drawer-form" :model="form" :rules="rules" label-position="top">
        <el-form-item label="上级菜单">
          <el-tree-select
            v-model="form.parentId"
            :data="parentOptions"
            node-key="id"
            :props="{ label: 'name', children: 'children' }"
            check-strictly
            clearable
            placeholder="根级菜单"
          />
        </el-form-item>
        <el-form-item label="类型" prop="type">
          <el-radio-group v-model="form.type">
            <el-radio-button value="DIRECTORY">目录</el-radio-button>
            <el-radio-button value="MENU">菜单</el-radio-button>
            <el-radio-button value="BUTTON">按钮</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="名称" prop="name">
          <el-input v-model.trim="form.name" maxlength="50" placeholder="请输入菜单或按钮名称" />
        </el-form-item>
        <el-form-item v-if="form.type !== 'BUTTON'" label="路由路径" prop="path">
          <el-input v-model.trim="form.path" maxlength="128" placeholder="例如 /projects" />
        </el-form-item>
        <el-form-item v-if="form.type === 'MENU'" label="前端组件">
          <el-input v-model.trim="form.component" maxlength="128" placeholder="例如 views/ProjectsView" />
        </el-form-item>
        <el-form-item v-if="form.type !== 'DIRECTORY'" label="权限标识" prop="permission">
          <el-input v-model.trim="form.permission" maxlength="128" placeholder="例如 project:list" />
        </el-form-item>
        <el-form-item label="排序">
          <el-input-number v-model="form.sort" :min="0" :max="9999" controls-position="right" />
        </el-form-item>
        <div class="switch-row">
          <el-form-item label="是否可见"><el-switch v-model="form.visible" /></el-form-item>
          <el-form-item label="是否启用"><el-switch v-model="form.enabled" /></el-form-item>
        </div>
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
import { computed, onMounted, reactive, ref } from 'vue'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import { menusApi } from '@/api/admin'
import PageHeader from '@/components/PageHeader.vue'
import RequestError from '@/components/RequestError.vue'
import StatusTag from '@/components/StatusTag.vue'
import { usePermission } from '@/composables/usePermission'
import type { MenuRecord } from '@/types/models'
import { displayError } from '@/utils/format'

type MenuType = NonNullable<MenuRecord['type']>
const { can } = usePermission()
interface MenuForm {
  parentId?: string
  name: string
  type: MenuType
  path: string
  component: string
  permission: string
  sort: number
  visible: boolean
  enabled: boolean
}

const rawRecords = ref<MenuRecord[]>([])
const loading = ref(false)
const saving = ref(false)
const errorMessage = ref('')
const drawerError = ref('')
const keyword = ref('')
const drawerOpen = ref(false)
const editingId = ref<MenuRecord['id'] | null>(null)
const formRef = ref<FormInstance>()
const form = reactive<MenuForm>({
  parentId: undefined,
  name: '',
  type: 'MENU',
  path: '',
  component: '',
  permission: '',
  sort: 0,
  visible: true,
  enabled: true,
})

const rules: FormRules<MenuForm> = {
  name: [{ required: true, message: '请输入名称', trigger: 'blur' }],
  type: [{ required: true, message: '请选择类型', trigger: 'change' }],
  permission: [
    {
      validator: (_rule, value: string, callback) => {
        if (form.type === 'DIRECTORY' || /^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)+$/.test(value)) callback()
        else callback(new Error('权限标识应类似 project:list'))
      },
      trigger: 'blur',
    },
  ],
}

function buildMenuTree(source: MenuRecord[]): MenuRecord[] {
  if (source.some((record) => record.children?.length)) return source
  const map = new Map<string, MenuRecord>()
  const roots: MenuRecord[] = []
  source.forEach((record) => map.set(record.id, { ...record, children: [] }))
  map.forEach((record) => {
    const parent = record.parentId ? map.get(record.parentId) : undefined
    if (parent && parent.id !== record.id) parent.children?.push(record)
    else roots.push(record)
  })
  return roots
}

const allMenuTree = computed(() => buildMenuTree(rawRecords.value))

const menuTree = computed(() => {
  const source = keyword.value
    ? rawRecords.value.filter((record) =>
        [record.name, record.permissionCode, record.path].some((value) =>
          value?.toLowerCase().includes(keyword.value.toLowerCase()),
        ),
      )
    : rawRecords.value
  return buildMenuTree(source)
})

const parentOptions = computed(() => filterTree(allMenuTree.value, editingId.value))

function filterTree(records: MenuRecord[], excludedId: MenuRecord['id'] | null): MenuRecord[] {
  return records
    .filter((record) => excludedId === null || record.id !== excludedId)
    .map((record) => ({ ...record, children: filterTree(record.children || [], excludedId) }))
}

function typeLabel(type: MenuType): string {
  return { DIRECTORY: '目录', MENU: '菜单', BUTTON: '按钮' }[type]
}

function resolveMenuType(menu: MenuRecord): MenuType {
  if (menu.type) return menu.type
  if (menu.permissionCode && !menu.path && !menu.component) return 'BUTTON'
  if (menu.path || menu.component) return 'MENU'
  return 'DIRECTORY'
}

async function loadMenus(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    rawRecords.value = await menusApi.list()
  } catch (error: unknown) {
    rawRecords.value = []
    errorMessage.value = displayError(error)
  } finally {
    loading.value = false
  }
}

function resetForm(): void {
  editingId.value = null
  drawerError.value = ''
  Object.assign(form, {
    parentId: undefined,
    name: '',
    type: 'MENU',
    path: '',
    component: '',
    permission: '',
    sort: 0,
    visible: true,
    enabled: true,
  })
  formRef.value?.clearValidate()
}

function openCreate(): void {
  resetForm()
  drawerOpen.value = true
}

function openChild(parent: MenuRecord): void {
  resetForm()
  form.parentId = parent.id
  form.type = resolveMenuType(parent) === 'BUTTON' ? 'BUTTON' : 'MENU'
  drawerOpen.value = true
}

function openEdit(menu: MenuRecord): void {
  resetForm()
  editingId.value = menu.id
  Object.assign(form, {
    parentId: menu.parentId,
    name: menu.name,
    type: resolveMenuType(menu),
    path: menu.path || '',
    component: menu.component || '',
    permission: menu.permissionCode || '',
    sort: menu.sortOrder || 0,
    visible: menu.visible !== false,
    enabled: menu.status !== 'DISABLED',
  })
  drawerOpen.value = true
}

async function save(): Promise<void> {
  if (!formRef.value || !(await formRef.value.validate().catch(() => false))) return
  saving.value = true
  drawerError.value = ''
  const payload = {
    parentId: form.parentId || undefined,
    name: form.name,
    path: form.type === 'BUTTON' ? undefined : form.path || undefined,
    component: form.type === 'MENU' ? form.component || undefined : undefined,
    icon: undefined,
    sortOrder: form.sort,
    visible: form.visible,
    status: form.enabled ? 'ENABLED' : 'DISABLED',
    permissionCode: form.type === 'DIRECTORY' ? undefined : form.permission,
  }
  try {
    if (editingId.value === null) await menusApi.create(payload)
    else await menusApi.update(editingId.value, payload)
    ElMessage.success(editingId.value === null ? '菜单权限创建成功' : '菜单权限更新成功')
    drawerOpen.value = false
    await loadMenus()
  } catch (error: unknown) {
    drawerError.value = displayError(error)
  } finally {
    saving.value = false
  }
}

async function confirmRemove(menu: MenuRecord): Promise<void> {
  try {
    await ElMessageBox.confirm(`确定删除“${menu.name}”及其关联关系吗？`, '删除菜单权限', { type: 'warning' })
    await menusApi.remove(menu.id)
    ElMessage.success('菜单权限已删除')
    await loadMenus()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    errorMessage.value = displayError(error)
  }
}

onMounted(loadMenus)
</script>

<style scoped>
.switch-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
}
</style>

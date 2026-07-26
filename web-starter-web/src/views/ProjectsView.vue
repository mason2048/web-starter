<template>
  <div class="page-content projects-page">
    <PageHeader title="项目示例" description="演示完整的增删改查、权限与审计链路">
      <template #actions>
        <el-button v-if="can('project:create')" type="primary" :icon="Plus" @click="openCreate">新建项目</el-button>
      </template>
    </PageHeader>

    <RequestError :failure="failure" />

    <section class="project-summary" aria-label="项目统计">
      <div><span>项目总数</span><strong>{{ total }}</strong></div>
      <div><span>当前页进行中</span><strong>{{ inProgressCount }}</strong></div>
      <div><span>当前页已归档</span><strong>{{ archivedCount }}</strong></div>
    </section>

    <div class="filter-row">
      <el-input
        v-model.trim="query.keyword"
        class="filter-input"
        placeholder="搜索项目名称或编码"
        clearable
        :prefix-icon="Search"
        @keyup.enter="search"
        @clear="search"
      />
      <el-select
        v-model="query.status"
        aria-label="按项目状态筛选"
        placeholder="全部状态"
        clearable
        style="width: 180px"
        @change="search"
      >
        <el-option v-for="option in statusOptions" :key="option.value" :label="option.label" :value="option.value" />
      </el-select>
      <el-button :icon="Refresh" :loading="loading" @click="loadProjects">刷新</el-button>
    </div>

    <div class="table-panel">
      <el-table v-loading="loading" :data="projects" row-key="id" empty-text="暂无项目数据">
        <el-table-column prop="name" label="项目名称" min-width="160" show-overflow-tooltip />
        <el-table-column prop="code" label="项目编码" min-width="145" show-overflow-tooltip />
        <el-table-column label="负责人" min-width="110">
          <template #default="{ row }">{{ row.ownerName || '—' }}</template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }"><StatusTag :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="更新时间" min-width="175">
          <template #default="{ row }">{{ formatDateTime(row.updatedAt || row.createdAt) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="188" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openView(row)">查看</el-button>
            <el-button v-if="can('project:update')" link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button v-if="can('project:remove')" link type="danger" @click="confirmRemove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="pagination-row">
      <span>共 {{ total }} 条</span>
      <el-select
        v-model="query.size"
        aria-label="每页显示条数"
        class="pagination-size-select"
        style="width: 112px"
        @change="handleSizeChange"
      >
        <el-option v-for="size in [10, 20, 50]" :key="size" :label="`${size}条/页`" :value="size" />
      </el-select>
      <el-pagination
        v-model:current-page="query.page"
        background
        layout="prev, pager, next, jumper"
        :page-size="query.size"
        :total="total"
        @current-change="loadProjects"
      />
    </div>

    <el-drawer v-model="drawerOpen" :title="drawerTitle" size="382px" :modal="false">
      <RequestError :failure="drawerFailure" />
      <el-form
        ref="formRef"
        class="drawer-form"
        :model="form"
        :rules="rules"
        label-position="top"
        :disabled="drawerMode === 'view' || detailLoading"
        v-loading="detailLoading"
      >
        <el-form-item label="项目名称" prop="name">
          <el-input v-model.trim="form.name" maxlength="120" show-word-limit placeholder="请输入项目名称" />
        </el-form-item>
        <el-form-item label="项目编码" prop="code">
          <el-input v-model.trim="form.code" maxlength="64" show-word-limit placeholder="请输入项目编码" />
        </el-form-item>
        <el-form-item label="负责人" prop="ownerId">
          <el-select
            v-model="form.ownerId"
            aria-label="项目负责人"
            placeholder="请选择负责人"
            filterable
            clearable
            :loading="ownersLoading"
          >
            <el-option
              v-for="owner in owners"
              :key="owner.id"
              :label="owner.displayName || owner.username"
              :value="owner.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="状态" prop="status">
          <el-select v-model="form.status" aria-label="项目状态" placeholder="请选择状态">
            <el-option v-for="option in statusOptions" :key="option.value" :label="option.label" :value="option.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="项目说明" prop="description">
          <el-input
            v-model="form.description"
            type="textarea"
            :rows="5"
            maxlength="2000"
            show-word-limit
            placeholder="请输入项目说明（可选）"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="drawer-footer">
          <el-button @click="drawerOpen = false">{{ drawerMode === 'view' ? '关闭' : '取消' }}</el-button>
          <el-button
            v-if="drawerMode !== 'view'"
            type="primary"
            :disabled="detailLoading"
            :loading="saving"
            @click="saveProject"
          >
            保存
          </el-button>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import { createProject, getProject, listProjectOwners, listProjects, removeProject, updateProject } from '@/api/projects'
import PageHeader from '@/components/PageHeader.vue'
import RequestError from '@/components/RequestError.vue'
import StatusTag from '@/components/StatusTag.vue'
import { usePermission } from '@/composables/usePermission'
import { useStandardCrudPage } from '@/crud/useStandardCrudPage'
import { toRequestFailure, type RequestFailure } from '@/api/requestFailure'
import type { Project, ProjectOwner, ProjectStatus } from '@/types/models'
import { formatDateTime } from '@/utils/format'
import { isValidProjectCode } from '@/utils/validators'

type DrawerMode = 'create' | 'edit' | 'view'
const { can } = usePermission()
const route = useRoute()
const router = useRouter()

const statusOptions: Array<{ label: string; value: ProjectStatus }> = [
  { label: '规划中', value: 'PLANNING' },
  { label: '进行中', value: 'IN_PROGRESS' },
  { label: '已归档', value: 'ARCHIVED' },
]

const owners = ref<ProjectOwner[]>([])
const ownersLoading = ref(false)
const detailLoading = ref(false)
const saving = ref(false)
const drawerFailure = ref<RequestFailure | null>(null)
const drawerOpen = ref(false)
const drawerMode = ref<DrawerMode>('create')
const selectedId = ref<Project['id'] | null>(null)
const selectedVersion = ref<number | null>(null)
const formRef = ref<FormInstance>()

const crudPage = useStandardCrudPage<Project>({
  route,
  router,
  statuses: statusOptions.map((option) => option.value),
  fetchPage: listProjects,
})
const {
  query,
  records: projects,
  total,
  loading,
  failure,
  load: loadProjects,
  search,
  handleSizeChange,
  captureFailure: setPageError,
} = crudPage
const form = reactive<{
  name: string
  code: string
  ownerId?: string
  status: ProjectStatus
  description?: string
}>({
  name: '',
  code: '',
  ownerId: undefined,
  status: 'IN_PROGRESS',
  description: '',
})

const rules: FormRules<typeof form> = {
  name: [
    { required: true, message: '请输入项目名称', trigger: 'blur' },
    { min: 2, max: 120, message: '项目名称长度应为 2 至 120 个字符', trigger: 'blur' },
  ],
  ownerId: [{ required: true, message: '请选择负责人', trigger: 'change' }],
  code: [
    { required: true, message: '请输入项目编码', trigger: 'blur' },
    {
      validator: (_rule, value: string, callback) => {
        if (isValidProjectCode(value)) callback()
        else callback(new Error('仅支持字母、数字、连字符和下划线'))
      },
      trigger: 'blur',
    },
  ],
  status: [{ required: true, message: '请选择状态', trigger: 'change' }],
}

const drawerTitle = computed(() => ({ create: '新建项目', edit: '编辑项目', view: '项目详情' })[drawerMode.value])
const inProgressCount = computed(() => projects.value.filter((project) => project.status === 'IN_PROGRESS').length)
const archivedCount = computed(() => projects.value.filter((project) => project.status === 'ARCHIVED').length)

function resetForm(): void {
  Object.assign(form, { name: '', code: '', ownerId: undefined, status: 'IN_PROGRESS', description: '' })
  selectedId.value = null
  selectedVersion.value = null
  drawerFailure.value = null
  formRef.value?.clearValidate()
}

function assignProject(project: Project): void {
  selectedId.value = project.id
  selectedVersion.value = project.version
  Object.assign(form, {
    name: project.name,
    code: project.code,
    ownerId: project.ownerId,
    status: project.status,
    description: project.description || '',
  })
}

async function loadOwners(): Promise<void> {
  ownersLoading.value = true
  try {
    owners.value = await listProjectOwners()
  } catch (error: unknown) {
    owners.value = []
    drawerFailure.value = toRequestFailure(error)
  } finally {
    ownersLoading.value = false
  }
}

function openCreate(): void {
  drawerMode.value = 'create'
  resetForm()
  drawerOpen.value = true
  void loadOwners()
}

async function openView(project: Project): Promise<void> {
  drawerMode.value = 'view'
  resetForm()
  assignProject(project)
  detailLoading.value = true
  drawerOpen.value = true
  try {
    await loadProjectDetail(project.id)
  } finally {
    detailLoading.value = false
  }
}

async function openEdit(project: Project): Promise<void> {
  drawerMode.value = 'edit'
  resetForm()
  assignProject(project)
  detailLoading.value = true
  drawerOpen.value = true
  try {
    await Promise.all([loadProjectDetail(project.id), loadOwners()])
  } finally {
    detailLoading.value = false
  }
}

async function loadProjectDetail(id: Project['id']): Promise<void> {
  try {
    assignProject(await getProject(id))
  } catch (error: unknown) {
    drawerFailure.value = toRequestFailure(error)
  }
}

async function saveProject(): Promise<void> {
  if (!formRef.value || !(await formRef.value.validate().catch(() => false))) return
  saving.value = true
  drawerFailure.value = null
  try {
    if (form.ownerId === undefined) return
    if (drawerMode.value === 'create') {
      await createProject({ ...form, ownerId: form.ownerId })
    } else if (selectedId.value !== null && selectedVersion.value !== null) {
      await updateProject(selectedId.value, {
        name: form.name,
        ownerId: form.ownerId,
        status: form.status,
        description: form.description,
        version: selectedVersion.value,
      })
    }
    ElMessage.success(drawerMode.value === 'create' ? '项目创建成功' : '项目更新成功')
    drawerOpen.value = false
    await loadProjects()
  } catch (error: unknown) {
    drawerFailure.value = toRequestFailure(error)
  } finally {
    saving.value = false
  }
}

async function confirmRemove(project: Project): Promise<void> {
  try {
    await ElMessageBox.confirm(`确定删除项目“${project.name}”吗？删除后无法恢复。`, '删除项目', {
      confirmButtonText: '删除',
      cancelButtonText: '取消',
      type: 'warning',
      confirmButtonClass: 'el-button--danger',
    })
    await removeProject(project.id, project.version)
    ElMessage.success('项目已删除')
    if (projects.value.length === 1 && query.page > 1) query.page -= 1
    await loadProjects()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    setPageError(error)
  }
}

</script>

<style scoped>
.project-summary {
  display: grid;
  margin-bottom: 28px;
  border-bottom: 1px solid var(--ws-border);
  grid-template-columns: repeat(3, 1fr);
}

.project-summary > div {
  position: relative;
  display: flex;
  min-height: 96px;
  padding: 12px 24px 24px;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

.project-summary > div + div::before {
  position: absolute;
  top: 16px;
  bottom: 22px;
  left: 0;
  width: 1px;
  content: '';
  background: var(--ws-border);
}

.project-summary span {
  margin-bottom: 8px;
  color: var(--ws-text-secondary);
  font-size: 13px;
}

.project-summary strong {
  color: var(--ws-teal-600);
  font-size: 31px;
  line-height: 1;
}

@media (max-width: 640px) {
  .project-summary > div { min-height: 82px; padding: 8px 5px 20px; }
  .project-summary strong { font-size: 25px; }
  .project-summary span { font-size: 12px; text-align: center; }
}
</style>

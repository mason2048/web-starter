import { request } from './http'
import type { PageData, PageQuery } from '@/types/api'
import type {
  ConfigRecord,
  LoginLog,
  McpCallLog,
  MenuRecord,
  OperationLog,
  PermissionRecord,
  RoleRecord,
  TraceAudit,
  UserRecord,
} from '@/types/models'

type ResourceId = string

export interface UserCreatePayload {
  username: string
  displayName: string
  password: string
  email?: string
  mobile?: string
  status: string
  roleIds: ResourceId[]
}

export interface UserUpdatePayload {
  displayName: string
  email?: string
  mobile?: string
  status: string
  version: number
  roleIds: ResourceId[]
}

export interface UserPasswordResetPayload {
  password: string
}

export interface RoleCreatePayload {
  code: string
  name: string
  description?: string
  status: string
  permissionIds: ResourceId[]
  menuIds: ResourceId[]
}

export interface RoleUpdatePayload {
  name: string
  description?: string
  status: string
  version: number
  permissionIds: ResourceId[]
  menuIds: ResourceId[]
}

export interface MenuPayload {
  parentId?: ResourceId
  name: string
  path?: string
  component?: string
  icon?: string
  sortOrder: number
  visible: boolean
  status: string
  permissionCode?: string
}

export interface ConfigPayload {
  configKey: string
  configValue: string
  valueType: string
  description?: string
}

function collection<T>(url: string, params: PageQuery): Promise<PageData<T>> {
  return request<PageData<T>>({ url, method: 'GET', params })
}

function create<T, P>(url: string, payload: P): Promise<T> {
  return request<T>({ url, method: 'POST', data: payload, csrf: true })
}

function update<T, P>(url: string, id: ResourceId, payload: P): Promise<T> {
  return request<T>({
    url: `${url}/${encodeURIComponent(id)}`,
    method: 'PUT',
    data: payload,
    csrf: true,
  })
}

function remove(url: string, id: ResourceId): Promise<void> {
  return request<void>({
    url: `${url}/${encodeURIComponent(id)}`,
    method: 'DELETE',
    csrf: true,
  })
}

export const usersApi = {
  list: (params: PageQuery) => collection<UserRecord>('/users', params),
  create: (payload: UserCreatePayload) => create<UserRecord, UserCreatePayload>('/users', payload),
  update: (id: ResourceId, payload: UserUpdatePayload) => update<UserRecord, UserUpdatePayload>('/users', id, payload),
  resetPassword: (id: ResourceId, payload: UserPasswordResetPayload) =>
    request<void>({
      url: `/users/${encodeURIComponent(id)}/password`,
      method: 'PUT',
      data: payload,
      csrf: true,
    }),
  remove: (id: ResourceId) => remove('/users', id),
}

export const rolesApi = {
  list: (params: PageQuery) => collection<RoleRecord>('/roles', params),
  create: (payload: RoleCreatePayload) => create<RoleRecord, RoleCreatePayload>('/roles', payload),
  update: (id: ResourceId, payload: RoleUpdatePayload) => update<RoleRecord, RoleUpdatePayload>('/roles', id, payload),
  remove: (id: ResourceId) => remove('/roles', id),
}

export const menusApi = {
  list: (status?: string) => request<MenuRecord[]>({ url: '/menus', method: 'GET', params: { status } }),
  create: (payload: MenuPayload) => create<MenuRecord, MenuPayload>('/menus', payload),
  update: (id: ResourceId, payload: MenuPayload) => update<MenuRecord, MenuPayload>('/menus', id, payload),
  remove: (id: ResourceId) => remove('/menus', id),
}

export const permissionsApi = {
  list: (params: { keyword?: string; status?: string } = {}) =>
    request<PermissionRecord[]>({ url: '/permissions', method: 'GET', params }),
}

export const configsApi = {
  list: (params: PageQuery) => collection<ConfigRecord>('/configs', params),
  create: (payload: ConfigPayload) => create<ConfigRecord, ConfigPayload>('/configs', payload),
  update: (id: ResourceId, payload: ConfigPayload) => update<ConfigRecord, ConfigPayload>('/configs', id, payload),
  remove: (id: ResourceId) => remove('/configs', id),
}

export const logsApi = {
  login: (params: PageQuery) => collection<LoginLog>('/logs/login', params),
  operation: (params: PageQuery) => collection<OperationLog>('/logs/operation', params),
  mcp: (params: PageQuery) => collection<McpCallLog>('/logs/mcp', params),
  trace: (traceId: string) => request<TraceAudit>({ url: `/logs/trace/${encodeURIComponent(traceId)}`, method: 'GET' }),
}

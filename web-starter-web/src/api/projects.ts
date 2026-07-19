import { request } from './http'
import type { PageData, PageQuery } from '@/types/api'
import type { Project, ProjectOwner, ProjectPayload, ProjectUpdatePayload } from '@/types/models'

export function listProjects(params: PageQuery): Promise<PageData<Project>> {
  return request<PageData<Project>>({ url: '/projects', method: 'GET', params })
}

export function getProject(id: Project['id']): Promise<Project> {
  return request<Project>({ url: `/projects/${encodeURIComponent(id)}`, method: 'GET' })
}

export function listProjectOwners(): Promise<ProjectOwner[]> {
  return request<ProjectOwner[]>({ url: '/projects/owners', method: 'GET' })
}

export function createProject(payload: ProjectPayload): Promise<Project> {
  return request<Project>({ url: '/projects', method: 'POST', data: payload, csrf: true })
}

export function updateProject(id: Project['id'], payload: ProjectUpdatePayload): Promise<Project> {
  return request<Project>({
    url: `/projects/${encodeURIComponent(id)}`,
    method: 'PUT',
    data: payload,
    csrf: true,
  })
}

export function removeProject(id: Project['id'], version: number): Promise<void> {
  return request<void>({
    url: `/projects/${encodeURIComponent(id)}`,
    method: 'DELETE',
    params: { version },
    csrf: true,
  })
}

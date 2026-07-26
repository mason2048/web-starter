import { request } from './http'
import {
  PRIVATE_API_OPERATIONS,
  type PrivateApiRequest,
  type PrivateApiResponse,
} from './generated/privateApiContract'

function pathWithId(template: string, id: string): string {
  return template.replace('{id}', encodeURIComponent(id))
}

export function listProjects(
  params: PrivateApiRequest<'project.list'>,
): Promise<PrivateApiResponse<'project.list'>> {
  const operation = PRIVATE_API_OPERATIONS['project.list']
  return request<PrivateApiResponse<'project.list'>>({ url: operation.path, method: operation.method, params })
}

export function getProject(
  id: PrivateApiRequest<'project.get'>,
): Promise<PrivateApiResponse<'project.get'>> {
  const operation = PRIVATE_API_OPERATIONS['project.get']
  return request<PrivateApiResponse<'project.get'>>({
    url: pathWithId(operation.path, id),
    method: operation.method,
  })
}

export function listProjectOwners(): Promise<PrivateApiResponse<'project.owners'>> {
  const operation = PRIVATE_API_OPERATIONS['project.owners']
  return request<PrivateApiResponse<'project.owners'>>({ url: operation.path, method: operation.method })
}

export function createProject(
  payload: PrivateApiRequest<'project.create'>,
): Promise<PrivateApiResponse<'project.create'>> {
  const operation = PRIVATE_API_OPERATIONS['project.create']
  return request<PrivateApiResponse<'project.create'>>({
    url: operation.path,
    method: operation.method,
    data: payload,
    csrf: operation.csrf,
  })
}

export function updateProject(
  id: PrivateApiRequest<'project.update'>['id'],
  payload: PrivateApiRequest<'project.update'>['payload'],
): Promise<PrivateApiResponse<'project.update'>> {
  const operation = PRIVATE_API_OPERATIONS['project.update']
  return request<PrivateApiResponse<'project.update'>>({
    url: pathWithId(operation.path, id),
    method: operation.method,
    data: payload,
    csrf: operation.csrf,
  })
}

export function removeProject(
  id: PrivateApiRequest<'project.remove'>['id'],
  version: PrivateApiRequest<'project.remove'>['version'],
): Promise<PrivateApiResponse<'project.remove'>> {
  const operation = PRIVATE_API_OPERATIONS['project.remove']
  return request<PrivateApiResponse<'project.remove'>>({
    url: pathWithId(operation.path, id),
    method: operation.method,
    params: { version },
    csrf: operation.csrf,
  })
}

export type EnableStatus = 'ENABLED' | 'DISABLED'
export type ProjectStatus = 'PLANNING' | 'IN_PROGRESS' | 'ARCHIVED'

export interface CurrentUser {
  callerType?: string
  subjectId: string
  username: string
  displayName?: string
  tokenId?: string
  clientId?: string
  scopes?: string[]
  permissions?: string[]
  menuIds?: string[]
  traceId?: string
}

export interface ChangeOwnPasswordPayload {
  currentPassword: string
  newPassword: string
}

export interface WebSessionSummary {
  reference: string
  current: boolean
  createdAt: string
  lastAccessedAt: string
  expiresAt: string
  ipAddress?: string
  userAgent?: string
}

export interface RevokedSessionsResult {
  revoked: number
}

export interface IssueTokenPayload {
  name: string
  scopes: string[]
  allowedIpCidrs: string[]
  expiresAt?: string
}

export interface IssuedToken {
  id: string
  type: string
  token: string
  tokenHint: string
  scopes: string[]
  expiresAt?: string
}

export interface TokenSummary {
  id: string
  type: string
  name: string
  tokenHint: string
  scopes: string[]
  allowedIpCidrs: string[]
  expiresAt?: string
  revokedAt?: string
  lastUsedAt?: string
  createdAt?: string
}

export interface ServiceAccount {
  id: string
  code: string
  displayName: string
  description?: string
  enabled: boolean
  roleIds: string[]
  createdAt?: string
  updatedAt?: string
}

export interface CreateServiceAccountPayload {
  code: string
  displayName: string
  description?: string
  roleIds: string[]
}

export interface UpdateServiceAccountPayload {
  displayName: string
  description?: string
  enabled: boolean
  roleIds: string[]
}

export interface OAuthClient {
  id: string
  clientId: string
  clientName: string
  authenticationMethods: string[]
  grantTypes: string[]
  redirectUris: string[]
  scopes: string[]
  requireConsent: boolean
  requirePkce: boolean
  serviceAccountId?: string
  clientSecretVersion?: string
  retiringClientSecretVersion?: string
  retiringClientSecretExpiresAt?: string
  clientSecretRotatedAt?: string
  enabled: boolean
  createdAt?: string
  updatedAt?: string
}

export interface CreateOAuthClientPayload {
  clientId: string
  clientName: string
  authenticationMethods: string[]
  grantTypes: string[]
  redirectUris: string[]
  scopes: string[]
  requireConsent: boolean
  serviceAccountId?: string
}

export interface UpdateOAuthClientPayload {
  clientName: string
  authenticationMethods: string[]
  grantTypes: string[]
  redirectUris: string[]
  scopes: string[]
  requireConsent: boolean
  serviceAccountId?: string
  enabled: boolean
}

export interface CreatedOAuthClient {
  client: OAuthClient
  clientSecret?: string | null
}

export interface Project {
  id: string
  name: string
  code: string
  ownerId?: string
  ownerName?: string
  status: ProjectStatus
  description?: string
  version: number
  createdAt?: string
  updatedAt?: string
}

export interface ProjectPayload {
  name: string
  code: string
  ownerId: string
  status: ProjectStatus
  description?: string
}

export interface ProjectUpdatePayload {
  name: string
  ownerId: string
  status: ProjectStatus
  description?: string
  version: number
}

export interface ProjectOwner {
  id: string
  username: string
  displayName: string
}

export interface UserRecord {
  id: string
  username: string
  displayName?: string
  email?: string
  mobile?: string
  enabled?: boolean
  status?: EnableStatus
  roleIds?: string[]
  roleNames?: string[]
  version: number
  createdAt?: string
  updatedAt?: string
}

export interface RoleRecord {
  id: string
  name: string
  code: string
  description?: string
  enabled?: boolean
  status?: EnableStatus
  menuIds?: string[]
  permissionIds?: string[]
  version: number
  createdAt?: string
  updatedAt?: string
}

export interface PermissionRecord {
  id: string
  code: string
  name: string
  type?: string
  description?: string
  status?: EnableStatus
}

export interface MenuRecord {
  id: string
  parentId?: string
  name: string
  type?: 'DIRECTORY' | 'MENU' | 'BUTTON'
  path?: string
  component?: string
  permissionCode?: string
  icon?: string
  sortOrder?: number
  visible?: boolean
  status?: EnableStatus
  children?: MenuRecord[]
}

export interface ConfigRecord {
  id: string
  configKey: string
  configValue: string
  valueType: string
  description?: string
  builtin: boolean
}

export interface LoginLog {
  id: string
  username?: string
  result?: string
  failureReason?: string
  ipAddress?: string
  userAgent?: string
  traceId?: string
  createdAt?: string
}

export interface OperationLog {
  id: string
  actorType?: string
  actorId?: string
  actorName?: string
  module?: string
  action?: string
  resourceType?: string
  resourceId?: string
  result?: string
  requestMethod?: string
  requestPath?: string
  ipAddress?: string
  durationMs?: number
  traceId?: string
  detailJson?: string
  createdAt?: string
}

export interface McpCallLog {
  id: string
  actorName?: string
  actorType?: string
  actorId?: string
  tokenId?: string
  clientId?: string
  toolName?: string
  permissionCode?: string
  result?: string
  durationMs?: number
  ipAddress?: string
  traceId?: string
  errorCode?: string
  idempotencyKeyHash?: string
  replayed?: boolean
  createdAt?: string
}

export interface TraceAudit {
  traceId: string
  loginLogs: LoginLog[]
  operationLogs: OperationLog[]
  mcpCalls: McpCallLog[]
  truncated: boolean
}

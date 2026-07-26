import { request } from './http'
import type {
  ChangeOwnPasswordPayload,
  CreateOAuthClientPayload,
  CreatedOAuthClient,
  CreateServiceAccountPayload,
  IssuedToken,
  IssueTokenPayload,
  OAuthClient,
  RevokedSessionsResult,
  ServiceAccount,
  TokenSummary,
  UpdateServiceAccountPayload,
  UpdateOAuthClientPayload,
  WebSessionSummary,
} from '@/types/models'

type ResourceId = string

function encoded(id: ResourceId): string {
  return encodeURIComponent(id)
}

export const accountSecurityApi = {
  changePassword: (payload: ChangeOwnPasswordPayload) =>
    request<void>({
      url: '/security/me/password',
      method: 'PUT',
      data: payload,
      csrf: true,
    }),
  listSessions: () =>
    request<WebSessionSummary[]>({
      url: '/security/me/sessions',
      method: 'GET',
    }),
  revokeSession: (reference: string) =>
    request<void>({
      url: `/security/me/sessions/${encoded(reference)}`,
      method: 'DELETE',
      csrf: true,
    }),
  revokeOtherSessions: () =>
    request<RevokedSessionsResult>({
      url: '/security/me/sessions/others',
      method: 'DELETE',
      csrf: true,
    }),
  securityLogout: () =>
    request<void>({
      url: '/security/me/security-logout',
      method: 'POST',
      csrf: true,
    }),
}

export const personalTokensApi = {
  list: () => request<TokenSummary[]>({ url: '/security/personal-tokens', method: 'GET' }),
  issue: (payload: IssueTokenPayload) =>
    request<IssuedToken>({
      url: '/security/personal-tokens',
      method: 'POST',
      data: payload,
      csrf: true,
    }),
  revoke: (id: ResourceId) =>
    request<void>({
      url: `/security/personal-tokens/${encoded(id)}`,
      method: 'DELETE',
      csrf: true,
    }),
}

export const serviceAccountsApi = {
  list: () => request<ServiceAccount[]>({ url: '/security/service-accounts', method: 'GET' }),
  create: (payload: CreateServiceAccountPayload) =>
    request<ServiceAccount>({
      url: '/security/service-accounts',
      method: 'POST',
      data: payload,
      csrf: true,
    }),
  update: (id: ResourceId, payload: UpdateServiceAccountPayload) =>
    request<ServiceAccount>({
      url: `/security/service-accounts/${encoded(id)}`,
      method: 'PUT',
      data: payload,
      csrf: true,
    }),
  disable: (id: ResourceId) =>
    request<void>({
      url: `/security/service-accounts/${encoded(id)}`,
      method: 'DELETE',
      csrf: true,
    }),
  listTokens: (id: ResourceId) =>
    request<TokenSummary[]>({
      url: `/security/service-accounts/${encoded(id)}/tokens`,
      method: 'GET',
    }),
  issueToken: (id: ResourceId, payload: IssueTokenPayload) =>
    request<IssuedToken>({
      url: `/security/service-accounts/${encoded(id)}/tokens`,
      method: 'POST',
      data: payload,
      csrf: true,
    }),
  revokeToken: (accountId: ResourceId, tokenId: ResourceId) =>
    request<void>({
      url: `/security/service-accounts/${encoded(accountId)}/tokens/${encoded(tokenId)}`,
      method: 'DELETE',
      csrf: true,
    }),
}

export const oauthClientsApi = {
  list: () => request<OAuthClient[]>({ url: '/security/oauth-clients', method: 'GET' }),
  create: (payload: CreateOAuthClientPayload) =>
    request<CreatedOAuthClient>({
      url: '/security/oauth-clients',
      method: 'POST',
      data: payload,
      csrf: true,
    }),
  update: (id: ResourceId, payload: UpdateOAuthClientPayload) =>
    request<OAuthClient>({
      url: `/security/oauth-clients/${encoded(id)}`,
      method: 'PUT',
      data: payload,
      csrf: true,
    }),
  rotateSecret: (id: ResourceId) =>
    request<CreatedOAuthClient>({
      url: `/security/oauth-clients/${encoded(id)}/rotate-secret`,
      method: 'POST',
      csrf: true,
    }),
  revokeRetiringSecret: (id: ResourceId) =>
    request<OAuthClient>({
      url: `/security/oauth-clients/${encoded(id)}/retiring-secret`,
      method: 'DELETE',
      csrf: true,
    }),
}

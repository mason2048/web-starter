import { beforeEach, describe, expect, it, vi } from 'vitest'
import { request } from './http'
import { configsApi, menusApi, rolesApi, usersApi } from './admin'
import { listProjectOwners, removeProject, updateProject } from './projects'
import { accountSecurityApi, oauthClientsApi, personalTokensApi, serviceAccountsApi } from './security'

vi.mock('./http', () => ({ request: vi.fn() }))

const requestMock = vi.mocked(request)

describe('backend request contracts', () => {
  beforeEach(() => {
    requestMock.mockReset()
  })

  it('sends optimistic-lock version for project update and delete', () => {
    updateProject('9007199254740993', {
      name: '项目七',
      ownerId: '9007199254740995',
      status: 'IN_PROGRESS',
      description: '说明',
      version: 4,
    })
    removeProject('9007199254740993', 4)

    expect(requestMock).toHaveBeenNthCalledWith(1, {
      url: '/projects/9007199254740993',
      method: 'PUT',
      data: {
        name: '项目七',
        ownerId: '9007199254740995',
        status: 'IN_PROGRESS',
        description: '说明',
        version: 4,
      },
      csrf: true,
    })
    expect(requestMock).toHaveBeenNthCalledWith(2, {
      url: '/projects/9007199254740993',
      method: 'DELETE',
      params: { version: 4 },
      csrf: true,
    })
  })

  it('loads project owner choices from the project permission boundary', () => {
    listProjectOwners()

    expect(requestMock).toHaveBeenCalledWith({
      url: '/projects/owners',
      method: 'GET',
    })
  })

  it('uses versioned user and role update DTOs', () => {
    usersApi.update('2', {
      displayName: '测试用户',
      status: 'ENABLED',
      version: 3,
      roleIds: ['1'],
    })
    rolesApi.update('1', {
      name: '项目管理员',
      status: 'ENABLED',
      version: 5,
      permissionIds: ['10', '11'],
      menuIds: ['20'],
    })

    expect(requestMock.mock.calls[0]?.[0]).toMatchObject({
      url: '/users/2',
      data: { displayName: '测试用户', status: 'ENABLED', version: 3, roleIds: ['1'] },
    })
    expect(requestMock.mock.calls[1]?.[0]).toMatchObject({
      url: '/roles/1',
      data: { name: '项目管理员', status: 'ENABLED', version: 5, permissionIds: ['10', '11'], menuIds: ['20'] },
    })
  })

  it('uses the dedicated CSRF-protected user password reset contract', () => {
    usersApi.resetPassword('2', { password: 'a-new-long-password' })

    expect(requestMock).toHaveBeenCalledWith({
      url: '/users/2/password',
      method: 'PUT',
      data: { password: 'a-new-long-password' },
      csrf: true,
    })
  })

  it('uses the self-service password and opaque Session management contracts', () => {
    accountSecurityApi.changePassword({
      currentPassword: 'current-password',
      newPassword: 'a-new-long-password',
    })
    accountSecurityApi.listSessions()
    accountSecurityApi.revokeSession('opaque/session reference')
    accountSecurityApi.revokeOtherSessions()
    accountSecurityApi.securityLogout()

    expect(requestMock.mock.calls).toEqual([
      [
        {
          url: '/security/me/password',
          method: 'PUT',
          data: { currentPassword: 'current-password', newPassword: 'a-new-long-password' },
          csrf: true,
        },
      ],
      [{ url: '/security/me/sessions', method: 'GET' }],
      [
        {
          url: '/security/me/sessions/opaque%2Fsession%20reference',
          method: 'DELETE',
          csrf: true,
        },
      ],
      [{ url: '/security/me/sessions/others', method: 'DELETE', csrf: true }],
      [{ url: '/security/me/security-logout', method: 'POST', csrf: true }],
    ])
  })

  it('uses backend field names for menu and config payloads', () => {
    menusApi.create({
      name: '项目列表',
      path: '/projects',
      sortOrder: 2,
      visible: true,
      status: 'ENABLED',
      permissionCode: 'project:list',
    })
    configsApi.create({
      configKey: 'system.page-size',
      configValue: '20',
      valueType: 'NUMBER',
    })

    expect(requestMock.mock.calls[0]?.[0]).toMatchObject({
      url: '/menus',
      data: { sortOrder: 2, permissionCode: 'project:list', status: 'ENABLED' },
    })
    expect(requestMock.mock.calls[1]?.[0]).toMatchObject({
      url: '/configs',
      data: { configKey: 'system.page-size', configValue: '20', valueType: 'NUMBER' },
    })
  })

  it('uses the personal and service-account credential contracts', () => {
    const payload = {
      name: '内网 Agent',
      scopes: ['project:list'],
      allowedIpCidrs: ['10.0.0.0/8'],
      expiresAt: '2027-01-01T00:00:00.000Z',
    }

    personalTokensApi.issue(payload)
    personalTokensApi.revoke('12')
    serviceAccountsApi.issueToken('8', payload)
    serviceAccountsApi.revokeToken('8', '16')

    expect(requestMock.mock.calls).toEqual([
      [{ url: '/security/personal-tokens', method: 'POST', data: payload, csrf: true }],
      [{ url: '/security/personal-tokens/12', method: 'DELETE', csrf: true }],
      [{ url: '/security/service-accounts/8/tokens', method: 'POST', data: payload, csrf: true }],
      [{ url: '/security/service-accounts/8/tokens/16', method: 'DELETE', csrf: true }],
    ])
  })

  it('uses exact service-account create and update DTOs', () => {
    serviceAccountsApi.create({
      code: 'report_agent',
      displayName: '报表 Agent',
      description: '固定自动化任务',
      roleIds: ['1', '2'],
    })
    serviceAccountsApi.update('8', {
      displayName: '报表 Agent',
      description: '已限制权限',
      enabled: false,
      roleIds: ['2'],
    })

    expect(requestMock).toHaveBeenNthCalledWith(1, {
      url: '/security/service-accounts',
      method: 'POST',
      data: {
        code: 'report_agent',
        displayName: '报表 Agent',
        description: '固定自动化任务',
        roleIds: ['1', '2'],
      },
      csrf: true,
    })
    expect(requestMock).toHaveBeenNthCalledWith(2, {
      url: '/security/service-accounts/8',
      method: 'PUT',
      data: {
        displayName: '报表 Agent',
        description: '已限制权限',
        enabled: false,
        roleIds: ['2'],
      },
      csrf: true,
    })
  })

  it('uses the OAuth client create and secret-rotation contracts', () => {
    const payload = {
      clientId: 'agent-console',
      clientName: 'Agent Console',
      authenticationMethods: ['client_secret_basic'],
      grantTypes: ['client_credentials'],
      redirectUris: [],
      scopes: ['project:list'],
      requireConsent: false,
      serviceAccountId: '8',
    }

    oauthClientsApi.create(payload)
    oauthClientsApi.update('client-record-id', {
      clientName: 'Agent Console',
      authenticationMethods: ['client_secret_basic'],
      grantTypes: ['client_credentials'],
      redirectUris: [],
      scopes: ['project:list'],
      requireConsent: false,
      serviceAccountId: '8',
      enabled: false,
    })
    oauthClientsApi.rotateSecret('client-record-id')
    oauthClientsApi.revokeRetiringSecret('client-record-id')

    expect(requestMock).toHaveBeenNthCalledWith(1, {
      url: '/security/oauth-clients',
      method: 'POST',
      data: payload,
      csrf: true,
    })
    expect(requestMock).toHaveBeenNthCalledWith(2, {
      url: '/security/oauth-clients/client-record-id',
      method: 'PUT',
      data: {
        clientName: 'Agent Console',
        authenticationMethods: ['client_secret_basic'],
        grantTypes: ['client_credentials'],
        redirectUris: [],
        scopes: ['project:list'],
        requireConsent: false,
        serviceAccountId: '8',
        enabled: false,
      },
      csrf: true,
    })
    expect(requestMock).toHaveBeenNthCalledWith(3, {
      url: '/security/oauth-clients/client-record-id/rotate-secret',
      method: 'POST',
      csrf: true,
    })
    expect(requestMock).toHaveBeenNthCalledWith(4, {
      url: '/security/oauth-clients/client-record-id/retiring-secret',
      method: 'DELETE',
      csrf: true,
    })
  })
})

/* eslint-disable vue/one-component-per-file */
import { createPinia, setActivePinia } from 'pinia'
import { defineComponent, h } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { ElMessage, ElMessageBox } from 'element-plus'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AccountSecurityView from './AccountSecurityView.vue'
import { accountSecurityApi } from '@/api/security'
import { useAuthStore } from '@/stores/auth'

const { replaceMock } = vi.hoisted(() => ({ replaceMock: vi.fn() }))

vi.mock('vue-router', () => ({
  useRouter: () => ({ replace: replaceMock }),
}))

vi.mock('@/api/security', () => ({
  accountSecurityApi: {
    changePassword: vi.fn(),
    listSessions: vi.fn(),
    revokeSession: vi.fn(),
    revokeOtherSessions: vi.fn(),
  },
}))

const FormStub = defineComponent({
  inheritAttrs: false,
  setup(_props, { attrs, expose, slots }) {
    expose({ validate: vi.fn().mockResolvedValue(true) })
    return () => h('form', attrs, slots.default?.())
  },
})

const InputStub = defineComponent({
  inheritAttrs: false,
  props: { modelValue: { type: String, default: '' } },
  emits: ['update:modelValue'],
  setup(props, { attrs, emit }) {
    return () =>
      h('input', {
        ...attrs,
        value: props.modelValue,
        onInput: (event: Event) => emit('update:modelValue', (event.target as HTMLInputElement).value),
      })
  },
})

const ButtonStub = defineComponent({
  inheritAttrs: false,
  props: {
    disabled: Boolean,
    nativeType: { type: String, default: 'button' },
  },
  emits: ['click'],
  setup(props, { attrs, emit, slots }) {
    return () =>
      h(
        'button',
        {
          ...attrs,
          disabled: props.disabled,
          type: props.nativeType,
          onClick: () => emit('click'),
        },
        slots.default?.(),
      )
  },
})

function mountView() {
  return mount(AccountSecurityView, {
    global: {
      directives: { loading: () => undefined },
      stubs: {
        PageHeader: { template: '<header />' },
        RequestError: { props: ['message'], template: '<p class="request-error">{{ message }}</p>' },
        ElAlert: true,
        ElForm: FormStub,
        ElFormItem: { template: '<label><slot /></label>' },
        ElInput: InputStub,
        ElButton: ButtonStub,
        ElEmpty: { props: ['description'], template: '<p>{{ description }}</p>' },
        ElTag: { template: '<span><slot /></span>' },
        ElIcon: { template: '<i><slot /></i>' },
        Lock: true,
        Monitor: true,
        Refresh: true,
      },
    },
  })
}

describe('AccountSecurityView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    replaceMock.mockReset()
    vi.mocked(accountSecurityApi.changePassword).mockReset().mockResolvedValue(undefined)
    vi.mocked(accountSecurityApi.revokeSession).mockReset().mockResolvedValue(undefined)
    vi.mocked(accountSecurityApi.revokeOtherSessions).mockReset().mockResolvedValue({ revoked: 1 })
    vi.mocked(accountSecurityApi.listSessions).mockReset().mockResolvedValue([
      {
        reference: 'current-ref',
        current: true,
        createdAt: '2026-07-19T01:00:00Z',
        lastAccessedAt: '2026-07-19T02:00:00Z',
        expiresAt: '2026-07-19T03:00:00Z',
        ipAddress: '10.0.0.10',
        userAgent: 'Mozilla/5.0 (Mac OS X) Chrome/140.0',
      },
      {
        reference: 'other-ref',
        current: false,
        createdAt: '2026-07-18T01:00:00Z',
        lastAccessedAt: '2026-07-18T02:00:00Z',
        expiresAt: '2026-07-20T03:00:00Z',
        ipAddress: '10.0.0.11',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0) Edg/140.0',
      },
    ])
    vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    vi.spyOn(ElMessage, 'success').mockReturnValue({ close: vi.fn() })
  })

  it('lists opaque sessions and supports targeted and other-device revocation', async () => {
    const wrapper = mountView()
    await flushPromises()

    expect(accountSecurityApi.listSessions).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('Chrome · macOS')
    expect(wrapper.text()).toContain('Edge · Windows')
    expect(wrapper.text()).not.toContain('角色分配')

    await wrapper.get('[data-testid="revoke-session-other-ref"]').trigger('click')
    await flushPromises()
    expect(accountSecurityApi.revokeSession).toHaveBeenCalledWith('other-ref')

    await wrapper.get('[data-testid="revoke-other-sessions"]').trigger('click')
    await flushPromises()
    expect(accountSecurityApi.revokeOtherSessions).toHaveBeenCalledTimes(1)
  })

  it('changes only the current user password, clears local auth and redirects to login', async () => {
    const auth = useAuthStore()
    auth.currentUser = { subjectId: '7', username: 'operator', permissions: [] }
    const wrapper = mountView()
    await flushPromises()

    await wrapper.get('[data-testid="current-password"]').setValue('old-password-value')
    await wrapper.get('[data-testid="new-password"]').setValue('new-password-value')
    await wrapper.get('[data-testid="confirm-password"]').setValue('new-password-value')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(accountSecurityApi.changePassword).toHaveBeenCalledWith({
      currentPassword: 'old-password-value',
      newPassword: 'new-password-value',
    })
    expect(auth.currentUser).toBeNull()
    expect(replaceMock).toHaveBeenCalledWith({ name: 'login', query: { reason: 'password-changed' } })
  })
})

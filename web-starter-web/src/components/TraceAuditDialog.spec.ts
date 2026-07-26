/* eslint-disable vue/one-component-per-file */
import { defineComponent, h } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import TraceAuditDialog from './TraceAuditDialog.vue'
import { logsApi } from '@/api/admin'

vi.mock('@/api/admin', () => ({
  logsApi: { trace: vi.fn() },
}))

const PassThrough = defineComponent({
  inheritAttrs: false,
  setup(_props, { attrs, slots }) {
    return () => h('div', attrs, slots.default?.())
  },
})

const DialogStub = defineComponent({
  inheritAttrs: false,
  props: { title: { type: String, default: '' } },
  setup(props, { attrs, slots }) {
    return () => h('section', { ...attrs, role: 'dialog', 'aria-label': props.title }, slots.default?.())
  },
})

function mountDialog() {
  return mount(TraceAuditDialog, {
    props: { modelValue: true, traceId: 'trace-dialog-1' },
    global: {
      stubs: {
        ElDialog: DialogStub,
        ElDescriptions: PassThrough,
        ElDescriptionsItem: PassThrough,
        ElEmpty: PassThrough,
        ElTimeline: PassThrough,
        ElTimelineItem: PassThrough,
        ElTag: PassThrough,
        ElSkeleton: PassThrough,
        RequestError: PassThrough,
      },
    },
  })
}

describe('TraceAuditDialog', () => {
  beforeEach(() => {
    vi.mocked(logsApi.trace).mockReset().mockResolvedValue({
      traceId: 'trace-dialog-1',
      truncated: false,
      loginLogs: [{
        id: '1', username: 'operator', result: 'SUCCESS', ipAddress: '10.0.0.1',
        userAgent: 'browser-without-secrets', traceId: 'trace-dialog-1',
        createdAt: '2026-07-19T10:00:00',
      }],
      operationLogs: [{
        id: '2', actorName: 'Operator', module: 'project', action: 'CREATE',
        resourceType: 'project', resourceId: '42', result: 'SUCCESS',
        detailJson: '{"password":"must-not-render"}', traceId: 'trace-dialog-1',
        createdAt: '2026-07-19T10:00:01',
      }],
      mcpCalls: [{
        id: '3', actorName: 'Operator', tokenId: 'credential-record-must-not-render',
        toolName: 'project.create', result: 'SUCCESS', traceId: 'trace-dialog-1',
        createdAt: '2026-07-19T10:00:02',
      }],
    })
  })

  it('renders one chronologically correlated login operation and MCP chain without secret-bearing fields', async () => {
    const wrapper = mountDialog()
    await flushPromises()

    expect(logsApi.trace).toHaveBeenCalledWith('trace-dialog-1')
    expect(wrapper.get('[data-testid="trace-login-count"]').text()).toBe('登录 1')
    expect(wrapper.get('[data-testid="trace-operation-count"]').text()).toBe('操作 1')
    expect(wrapper.get('[data-testid="trace-mcp-count"]').text()).toBe('MCP 1')
    expect(wrapper.findAll('[data-testid^="trace-entry-"]').map((item) => item.attributes('data-testid')))
      .toEqual(['trace-entry-login-1', 'trace-entry-operation-2', 'trace-entry-mcp-3'])
    expect(wrapper.text()).toContain('操作 · project · CREATE')
    expect(wrapper.text()).toContain('资源 project 42')
    expect(wrapper.text()).toContain('MCP · project.create')
    expect(wrapper.text()).toContain('凭据已脱敏')
    expect(wrapper.text()).not.toContain('must-not-render')
    expect(wrapper.text()).not.toContain('credential-record-must-not-render')
  })
})

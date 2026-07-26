import { defineComponent, h } from 'vue'
import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import RequestError from './RequestError.vue'
import type { RequestFailure } from '@/api/requestFailure'

const AlertStub = defineComponent({
  props: { title: { type: String, default: '' } },
  setup(props, { slots }) {
    return () => h('section', [h('strong', props.title), slots.default?.()])
  },
})

describe('RequestError', () => {
  it('shows a server failure message and its trace id to the operator', () => {
    const wrapper = mount(RequestError, {
      props: {
        message: '服务器暂时无法处理请求，请稍后重试',
        traceId: 'trace-http-500',
      },
      global: {
        stubs: { ElAlert: AlertStub },
      },
    })

    expect(wrapper.text()).toContain('服务器暂时无法处理请求，请稍后重试')
    expect(wrapper.text()).toContain('Trace ID：trace-http-500')
  })

  it('renders a normalized failure title, guidance and trace id', () => {
    const failure: RequestFailure = {
      kind: 'conflict',
      title: '数据已发生变化',
      message: '数据已被其他操作更新，请刷新后重试。',
      status: 409,
      traceId: 'trace-conflict',
      retryable: true,
    }
    const wrapper = mount(RequestError, {
      props: { failure },
      global: { stubs: { ElAlert: AlertStub } },
    })

    expect(wrapper.text()).toContain('数据已发生变化')
    expect(wrapper.text()).toContain('请刷新后重试')
    expect(wrapper.text()).toContain('Trace ID：trace-conflict')
  })
})

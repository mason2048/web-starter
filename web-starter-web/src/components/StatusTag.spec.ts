import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import StatusTag from './StatusTag.vue'

describe('StatusTag', () => {
  it('renders project state in Chinese', () => {
    const wrapper = mount(StatusTag, { props: { value: 'IN_PROGRESS' } })
    expect(wrapper.text()).toContain('进行中')
  })

  it('renders disabled state consistently', () => {
    const wrapper = mount(StatusTag, { props: { value: false } })
    expect(wrapper.text()).toContain('停用')
  })
})

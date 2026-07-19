/* eslint-disable vue/one-component-per-file */
import { defineComponent, h, nextTick } from 'vue'
import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import OneTimeSecretDialog from './OneTimeSecretDialog.vue'

const DialogStub = defineComponent({
  props: { modelValue: Boolean },
  setup(props, { slots }) {
    return () => (props.modelValue ? h('section', [slots.header?.(), slots.default?.(), slots.footer?.()]) : null)
  },
})

const CheckboxStub = defineComponent({
  props: { modelValue: Boolean },
  emits: ['update:modelValue'],
  setup(props, { emit, slots }) {
    return () =>
      h('label', [
        h('input', {
          type: 'checkbox',
          checked: props.modelValue,
          onChange: (event: Event) => emit('update:modelValue', (event.target as HTMLInputElement).checked),
        }),
        slots.default?.(),
      ])
  },
})

const ButtonStub = defineComponent({
  inheritAttrs: false,
  props: { disabled: Boolean },
  emits: ['click'],
  setup(props, { attrs, emit, slots }) {
    return () =>
      h(
        'button',
        {
          ...attrs,
          disabled: props.disabled,
          onClick: () => emit('click'),
        },
        slots.default?.(),
      )
  },
})

describe('OneTimeSecretDialog', () => {
  it('requires acknowledgement and erases its displayed plaintext after consumption', async () => {
    const wrapper = mount(OneTimeSecretDialog, {
      props: { modelValue: true, secret: 'ws_pat_once_only' },
      global: {
        stubs: {
          ElDialog: DialogStub,
          ElAlert: true,
          ElCheckbox: CheckboxStub,
          ElButton: ButtonStub,
          ElIcon: true,
          Lock: true,
        },
      },
    })

    expect(wrapper.get('[data-testid="one-time-secret"]').text()).toBe('ws_pat_once_only')
    expect(wrapper.get('[data-testid="secret-confirm"]').attributes('disabled')).toBeDefined()

    await wrapper.get('input[type="checkbox"]').setValue(true)
    await nextTick()
    expect(wrapper.get('[data-testid="secret-confirm"]').attributes('disabled')).toBeUndefined()

    await wrapper.get('[data-testid="secret-confirm"]').trigger('click')
    expect(wrapper.emitted('consumed')).toHaveLength(1)
    expect(wrapper.emitted('update:modelValue')).toEqual([[false]])
    expect(wrapper.get('[data-testid="one-time-secret"]').text()).toBe('')
  })
})

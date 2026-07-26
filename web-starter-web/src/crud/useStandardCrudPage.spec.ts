/* eslint-disable vue/one-component-per-file */
import { defineComponent, h } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter, useRoute, useRouter } from 'vue-router'
import { describe, expect, it, vi } from 'vitest'
import {
  parseStandardCrudQuery,
  serializeStandardCrudQuery,
  standardCrudRequestQuery,
  useStandardCrudPage,
} from './useStandardCrudPage'

describe('standard CRUD URL state', () => {
  const statuses = ['PLANNING', 'IN_PROGRESS', 'ARCHIVED']

  it('parses a safe allow-listed URL query', () => {
    expect(
      parseStandardCrudQuery(
        { page: '3', size: '20', keyword: 'starter', status: 'IN_PROGRESS' },
        statuses,
      ),
    ).toEqual({ page: 3, size: 20, keyword: 'starter', status: 'IN_PROGRESS' })
  })

  it('fails closed to defaults for malformed page, size and status values', () => {
    expect(parseStandardCrudQuery({ page: '-1', size: '999', status: 'DELETED' }, statuses)).toEqual({
      page: 1,
      size: 10,
      keyword: '',
      status: '',
    })
  })

  it('serializes canonical URL state and omits empty API filters', () => {
    const query = { page: 2, size: 50, keyword: '', status: '' }
    expect(serializeStandardCrudQuery(query)).toEqual({ page: '2', size: '50' })
    expect(standardCrudRequestQuery(query)).toEqual({
      page: 2,
      size: 50,
      keyword: undefined,
      status: undefined,
    })
  })

  it('loads from the URL and reloads when browser navigation changes the query', async () => {
    const fetchPage = vi.fn().mockResolvedValue({ records: [{ id: '1' }], total: 1, page: 3, size: 20 })
    const Harness = defineComponent({
      setup() {
        const page = useStandardCrudPage<{ id: string }>({
          route: useRoute(),
          router: useRouter(),
          statuses,
          fetchPage,
        })
        return () => h('span', `${page.query.page}:${page.query.keyword}:${page.phase.value}`)
      },
    })
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/items', component: Harness }],
    })
    await router.push('/items?page=3&size=20&keyword=starter&status=IN_PROGRESS')
    await router.isReady()
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()

    expect(fetchPage).toHaveBeenNthCalledWith(1, {
      page: 3,
      size: 20,
      keyword: 'starter',
      status: 'IN_PROGRESS',
    })
    expect(wrapper.text()).toBe('3:starter:ready')

    fetchPage.mockResolvedValue({ records: [], total: 0, page: 2, size: 20 })
    await router.push('/items?page=2&size=20&keyword=next')
    await flushPromises()
    expect(fetchPage).toHaveBeenNthCalledWith(2, {
      page: 2,
      size: 20,
      keyword: 'next',
      status: undefined,
    })
    expect(wrapper.text()).toBe('2:next:empty')
    wrapper.unmount()
  })

  it('uses the submitted query snapshot when URL synchronization is delayed', async () => {
    let releaseNavigation!: () => void
    let navigationStarted!: () => void
    const navigationGate = new Promise<void>((resolve) => {
      releaseNavigation = resolve
    })
    const navigationStart = new Promise<void>((resolve) => {
      navigationStarted = resolve
    })
    const fetchPage = vi.fn().mockImplementation(async (query: { page: number; size: number; keyword?: string }) => ({
      records: [{ id: query.keyword || 'initial' }],
      total: 1,
      page: query.page,
      size: query.size,
    }))
    let crudPage!: ReturnType<typeof useStandardCrudPage<{ id: string }>>
    const Harness = defineComponent({
      setup() {
        crudPage = useStandardCrudPage<{ id: string }>({
          route: useRoute(),
          router: useRouter(),
          statuses,
          fetchPage,
        })
        return () => h('span', `${crudPage.query.keyword}:${crudPage.phase.value}`)
      },
    })
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/items', component: Harness }],
    })
    router.beforeEach(async (to) => {
      if (to.query.keyword !== 'Roadmap') return true
      navigationStarted()
      await navigationGate
      return true
    })
    await router.push('/items?page=2&size=20&keyword=Initial')
    await router.isReady()
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()

    crudPage.query.keyword = 'Roadmap'
    const submittedSearch = crudPage.search()
    await navigationStart
    crudPage.query.keyword = 'DraftOnly'
    releaseNavigation()
    await submittedSearch

    expect(fetchPage).toHaveBeenNthCalledWith(2, {
      page: 1,
      size: 20,
      keyword: 'Roadmap',
      status: undefined,
    })
    expect(router.currentRoute.value.query.keyword).toBe('Roadmap')
    expect(crudPage.query.keyword).toBe('DraftOnly')
    wrapper.unmount()
  })

  it('does not let an older slow response replace the latest search result', async () => {
    let resolveInitial!: (value: { records: Array<{ id: string }>; total: number; page: number; size: number }) => void
    const initialPage = new Promise<{ records: Array<{ id: string }>; total: number; page: number; size: number }>((resolve) => {
      resolveInitial = resolve
    })
    const fetchPage = vi.fn().mockImplementation((query: { page: number; size: number; keyword?: string }) => {
      if (query.keyword === 'Initial') return initialPage
      return Promise.resolve({
        records: [{ id: query.keyword || 'latest' }],
        total: 1,
        page: query.page,
        size: query.size,
      })
    })
    let crudPage!: ReturnType<typeof useStandardCrudPage<{ id: string }>>
    const Harness = defineComponent({
      setup() {
        crudPage = useStandardCrudPage<{ id: string }>({
          route: useRoute(),
          router: useRouter(),
          statuses,
          fetchPage,
        })
        return () => h('span', crudPage.records.value.map((record) => record.id).join(','))
      },
    })
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/items', component: Harness }],
    })
    await router.push('/items?page=2&size=20&keyword=Initial')
    await router.isReady()
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    expect(fetchPage).toHaveBeenCalledTimes(1)

    crudPage.query.keyword = 'Roadmap'
    await crudPage.search()
    expect(crudPage.records.value).toEqual([{ id: 'Roadmap' }])

    resolveInitial({ records: [{ id: 'Initial' }], total: 1, page: 2, size: 20 })
    await flushPromises()
    expect(crudPage.records.value).toEqual([{ id: 'Roadmap' }])
    wrapper.unmount()
  })

  it('preserves an external navigation that overlaps an internal URL replacement', async () => {
    let releaseInternalNavigation!: () => void
    let internalNavigationStarted!: () => void
    const internalNavigationGate = new Promise<void>((resolve) => {
      releaseInternalNavigation = resolve
    })
    const internalNavigationStart = new Promise<void>((resolve) => {
      internalNavigationStarted = resolve
    })
    const fetchPage = vi.fn().mockImplementation(async (query: { page: number; size: number; keyword?: string }) => ({
      records: [{ id: query.keyword || 'initial' }],
      total: 1,
      page: query.page,
      size: query.size,
    }))
    let crudPage!: ReturnType<typeof useStandardCrudPage<{ id: string }>>
    const Harness = defineComponent({
      setup() {
        crudPage = useStandardCrudPage<{ id: string }>({
          route: useRoute(),
          router: useRouter(),
          statuses,
          fetchPage,
        })
        return () => h('span', crudPage.records.value.map((record) => record.id).join(','))
      },
    })
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/items', component: Harness }],
    })
    router.beforeEach(async (to) => {
      if (to.query.keyword !== 'Roadmap') return true
      internalNavigationStarted()
      await internalNavigationGate
      return true
    })
    await router.push('/items?page=1&size=10&keyword=Initial')
    await router.isReady()
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()

    crudPage.query.keyword = 'Roadmap'
    const internalSearch = crudPage.search()
    await internalNavigationStart
    await router.push('/items?page=3&size=20&keyword=External')
    await flushPromises()
    releaseInternalNavigation()
    await internalSearch
    await flushPromises()

    expect(router.currentRoute.value.query.keyword).toBe('External')
    expect(crudPage.query.keyword).toBe('External')
    expect(crudPage.records.value).toEqual([{ id: 'External' }])
    wrapper.unmount()
  })
})

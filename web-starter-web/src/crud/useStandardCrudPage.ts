import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, shallowRef, watch, type Ref } from 'vue'
import type { LocationQuery, LocationQueryRaw, RouteLocationNormalizedLoaded, Router } from 'vue-router'
import type { PageData, PageQuery } from '@/types/api'
import { toRequestFailure, type RequestFailure } from '@/api/requestFailure'

export const STANDARD_PAGE_SIZES = [10, 20, 50] as const

export interface StandardCrudQuery {
  page: number
  size: number
  keyword: string
  status: string
}

export interface StandardCrudPageOptions<T> {
  route: RouteLocationNormalizedLoaded
  router: Router
  statuses?: readonly string[]
  fetchPage: (query: PageQuery) => Promise<PageData<T>>
}

function scalar(value: LocationQuery[string] | undefined): string | undefined {
  const candidate = Array.isArray(value) ? value[0] : value
  return candidate ?? undefined
}

function positiveInteger(value: string | undefined, fallback: number): number {
  if (!value || !/^\d+$/.test(value)) return fallback
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback
}

export function parseStandardCrudQuery(
  locationQuery: LocationQuery,
  statuses: readonly string[] = [],
): StandardCrudQuery {
  const requestedSize = positiveInteger(scalar(locationQuery.size), STANDARD_PAGE_SIZES[0])
  const requestedStatus = scalar(locationQuery.status) ?? ''
  return {
    page: positiveInteger(scalar(locationQuery.page), 1),
    size: STANDARD_PAGE_SIZES.includes(requestedSize as (typeof STANDARD_PAGE_SIZES)[number])
      ? requestedSize
      : STANDARD_PAGE_SIZES[0],
    keyword: (scalar(locationQuery.keyword) ?? '').slice(0, 120),
    status: statuses.includes(requestedStatus) ? requestedStatus : '',
  }
}

export function serializeStandardCrudQuery(query: StandardCrudQuery): LocationQueryRaw {
  return {
    page: String(query.page),
    size: String(query.size),
    ...(query.keyword ? { keyword: query.keyword } : {}),
    ...(query.status ? { status: query.status } : {}),
  }
}

export function standardCrudRequestQuery(query: StandardCrudQuery): PageQuery {
  return {
    page: query.page,
    size: query.size,
    keyword: query.keyword || undefined,
    status: query.status || undefined,
  }
}

function sameQuery(left: StandardCrudQuery, right: StandardCrudQuery): boolean {
  return left.page === right.page && left.size === right.size && left.keyword === right.keyword && left.status === right.status
}

function snapshotQuery(query: StandardCrudQuery): StandardCrudQuery {
  return { page: query.page, size: query.size, keyword: query.keyword, status: query.status }
}

function queryKey(query: StandardCrudQuery): string {
  return JSON.stringify([query.page, query.size, query.keyword, query.status])
}

function canonicalLocationMatches(route: RouteLocationNormalizedLoaded, query: StandardCrudQuery): boolean {
  const expected = serializeStandardCrudQuery(query)
  const actualKeys = Object.keys(route.query).sort()
  const expectedKeys = Object.keys(expected).sort()
  if (actualKeys.join('|') !== expectedKeys.join('|')) return false
  return expectedKeys.every((key) => scalar(route.query[key]) === expected[key])
}

export function useStandardCrudPage<T>(options: StandardCrudPageOptions<T>): {
  query: StandardCrudQuery
  records: Ref<T[]>
  total: Ref<number>
  loading: Ref<boolean>
  failure: Ref<RequestFailure | null>
  phase: Ref<'loading' | 'empty' | 'ready' | 'error'>
  load: () => Promise<void>
  search: () => Promise<void>
  handleSizeChange: () => Promise<void>
  captureFailure: (error: unknown) => void
} {
  const query = reactive(parseStandardCrudQuery(options.route.query, options.statuses))
  const records = shallowRef<T[]>([])
  const total = ref(0)
  const loading = ref(false)
  const failure = shallowRef<RequestFailure | null>(null)
  const pendingLocationTargets = new Map<string, number>()
  let mounted = false
  let requestSequence = 0

  const phase = computed<'loading' | 'empty' | 'ready' | 'error'>(() => {
    if (loading.value) return 'loading'
    if (failure.value) return 'error'
    return records.value.length === 0 ? 'empty' : 'ready'
  })

  async function syncLocation(target: StandardCrudQuery): Promise<void> {
    if (canonicalLocationMatches(options.route, target)) return
    const targetKey = queryKey(target)
    pendingLocationTargets.set(targetKey, (pendingLocationTargets.get(targetKey) ?? 0) + 1)
    try {
      await options.router.replace({ query: serializeStandardCrudQuery(target) })
      // Keep the guard active until Vue has delivered the route watcher for this navigation.
      await nextTick()
    } finally {
      const remaining = (pendingLocationTargets.get(targetKey) ?? 1) - 1
      if (remaining > 0) pendingLocationTargets.set(targetKey, remaining)
      else pendingLocationTargets.delete(targetKey)
    }
  }

  function captureFailure(error: unknown): void {
    failure.value = toRequestFailure(error)
  }

  async function performLoad(syncUrl: boolean): Promise<void> {
    const requestId = ++requestSequence
    const requestedQuery = snapshotQuery(query)
    loading.value = true
    failure.value = null
    try {
      if (syncUrl) await syncLocation(requestedQuery)
      if (requestId !== requestSequence) return
      const page = await options.fetchPage(standardCrudRequestQuery(requestedQuery))
      if (requestId !== requestSequence) return
      records.value = page.records
      total.value = page.total
      const resolvedQuery = {
        ...requestedQuery,
        page: page.page || requestedQuery.page,
        size: page.size || requestedQuery.size,
      }
      if (sameQuery(query, requestedQuery)) Object.assign(query, resolvedQuery)
      await syncLocation(resolvedQuery)
    } catch (error: unknown) {
      if (requestId !== requestSequence) return
      records.value = []
      total.value = 0
      captureFailure(error)
    } finally {
      if (requestId === requestSequence) loading.value = false
    }
  }

  async function load(): Promise<void> {
    await performLoad(true)
  }

  async function search(): Promise<void> {
    query.page = 1
    await load()
  }

  async function handleSizeChange(): Promise<void> {
    query.page = 1
    await load()
  }

  const stopRouteWatch = watch(
    () => options.route.query,
    (locationQuery) => {
      if (!mounted) return
      const next = parseStandardCrudQuery(locationQuery, options.statuses)
      if (canonicalLocationMatches(options.route, next) && pendingLocationTargets.has(queryKey(next))) return
      if (sameQuery(query, next)) return
      Object.assign(query, next)
      void performLoad(false)
    },
    { deep: true },
  )

  onMounted(() => {
    mounted = true
    void load()
  })
  onBeforeUnmount(stopRouteWatch)

  return { query, records, total, loading, failure, phase, load, search, handleSizeChange, captureFailure }
}

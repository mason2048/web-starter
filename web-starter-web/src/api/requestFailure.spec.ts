import { describe, expect, it } from 'vitest'
import { ApiError } from '@/types/api'
import { toRequestFailure } from './requestFailure'

describe('request failure presentation', () => {
  it.each([
    [400, 'validation', '输入内容有误'],
    [422, 'validation', '输入内容有误'],
    [401, 'authentication', '登录状态已失效'],
    [403, 'authorization', '没有操作权限'],
    [404, 'not-found', '资源不存在'],
    [409, 'conflict', '数据已发生变化'],
    [429, 'rate-limit', '请求过于频繁'],
    [500, 'server', '服务器处理失败'],
    [503, 'server', '服务器处理失败'],
  ] as const)('normalizes HTTP %s into the shared %s state', (status, kind, title) => {
    const failure = toRequestFailure(new ApiError('backend detail', { status, traceId: `trace-${status}` }))

    expect(failure).toMatchObject({ status, kind, title, traceId: `trace-${status}` })
  })

  it('normalizes envelope codes even when the HTTP response was successful', () => {
    expect(toRequestFailure(new ApiError('conflict', { code: 4090, traceId: 'trace-envelope' }))).toMatchObject({
      status: 409,
      kind: 'conflict',
      traceId: 'trace-envelope',
    })
  })
})

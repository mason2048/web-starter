import { ApiError } from '@/types/api'

export type RequestFailureKind =
  | 'validation'
  | 'authentication'
  | 'authorization'
  | 'not-found'
  | 'conflict'
  | 'rate-limit'
  | 'server'
  | 'network'
  | 'unknown'

export interface RequestFailure {
  kind: RequestFailureKind
  title: string
  message: string
  status?: number
  traceId?: string
  retryable: boolean
}

interface FailurePreset {
  kind: RequestFailureKind
  title: string
  message: string
  retryable: boolean
}

const FAILURE_PRESETS: Record<number, FailurePreset> = {
  400: { kind: 'validation', title: '输入内容有误', message: '请检查输入内容后重试。', retryable: false },
  401: { kind: 'authentication', title: '登录状态已失效', message: '请重新登录后继续操作。', retryable: false },
  403: { kind: 'authorization', title: '没有操作权限', message: '当前账号无权执行此操作。', retryable: false },
  404: { kind: 'not-found', title: '资源不存在', message: '资源不存在或已被删除，请刷新后重试。', retryable: false },
  409: { kind: 'conflict', title: '数据已发生变化', message: '数据已被其他操作更新，请刷新后重试。', retryable: true },
  429: { kind: 'rate-limit', title: '请求过于频繁', message: '请稍后再试，避免重复提交。', retryable: true },
  500: { kind: 'server', title: '服务器处理失败', message: '服务器暂时无法处理请求，请稍后重试。', retryable: true },
}

function statusFrom(error: ApiError): number | undefined {
  if (error.status !== undefined) return error.status
  if (error.code === undefined) return undefined
  if (error.code >= 5000) return 500
  if (error.code >= 4290) return 429
  if (error.code >= 4090) return 409
  if (error.code === 4004) return 404
  if (error.code === 4003) return 403
  if (error.code === 4001) return 401
  if (error.code >= 4000) return 400
  return undefined
}

function presetFor(status?: number): FailurePreset | undefined {
  if (status === undefined) return undefined
  if (status >= 500) return FAILURE_PRESETS[500]
  if (status === 422) return FAILURE_PRESETS[400]
  return FAILURE_PRESETS[status]
}

export function toRequestFailure(error: unknown): RequestFailure {
  if (error instanceof ApiError) {
    const status = statusFrom(error)
    const preset = presetFor(status)
    if (preset) return { ...preset, status, traceId: error.traceId }

    const network = error.message.includes('无法连接服务器')
    return {
      kind: network ? 'network' : 'unknown',
      title: network ? '无法连接服务器' : '请求失败',
      message: error.message,
      status,
      traceId: error.traceId,
      retryable: true,
    }
  }

  return {
    kind: 'unknown',
    title: '请求失败',
    message: error instanceof Error ? error.message : '请求失败，请稍后重试。',
    retryable: true,
  }
}

import axios, { AxiosError, type AxiosRequestConfig, type CreateAxiosDefaults } from 'axios'
import type { ApiResponse, CsrfToken } from '@/types/api'
import { ApiError } from '@/types/api'

export const httpClientDefaults: CreateAxiosDefaults = {
  baseURL: '/api',
  timeout: 15_000,
  withCredentials: true,
  // Spring Security returns an XOR-masked token from /auth/csrf. Axios would
  // otherwise replace the explicit masked header with the raw cookie value.
  withXSRFToken: false,
  headers: {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  },
}

const client = axios.create(httpClientDefaults)

let csrfToken: CsrfToken | null = null
let csrfPromise: Promise<CsrfToken> | null = null

function isSuccessfulCode(code: number): boolean {
  return code === 0 || code === 200
}

function parseEnvelope<T>(payload: ApiResponse<T>): T {
  if (!isSuccessfulCode(payload.code)) {
    throw new ApiError(payload.message || '请求失败', {
      code: payload.code,
      traceId: payload.traceId,
    })
  }
  return payload.data
}

function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error
  if (error instanceof AxiosError) {
    const payload = error.response?.data as Partial<ApiResponse<unknown>> | undefined
    const status = error.response?.status
    if (status === 401 && typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('auth:unauthorized'))
    }
    if (!error.response) {
      return new ApiError('无法连接服务器，请确认后端服务已启动', { status })
    }
    return new ApiError(payload?.message || `请求失败（HTTP ${status ?? '未知'}）`, {
      code: payload?.code,
      traceId: payload?.traceId,
      status,
    })
  }
  return new ApiError(error instanceof Error ? error.message : '请求失败，请稍后重试')
}

export async function getCsrfToken(force = false): Promise<CsrfToken> {
  if (!force && csrfToken) return csrfToken
  if (!force && csrfPromise) return csrfPromise

  csrfPromise = client
    .get<ApiResponse<CsrfToken>>('/auth/csrf')
    .then((response) => {
      csrfToken = parseEnvelope(response.data)
      return csrfToken
    })
    .catch((error: unknown) => {
      throw toApiError(error)
    })
    .finally(() => {
      csrfPromise = null
    })

  return csrfPromise
}

interface RequestOptions extends AxiosRequestConfig {
  csrf?: boolean
}

export async function request<T>(options: RequestOptions): Promise<T> {
  const { csrf, ...config } = options
  try {
    if (csrf) {
      const token = await getCsrfToken()
      config.headers = {
        ...config.headers,
        [token.headerName || 'X-CSRF-TOKEN']: token.token,
      }
    }
    const response = await client.request<ApiResponse<T>>(config)
    if (response.status === 204 || response.data === undefined || response.data === null) {
      return undefined as T
    }
    return parseEnvelope(response.data)
  } catch (error: unknown) {
    const apiError = toApiError(error)
    if (apiError.status === 403 && csrf) csrfToken = null
    throw apiError
  }
}

export function clearCsrfToken(): void {
  csrfToken = null
}

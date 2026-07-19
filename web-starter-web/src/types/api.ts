export interface ApiResponse<T> {
  code: number
  message: string
  data: T
  traceId?: string
}

export interface PageData<T> {
  records: T[]
  total: number
  page: number
  size: number
}

export interface PageQuery {
  page: number
  size: number
  keyword?: string
  [key: string]: string | number | boolean | undefined
}

export interface CsrfToken {
  token: string
  headerName?: string
  parameterName?: string
}

export class ApiError extends Error {
  readonly code?: number
  readonly traceId?: string
  readonly status?: number

  constructor(message: string, options: { code?: number; traceId?: string; status?: number } = {}) {
    super(message)
    this.name = 'ApiError'
    this.code = options.code
    this.traceId = options.traceId
    this.status = options.status
  }
}

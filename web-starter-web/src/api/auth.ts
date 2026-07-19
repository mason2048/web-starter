import { clearCsrfToken, request } from './http'
import type { CurrentUser } from '@/types/models'

export interface LoginPayload {
  username: string
  password: string
}

export async function login(payload: LoginPayload): Promise<CurrentUser | null> {
  return request<CurrentUser | null>({
    url: '/auth/login',
    method: 'POST',
    data: payload,
    csrf: true,
  })
}

export async function logout(): Promise<void> {
  try {
    await request<void>({ url: '/auth/logout', method: 'POST', csrf: true })
  } finally {
    clearCsrfToken()
  }
}

export function getCurrentUser(): Promise<CurrentUser> {
  return request<CurrentUser>({ url: '/auth/me', method: 'GET' })
}

const DEFAULT_REDIRECT = '/overview'

export function safeInternalRedirect(value: unknown): string {
  if (typeof value !== 'string') return DEFAULT_REDIRECT
  if (!value.startsWith('/') || value.startsWith('//')) return DEFAULT_REDIRECT
  if (value.includes('\\') || Array.from(value).some((character) => character.charCodeAt(0) < 32)) {
    return DEFAULT_REDIRECT
  }
  return value
}

export function isOAuthAuthorizationRedirect(path: string): boolean {
  return path.startsWith('/oauth2/') || path.startsWith('/connect/')
}

export const PROJECT_CODE_PATTERN = /^[A-Za-z][A-Za-z0-9_-]{1,63}$/

export function isValidProjectCode(value: string): boolean {
  return PROJECT_CODE_PATTERN.test(value)
}

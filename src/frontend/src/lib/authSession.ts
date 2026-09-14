// Authentication Session Manager

const STORAGE_KEY = 'threatlens-auth-session'
const TOKEN_KEY = 'threatlens-access-token'
const REFRESH_KEY = 'threatlens-refresh-token'

export interface UserProfile {
  id: string
  email: string
  full_name: string
  role: string
  permissions: string[]
}

export interface AuthSession {
  user: UserProfile
  role: string
}

export function setTokens(access_token: string, refresh_token: string) {
  localStorage.setItem(TOKEN_KEY, access_token)
  localStorage.setItem(REFRESH_KEY, refresh_token)
}

export function getAccessToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_KEY)
}

export function setAuthSession(session: AuthSession) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(session))
}

export function getAuthSession(): AuthSession | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    return JSON.parse(raw) as AuthSession
  } catch {
    return null
  }
}

export function clearAuthSession() {
  localStorage.removeItem(STORAGE_KEY)
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(REFRESH_KEY)
}

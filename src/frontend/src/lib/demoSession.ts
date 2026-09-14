export interface DemoSession {
  displayName: string
  startedAt: string
}

const STORAGE_KEY = 'threatlens-demo-session'

export function getDemoSession(): DemoSession | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as DemoSession
    if (typeof parsed.displayName !== 'string' || typeof parsed.startedAt !== 'string') return null
    return parsed
  } catch {
    return null
  }
}

export function startDemoSession(displayName: string) {
  try {
    const session: DemoSession = { displayName, startedAt: new Date().toISOString() }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(session))
  } catch {
    // no-op: simulated session persistence is best-effort
  }
}

export function endDemoSession() {
  try {
    localStorage.removeItem(STORAGE_KEY)
  } catch {
    // no-op
  }
}
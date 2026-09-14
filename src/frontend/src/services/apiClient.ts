import { getAccessToken, clearAuthSession } from '../lib/authSession'

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

const BASE_URL = '' // Empty uses the relative URL which Vite proxies to http://localhost:8000

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getAccessToken()
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...options.headers,
  }

  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const response = await fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    headers,
  })

  if (!response.ok) {
    if (response.status === 401) {
      clearAuthSession()
      window.location.href = '/login'
      throw new ApiError(401, 'Authentication required')
    }
    
    let message = 'An error occurred'
    try {
      const data = await response.json()
      if (data.detail) message = typeof data.detail === 'string' ? data.detail : data.detail[0]?.msg || JSON.stringify(data.detail)
      if (data.error && data.error.message) message = data.error.message
    } catch {
      message = response.statusText
    }
    throw new ApiError(response.status, message)
  }

  if (response.status === 204) {
    return {} as T
  }

  return response.json()
}

// Authentication
export async function login(email: string, password: string) {
  return request<any>('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
}

export async function getAuthMe() {
  return request<any>('/api/v1/auth/me')
}

// Dashboard
export async function getDashboardOverview() {
  return request<any>('/api/v1/dashboard/overview')
}

export async function getAlertTrends(range: string = '24h') {
  return request<any[]>(`/api/v1/alerts/trend?range=${range}`)
}

export async function getSeverityDistribution() {
  return request<any>('/api/v1/dashboard/severity-distribution')
}

export async function getTopTechniques() {
  return request<any>('/api/v1/dashboard/top-techniques')
}

export async function getRecentThreats() {
  return request<any[]>('/api/v1/dashboard/recent-threats')
}

// Alerts
export async function getAlerts(params?: Record<string, string>) {
  const qs = params ? new URLSearchParams(params).toString() : ''
  return request<any[]>(`/api/v1/alerts${qs ? '?' + qs : ''}`)
}

export async function getAlert(id: string) {
  return request<any>(`/api/v1/alerts/${id}`)
}

export async function getRelatedAlerts(id: string) {
  return request<any[]>(`/api/v1/alerts/${id}/related`)
}

// Threats
export async function getThreats(params?: Record<string, string>) {
  const query = params ? `?${new URLSearchParams(params).toString()}` : ''
  return request<any[]>(`/api/v1/threats${query}`)
}

export async function getThreatAlerts(id: string) {
  return request<any[]>(`/api/v1/threats/${id}/alerts`)
}

export async function getThreat(id: string) {
  return request<any>(`/api/v1/threats/${id}`)
}

export async function getThreatAlerts(id: string) {
  return request<any[]>(`/api/v1/threats/${id}/alerts`)
}

export async function getThreatTimeline(id: string) {
  return request<any[]>(`/api/v1/threats/${id}/timeline`)
}

// BLUF
export async function getBlufReports() {
  return request<Record<string, any>>('/api/v1/bluf')
}

// MITRE
export async function getMitreTechniques(params?: Record<string, string>) {
  const query = params ? `?${new URLSearchParams(params).toString()}` : ''
  return request<any[]>(`/api/v1/mitre/techniques${query}`)
}

export async function generateBluf(threatId: string) {
  return request<any>(`/api/v1/bluf/${threatId}/generate`, { method: 'POST' })
// MITRE
export async function getMitreTechniques() {
  return request<any[]>('/api/v1/mitre/techniques')
}

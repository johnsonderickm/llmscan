import type { Audience, Finding, Plugin, ReportResponse, Scan, ScanCreate } from '../types'

const BASE = '/api'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`${res.status}: ${text}`)
  }
  return res.json() as Promise<T>
}

export const api = {
  scans: {
    create: (body: ScanCreate) =>
      request<Scan>('/scans', { method: 'POST', body: JSON.stringify(body) }),
    list: () => request<Scan[]>('/scans'),
    get: (id: string) => request<Scan>(`/scans/${id}`),
  },
  findings: {
    list: (
      scanId: string,
      filters?: { owasp_id?: string; failure_mode?: string; min_score?: number }
    ) => {
      const params = new URLSearchParams()
      if (filters?.owasp_id) params.set('owasp_id', filters.owasp_id)
      if (filters?.failure_mode) params.set('failure_mode', filters.failure_mode)
      if (filters?.min_score != null) params.set('min_score', String(filters.min_score))
      const qs = params.toString()
      return request<Finding[]>(`/scans/${scanId}/findings${qs ? `?${qs}` : ''}`)
    },
  },
  plugins: {
    list: () => request<Plugin[]>('/plugins'),
    update: () => request<{ message: string; count: number }>('/plugins/update', { method: 'POST' }),
  },
  reports: {
    generate: (scanId: string, audience: Audience, format: 'html' | 'pdf' = 'html') =>
      request<ReportResponse>(`/scans/${scanId}/report`, {
        method: 'POST',
        body: JSON.stringify({ audience, format }),
      }),
  },
}

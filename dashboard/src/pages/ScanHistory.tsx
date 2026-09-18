import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { RiskRadar } from '../components/RiskRadar'
import { PluginGrid } from '../components/PluginGrid'
import { useApp } from '../context/AppContext'
import { api } from '../lib/api'
import type { Finding } from '../types'

export function ScanHistory() {
  const { state, dispatch } = useApp()
  const navigate = useNavigate()

  const [selectedScanId, setSelectedScanId] = useState<string | null>(null)
  const [scopedFindings, setScopedFindings] = useState<Finding[]>([])

  useEffect(() => {
    api.scans.list().then(scans => {
      dispatch({ type: 'SET_SCANS', payload: scans })
      // Default to the most recently started scan so the page isn't empty
      if (scans.length > 0) setSelectedScanId(prev => prev ?? scans[0].id)
    }).catch(console.error)
    api.plugins.list().then(plugins => dispatch({ type: 'SET_PLUGINS', payload: plugins })).catch(console.error)
  }, [dispatch])

  useEffect(() => {
    if (!selectedScanId) {
      setScopedFindings([])
      return
    }
    api.findings.list(selectedScanId).then(setScopedFindings).catch(console.error)
  }, [selectedScanId])

  const selectedScan = state.scans.find(s => s.id === selectedScanId) ?? null

  const STATUS_COLOR: Record<string, string> = {
    pending: '#6b7280', running: '#f59e0b', complete: '#10b981', failed: '#ef4444',
    cancelled: '#f59e0b',
  }

  return (
    <div className="max-w-5xl mx-auto mt-8 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold" style={{ color: 'var(--color-text)' }}>Scan history</h1>
        <button
          onClick={() => navigate('/')}
          className="px-4 py-2 rounded-lg text-sm font-medium text-white"
          style={{ background: 'var(--color-accent)' }}
        >
          + New scan
        </button>
      </div>

      <div>
        <p className="text-xs mb-2" style={{ color: 'var(--color-muted)' }}>
          {selectedScan
            ? <>Showing risk profile for <span className="font-mono">{selectedScan.target_url}</span> — click a row below to switch scans</>
            : 'Select a scan below to see its risk profile'}
        </p>
        <div className="grid md:grid-cols-2 gap-4">
          <RiskRadar findings={scopedFindings} />
          <div className="rounded-xl border p-4" style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
            <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--color-text)' }}>Plugin coverage</h2>
            <PluginGrid plugins={state.plugins} findings={scopedFindings} />
          </div>
        </div>
      </div>

      <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--color-border)' }}>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'var(--color-surface)', borderBottom: `1px solid var(--color-border)` }}>
              {['Target', 'Profile', 'Status', 'Risk', 'Started', ''].map(h => (
                <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--color-muted)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {state.scans.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-sm" style={{ color: 'var(--color-muted)' }}>No scans yet. Launch one above.</td></tr>
            )}
            {state.scans.map(s => (
              <tr
                key={s.id}
                onClick={() => setSelectedScanId(s.id)}
                className="cursor-pointer transition-colors"
                style={{
                  borderBottom: `1px solid var(--color-border)`,
                  background: s.id === selectedScanId
                    ? 'color-mix(in srgb, var(--color-accent) 12%, var(--color-surface))'
                    : 'var(--color-surface)',
                  outline: s.id === selectedScanId ? '1px solid var(--color-accent)' : 'none',
                  outlineOffset: '-1px',
                }}
              >
                <td className="px-4 py-3 max-w-xs truncate font-mono text-xs" style={{ color: 'var(--color-text)' }}>{s.target_url}</td>
                <td className="px-4 py-3 capitalize text-xs" style={{ color: 'var(--color-muted)' }}>{s.profile}</td>
                <td className="px-4 py-3">
                  <span className="px-2 py-0.5 rounded-full text-xs font-semibold text-white capitalize" style={{ background: STATUS_COLOR[s.status] ?? '#6b7280' }}>
                    {s.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs font-mono" style={{ color: s.risk_score != null && s.risk_score >= 7 ? 'var(--color-danger)' : 'var(--color-text)' }}>
                  {s.risk_score != null ? `${s.risk_score.toFixed(1)}/10` : '—'}
                </td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--color-muted)' }}>{new Date(s.started_at).toLocaleString()}</td>
                <td className="px-4 py-3">
                  <div className="flex gap-2">
                    {s.status === 'running' && (
                      <button onClick={e => { e.stopPropagation(); navigate(`/scans/${s.id}/live`) }} className="text-xs px-2 py-1 rounded" style={{ color: 'var(--color-accent)' }}>Live</button>
                    )}
                    {s.status === 'complete' && (
                      <button onClick={e => { e.stopPropagation(); navigate(`/scans/${s.id}/findings`) }} className="text-xs px-2 py-1 rounded" style={{ color: 'var(--color-accent)' }}>Findings</button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

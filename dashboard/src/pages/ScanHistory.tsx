import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { RiskRadar } from '../components/RiskRadar'
import { PluginGrid } from '../components/PluginGrid'
import { useApp } from '../context/AppContext'
import { api } from '../lib/api'

export function ScanHistory() {
  const { state, dispatch } = useApp()
  const navigate = useNavigate()

  useEffect(() => {
    api.scans.list().then(scans => dispatch({ type: 'SET_SCANS', payload: scans })).catch(console.error)
    api.plugins.list().then(plugins => dispatch({ type: 'SET_PLUGINS', payload: plugins })).catch(console.error)
  }, [dispatch])

  const STATUS_COLOR: Record<string, string> = {
    pending: '#6b7280', running: '#f59e0b', complete: '#10b981', failed: '#ef4444',
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

      <div className="grid md:grid-cols-2 gap-4">
        <RiskRadar findings={state.findings} />
        <div className="rounded-xl border p-4" style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
          <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--color-text)' }}>Plugin coverage</h2>
          <PluginGrid plugins={state.plugins} findings={state.findings} />
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
                className="cursor-pointer"
                style={{ borderBottom: `1px solid var(--color-border)`, background: 'var(--color-surface)' }}
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
                      <button onClick={() => navigate(`/scans/${s.id}/live`)} className="text-xs px-2 py-1 rounded" style={{ color: 'var(--color-accent)' }}>Live</button>
                    )}
                    {s.status === 'complete' && (
                      <button onClick={() => navigate(`/scans/${s.id}/findings`)} className="text-xs px-2 py-1 rounded" style={{ color: 'var(--color-accent)' }}>Findings</button>
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

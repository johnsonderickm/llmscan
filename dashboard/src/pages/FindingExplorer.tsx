import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { FindingDetail } from '../components/FindingDetail'
import { useApp } from '../context/AppContext'
import { api } from '../lib/api'
import type { FailureMode, Finding } from '../types'

const OWASP_IDS = ['LLM01', 'LLM02', 'LLM03', 'LLM04', 'LLM05', 'LLM06', 'LLM07', 'LLM08', 'LLM09', 'LLM10']
const FAILURE_MODES: FailureMode[] = ['COMPLIED', 'PARTIAL', 'PII_LEAKED', 'HALLUCINATED_REFUSAL', 'FALSE_POSITIVE']

const SEVERITY_COLOR: Record<string, string> = {
  COMPLIED: '#ef4444',
  PARTIAL: '#f59e0b',
  PII_LEAKED: '#dc2626',
  HALLUCINATED_REFUSAL: '#f97316',
  FALSE_POSITIVE: '#6b7280',
  REFUSED: '#10b981',
}

export function FindingExplorer() {
  const { scanId } = useParams<{ scanId: string }>()
  const { dispatch } = useApp()

  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<Finding | null>(null)
  const [owaspFilter, setOwaspFilter] = useState('')
  const [modeFilter, setModeFilter] = useState('')
  const [minScore, setMinScore] = useState(0)

  useEffect(() => {
    if (!scanId) return
    setLoading(true)
    api.findings
      .list(scanId, {
        owasp_id: owaspFilter || undefined,
        failure_mode: modeFilter || undefined,
        min_score: minScore > 0 ? minScore : undefined,
      })
      .then(data => { setFindings(data); dispatch({ type: 'SET_FINDINGS', payload: data }) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [scanId, owaspFilter, modeFilter, minScore, dispatch])

  return (
    <div className="max-w-5xl mx-auto mt-8 space-y-4">
      <h1 className="text-2xl font-bold" style={{ color: 'var(--color-text)' }}>Findings</h1>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 p-4 rounded-xl border" style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
        <select
          value={owaspFilter}
          onChange={e => setOwaspFilter(e.target.value)}
          className="px-3 py-1.5 rounded-lg border text-sm"
          style={{ background: 'var(--color-bg)', borderColor: 'var(--color-border)', color: 'var(--color-text)' }}
        >
          <option value="">All categories</option>
          {OWASP_IDS.map(id => <option key={id} value={id}>{id}</option>)}
        </select>

        <select
          value={modeFilter}
          onChange={e => setModeFilter(e.target.value)}
          className="px-3 py-1.5 rounded-lg border text-sm"
          style={{ background: 'var(--color-bg)', borderColor: 'var(--color-border)', color: 'var(--color-text)' }}
        >
          <option value="">All failure modes</option>
          {FAILURE_MODES.map(m => <option key={m} value={m}>{m}</option>)}
        </select>

        <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--color-text)' }}>
          <label>Min score</label>
          <input
            type="range" min={0} max={10} step={0.5}
            value={minScore}
            onChange={e => setMinScore(Number(e.target.value))}
            className="w-24"
          />
          <span className="w-8 text-right">{minScore}</span>
        </div>

        <span className="ml-auto text-sm self-center" style={{ color: 'var(--color-muted)' }}>
          {findings.length} finding{findings.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Table */}
      <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--color-border)' }}>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'var(--color-surface)', borderBottom: `1px solid var(--color-border)` }}>
              {['OWASP', 'Plugin', 'Failure mode', 'Score', 'MITRE', 'Created'].map(h => (
                <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--color-muted)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-sm" style={{ color: 'var(--color-muted)' }}>Loading…</td></tr>
            )}
            {!loading && findings.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-sm" style={{ color: 'var(--color-muted)' }}>No findings match the current filters.</td></tr>
            )}
            {findings.map(f => (
              <tr
                key={f.id}
                onClick={() => setSelected(f)}
                className="cursor-pointer transition-colors hover:bg-opacity-50"
                style={{
                  borderBottom: `1px solid var(--color-border)`,
                  background: selected?.id === f.id ? 'color-mix(in srgb, var(--color-accent) 10%, transparent)' : 'var(--color-surface)',
                }}
              >
                <td className="px-4 py-3 font-mono text-xs">{f.owasp_id}</td>
                <td className="px-4 py-3 font-mono text-xs">{f.plugin_id}</td>
                <td className="px-4 py-3">
                  <span className="px-2 py-0.5 rounded-full text-xs font-semibold text-white" style={{ background: SEVERITY_COLOR[f.failure_mode] ?? '#6b7280' }}>
                    {f.failure_mode}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <ScoreBar score={f.score} />
                </td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--color-muted)' }}>{f.mitre_atlas_id ?? '—'}</td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--color-muted)' }}>{new Date(f.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Detail drawer */}
      {selected && (
        <FindingDetail finding={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}

function ScoreBar({ score }: { score: number }) {
  const pct = (score / 10) * 100
  const color = score >= 8 ? '#ef4444' : score >= 5 ? '#f59e0b' : '#10b981'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 rounded-full bg-gray-200 overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="text-xs font-mono" style={{ color: 'var(--color-text)' }}>{score.toFixed(1)}</span>
    </div>
  )
}

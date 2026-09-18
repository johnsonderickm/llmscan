import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useApp } from '../context/AppContext'
import { useScanFeed } from '../hooks/useScanFeed'
import { api } from '../lib/api'
import type { ScanEvent } from '../types'

const EVENT_COLORS: Record<string, string> = {
  scan_start: 'var(--color-accent)',
  scan_complete: 'var(--color-success)',
  scan_error: 'var(--color-danger)',
  finding: 'var(--color-danger)',
  plugin_start: 'var(--color-warning)',
  plugin_complete: 'var(--color-success)',
  fingerprint_complete: 'var(--color-accent)',
  probe_sent: 'var(--color-muted)',
  probe_complete: 'var(--color-muted)',
  probe_failed: 'var(--color-danger)',
}

export function ScanLive() {
  const { scanId } = useParams<{ scanId: string }>()
  const { state, dispatch } = useApp()
  const navigate = useNavigate()
  const { events, connected } = useScanFeed(scanId ?? null)

  const scan = state.scans.find(s => s.id === scanId)
  const [stopping, setStopping] = useState(false)
  const [stopError, setStopError] = useState<string | null>(null)

  // Poll scan status until complete
  useEffect(() => {
    if (!scanId) return
    const interval = setInterval(async () => {
      try {
        const updated = await api.scans.get(scanId)
        dispatch({ type: 'UPDATE_SCAN', payload: updated })
        if (['complete', 'failed', 'cancelled'].includes(updated.status)) {
          clearInterval(interval)
        }
      } catch { /* ignore */ }
    }, 2000)
    return () => clearInterval(interval)
  }, [scanId, dispatch])

  async function handleStop() {
    if (!scanId) return
    setStopping(true)
    setStopError(null)
    try {
      const updated = await api.scans.cancel(scanId)
      dispatch({ type: 'UPDATE_SCAN', payload: updated })
    } catch (err) {
      setStopError(err instanceof Error ? err.message : 'Failed to stop scan')
    } finally {
      setStopping(false)
    }
  }

  const findings = events.filter(e => e.event_type === 'finding')
  const isRunning = scan?.status === 'pending' || scan?.status === 'running'
  const isComplete = !isRunning

  return (
    <div className="max-w-3xl mx-auto mt-8 space-y-6">
      {/* Header */}
      <div className="p-6 rounded-xl border" style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
        <div className="flex items-center justify-between mb-3">
          <h1 className="text-xl font-bold" style={{ color: 'var(--color-text)' }}>
            Live scan feed
          </h1>
          <StatusBadge status={scan?.status ?? 'pending'} />
        </div>
        <p className="text-sm truncate" style={{ color: 'var(--color-muted)' }}>
          {scan?.target_url ?? scanId}
        </p>

        <div className="mt-4 grid grid-cols-3 gap-4 text-center">
          <Stat label="Profile" value={scan?.profile ?? '—'} />
          <Stat label="Findings" value={String(findings.length)} highlight={findings.length > 0} />
          <Stat label="Risk score" value={scan?.risk_score != null ? `${scan.risk_score.toFixed(1)}/10` : '—'} highlight={(scan?.risk_score ?? 0) >= 7} />
        </div>

        {isRunning && (
          <div className="mt-4">
            <button
              onClick={handleStop}
              disabled={stopping}
              className="px-4 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-50"
              style={{ background: 'var(--color-danger)' }}
            >
              {stopping ? 'Stopping…' : 'Stop scan'}
            </button>
            {stopError && (
              <p className="text-xs mt-2" style={{ color: 'var(--color-danger)' }}>{stopError}</p>
            )}
          </div>
        )}

        {isComplete && (
          <div className="mt-4 flex gap-3">
            <button
              onClick={() => navigate(`/scans/${scanId}/findings`)}
              className="px-4 py-2 rounded-lg text-sm font-medium text-white"
              style={{ background: 'var(--color-accent)' }}
            >
              View findings
            </button>
            <button
              onClick={() => navigate('/')}
              className="px-4 py-2 rounded-lg text-sm font-medium border"
              style={{ borderColor: 'var(--color-border)', color: 'var(--color-text)' }}
            >
              New scan
            </button>
          </div>
        )}
      </div>

      {/* Event feed */}
      <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--color-border)' }}>
        <div className="px-4 py-3 border-b flex items-center gap-2" style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
          <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-400' : 'bg-gray-400'}`} />
          <span className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>
            {connected ? 'Connected' : 'Disconnected'} · {events.length} events
          </span>
        </div>
        <div className="h-96 overflow-y-auto font-mono text-xs p-4 space-y-1" style={{ background: 'var(--color-bg)' }}>
          {events.length === 0 && (
            <p style={{ color: 'var(--color-muted)' }}>Waiting for events…</p>
          )}
          {events.map((e, i) => <EventRow key={i} event={e} />)}
        </div>
      </div>
    </div>
  )
}

function EventRow({ event }: { event: ScanEvent }) {
  const color = EVENT_COLORS[event.event_type] ?? 'var(--color-text)'
  const time = new Date(event.created_at).toLocaleTimeString()
  return (
    <div className="flex gap-3">
      <span style={{ color: 'var(--color-muted)', minWidth: '5rem' }}>{time}</span>
      <span style={{ color, minWidth: '9rem' }}>{event.event_type}</span>
      <span style={{ color: 'var(--color-text)' }}>{event.message}</span>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    pending: '#6b7280',
    running: '#f59e0b',
    complete: '#10b981',
    failed: '#ef4444',
    cancelled: '#f59e0b',
  }
  return (
    <span className="px-3 py-1 rounded-full text-xs font-semibold text-white capitalize" style={{ background: colors[status] ?? '#6b7280' }}>
      {status}
    </span>
  )
}

function Stat({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div>
      <p className="text-xs mb-0.5" style={{ color: 'var(--color-muted)' }}>{label}</p>
      <p className="text-lg font-bold" style={{ color: highlight ? 'var(--color-danger)' : 'var(--color-text)' }}>{value}</p>
    </div>
  )
}

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import { useApp } from '../context/AppContext'

const PROFILES = ['quick', 'standard', 'full'] as const

export function ScanSetup() {
  const { dispatch } = useApp()
  const navigate = useNavigate()

  const [targetUrl, setTargetUrl] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [model, setModel] = useState('')
  const [profile, setProfile] = useState<string>('standard')
  const [useGarak, setUseGarak] = useState(true)
  const [dryRun, setDryRun] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleLaunch(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const scan = await api.scans.create({
        target_url: targetUrl,
        api_key: apiKey,
        profile,
        dry_run: dryRun,
        use_garak: useGarak,
        model: model.trim() || undefined,
      })
      dispatch({ type: 'ADD_SCAN', payload: scan })
      dispatch({ type: 'SET_ACTIVE_SCAN', payload: scan.id })
      navigate(`/scans/${scan.id}/live`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-xl mx-auto mt-12 p-8 rounded-xl border" style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
      <h1 className="text-2xl font-bold mb-1" style={{ color: 'var(--color-text)' }}>New Scan</h1>
      <p className="text-sm mb-6" style={{ color: 'var(--color-muted)' }}>Configure and launch an LLM penetration test</p>

      <form onSubmit={handleLaunch} className="space-y-5">
        <Field label="Target endpoint URL">
          <input
            type="url"
            required
            placeholder="http://localhost:11434/v1/chat/completions"
            value={targetUrl}
            onChange={e => setTargetUrl(e.target.value)}
            className="w-full px-3 py-2 rounded-lg border text-sm focus:outline-none focus:ring-2"
            style={{ background: 'var(--color-bg)', borderColor: 'var(--color-border)', color: 'var(--color-text)' }}
          />
        </Field>

        <Field label="API key">
          <input
            type="password"
            required
            placeholder="sk-… or 'none' for local endpoints"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            className="w-full px-3 py-2 rounded-lg border text-sm focus:outline-none focus:ring-2"
            style={{ background: 'var(--color-bg)', borderColor: 'var(--color-border)', color: 'var(--color-text)' }}
          />
        </Field>

        <Field label="Model name">
          <input
            type="text"
            placeholder="e.g. llama3, mistral, gpt-4o — required by Ollama / vLLM / LM Studio"
            value={model}
            onChange={e => setModel(e.target.value)}
            className="w-full px-3 py-2 rounded-lg border text-sm focus:outline-none focus:ring-2"
            style={{ background: 'var(--color-bg)', borderColor: 'var(--color-border)', color: 'var(--color-text)' }}
          />
        </Field>

        <Field label="Scan profile">
          <div className="flex gap-2">
            {PROFILES.map(p => (
              <button
                key={p}
                type="button"
                onClick={() => setProfile(p)}
                className="flex-1 py-2 rounded-lg border text-sm font-medium capitalize transition-colors"
                style={{
                  background: profile === p ? 'var(--color-accent)' : 'var(--color-bg)',
                  borderColor: profile === p ? 'var(--color-accent)' : 'var(--color-border)',
                  color: profile === p ? '#fff' : 'var(--color-text)',
                }}
              >
                {p}
              </button>
            ))}
          </div>
          <p className="text-xs mt-1" style={{ color: 'var(--color-muted)' }}>
            {profile === 'quick' && '1 plugin family · ~20 payloads · no Garak'}
            {profile === 'standard' && 'All 10 families · 20 payloads each · Garak if installed'}
            {profile === 'full' && 'All families · unlimited payloads · Garak required'}
          </p>
        </Field>

        <div className="flex gap-6">
          <Toggle label="Use Garak probes" checked={useGarak} onChange={setUseGarak} />
          <Toggle label="Dry run (no HTTP)" checked={dryRun} onChange={setDryRun} />
        </div>

        {error && (
          <p className="text-sm p-3 rounded-lg" style={{ background: '#fef2f2', color: 'var(--color-danger)' }}>
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full py-3 rounded-lg font-semibold text-white transition-opacity disabled:opacity-50"
          style={{ background: 'var(--color-accent)' }}
        >
          {loading ? 'Launching…' : 'Launch scan'}
        </button>
      </form>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-sm font-medium mb-1" style={{ color: 'var(--color-text)' }}>{label}</label>
      {children}
    </div>
  )
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-2 cursor-pointer text-sm" style={{ color: 'var(--color-text)' }}>
      <div
        onClick={() => onChange(!checked)}
        className="w-10 h-5 rounded-full relative transition-colors"
        style={{ background: checked ? 'var(--color-accent)' : 'var(--color-border)' }}
      >
        <div
          className="absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform"
          style={{ transform: checked ? 'translateX(1.25rem)' : 'translateX(0.125rem)' }}
        />
      </div>
      {label}
    </label>
  )
}

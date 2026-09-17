import type { Finding, Plugin } from '../types'

const OWASP_DESCS: Record<string, string> = {
  LLM01: 'Prompt Injection', LLM02: 'Sensitive Information', LLM03: 'Insecure Output',
  LLM04: 'Model DoS', LLM05: 'Supply Chain', LLM06: 'Excessive Agency',
  LLM07: 'System Prompt Leak', LLM08: 'Overreliance', LLM09: 'Model Theft', LLM10: 'Multimodal',
}

interface Props {
  plugins: Plugin[]
  findings: Finding[]
}

export function PluginGrid({ plugins, findings }: Props) {
  if (plugins.length === 0) {
    return (
      <div className="text-sm p-4 rounded-xl border text-center" style={{ borderColor: 'var(--color-border)', color: 'var(--color-muted)' }}>
        No plugins loaded.
      </div>
    )
  }

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
      {plugins.map(p => {
        const pluginFindings = findings.filter(f => f.plugin_id === p.id)
        const worst = pluginFindings.length > 0 ? Math.max(...pluginFindings.map(f => f.score)) : null
        const hasFindings = pluginFindings.length > 0
        return (
          <div
            key={p.id}
            className="p-3 rounded-xl border flex flex-col gap-1"
            style={{
              background: 'var(--color-surface)',
              borderColor: hasFindings ? 'var(--color-danger)' : 'var(--color-border)',
              borderWidth: hasFindings ? 2 : 1,
            }}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold" style={{ color: 'var(--color-accent)' }}>{p.owasp_id}</span>
              {hasFindings && (
                <span className="text-xs px-1.5 py-0.5 rounded-full font-semibold text-white" style={{ background: 'var(--color-danger)' }}>
                  {pluginFindings.length}
                </span>
              )}
            </div>
            <p className="text-xs font-medium leading-tight" style={{ color: 'var(--color-text)' }}>
              {OWASP_DESCS[p.owasp_id] ?? p.name}
            </p>
            <p className="text-xs truncate" style={{ color: 'var(--color-muted)' }}>{p.name}</p>
            {worst != null && (
              <p className="text-xs font-mono mt-auto" style={{ color: 'var(--color-danger)' }}>
                worst: {worst.toFixed(1)}
              </p>
            )}
            {!hasFindings && (
              <p className="text-xs mt-auto" style={{ color: 'var(--color-success)' }}>✓ clean</p>
            )}
          </div>
        )
      })}
    </div>
  )
}

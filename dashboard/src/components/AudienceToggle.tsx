import { useApp } from '../context/AppContext'
import type { Audience } from '../types'

const OPTIONS: { value: Audience; label: string; desc: string }[] = [
  { value: 'pentester', label: 'Pentester', desc: 'Raw technical detail' },
  { value: 'manager', label: 'Manager', desc: 'Risk + remediation effort' },
  { value: 'cxo', label: 'CXO', desc: 'Business impact + compliance' },
]

export function AudienceToggle() {
  const { state, dispatch } = useApp()

  return (
    <div className="flex gap-1 p-1 rounded-xl border" style={{ background: 'var(--color-bg)', borderColor: 'var(--color-border)' }}>
      {OPTIONS.map(opt => (
        <button
          key={opt.value}
          onClick={() => dispatch({ type: 'SET_AUDIENCE', payload: opt.value })}
          title={opt.desc}
          className="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors"
          style={{
            background: state.audience === opt.value ? 'var(--color-accent)' : 'transparent',
            color: state.audience === opt.value ? '#fff' : 'var(--color-muted)',
          }}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}

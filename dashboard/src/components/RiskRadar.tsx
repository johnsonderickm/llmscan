import { PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer, Tooltip } from 'recharts'
import type { Finding } from '../types'

const OWASP_LABELS: Record<string, string> = {
  LLM01: 'Injection', LLM02: 'Sensitive Data', LLM03: 'Output', LLM04: 'DoS',
  LLM05: 'Supply Chain', LLM06: 'Agency', LLM07: 'Sys Leak', LLM08: 'Overreliance',
  LLM09: 'Theft', LLM10: 'Multimodal',
}

interface Props { findings: Finding[] }

export function RiskRadar({ findings }: Props) {
  const data = Object.entries(OWASP_LABELS).map(([id, label]) => {
    const relevant = findings.filter(f => f.owasp_id === id)
    const score = relevant.length > 0 ? Math.max(...relevant.map(f => f.score)) : 0
    return { subject: label, score: parseFloat(score.toFixed(1)), fullMark: 10 }
  })

  if (findings.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 rounded-xl border" style={{ borderColor: 'var(--color-border)', color: 'var(--color-muted)' }}>
        <p className="text-sm">No findings to chart yet.</p>
      </div>
    )
  }

  return (
    <div className="rounded-xl border p-4" style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
      <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--color-text)' }}>OWASP LLM Risk Radar</h2>
      <ResponsiveContainer width="100%" height={280}>
        <RadarChart data={data}>
          <PolarGrid stroke="var(--color-border)" />
          <PolarAngleAxis dataKey="subject" tick={{ fontSize: 11, fill: 'var(--color-muted)' }} />
          <Radar name="Risk" dataKey="score" stroke="var(--color-accent)" fill="var(--color-accent)" fillOpacity={0.3} />
          <Tooltip
            contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 8 }}
            labelStyle={{ color: 'var(--color-text)' }}
            itemStyle={{ color: 'var(--color-accent)' }}
          />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  )
}

import { useEffect, useState } from 'react'
import type { Finding, FindingEvidence } from '../types'
import { useApp } from '../context/AppContext'
import { api } from '../lib/api'

const REMEDIATION: Record<string, Record<string, string>> = {
  pentester: {
    LLM01: 'Test all input vectors for injection. Use context-aware output encoding and input validation.',
    LLM02: 'Audit prompt templates for PII patterns. Implement data masking and output filtering.',
    LLM03: 'Sanitize all LLM outputs before rendering. Treat model output as untrusted user input.',
    LLM04: 'Implement request throttling and payload size limits. Monitor for degenerate response loops.',
    LLM05: 'Pin model versions and checksums. Audit third-party plugin manifests.',
    LLM06: 'Scope tool permissions to minimum required. Require human-in-the-loop for destructive actions.',
    LLM07: 'Never include secrets in system prompts. Test with extraction and completion attacks.',
    LLM08: 'Implement confidence thresholds. Cite sources and surface uncertainty to users.',
    LLM09: 'Restrict access to training data queries. Monitor for model inversion patterns.',
    LLM10: 'Validate and sanitize multimodal inputs. Block prompt injection via image/audio channels.',
  },
  manager: {
    LLM01: 'The model accepted adversarial instructions. Remediation requires input guardrails (2–5 days).',
    LLM02: 'Sensitive data was returned. Apply output filtering rules and review data-minimisation policy.',
    LLM03: 'Unsafe content in model output. Enforce output encoding in the application layer.',
    LLM04: 'Model can be abused for resource exhaustion. Add rate limiting and payload caps.',
    LLM05: 'Third-party model or plugin supply chain risk. Enforce version pinning and checksum verification.',
    LLM06: 'Model took or claimed autonomous actions. Restrict tool scope and add approval workflows.',
    LLM07: 'System prompt leaked. Remove secrets from prompts and use vault-based injection.',
    LLM08: 'Model hallucinated confident false answers. Add citation requirements and review thresholds.',
    LLM09: 'Model revealed training data patterns. Restrict model introspection endpoints.',
    LLM10: 'Injection via image/audio channel. Apply content policy to all modalities.',
  },
  cxo: {
    LLM01: 'Prompt injection enables attackers to hijack AI behaviour. Estimated CVSS impact: HIGH.',
    LLM02: 'Regulatory risk: PII exposure may violate GDPR/CCPA. Immediate legal review recommended.',
    LLM03: 'Insecure AI output increases XSS/SQLi attack surface. Patch before next production deploy.',
    LLM04: 'DoS risk via AI resource exhaustion. Could impact SLA uptime commitments.',
    LLM05: 'Supply chain compromise of AI models. Review vendor security posture.',
    LLM06: 'Unconstrained AI agency could trigger unintended business actions. Governance review needed.',
    LLM07: 'System prompt exposure risks IP theft. Classify prompts as confidential assets.',
    LLM08: 'AI overreliance may produce incorrect decisions at scale. Add human oversight controls.',
    LLM09: 'Model inversion threatens training data privacy. Assess regulatory obligations.',
    LLM10: 'Multimodal injection bypasses text-only safeguards. Expand security policy to all inputs.',
  },
}

interface Props {
  finding: Finding
  onClose: () => void
}

export function FindingDetail({ finding, onClose }: Props) {
  const { state } = useApp()
  const audience = state.audience
  const remediation = REMEDIATION[audience]?.[finding.owasp_id] ?? 'No remediation guidance available.'

  const [evidence, setEvidence] = useState<FindingEvidence | null>(null)
  const [evidenceError, setEvidenceError] = useState<string | null>(null)

  useEffect(() => {
    setEvidence(null)
    setEvidenceError(null)
    api.findings
      .evidence(finding.scan_id, finding.id)
      .then(setEvidence)
      .catch(err => setEvidenceError(err instanceof Error ? err.message : 'Evidence unavailable'))
  }, [finding.scan_id, finding.id])

  return (
    <div
      className="fixed inset-0 z-50 flex items-end sm:items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.5)' }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-3xl max-h-[85vh] overflow-y-auto rounded-xl border"
        style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b" style={{ borderColor: 'var(--color-border)' }}>
          <div>
            <h2 className="text-lg font-bold" style={{ color: 'var(--color-text)' }}>
              {finding.owasp_id} — {finding.failure_mode}
            </h2>
            <p className="text-xs" style={{ color: 'var(--color-muted)' }}>{finding.plugin_id}</p>
          </div>
          <button onClick={onClose} className="text-xl leading-none" style={{ color: 'var(--color-muted)' }}>✕</button>
        </div>

        <div className="p-6 space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
            <MetaCell label="Risk score" value={`${finding.score.toFixed(1)}/10`} />
            <MetaCell label="MITRE Atlas" value={finding.mitre_atlas_id ?? '—'} />
            <MetaCell label="HTTP status" value={evidence ? String(evidence.status_code) : '—'} />
            <MetaCell label="Latency" value={evidence ? `${evidence.latency_ms.toFixed(0)} ms` : '—'} />
          </div>

          {evidenceError && (
            <p className="text-sm p-3 rounded-lg" style={{ background: 'var(--color-bg)', color: 'var(--color-muted)' }}>
              {evidenceError}
            </p>
          )}

          {!evidence && !evidenceError && (
            <p className="text-sm" style={{ color: 'var(--color-muted)' }}>Loading evidence…</p>
          )}

          {evidence && (
            <>
              <TextBlock label="Prompt sent" text={evidence.prompt_text} />
              <TextBlock label="Model response" text={evidence.response_text} />
            </>
          )}

          <div className="p-4 rounded-lg border-l-4" style={{ background: 'var(--color-bg)', borderLeftColor: 'var(--color-accent)' }}>
            <h3 className="text-sm font-semibold mb-1" style={{ color: 'var(--color-text)' }}>
              Remediation ({audience})
            </h3>
            <p className="text-sm" style={{ color: 'var(--color-muted)' }}>{remediation}</p>
          </div>

          <p className="text-xs font-mono" style={{ color: 'var(--color-muted)' }}>
            payload {finding.payload_hash} · response {finding.response_hash}
          </p>
        </div>
      </div>
    </div>
  )
}

function TextBlock({ label, text }: { label: string; text: string }) {
  return (
    <div>
      <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--color-text)' }}>{label}</h3>
      <pre
        className="text-xs p-3 rounded-lg border whitespace-pre-wrap break-words max-h-64 overflow-y-auto"
        style={{ background: 'var(--color-bg)', borderColor: 'var(--color-border)', color: 'var(--color-text)' }}
      >
        {text}
      </pre>
    </div>
  )
}

function MetaCell({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs mb-0.5" style={{ color: 'var(--color-muted)' }}>{label}</p>
      <p className="text-sm font-semibold truncate" style={{ color: 'var(--color-text)' }}>{value}</p>
    </div>
  )
}

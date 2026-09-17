import type { Audience } from '../types'

interface Props {
  src: string
  audience: Audience
  onClose: () => void
}

export function ReportViewer({ src, audience, onClose }: Props) {
  return (
    <div className="fixed inset-0 z-50 flex flex-col" style={{ background: 'rgba(0,0,0,0.6)' }}>
      <div
        className="flex items-center justify-between px-4 py-3 border-b"
        style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}
      >
        <span className="text-sm font-semibold capitalize" style={{ color: 'var(--color-text)' }}>
          {audience} report
        </span>
        <div className="flex items-center gap-4">
          <a
            href={src}
            target="_blank"
            rel="noreferrer"
            className="text-xs font-medium"
            style={{ color: 'var(--color-accent)' }}
          >
            Open in new tab
          </a>
          <button onClick={onClose} className="text-xl leading-none" style={{ color: 'var(--color-muted)' }}>
            ✕
          </button>
        </div>
      </div>
      <iframe src={src} title={`${audience} report`} className="flex-1 w-full border-0" style={{ background: '#fff' }} />
    </div>
  )
}

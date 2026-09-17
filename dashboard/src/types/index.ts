export type ScanStatus = 'pending' | 'running' | 'complete' | 'failed'

export type FailureMode =
  | 'COMPLIED'
  | 'PARTIAL'
  | 'PII_LEAKED'
  | 'HALLUCINATED_REFUSAL'
  | 'REFUSED'
  | 'FALSE_POSITIVE'

export type Audience = 'pentester' | 'manager' | 'cxo'

export interface Scan {
  id: string
  target_url: string
  profile: string
  started_at: string
  finished_at: string | null
  risk_score: number | null
  status: ScanStatus
}

export interface Finding {
  id: string
  scan_id: string
  plugin_id: string
  owasp_id: string
  mitre_atlas_id: string | null
  failure_mode: FailureMode
  score: number
  payload_hash: string
  response_hash: string
  evidence_path: string | null
  created_at: string
}

export interface Plugin {
  id: string
  name: string
  version: string
  owasp_id: string
  mitre_atlas_id: string | null
  severity_weight: number
  tags: string[]
}

export interface ScanEvent {
  scan_id: string
  event_type: string
  message: string
  created_at: string
}

export interface ScanCreate {
  target_url: string
  api_key: string
  profile: string
  dry_run: boolean
  use_garak: boolean
}

export interface ReportResponse {
  scan_id: string
  audience: Audience
  format: string
  path: string
  message: string
}

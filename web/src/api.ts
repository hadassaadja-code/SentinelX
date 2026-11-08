export async function api<T = any>(path: string, opts: { method?: string; body?: any } = {}): Promise<T> {
  const hasBody = opts.body !== undefined
  const res = await fetch('/api' + path, {
    method: opts.method ?? 'GET',
    credentials: 'same-origin',
    headers: { 'x-requested-with': 'sentinelx', ...(hasBody ? { 'content-type': 'application/json' } : {}) },
    body: hasBody ? JSON.stringify(opts.body) : undefined,
  })
  const data = await res.json().catch(() => null)
  if (!res.ok) throw new Error(data?.error ?? `Erreur ${res.status}`)
  return data as T
}

export const ROLE_FR: Record<string, string> = { ADMIN: 'Administrateur', TECH_LEAD: 'Responsable technique', ANALYST: 'Auditeur / Analyste', READER: 'Lecteur' }
export const SEV_FR: Record<string, string> = { CRITICAL: 'Critique', HIGH: 'Élevée', MEDIUM: 'Moyenne', LOW: 'Faible', INFO: 'Info' }
export const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
export const STATUS_FR: Record<string, string> = {
  DETECTED: 'Détectée', CONFIRMED: 'Confirmée', ASSIGNED: 'Assignée', IN_PROGRESS: 'En cours',
  FIXED: 'Corrigée', RETESTED: 'Retestée', CLOSED: 'Clôturée', FALSE_POSITIVE: 'Faux positif',
}
export const SCAN_FR: Record<string, string> = { QUEUED: 'En file', RUNNING: 'En cours', DONE: 'Terminé', FAILED: 'Échec' }
export const MODULE_FR: Record<string, string> = { QA: 'QA', SECURITY: 'Sécurité', PERFORMANCE: 'Performance' }
export const ENV_FR: Record<string, string> = { DEVELOPMENT: 'Development', STAGING: 'Staging', PRODUCTION: 'Production' }
export const fmt = (d: any) => (d ? new Date(d).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' }) : '—')

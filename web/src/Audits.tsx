import React, { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api, MODULE_FR, SCAN_FR, SEVS, SEV_FR, STATUS_FR, fmt } from './api'
import { Empty, Err, Loading, PageHead, Score, Sev, useAction, useAuth, useCan, useLoad } from './ui'

const ScanBadge = ({ s }: { s: string }) => (
  <span className={`badge ${s === 'DONE' ? 'ok' : s === 'FAILED' ? 'bad' : 'run'}`}>
    {(s === 'RUNNING' || s === 'QUEUED') && <span className="spin" style={{ width: 10, height: 10 }} />}
    {SCAN_FR[s] ?? s}
  </span>
)
const active = (s: any) => s.status === 'QUEUED' || s.status === 'RUNNING'

// ================= CAMPAGNES =================
export function Scans() {
  const can = useCan()
  const { reload: reloadMe } = useAuth()
  const [params] = useSearchParams()
  const scans = useLoad<any[]>(() => api('/scans'))
  const apps = useLoad<any[]>(() => api('/applications'))
  const act = useAction()
  const [appId, setAppId] = useState(params.get('app') ?? '')
  const [mods, setMods] = useState<string[]>(['QA', 'SECURITY', 'PERFORMANCE'])
  const authorized = (apps.data ?? []).filter((a) => a.authorized)

  // Rafraîchissement automatique tant qu'un audit est en cours
  const running = (scans.data ?? []).some(active)
  useEffect(() => {
    if (!running) return
    const t = setInterval(() => scans.reload(), 2500)
    return () => { clearInterval(t); reloadMe() }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running])

  const launch = async (e: React.FormEvent) => {
    e.preventDefault()
    if (await act.run(() => api('/scans', { method: 'POST', body: { applicationId: appId, modules: mods } }))) scans.reload()
  }
  const toggle = (m: string) => setMods(mods.includes(m) ? mods.filter((x) => x !== m) : [...mods, m])

  return (
    <>
      <PageHead title="Campagnes d'audit" sub="Lancez un audit sur une application autorisée et suivez son exécution." />
      <Err msg={scans.error || apps.error || act.error} />
      {can.operate && (
        <form className="card" onSubmit={launch}>
          <h2>Nouvel audit</h2>
          {apps.data && authorized.length === 0 ? (
            <div className="note" style={{ marginBottom: 0 }}>Aucune application autorisée. <Link to="/app/projects">Ajoutez une application et déclarez votre autorisation</Link> pour pouvoir l'auditer.</div>
          ) : (
            <div className="row" style={{ alignItems: 'flex-end' }}>
              <label className="f">Application
                <select required value={appId} onChange={(e) => setAppId(e.target.value)}>
                  <option value="">Choisir…</option>
                  {authorized.map((a) => <option key={a.id} value={a.id}>{a.name} — {a.url}</option>)}
                </select>
              </label>
              <div className="row" style={{ flex: '1 1 260px' }}>
                {Object.keys(MODULE_FR).map((m) => (
                  <label key={m} className="chk"><input type="checkbox" checked={mods.includes(m)} onChange={() => toggle(m)} />{MODULE_FR[m]}</label>
                ))}
              </div>
              <button className="btn" disabled={act.busy || !appId || mods.length === 0}>Lancer l'audit</button>
            </div>
          )}
        </form>
      )}
      <div className="card">
        {!scans.data ? <Loading /> : scans.data.length === 0 ? <Empty>Aucun audit pour l'instant.</Empty> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th>Application</th><th>Modules</th><th>État</th><th>Score</th><th>Constats</th><th>Date</th><th></th></tr></thead>
              <tbody>
                {scans.data.map((s) => (
                  <tr key={s.id}>
                    <td><b>{s.application.name}</b><div className="muted small mono">{s.application.url}</div></td>
                    <td>{s.modules.split(',').map((m: string) => <span key={m} className="badge" style={{ marginRight: 4 }}>{MODULE_FR[m]}</span>)}</td>
                    <td><ScanBadge s={s.status} /></td>
                    <td><b>{s.score ?? '—'}</b></td>
                    <td>{s.summary?.security?.total ?? '—'}</td>
                    <td className="muted small">{fmt(s.createdAt)}</td>
                    <td><Link to={`/app/scans/${s.id}`}>Détail</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}

// ================= DÉTAIL D'UN AUDIT =================
function FindingCard({ f, children }: { f: any; children?: React.ReactNode }) {
  return (
    <div className={`finding ${f.severity}`}>
      <div className="row between">
        <div className="row"><Sev s={f.severity} /><b>{f.title}</b></div>
        <span className="badge">{STATUS_FR[f.status]}</span>
      </div>
      <dl>
        <dt>Description</dt><dd>{f.description}</dd>
        <dt>Ressource</dt><dd className="mono">{f.resource}</dd>
        <dt>Preuve</dt><dd className="mono">{f.evidence}</dd>
        <dt>Recommandation</dt><dd>{f.recommendation}</dd>
        {f.note && (<><dt>Note</dt><dd>{f.note}</dd></>)}
      </dl>
      {children}
    </div>
  )
}

export function ScanDetail() {
  const { id } = useParams()
  const { data: s, error, reload } = useLoad<any>(() => api(`/scans/${id}`), [id])
  const running = s && active(s)
  useEffect(() => {
    if (!running) return
    const t = setInterval(reload, 2000)
    return () => clearInterval(t)
  }, [running, reload])
  if (error) return <Err msg={error} />
  if (!s) return <Loading />
  const sum = s.summary ?? {}
  const dl = (f: string) => `/api/scans/${s.id}/report?format=${f}`
  return (
    <>
      <PageHead title={`Audit — ${s.application.name}`} sub={`${s.application.url} · lancé le ${fmt(s.createdAt)}`}>
        <ScanBadge s={s.status} />
        {s.status === 'DONE' && (
          <>
            <a className="btn" href={dl('pdf')}>Rapport PDF</a>
            <a className="btn ghost" href={dl('json')}>JSON</a>
            <a className="btn ghost" href={dl('csv')}>CSV</a>
          </>
        )}
      </PageHead>
      {running && <div className="note"><span className="spin" />Audit en cours. Cette page se met à jour automatiquement.</div>}
      {s.status === 'FAILED' && <Err msg={`L'audit a échoué : ${s.error ?? 'erreur inconnue'}`} />}
      {s.status === 'DONE' && (
        <div className="card row" style={{ gap: 22 }}>
          <Score value={s.score} />
          <div style={{ flex: 1, minWidth: 240 }}>
            <h2>Synthèse</h2>
            {sum.qa && <div>QA : {sum.qa.error ? <span className="muted">module en échec ({sum.qa.error})</span> : <><b>{sum.qa.passed}/{sum.qa.total}</b> tests réussis ({sum.qa.rate} %)</>}</div>}
            {sum.security && <div>Sécurité : {sum.security.error ? <span className="muted">module en échec ({sum.security.error})</span> : <><b>{sum.security.total}</b> constat(s) — {SEVS.filter((x) => sum.security.counts[x]).map((x) => `${sum.security.counts[x]} ${SEV_FR[x].toLowerCase()}`).join(', ') || 'aucun'}</>}</div>}
            {sum.performance && <div>Performance : {sum.performance.error ? <span className="muted">module en échec ({sum.performance.error})</span> : <>score <b>{sum.performance.score}/100</b>, temps moyen {sum.performance.avg} ms, P95 {sum.performance.p95} ms</>}</div>}
            {sum.security?.info?.tls && <div className="muted small" style={{ marginTop: 6 }}>Certificat TLS : {sum.security.info.tls.subject} — émis par {sum.security.info.tls.issuer} — {sum.security.info.tls.protocol} — expire dans {sum.security.info.tls.daysLeft} jour(s)</div>}
          </div>
        </div>
      )}
      {s.comparison && (
        <div className="card">
          <h2>Comparaison avec l'audit précédent ({fmt(s.comparison.previousDate)})</h2>
          <div className="grid g3">
            <div className="stat"><b style={{ color: 'var(--ok)' }}>{s.comparison.fixed.length}</b><span>Corrigée(s)</span></div>
            <div className="stat"><b style={{ color: s.comparison.added.length ? 'var(--high)' : undefined }}>{s.comparison.added.length}</b><span>Nouvelle(s)</span></div>
            <div className="stat"><b>{s.comparison.persistent}</b><span>Persistante(s)</span></div>
          </div>
          {s.comparison.fixed.length > 0 && <p className="small" style={{ marginTop: 10 }}>Corrigées : {s.comparison.fixed.join(' · ')}</p>}
          {s.comparison.added.length > 0 && <p className="small">Nouvelles : {s.comparison.added.join(' · ')}</p>}
        </div>
      )}
      {s.modules.includes('SECURITY') && s.status === 'DONE' && !sum.security?.error && (
        <>
          <h2 style={{ marginTop: 22 }}>Sécurité — {s.findings.length} constat(s)</h2>
          {s.findings.length === 0 ? <div className="card"><Empty>Aucun constat relevé par les contrôles exécutés.</Empty></div> : s.findings.map((f: any) => <FindingCard key={f.id} f={f} />)}
        </>
      )}
      {s.testResults.length > 0 && (
        <div className="card">
          <h2>Résultats QA</h2>
          <table><tbody>
            {s.testResults.map((t: any) => (
              <tr key={t.id}>
                <td style={{ width: 90 }}><span className={`badge ${t.status === 'PASS' ? 'ok' : 'bad'}`}>{t.status === 'PASS' ? 'Réussi' : 'Échec'}</span></td>
                <td><b>{t.name}</b>{t.detail && <div className="muted small mono">{t.detail}</div>}</td>
                <td className="muted small" style={{ textAlign: 'right' }}>{t.durationMs ? `${t.durationMs} ms` : ''}</td>
              </tr>
            ))}
          </tbody></table>
        </div>
      )}
      {s.metrics.length > 0 && (
        <>
          <h2 style={{ marginTop: 22 }}>Performance</h2>
          <div className="grid g5">
            {s.metrics.map((m: any) => <div className="stat" key={m.id}><b>{m.value} <span>{m.unit}</span></b><span>{m.name}</span></div>)}
          </div>
          <p className="muted small" style={{ marginTop: 8 }}>Mesure sur 10 requêtes successives. Il ne s'agit pas d'un test de charge.</p>
        </>
      )}
    </>
  )
}

// ================= VULNÉRABILITÉS =================
export function Findings() {
  const can = useCan()
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const { data, error, reload } = useLoad<any[]>(() => api(`/findings?severity=${severity}&status=${status}`), [severity, status])
  const act = useAction()
  const [notes, setNotes] = useState<Record<string, string>>({})
  const change = async (f: any, st: string) => {
    if (await act.run(() => api(`/findings/${f.id}`, { method: 'PATCH', body: { status: st, note: notes[f.id] ?? '' } }))) reload()
  }
  return (
    <>
      <PageHead title="Vulnérabilités" sub="Suivi des constats : Détectée → Confirmée → Assignée → En cours → Corrigée → Retestée → Clôturée.">
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Filtrer par gravité">
          <option value="">Toutes les gravités</option>
          {SEVS.map((s) => <option key={s} value={s}>{SEV_FR[s]}</option>)}
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filtrer par statut">
          <option value="">Tous les statuts</option>
          {Object.keys(STATUS_FR).map((s) => <option key={s} value={s}>{STATUS_FR[s]}</option>)}
        </select>
      </PageHead>
      <Err msg={error || act.error} />
      {!data ? <Loading /> : data.length === 0 ? <div className="card"><Empty>Aucune vulnérabilité ne correspond à ces critères.</Empty></div> : data.map((f) => (
        <FindingCard key={f.id} f={f}>
          <div className="row" style={{ marginTop: 10 }}>
            <span className="muted small">{f.application} · {fmt(f.createdAt)} · <Link to={`/app/scans/${f.scanId}`}>voir l'audit</Link></span>
            {can.operate && (
              <div className="row" style={{ marginLeft: 'auto' }}>
                <input placeholder="Note ou justification" value={notes[f.id] ?? ''} onChange={(e) => setNotes({ ...notes, [f.id]: e.target.value })} style={{ width: 220 }} />
                <select value={f.status} onChange={(e) => change(f, e.target.value)} aria-label="Changer le statut">
                  {Object.keys(STATUS_FR).map((s) => <option key={s} value={s}>{STATUS_FR[s]}</option>)}
                </select>
              </div>
            )}
          </div>
        </FindingCard>
      ))}
    </>
  )
}

// ================= MONITORING =================
export function Monitoring() {
  const can = useCan()
  const { me } = useAuth()
  const apps = useLoad<any[]>(() => api('/applications'))
  const incidents = useLoad<any[]>(() => api('/incidents'))
  const act = useAction()
  const refresh = () => { apps.reload(); incidents.reload() }
  const call = async (fn: () => Promise<any>) => { if (await act.run(fn)) refresh() }
  return (
    <>
      <PageHead title="Monitoring" sub={`Disponibilité, code HTTP et temps de réponse. Fréquence minimale de votre formule : ${me.plan.minMonitorInterval} min.`} />
      <Err msg={apps.error || incidents.error || act.error} />
      <div className="card">
        {!apps.data ? <Loading /> : apps.data.length === 0 ? <Empty>Aucune application à surveiller.</Empty> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th>Application</th><th>État</th><th>HTTP</th><th>Réponse</th><th>Dernière vérification</th><th>Surveillance</th><th></th></tr></thead>
              <tbody>
                {apps.data.map((a) => (
                  <tr key={a.id}>
                    <td><b>{a.name}</b><div className="muted small">{a.project.name}</div></td>
                    <td><span className={`dot ${a.lastStatus}`} />{a.lastStatus === 'UP' ? 'Disponible' : a.lastStatus === 'DOWN' ? 'Indisponible' : 'Non vérifiée'}</td>
                    <td>{a.lastHttpCode ?? '—'}</td>
                    <td>{a.lastResponseMs != null ? `${a.lastResponseMs} ms` : '—'}</td>
                    <td className="muted small">{fmt(a.lastCheckedAt)}</td>
                    <td>
                      {!a.authorized ? <span className="badge bad">Autorisation requise</span> : can.manage ? (
                        <div className="row">
                          <label className="chk"><input type="checkbox" checked={a.monitoring} onChange={(e) => call(() => api(`/applications/${a.id}`, { method: 'PATCH', body: { monitoring: e.target.checked } }))} />Active</label>
                          <select value={a.monitorInterval} onChange={(e) => call(() => api(`/applications/${a.id}`, { method: 'PATCH', body: { monitorInterval: Number(e.target.value) } }))} aria-label="Fréquence">
                            {[5, 15, 30, 60].map((n) => <option key={n} value={n}>{n === 60 ? '1 heure' : `${n} min`}</option>)}
                          </select>
                        </div>
                      ) : <span className="badge">{a.monitoring ? `Toutes les ${a.monitorInterval} min` : 'Inactive'}</span>}
                    </td>
                    <td>{a.authorized && can.operate && <button className="btn ghost sm" disabled={act.busy} onClick={() => call(() => api(`/applications/${a.id}/check`, { method: 'POST' }))}>Vérifier maintenant</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <div className="card">
        <h2>Historique des incidents</h2>
        {!incidents.data ? <Loading /> : incidents.data.length === 0 ? <Empty>Aucun incident enregistré.</Empty> : (
          <table>
            <thead><tr><th>Incident</th><th>État</th><th>Occurrences</th><th>Début</th><th>Résolution</th></tr></thead>
            <tbody>
              {incidents.data.map((i) => (
                <tr key={i.id}>
                  <td>{i.title}</td>
                  <td><span className={`badge ${i.status === 'OPEN' ? 'bad' : 'ok'}`}>{i.status === 'OPEN' ? 'Ouvert' : 'Résolu'}</span></td>
                  <td>{i.occurrences}</td>
                  <td className="muted small">{fmt(i.startedAt)}</td>
                  <td className="muted small">{fmt(i.resolvedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}

// ================= RAPPORTS =================
export function Reports() {
  const { data, error } = useLoad<any[]>(() => api('/scans'))
  const done = (data ?? []).filter((s) => s.status === 'DONE')
  return (
    <>
      <PageHead title="Rapports" sub="Un rapport par campagne terminée, aux formats PDF, JSON et CSV." />
      <Err msg={error} />
      <div className="card">
        {!data ? <Loading /> : done.length === 0 ? <Empty>Aucun rapport disponible. Lancez un audit pour en générer un.</Empty> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th>Application</th><th>Date</th><th>Modules</th><th>Score</th><th>Télécharger</th></tr></thead>
              <tbody>
                {done.map((s) => (
                  <tr key={s.id}>
                    <td><Link to={`/app/scans/${s.id}`}><b>{s.application.name}</b></Link></td>
                    <td className="muted small">{fmt(s.createdAt)}</td>
                    <td>{s.modules.split(',').map((m: string) => MODULE_FR[m]).join(', ')}</td>
                    <td><b>{s.score ?? '—'}</b></td>
                    <td>
                      <div className="row">
                        {['pdf', 'json', 'csv'].map((f) => <a key={f} className="btn ghost sm" href={`/api/scans/${s.id}/report?format=${f}`}>{f.toUpperCase()}</a>)}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}

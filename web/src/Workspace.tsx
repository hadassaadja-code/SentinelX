import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, ENV_FR, SEVS, SEV_FR, fmt } from './api'
import { Empty, Err, Loading, PageHead, useAction, useAuth, useCan, useLoad } from './ui'

// ================= TABLEAU DE BORD =================
export function Dashboard() {
  const { me } = useAuth()
  const { data: d, error } = useLoad(() => api('/dashboard'))
  if (error) return <Err msg={error} />
  if (!d) return <Loading />
  const maxSev = Math.max(1, ...SEVS.map((s) => d.severities[s]))
  return (
    <>
      <PageHead title="Tableau de bord" sub={`${me.org.name} — formule ${me.plan.label}`}>
        <Link className="btn" to="/app/scans">Lancer un audit</Link>
      </PageHead>
      {d.applications === 0 && (
        <div className="note">
          Pour commencer : créez un projet, ajoutez une application, déclarez votre autorisation, puis lancez un audit. <Link to="/app/projects">Créer un projet</Link>
        </div>
      )}
      <div className="grid g5" style={{ marginBottom: 16 }}>
        <div className="stat"><b>{d.projects}</b><span>Projets</span></div>
        <div className="stat"><b>{d.applications}</b><span>Applications</span></div>
        <div className="stat"><b>{d.scans}</b><span>Audits réalisés</span></div>
        <div className="stat"><b>{d.openFindings}</b><span>Vulnérabilités ouvertes</span></div>
        <div className="stat"><b style={{ color: d.severities.CRITICAL ? 'var(--crit)' : undefined }}>{d.severities.CRITICAL}</b><span>Critiques</span></div>
        <div className="stat"><b>{d.qaRate != null ? d.qaRate + ' %' : '—'}</b><span>Taux de réussite QA</span></div>
        <div className="stat"><b>{d.perfScore ?? '—'}</b><span>Score de performance</span></div>
      </div>
      <div className="grid g2">
        <div className="card">
          <h2>Vulnérabilités ouvertes par gravité</h2>
          {SEVS.map((s) => (
            <div className="row" key={s} style={{ marginBottom: 8 }}>
              <span style={{ width: 70 }} className="small">{SEV_FR[s]}</span>
              <div className="bar"><i style={{ width: `${(d.severities[s] / maxSev) * 100}%`, background: `var(--${{ CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', INFO: 'info' }[s]})` }} /></div>
              <b style={{ width: 28, textAlign: 'right' }}>{d.severities[s]}</b>
            </div>
          ))}
          <Link to="/app/findings" className="small">Voir toutes les vulnérabilités</Link>
        </div>
        <div className="card">
          <h2>Évolution du score global</h2>
          {d.trend.length === 0 ? (
            <Empty>Aucun audit terminé pour l'instant.</Empty>
          ) : (
            <>
              <div className="trend">
                {d.trend.map((t: any) => (
                  <div key={t.id} style={{ height: `${Math.max(3, t.score ?? 0)}%` }} title={`${t.app} — ${t.score}/100 — ${fmt(t.date)}`} />
                ))}
              </div>
              <div className="muted small" style={{ marginTop: 6 }}>Les {d.trend.length} derniers audits, du plus ancien au plus récent (score sur 100).</div>
            </>
          )}
        </div>
        <div className="card">
          <h2>État des applications</h2>
          {d.apps.length === 0 ? <Empty>Aucune application enregistrée.</Empty> : (
            <table><tbody>
              {d.apps.map((a: any) => (
                <tr key={a.id}>
                  <td><span className={`dot ${a.lastStatus}`} />{a.name}</td>
                  <td className="muted small">{a.lastStatus === 'UP' ? 'Disponible' : a.lastStatus === 'DOWN' ? 'Indisponible' : 'Non vérifiée'}</td>
                  <td className="muted small" style={{ textAlign: 'right' }}>{a.lastResponseMs != null ? `${a.lastResponseMs} ms` : ''}</td>
                </tr>
              ))}
            </tbody></table>
          )}
        </div>
        <div className="card">
          <h2>Derniers incidents</h2>
          {d.incidents.length === 0 ? <Empty>Aucun incident enregistré.</Empty> : (
            <table><tbody>
              {d.incidents.map((i: any) => (
                <tr key={i.id}>
                  <td>{i.title}</td>
                  <td><span className={`badge ${i.status === 'OPEN' ? 'bad' : 'ok'}`}>{i.status === 'OPEN' ? 'Ouvert' : 'Résolu'}</span></td>
                  <td className="muted small">{fmt(i.startedAt)}</td>
                </tr>
              ))}
            </tbody></table>
          )}
        </div>
      </div>
    </>
  )
}

// ================= PROJETS ET APPLICATIONS =================
export function Projects() {
  const can = useCan()
  const { reload: reloadMe } = useAuth()
  const { data, error, reload } = useLoad<any[]>(() => api('/projects'))
  const act = useAction()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const refresh = () => Promise.all([reload(), reloadMe()])
  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    if (await act.run(() => api('/projects', { method: 'POST', body: { name, description } }))) {
      setName('')
      setDescription('')
      refresh()
    }
  }
  return (
    <>
      <PageHead title="Projets et applications" sub="Organisez vos applications par projet et par environnement." />
      <Err msg={error || act.error} />
      {can.manage && (
        <form className="card row" onSubmit={create}>
          <label className="f">Nom du projet<input required value={name} onChange={(e) => setName(e.target.value)} placeholder="Site vitrine" /></label>
          <label className="f" style={{ flexGrow: 2 }}>Description (facultatif)<input value={description} onChange={(e) => setDescription(e.target.value)} /></label>
          <button className="btn" disabled={act.busy} style={{ alignSelf: 'flex-end' }}>Créer le projet</button>
        </form>
      )}
      {!data ? <Loading /> : data.length === 0 ? <div className="card"><Empty>Aucun projet. Créez-en un pour enregistrer vos applications.</Empty></div> : data.map((p) => <ProjectCard key={p.id} p={p} refresh={refresh} />)}
    </>
  )
}

function ProjectCard({ p, refresh }: { p: any; refresh: () => any }) {
  const can = useCan()
  const act = useAction()
  const nav = useNavigate()
  const [adding, setAdding] = useState(false)
  const [authFor, setAuthFor] = useState<string | null>(null)
  const [declared, setDeclared] = useState(false)
  const [f, setF] = useState({ name: '', url: 'https://', type: 'WEB', environment: 'PRODUCTION' })
  const call = async (fn: () => Promise<any>) => {
    if (await act.run(fn)) refresh()
  }
  const add = async (e: React.FormEvent) => {
    e.preventDefault()
    if (await act.run(() => api('/applications', { method: 'POST', body: { ...f, projectId: p.id } }))) {
      setAdding(false)
      setF({ name: '', url: 'https://', type: 'WEB', environment: 'PRODUCTION' })
      refresh()
    }
  }
  return (
    <div className="card" style={{ opacity: p.archived ? 0.65 : 1 }}>
      <div className="row between">
        <div>
          <h2 style={{ marginBottom: 2 }}>{p.name} {p.archived && <span className="badge">Archivé</span>}</h2>
          {p.description && <div className="muted small">{p.description}</div>}
        </div>
        {can.manage && (
          <div className="row">
            {!p.archived && <button className="btn sm" onClick={() => setAdding(!adding)}>Ajouter une application</button>}
            <button className="btn ghost sm" onClick={() => call(() => api(`/projects/${p.id}`, { method: 'PATCH', body: { archived: !p.archived } }))}>{p.archived ? 'Désarchiver' : 'Archiver'}</button>
            {can.admin && <button className="btn danger sm" onClick={() => window.confirm(`Supprimer le projet « ${p.name} » et toutes ses applications ?`) && call(() => api(`/projects/${p.id}`, { method: 'DELETE' }))}>Supprimer</button>}
          </div>
        )}
      </div>
      <Err msg={act.error} />
      {adding && (
        <form className="row" onSubmit={add} style={{ margin: '14px 0', padding: 12, background: 'var(--panel2)', borderRadius: 10 }}>
          <label className="f">Nom<input required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
          <label className="f" style={{ flexGrow: 2 }}>URL principale<input required type="url" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} /></label>
          <label className="f">Type<select value={f.type} onChange={(e) => setF({ ...f, type: e.target.value })}><option value="WEB">Application web</option><option value="API">API</option></select></label>
          <label className="f">Environnement<select value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })}>{Object.keys(ENV_FR).map((k) => <option key={k} value={k}>{ENV_FR[k]}</option>)}</select></label>
          <button className="btn" disabled={act.busy} style={{ alignSelf: 'flex-end' }}>Enregistrer</button>
        </form>
      )}
      {p.applications.length === 0 ? <Empty>Aucune application dans ce projet.</Empty> : (
        <div className="tablewrap">
          <table style={{ marginTop: 10 }}>
            <thead><tr><th>Application</th><th>Environnement</th><th>Autorisation d'audit</th><th></th></tr></thead>
            <tbody>
              {p.applications.map((a: any) => (
                <React.Fragment key={a.id}>
                  <tr>
                    <td><b>{a.name}</b> <span className="badge">{a.type}</span><div className="muted small mono">{a.url}</div></td>
                    <td><span className="badge">{ENV_FR[a.environment]}</span></td>
                    <td>{a.authorized ? <span className="badge ok">Autorisée le {fmt(a.authorizedAt)}</span> : <span className="badge bad">Non déclarée</span>}</td>
                    <td>
                      <div className="row" style={{ justifyContent: 'flex-end' }}>
                        {!a.authorized && can.manage && <button className="btn sm" onClick={() => { setAuthFor(authFor === a.id ? null : a.id); setDeclared(false) }}>Déclarer l'autorisation</button>}
                        {a.authorized && can.operate && <button className="btn sm" onClick={() => nav(`/app/scans?app=${a.id}`)}>Auditer</button>}
                        {can.manage && <button className="btn danger sm" onClick={() => window.confirm(`Supprimer l'application « ${a.name} » et ses résultats ?`) && call(() => api(`/applications/${a.id}`, { method: 'DELETE' }))}>Supprimer</button>}
                      </div>
                    </td>
                  </tr>
                  {authFor === a.id && (
                    <tr>
                      <td colSpan={4} style={{ background: 'var(--panel2)' }}>
                        <label className="chk">
                          <input type="checkbox" checked={declared} onChange={(e) => setDeclared(e.target.checked)} />
                          <span>Je déclare être propriétaire de <b>{a.url}</b> ou détenir une autorisation écrite pour la tester. Cette déclaration est enregistrée dans le journal de l'organisation avec mon identité et la date.</span>
                        </label>
                        <button className="btn sm" style={{ marginTop: 10 }} disabled={!declared || act.busy} onClick={async () => { if (await act.run(() => api(`/applications/${a.id}/authorize`, { method: 'POST', body: { declaration: true } }))) { setAuthFor(null); refresh() } }}>Confirmer l'autorisation</button>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

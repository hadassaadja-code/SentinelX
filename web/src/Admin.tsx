import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ROLE_FR, fmt } from './api'
import { Empty, Err, Loading, PageHead, useAction, useAuth, useCan, useLoad, useTheme } from './ui'

// ================= NOTIFICATIONS =================
export function Notifications() {
  const { reload: reloadMe } = useAuth()
  const { data, error, reload } = useLoad<any[]>(() => api('/notifications'))
  const readAll = async () => {
    await api('/notifications/read-all', { method: 'POST' }).catch(() => {})
    reload()
    reloadMe()
  }
  return (
    <>
      <PageHead title="Notifications" sub="Audits terminés, vulnérabilités critiques, indisponibilités et incidents résolus.">
        <button className="btn ghost" onClick={readAll}>Tout marquer comme lu</button>
      </PageHead>
      <Err msg={error} />
      <div className="card">
        {!data ? <Loading /> : data.length === 0 ? <Empty>Aucune notification.</Empty> : (
          <table><tbody>
            {data.map((n) => (
              <tr key={n.id} style={{ opacity: n.read ? 0.6 : 1 }}>
                <td style={{ width: 14 }}>{!n.read && <span className="dot UP" style={{ background: 'var(--accent)', boxShadow: 'none' }} />}</td>
                <td><b>{n.title}</b>{n.body && <div className="muted small">{n.body}</div>}</td>
                <td className="muted small">{fmt(n.createdAt)}</td>
                <td>{n.link && <Link to={n.link}>Ouvrir</Link>}</td>
              </tr>
            ))}
          </tbody></table>
        )}
      </div>
    </>
  )
}

// ================= MEMBRES =================
export function Members() {
  const can = useCan()
  const { me, reload: reloadMe } = useAuth()
  const { data, error, reload } = useLoad<any[]>(() => api('/members'))
  const act = useAction()
  const empty = { name: '', email: '', password: '', role: 'ANALYST' }
  const [f, setF] = useState(empty)
  const refresh = () => { reload(); reloadMe() }
  const call = async (fn: () => Promise<any>) => { if (await act.run(fn)) refresh() }
  const add = async (e: React.FormEvent) => {
    e.preventDefault()
    if (await act.run(() => api('/members', { method: 'POST', body: f }))) {
      setF(empty)
      refresh()
    }
  }
  return (
    <>
      <PageHead title="Membres et rôles" sub={`${me.usage.members} collaborateur(s) sur ${me.plan.members} autorisés par la formule ${me.plan.label}.`} />
      <Err msg={error || act.error} />
      {can.admin && (
        <form className="card" onSubmit={add}>
          <h2>Ajouter un collaborateur</h2>
          <div className="row" style={{ alignItems: 'flex-end' }}>
            <label className="f">Nom<input required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
            <label className="f">E-mail<input required type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></label>
            <label className="f">Mot de passe provisoire<input required type="password" minLength={10} autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></label>
            <label className="f">Rôle<select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>{Object.keys(ROLE_FR).map((r) => <option key={r} value={r}>{ROLE_FR[r]}</option>)}</select></label>
            <button className="btn" disabled={act.busy}>Ajouter</button>
          </div>
          <p className="muted small" style={{ margin: '10px 0 0' }}>Communiquez le mot de passe provisoire au collaborateur, qui pourra le changer dans ses paramètres.</p>
        </form>
      )}
      <div className="card">
        {!data ? <Loading /> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th>Membre</th><th>Rôle</th><th>Ajouté le</th><th></th></tr></thead>
              <tbody>
                {data.map((m) => (
                  <tr key={m.memberId}>
                    <td><b>{m.name}</b> {m.self && <span className="badge">Vous</span>}<div className="muted small">{m.email}</div></td>
                    <td>
                      {can.admin ? (
                        <select value={m.role} onChange={(e) => call(() => api(`/members/${m.memberId}`, { method: 'PATCH', body: { role: e.target.value } }))} aria-label="Rôle">
                          {Object.keys(ROLE_FR).map((r) => <option key={r} value={r}>{ROLE_FR[r]}</option>)}
                        </select>
                      ) : <span className="badge">{ROLE_FR[m.role]}</span>}
                    </td>
                    <td className="muted small">{fmt(m.createdAt)}</td>
                    <td style={{ textAlign: 'right' }}>{can.admin && !m.self && <button className="btn danger sm" onClick={() => window.confirm(`Retirer ${m.name} de l'organisation ? Son compte sera supprimé.`) && call(() => api(`/members/${m.memberId}`, { method: 'DELETE' }))}>Retirer</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <div className="card">
        <h2>Permissions par rôle</h2>
        <table><tbody>
          <tr><td><b>Administrateur</b></td><td className="muted">Membres, rôles, projets, audits, paramètres et abonnement.</td></tr>
          <tr><td><b>Responsable technique</b></td><td className="muted">Projets, applications, autorisations, audits et suivi des corrections.</td></tr>
          <tr><td><b>Auditeur / Analyste</b></td><td className="muted">Lancer les audits autorisés, qualifier les vulnérabilités, télécharger les rapports.</td></tr>
          <tr><td><b>Lecteur</b></td><td className="muted">Consultation uniquement.</td></tr>
        </tbody></table>
      </div>
    </>
  )
}

// ================= ABONNEMENT =================
export function Billing() {
  const can = useCan()
  const { reload: reloadMe } = useAuth()
  const { data, error, reload } = useLoad<any>(() => api('/billing'))
  const act = useAction()
  if (!data) return error ? <Err msg={error} /> : <Loading />
  const cur = data.plans[data.current]
  const choose = async (k: string) => {
    if (await act.run(() => api('/billing/plan', { method: 'POST', body: { plan: k } }))) {
      reload()
      reloadMe()
    }
  }
  const Usage = ({ label, used, max }: { label: string; used: number; max: number }) => (
    <div style={{ marginBottom: 12 }}>
      <div className="row between small"><span>{label}</span><b>{used} / {max}</b></div>
      <div className="bar" style={{ marginTop: 4 }}><i style={{ width: `${Math.min(100, (used / max) * 100)}%`, background: used >= max ? 'var(--danger)' : undefined }} /></div>
    </div>
  )
  return (
    <>
      <PageHead title="Abonnement" sub={`Formule actuelle : ${cur.label}`} />
      <Err msg={error || act.error} />
      <div className="note">Version de démonstration : le changement de formule est immédiat et sans paiement. Le fournisseur de paiement reste à intégrer.</div>
      <div className="card">
        <h2>Consommation</h2>
        <Usage label="Applications" used={data.usage.apps} max={cur.apps} />
        <Usage label="Collaborateurs" used={data.usage.members} max={cur.members} />
        <Usage label="Audits ce mois-ci" used={data.usage.scansThisMonth} max={cur.scansPerMonth} />
      </div>
      <div className="grid g3">
        {Object.keys(data.plans).map((k) => {
          const p = data.plans[k]
          const isCur = k === data.current
          return (
            <div className="card" key={k} style={{ borderColor: isCur ? 'var(--accent)' : undefined, marginBottom: 0 }}>
              <div className="row between"><h2 style={{ margin: 0 }}>{p.label}</h2>{isCur && <span className="badge run">Formule actuelle</span>}</div>
              <table style={{ margin: '10px 0' }}><tbody>
                <tr><td className="muted">Applications</td><td><b>{p.apps}</b></td></tr>
                <tr><td className="muted">Collaborateurs</td><td><b>{p.members}</b></td></tr>
                <tr><td className="muted">Audits par mois</td><td><b>{p.scansPerMonth}</b></td></tr>
                <tr><td className="muted">Audits simultanés</td><td><b>{p.concurrent}</b></td></tr>
                <tr><td className="muted">Historique</td><td><b>{p.historyDays} jours</b></td></tr>
                <tr><td className="muted">Monitoring</td><td><b>dès {p.minMonitorInterval} min</b></td></tr>
              </tbody></table>
              {can.admin && !isCur && <button className="btn" disabled={act.busy} onClick={() => choose(k)}>Choisir {p.label}</button>}
            </div>
          )
        })}
      </div>
    </>
  )
}

// ================= PARAMÈTRES =================
export function Settings() {
  const can = useCan()
  const { me, reload: reloadMe } = useAuth()
  const [theme, toggle] = useTheme()
  const sessions = useLoad<any[]>(() => api('/auth/sessions'))
  const logs = useLoad<any[]>(() => (can.admin ? api('/audit-logs') : Promise.resolve([])), [can.admin])
  const prof = useAction()
  const pwd = useAction()
  const [name, setName] = useState(me.user.name)
  const [p, setP] = useState({ current: '', next: '' })
  const [done, setDone] = useState('')
  return (
    <>
      <PageHead title="Paramètres" sub="Profil, sécurité du compte et journal de l'organisation." />
      <div className="grid g2">
        <form className="card" onSubmit={async (e) => { e.preventDefault(); if (await prof.run(() => api('/auth/profile', { method: 'PATCH', body: { name } }))) reloadMe() }}>
          <h2>Profil</h2>
          <Err msg={prof.error} />
          <div className="row" style={{ alignItems: 'flex-end' }}>
            <label className="f">Nom<input required value={name} onChange={(e) => setName(e.target.value)} /></label>
            <button className="btn" disabled={prof.busy}>Enregistrer</button>
          </div>
          <p className="muted small" style={{ marginTop: 10 }}>{me.user.email}</p>
          <button type="button" className="btn ghost sm" onClick={toggle}>Passer au thème {theme === 'dark' ? 'clair' : 'sombre'}</button>
        </form>
        <form className="card" onSubmit={async (e) => { e.preventDefault(); setDone(''); if (await pwd.run(() => api('/auth/password', { method: 'POST', body: p }))) { setP({ current: '', next: '' }); setDone('Mot de passe modifié. Vos autres sessions ont été fermées.'); sessions.reload() } }}>
          <h2>Mot de passe</h2>
          <Err msg={pwd.error} />
          {done && <div className="note">{done}</div>}
          <div className="row" style={{ alignItems: 'flex-end' }}>
            <label className="f">Actuel<input required type="password" autoComplete="current-password" value={p.current} onChange={(e) => setP({ ...p, current: e.target.value })} /></label>
            <label className="f">Nouveau (10 caractères min.)<input required type="password" minLength={10} autoComplete="new-password" value={p.next} onChange={(e) => setP({ ...p, next: e.target.value })} /></label>
            <button className="btn" disabled={pwd.busy}>Modifier</button>
          </div>
        </form>
      </div>
      <div className="card">
        <h2>Sessions actives</h2>
        <Err msg={sessions.error} />
        {!sessions.data ? <Loading /> : (
          <table><tbody>
            {sessions.data.map((s) => (
              <tr key={s.id}>
                <td className="small">{s.userAgent || 'Navigateur inconnu'}</td>
                <td className="muted small">{s.ip}</td>
                <td className="muted small">{fmt(s.createdAt)}</td>
                <td style={{ textAlign: 'right' }}>{s.current ? <span className="badge ok">Session actuelle</span> : <button className="btn danger sm" onClick={async () => { await api(`/auth/sessions/${s.id}`, { method: 'DELETE' }).catch(() => {}); sessions.reload() }}>Révoquer</button>}</td>
              </tr>
            ))}
          </tbody></table>
        )}
      </div>
      {can.admin && (
        <div className="card">
          <h2>Journal des actions</h2>
          <Err msg={logs.error} />
          {!logs.data ? <Loading /> : logs.data.length === 0 ? <Empty>Aucune action enregistrée.</Empty> : (
            <div className="tablewrap">
              <table>
                <thead><tr><th>Date</th><th>Action</th><th>Détail</th><th>IP</th></tr></thead>
                <tbody>
                  {logs.data.map((l) => (
                    <tr key={l.id}>
                      <td className="muted small" style={{ whiteSpace: 'nowrap' }}>{fmt(l.createdAt)}</td>
                      <td><span className="badge">{l.action}</span></td>
                      <td className="small">{l.detail}</td>
                      <td className="muted small">{l.ip}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </>
  )
}

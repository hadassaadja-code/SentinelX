import React, { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { api } from './api'
import { Brand, Err, useAction, useAuth } from './ui'

export function Landing() {
  const { me } = useAuth()
  return (
    <div className="pub">
      <nav className="pubnav">
        <Brand />
        <div className="row">
          {me ? (
            <Link className="btn" to="/app">Ouvrir mon espace</Link>
          ) : (
            <>
              <Link className="btn ghost" to="/login">Connexion</Link>
              <Link className="btn" to="/register">Créer un compte</Link>
            </>
          )}
        </div>
      </nav>
      <section className="hero">
        <h1>Qualité, sécurité et performance de vos applications, <em>au même endroit</em>.</h1>
        <p>SentinelX audite vos sites et API, centralise les résultats et suit les corrections. Chaque constat est accompagné de sa preuve et d'une recommandation.</p>
        <div className="row">
          <Link className="btn" to={me ? '/app' : '/register'}>Démarrer un audit</Link>
          <a className="btn ghost" href="#modules">Voir les modules</a>
        </div>
      </section>
      <section id="modules" className="grid g3" style={{ marginTop: 64 }}>
        <div className="card">
          <h2>Quality Assurance</h2>
          <p className="muted">Accessibilité des pages, liens cassés, ressources manquantes, structure HTML et formulaires.</p>
        </div>
        <div className="card">
          <h2>Cybersécurité</h2>
          <p className="muted">En-têtes de sécurité, HTTPS et certificat TLS, cookies, fichiers sensibles exposés. Contrôles non destructifs.</p>
        </div>
        <div className="card">
          <h2>Performance</h2>
          <p className="muted">Temps de réponse moyen, P95, P99, débit et taux d'erreur, avec un historique par application.</p>
        </div>
        <div className="card">
          <h2>Monitoring</h2>
          <p className="muted">Surveillance de disponibilité à fréquence réglable, incidents regroupés et alertes.</p>
        </div>
        <div className="card">
          <h2>Rapports</h2>
          <p className="muted">Rapports PDF, JSON et CSV par campagne, avec comparaison entre deux audits.</p>
        </div>
        <div className="card">
          <h2>Multi-organisation</h2>
          <p className="muted">Chaque entreprise dispose d'un espace isolé, de rôles et de quotas selon sa formule.</p>
        </div>
      </section>
      <p className="muted small" style={{ marginTop: 30 }}>
        Les audits ne sont lancés que sur des cibles dont vous êtes propriétaire ou pour lesquelles vous détenez une autorisation explicite.
      </p>
    </div>
  )
}

export function Login() {
  const { me, reload } = useAuth()
  const nav = useNavigate()
  const { error, busy, run } = useAction()
  const [f, setF] = useState({ email: '', password: '' })
  if (me) return <Navigate to="/app" replace />
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (await run(() => api('/auth/login', { method: 'POST', body: f }))) {
      await reload()
      nav('/app')
    }
  }
  return (
    <div className="auth">
      <Brand />
      <div className="card">
        <h1>Connexion</h1>
        <p className="muted">Accédez à l'espace de votre organisation.</p>
        <Err msg={error} />
        <form onSubmit={submit}>
          <label className="f">Adresse e-mail<input type="email" required autoComplete="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></label>
          <label className="f">Mot de passe<input type="password" required autoComplete="current-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></label>
          <button className="btn" disabled={busy}>Se connecter</button>
        </form>
      </div>
      <p className="muted">Pas encore de compte ? <Link to="/register">Créer une organisation</Link></p>
    </div>
  )
}

export function Register() {
  const { me, reload } = useAuth()
  const nav = useNavigate()
  const { error, busy, run } = useAction()
  const [f, setF] = useState({ name: '', orgName: '', email: '', password: '' })
  if (me) return <Navigate to="/app" replace />
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value })
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (await run(() => api('/auth/register', { method: 'POST', body: f }))) {
      await reload()
      nav('/app/projects')
    }
  }
  return (
    <div className="auth">
      <Brand />
      <div className="card">
        <h1>Créer votre espace</h1>
        <p className="muted">Vous serez administrateur de l'organisation créée.</p>
        <Err msg={error} />
        <form onSubmit={submit}>
          <label className="f">Votre nom<input required value={f.name} onChange={set('name')} autoComplete="name" /></label>
          <label className="f">Nom de l'organisation<input required value={f.orgName} onChange={set('orgName')} autoComplete="organization" /></label>
          <label className="f">Adresse e-mail<input type="email" required value={f.email} onChange={set('email')} autoComplete="email" /></label>
          <label className="f">Mot de passe (10 caractères minimum)<input type="password" required minLength={10} value={f.password} onChange={set('password')} autoComplete="new-password" /></label>
          <button className="btn" disabled={busy}>Créer le compte</button>
        </form>
      </div>
      <p className="muted">Déjà inscrit ? <Link to="/login">Se connecter</Link></p>
    </div>
  )
}

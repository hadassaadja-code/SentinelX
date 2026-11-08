import React, { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { Link, NavLink, Navigate, Outlet, useNavigate } from 'react-router-dom'
import { api, ROLE_FR, SEV_FR } from './api'

// ---------- Authentification ----------
const AuthCtx = createContext<{ me: any; loading: boolean; reload: () => Promise<void> }>(null as any)
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [me, setMe] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const reload = useCallback(async () => {
    try {
      setMe(await api('/auth/me'))
    } catch {
      setMe(null)
    } finally {
      setLoading(false)
    }
  }, [])
  useEffect(() => {
    reload()
  }, [reload])
  return <AuthCtx.Provider value={{ me, loading, reload }}>{children}</AuthCtx.Provider>
}
export const useAuth = () => useContext(AuthCtx)
export function useCan() {
  const { me } = useAuth()
  const r = me?.role
  return { admin: r === 'ADMIN', manage: r === 'ADMIN' || r === 'TECH_LEAD', operate: r !== 'READER' && !!r }
}

// ---------- Chargement de données ----------
export function useLoad<T = any>(fn: () => Promise<T>, deps: any[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState('')
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const reload = useCallback(() => fn().then((d) => { setData(d); setError('') }).catch((e) => setError(e.message)), deps)
  useEffect(() => {
    reload()
  }, [reload])
  return { data, error, reload }
}

/** Exécute une action et expose l'erreur éventuelle. */
export function useAction() {
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const run = async (fn: () => Promise<any>) => {
    setBusy(true)
    setError('')
    try {
      await fn()
      return true
    } catch (e: any) {
      setError(e.message)
      return false
    } finally {
      setBusy(false)
    }
  }
  return { error, busy, run, setError }
}

// ---------- Thème ----------
export function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem('sx-theme') ?? 'dark'
    } catch {
      return 'dark'
    }
  })
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('sx-theme', theme)
    } catch {}
  }, [theme])
  return [theme, () => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))]
}

// ---------- Petits composants ----------
export const Err = ({ msg }: { msg?: string }) => (msg ? <div className="err" role="alert">{msg}</div> : null)
export const Sev = ({ s }: { s: string }) => <span className={`badge sev ${s}`}>{SEV_FR[s] ?? s}</span>
export const Empty = ({ children }: { children: React.ReactNode }) => <div className="empty">{children}</div>
export const Loading = () => <div className="empty"><span className="spin" />Chargement…</div>
export function Score({ value }: { value: number | null | undefined }) {
  if (value == null) return <div className="score" style={{ borderColor: 'var(--line)' }}>—</div>
  return <div className={`score ${value >= 75 ? '' : value >= 50 ? 'mid' : 'low'}`}>{value}</div>
}
export function PageHead({ title, sub, children }: { title: string; sub?: string; children?: React.ReactNode }) {
  return (
    <div className="head">
      <div>
        <h1>{title}</h1>
        {sub && <div className="muted">{sub}</div>}
      </div>
      <div className="row">{children}</div>
    </div>
  )
}
export const Brand = ({ to = '/' }: { to?: string }) => (
  <Link to={to} className="brand"><i />SENTINELX</Link>
)

// ---------- Coquille de l'espace de travail ----------
export function Shell() {
  const { me, loading, reload } = useAuth()
  const [theme, toggle] = useTheme()
  const nav = useNavigate()
  if (loading) return <Loading />
  if (!me) return <Navigate to="/login" replace />
  const item = (to: string, label: string, extra?: React.ReactNode, end = false) => (
    <NavLink to={to} end={end} className={({ isActive }) => 'nav' + (isActive ? ' active' : '')}>
      {label}
      {extra}
    </NavLink>
  )
  const logout = async () => {
    await api('/auth/logout', { method: 'POST' }).catch(() => {})
    await reload()
    nav('/login')
  }
  return (
    <div className="shell">
      <aside className="side">
        <Brand to="/app" />
        {item('/app', 'Tableau de bord', null, true)}
        <div className="navgroup">Périmètre</div>
        {item('/app/projects', 'Projets et applications')}
        <div className="navgroup">Audits</div>
        {item('/app/scans', "Campagnes d'audit")}
        {item('/app/findings', 'Vulnérabilités')}
        {item('/app/monitoring', 'Monitoring')}
        {item('/app/reports', 'Rapports')}
        <div className="navgroup">Organisation</div>
        {item('/app/notifications', 'Notifications', me.unread > 0 ? <span className="pill">{me.unread}</span> : null)}
        {item('/app/members', 'Membres et rôles')}
        {item('/app/billing', 'Abonnement')}
        {item('/app/settings', 'Paramètres')}
        <div className="foot">
          <div><b>{me.user.name}</b></div>
          <div className="muted">{me.org.name} · {ROLE_FR[me.role]}</div>
          <div className="row" style={{ marginTop: 10 }}>
            <button className="btn ghost sm" onClick={toggle}>{theme === 'dark' ? 'Thème clair' : 'Thème sombre'}</button>
            <button className="btn ghost sm" onClick={logout}>Déconnexion</button>
          </div>
        </div>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}

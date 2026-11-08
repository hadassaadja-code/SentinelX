import { PrismaClient } from '@prisma/client'
import { hash, verify } from '@node-rs/argon2'
import jwt from 'jsonwebtoken'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const prisma = new PrismaClient()
export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

// ---------- Erreurs ----------
export class HttpError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

// ---------- Formules et quotas (section 12) ----------
export const PLANS: Record<string, any> = {
  STARTER: { label: 'Starter', apps: 2, members: 2, scansPerMonth: 20, concurrent: 1, historyDays: 7, minMonitorInterval: 60, security: 'Basique' },
  PROFESSIONAL: { label: 'Professional', apps: 10, members: 5, scansPerMonth: 200, concurrent: 2, historyDays: 30, minMonitorInterval: 15, security: 'Avancé' },
  BUSINESS: { label: 'Business', apps: 50, members: 25, scansPerMonth: 2000, concurrent: 5, historyDays: 90, minMonitorInterval: 5, security: 'Avancé' },
}
export const planOf = (org: any) => PLANS[org.plan] ?? PLANS.STARTER

// ---------- Rôles (section 2.3) ----------
export const ROLES = ['ADMIN', 'TECH_LEAD', 'ANALYST', 'READER']
export const MANAGE = ['ADMIN', 'TECH_LEAD']
export const OPERATE = ['ADMIN', 'TECH_LEAD', 'ANALYST']

// ---------- Secret JWT ----------
function loadSecret(): string {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET
  const f = path.join(ROOT, '.jwt-secret')
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8').trim()
  const s = crypto.randomBytes(48).toString('hex')
  fs.writeFileSync(f, s)
  return s
}
const SECRET = loadSecret()
const COOKIE = 'sx_session'
const SESSION_DAYS = 7

// ---------- Mots de passe : Argon2id (section 3) ----------
export const hashPassword = (p: string) => hash(p, { algorithm: 2, memoryCost: 19456, timeCost: 2, parallelism: 1 })
export const verifyPassword = async (h: string, p: string) => {
  try {
    return await verify(h, p)
  } catch {
    return false
  }
}

// ---------- Sessions ----------
export async function createSession(req: any, reply: any, userId: string) {
  const session = await prisma.session.create({
    data: {
      userId,
      userAgent: String(req.headers['user-agent'] ?? '').slice(0, 200),
      ip: req.ip ?? '',
      expiresAt: new Date(Date.now() + SESSION_DAYS * 86400_000),
    },
  })
  const token = jwt.sign({ sid: session.id }, SECRET, { algorithm: 'HS256', expiresIn: `${SESSION_DAYS}d` })
  reply.setCookie(COOKIE, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: SESSION_DAYS * 86400,
  })
}
export const clearSessionCookie = (reply: any) => reply.clearCookie(COOKIE, { path: '/' })

export type Ctx = { user: any; org: any; orgId: string; role: string; sessionId: string }

/** Authentifie la requête et renvoie le contexte (utilisateur + organisation + rôle). */
export async function getCtx(req: any): Promise<Ctx> {
  const token = req.cookies?.[COOKIE]
  if (!token) throw new HttpError(401, 'Non authentifié')
  let payload: any
  try {
    payload = jwt.verify(token, SECRET, { algorithms: ['HS256'] })
  } catch {
    throw new HttpError(401, 'Session invalide')
  }
  const session = await prisma.session.findUnique({
    where: { id: String(payload.sid) },
    include: { user: { include: { memberships: { include: { org: true } } } } },
  })
  if (!session || session.revoked || session.expiresAt < new Date()) throw new HttpError(401, 'Session expirée')
  const m = session.user.memberships[0]
  if (!m) throw new HttpError(403, 'Aucune organisation associée à ce compte')
  return { user: session.user, org: m.org, orgId: m.orgId, role: m.role, sessionId: session.id }
}

export function need(ctx: Ctx, roles: string[]) {
  if (!roles.includes(ctx.role)) throw new HttpError(403, 'Permission insuffisante pour cette action')
}

// ---------- Utilitaires ----------
export const str = (v: any, max = 200) => String(v ?? '').trim().slice(0, max)

export async function audit(req: any, ctx: { orgId?: string; user?: any } | null, action: string, detail = '') {
  await prisma.auditLog.create({
    data: { orgId: ctx?.orgId ?? null, userId: ctx?.user?.id ?? null, action, detail: detail.slice(0, 500), ip: req?.ip ?? '' },
  })
}

export async function notify(orgId: string, type: string, title: string, body = '', link = '') {
  await prisma.notification.create({ data: { orgId, type, title, body: body.slice(0, 500), link } })
}

/** Verrou par organisation : rend atomique "vérifier le quota puis créer" (les quotas ne se contournent pas en multipliant les requêtes). */
const locks = new Map<string, Promise<any>>()
export function withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(key) ?? Promise.resolve()
  const next = prev.catch(() => {}).then(fn)
  locks.set(key, next.catch(() => {}))
  return next
}

// ---------- Anti force brute sur la connexion ----------
const attempts = new Map<string, { count: number; until: number }>()
export function checkLoginAllowed(key: string) {
  const a = attempts.get(key)
  if (a && a.count >= 5 && a.until > Date.now()) throw new HttpError(429, 'Trop de tentatives. Réessayez dans 15 minutes.')
  if (a && a.until <= Date.now()) attempts.delete(key)
}
export function recordLoginFailure(key: string) {
  const a = attempts.get(key) ?? { count: 0, until: 0 }
  a.count++
  a.until = Date.now() + 15 * 60_000
  attempts.set(key, a)
}
export const clearLoginFailures = (key: string) => attempts.delete(key)

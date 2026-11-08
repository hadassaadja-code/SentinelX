// API REST SentinelX. Règle d'isolation multi-tenant : TOUTE requête filtre sur ctx.orgId (jamais sur un id seul).
import {
  prisma, HttpError, PLANS, planOf, ROLES, MANAGE, OPERATE, getCtx, need, str, audit, withLock,
  hashPassword, verifyPassword, createSession, clearSessionCookie, checkLoginAllowed, recordLoginFailure, clearLoginFailures,
} from './core.js'
import { assertAllowedUrl, launchScan, checkApplication } from './engine.js'
import { buildPdf, buildCsv } from './report.js'

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const FINDING_STATUS = ['DETECTED', 'CONFIRMED', 'ASSIGNED', 'IN_PROGRESS', 'FIXED', 'RETESTED', 'CLOSED', 'FALSE_POSITIVE']
const MODULES = ['QA', 'SECURITY', 'PERFORMANCE']
const ENVS = ['DEVELOPMENT', 'STAGING', 'PRODUCTION']
const monthStart = () => new Date(new Date().getFullYear(), new Date().getMonth(), 1)

function checkPassword(p: string) {
  if (p.length < 10) throw new HttpError(400, 'Le mot de passe doit contenir au moins 10 caractères')
  if (p.length > 200) throw new HttpError(400, 'Mot de passe trop long')
}

async function usage(orgId: string) {
  const [apps, members, scansThisMonth, running] = await Promise.all([
    prisma.application.count({ where: { orgId } }),
    prisma.organizationMember.count({ where: { orgId } }),
    prisma.scan.count({ where: { orgId, createdAt: { gte: monthStart() } } }),
    prisma.scan.count({ where: { orgId, status: { in: ['QUEUED', 'RUNNING'] } } }),
  ])
  return { apps, members, scansThisMonth, running }
}

export default async function routes(app: any) {
  // ================= AUTHENTIFICATION =================
  app.post('/auth/register', async (req: any, reply: any) => {
    const b = req.body ?? {}
    const name = str(b.name, 80), email = str(b.email, 160).toLowerCase(), orgName = str(b.orgName, 80), password = String(b.password ?? '')
    if (!name || !orgName) throw new HttpError(400, 'Nom et organisation requis')
    if (!EMAIL.test(email)) throw new HttpError(400, 'Adresse e-mail invalide')
    checkPassword(password)
    if (await prisma.user.findUnique({ where: { email } })) throw new HttpError(409, 'Un compte existe déjà avec cet e-mail')
    const passwordHash = await hashPassword(password)
    const user = await prisma.user.create({ data: { name, email, passwordHash } })
    const org = await prisma.organization.create({ data: { name: orgName, members: { create: { userId: user.id, role: 'ADMIN' } } } })
    await createSession(req, reply, user.id)
    await audit(req, { orgId: org.id, user }, 'auth.register', `Organisation « ${orgName} » créée`)
    return { ok: true }
  })

  app.post('/auth/login', async (req: any, reply: any) => {
    const email = str(req.body?.email, 160).toLowerCase(), password = String(req.body?.password ?? '')
    const key = `${req.ip}|${email}`
    checkLoginAllowed(key)
    const user = await prisma.user.findUnique({ where: { email }, include: { memberships: true } })
    const ok = user ? await verifyPassword(user.passwordHash, password) : false
    if (!user || !ok) {
      recordLoginFailure(key)
      await audit(req, user ? { orgId: user.memberships[0]?.orgId, user } : null, 'auth.login_failed', email)
      throw new HttpError(401, 'E-mail ou mot de passe incorrect')
    }
    clearLoginFailures(key)
    await createSession(req, reply, user.id)
    await audit(req, { orgId: user.memberships[0]?.orgId, user }, 'auth.login')
    return { ok: true }
  })

  app.post('/auth/logout', async (req: any, reply: any) => {
    try {
      const ctx = await getCtx(req)
      await prisma.session.update({ where: { id: ctx.sessionId }, data: { revoked: true } })
      await audit(req, ctx, 'auth.logout')
    } catch {}
    clearSessionCookie(reply)
    return { ok: true }
  })

  app.get('/auth/me', async (req: any) => {
    const ctx = await getCtx(req)
    const unread = await prisma.notification.count({ where: { orgId: ctx.orgId, read: false } })
    return {
      user: { id: ctx.user.id, name: ctx.user.name, email: ctx.user.email },
      org: { id: ctx.org.id, name: ctx.org.name, plan: ctx.org.plan },
      role: ctx.role, plan: planOf(ctx.org), usage: await usage(ctx.orgId), unread,
    }
  })

  app.patch('/auth/profile', async (req: any) => {
    const ctx = await getCtx(req)
    const name = str(req.body?.name, 80)
    if (!name) throw new HttpError(400, 'Nom requis')
    await prisma.user.update({ where: { id: ctx.user.id }, data: { name } })
    return { ok: true }
  })

  app.post('/auth/password', async (req: any) => {
    const ctx = await getCtx(req)
    const next = String(req.body?.next ?? '')
    if (!(await verifyPassword(ctx.user.passwordHash, String(req.body?.current ?? '')))) throw new HttpError(400, 'Mot de passe actuel incorrect')
    checkPassword(next)
    await prisma.user.update({ where: { id: ctx.user.id }, data: { passwordHash: await hashPassword(next) } })
    await prisma.session.updateMany({ where: { userId: ctx.user.id, id: { not: ctx.sessionId } }, data: { revoked: true } })
    await audit(req, ctx, 'auth.password_changed', 'Autres sessions révoquées')
    return { ok: true }
  })

  app.get('/auth/sessions', async (req: any) => {
    const ctx = await getCtx(req)
    const list = await prisma.session.findMany({ where: { userId: ctx.user.id, revoked: false, expiresAt: { gt: new Date() } }, orderBy: { createdAt: 'desc' } })
    return list.map((s) => ({ id: s.id, userAgent: s.userAgent, ip: s.ip, createdAt: s.createdAt, current: s.id === ctx.sessionId }))
  })

  app.delete('/auth/sessions/:id', async (req: any) => {
    const ctx = await getCtx(req)
    const r = await prisma.session.updateMany({ where: { id: req.params.id, userId: ctx.user.id }, data: { revoked: true } })
    if (!r.count) throw new HttpError(404, 'Session introuvable')
    await audit(req, ctx, 'auth.session_revoked')
    return { ok: true }
  })

  // ================= TABLEAU DE BORD =================
  app.get('/dashboard', async (req: any) => {
    const ctx = await getCtx(req)
    const orgId = ctx.orgId
    const open = { orgId, status: { notIn: ['FIXED', 'RETESTED', 'CLOSED', 'FALSE_POSITIVE'] } }
    const [projects, apps, scans, bySev, incidents, recent] = await Promise.all([
      prisma.project.count({ where: { orgId, archived: false } }),
      prisma.application.findMany({ where: { orgId }, select: { id: true, name: true, lastStatus: true, lastResponseMs: true, monitoring: true } }),
      prisma.scan.count({ where: { orgId } }),
      prisma.finding.groupBy({ by: ['severity'], where: open, _count: true }),
      prisma.incident.findMany({ where: { orgId }, orderBy: { startedAt: 'desc' }, take: 5, include: { application: { select: { name: true } } } }),
      prisma.scan.findMany({ where: { orgId, status: 'DONE' }, orderBy: { createdAt: 'desc' }, take: 12, include: { application: { select: { name: true } } } }),
    ])
    const sev: any = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    bySev.forEach((s: any) => (sev[s.severity] = s._count))
    const sums = recent.map((s) => ({ ...JSON.parse(s.summary), id: s.id }))
    const qa = sums.filter((s) => s.qa?.rate != null).map((s) => s.qa.rate)
    const perf = sums.filter((s) => s.performance?.score != null).map((s) => s.performance.score)
    const avg = (a: number[]) => (a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : null)
    return {
      projects, applications: apps.length, scans, severities: sev,
      openFindings: Object.values(sev).reduce((a: any, b: any) => a + b, 0),
      qaRate: avg(qa), perfScore: avg(perf), apps, incidents,
      trend: recent.reverse().map((s) => ({ id: s.id, app: s.application.name, score: s.score, date: s.createdAt })),
    }
  })

  // ================= PROJETS =================
  app.get('/projects', async (req: any) => {
    const ctx = await getCtx(req)
    return prisma.project.findMany({ where: { orgId: ctx.orgId }, orderBy: { createdAt: 'desc' }, include: { applications: { orderBy: { createdAt: 'asc' } } } })
  })

  app.post('/projects', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, MANAGE)
    const name = str(req.body?.name, 80)
    if (!name) throw new HttpError(400, 'Nom du projet requis')
    const p = await prisma.project.create({ data: { orgId: ctx.orgId, name, description: str(req.body?.description, 500) } })
    await audit(req, ctx, 'project.create', name)
    return p
  })

  app.patch('/projects/:id', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, MANAGE)
    const data: any = {}
    if (req.body?.name !== undefined) data.name = str(req.body.name, 80) || undefined
    if (req.body?.description !== undefined) data.description = str(req.body.description, 500)
    if (req.body?.archived !== undefined) data.archived = !!req.body.archived
    const r = await prisma.project.updateMany({ where: { id: req.params.id, orgId: ctx.orgId }, data })
    if (!r.count) throw new HttpError(404, 'Projet introuvable')
    await audit(req, ctx, 'project.update', req.params.id)
    return { ok: true }
  })

  app.delete('/projects/:id', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, ['ADMIN'])
    const r = await prisma.project.deleteMany({ where: { id: req.params.id, orgId: ctx.orgId } })
    if (!r.count) throw new HttpError(404, 'Projet introuvable')
    await audit(req, ctx, 'project.delete', req.params.id)
    return { ok: true }
  })

  // ================= APPLICATIONS =================
  app.get('/applications', async (req: any) => {
    const ctx = await getCtx(req)
    return prisma.application.findMany({ where: { orgId: ctx.orgId }, orderBy: { createdAt: 'desc' }, include: { project: { select: { name: true } } } })
  })

  app.post('/applications', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, MANAGE)
    const b = req.body ?? {}
    const name = str(b.name, 80)
    if (!name) throw new HttpError(400, "Nom de l'application requis")
    let url: URL
    try {
      url = assertAllowedUrl(str(b.url, 500))
    } catch (e: any) {
      throw new HttpError(400, e.message)
    }
    return withLock(ctx.orgId, async () => {
      const project = await prisma.project.findFirst({ where: { id: str(b.projectId), orgId: ctx.orgId } })
      if (!project) throw new HttpError(404, 'Projet introuvable')
      const plan = planOf(ctx.org)
      if ((await prisma.application.count({ where: { orgId: ctx.orgId } })) >= plan.apps) {
        throw new HttpError(402, `Quota atteint : ${plan.apps} application(s) maximum avec la formule ${plan.label}`)
      }
      const a = await prisma.application.create({
        data: {
          orgId: ctx.orgId, projectId: project.id, name, url: url.href, description: str(b.description, 500),
          type: b.type === 'API' ? 'API' : 'WEB', environment: ENVS.includes(b.environment) ? b.environment : 'PRODUCTION',
          monitorInterval: plan.minMonitorInterval,
        },
      })
      await audit(req, ctx, 'application.create', `${name} (${url.href})`)
      return a
    })
  })

  app.patch('/applications/:id', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, MANAGE)
    const b = req.body ?? {}
    const data: any = {}
    if (b.name !== undefined) data.name = str(b.name, 80) || undefined
    if (b.description !== undefined) data.description = str(b.description, 500)
    if (b.environment !== undefined && ENVS.includes(b.environment)) data.environment = b.environment
    if (b.monitoring !== undefined) data.monitoring = !!b.monitoring
    if (b.monitorInterval !== undefined) {
      const n = Number(b.monitorInterval), min = planOf(ctx.org).minMonitorInterval
      if (![5, 15, 30, 60].includes(n)) throw new HttpError(400, 'Fréquence invalide (5, 15, 30 ou 60 minutes)')
      if (n < min) throw new HttpError(402, `Votre formule autorise une fréquence minimale de ${min} minutes`)
      data.monitorInterval = n
    }
    const r = await prisma.application.updateMany({ where: { id: req.params.id, orgId: ctx.orgId }, data })
    if (!r.count) throw new HttpError(404, 'Application introuvable')
    await audit(req, ctx, 'application.update', req.params.id)
    return { ok: true }
  })

  // Autorisation d'audit (section 14.4) : déclaration explicite, tracée dans le journal
  app.post('/applications/:id/authorize', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, MANAGE)
    if (req.body?.declaration !== true) throw new HttpError(400, 'Vous devez déclarer être propriétaire de la cible ou détenir une autorisation écrite')
    const r = await prisma.application.updateMany({ where: { id: req.params.id, orgId: ctx.orgId }, data: { authorized: true, authorizedAt: new Date(), authorizedBy: ctx.user.id } })
    if (!r.count) throw new HttpError(404, 'Application introuvable')
    await audit(req, ctx, 'application.authorize', `Déclaration de propriété/autorisation par ${ctx.user.email} pour ${req.params.id}`)
    return { ok: true }
  })

  app.post('/applications/:id/check', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, OPERATE)
    const a = await prisma.application.findFirst({ where: { id: req.params.id, orgId: ctx.orgId } })
    if (!a) throw new HttpError(404, 'Application introuvable')
    if (!a.authorized) throw new HttpError(403, "Autorisation requise avant toute vérification de cette cible")
    return checkApplication(a)
  })

  app.delete('/applications/:id', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, MANAGE)
    const r = await prisma.application.deleteMany({ where: { id: req.params.id, orgId: ctx.orgId } })
    if (!r.count) throw new HttpError(404, 'Application introuvable')
    await audit(req, ctx, 'application.delete', req.params.id)
    return { ok: true }
  })

  // ================= CAMPAGNES D'AUDIT =================
  app.get('/scans', async (req: any) => {
    const ctx = await getCtx(req)
    const list = await prisma.scan.findMany({ where: { orgId: ctx.orgId }, orderBy: { createdAt: 'desc' }, take: 100, include: { application: { select: { name: true, url: true } } } })
    return list.map((s) => ({ ...s, summary: JSON.parse(s.summary) }))
  })

  app.post('/scans', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, OPERATE)
    const modules: string[] = (Array.isArray(req.body?.modules) ? req.body.modules : []).filter((m: any) => MODULES.includes(m))
    if (!modules.length) throw new HttpError(400, 'Sélectionnez au moins un module')
    return withLock(ctx.orgId, async () => {
      const a = await prisma.application.findFirst({ where: { id: str(req.body?.applicationId), orgId: ctx.orgId } })
      if (!a) throw new HttpError(404, 'Application introuvable')
      if (!a.authorized) throw new HttpError(403, "Aucun audit ne peut être lancé sans autorisation explicite sur la cible")
      const plan = planOf(ctx.org), u = await usage(ctx.orgId)
      if (u.scansThisMonth >= plan.scansPerMonth) throw new HttpError(402, `Quota mensuel atteint : ${plan.scansPerMonth} audits avec la formule ${plan.label}`)
      if (u.running >= plan.concurrent) throw new HttpError(429, `Limite d'audits simultanés atteinte (${plan.concurrent}). Attendez la fin de l'audit en cours.`)
      const scan = await prisma.scan.create({ data: { orgId: ctx.orgId, applicationId: a.id, modules: [...new Set(modules)].join(','), createdById: ctx.user.id } })
      await audit(req, ctx, 'scan.launch', `${a.name} — modules : ${scan.modules}`)
      launchScan(scan.id)
      return scan
    })
  })

  async function loadScan(ctx: any, id: string) {
    const scan = await prisma.scan.findFirst({
      where: { id, orgId: ctx.orgId },
      include: { application: true, findings: true, testResults: true, metrics: true },
    })
    if (!scan) throw new HttpError(404, 'Audit introuvable')
    const order = (s: string) => SEVERITIES.indexOf(s)
    scan.findings.sort((a, b) => order(a.severity) - order(b.severity))
    // Comparaison avec la campagne précédente de la même application (section 10.3)
    const prev = await prisma.scan.findFirst({
      where: { orgId: ctx.orgId, applicationId: scan.applicationId, status: 'DONE', createdAt: { lt: scan.createdAt }, modules: { contains: 'SECURITY' } },
      orderBy: { createdAt: 'desc' }, include: { findings: true },
    })
    let comparison: any = null
    if (prev && scan.modules.includes('SECURITY')) {
      const before = new Set(prev.findings.map((f) => f.fingerprint)), now = new Set(scan.findings.map((f) => f.fingerprint))
      comparison = {
        previousId: prev.id, previousDate: prev.createdAt, previousScore: prev.score,
        fixed: prev.findings.filter((f) => !now.has(f.fingerprint)).map((f) => f.title),
        added: scan.findings.filter((f) => !before.has(f.fingerprint)).map((f) => f.title),
        persistent: scan.findings.filter((f) => before.has(f.fingerprint)).length,
      }
    }
    return { ...scan, summary: JSON.parse(scan.summary), comparison }
  }

  app.get('/scans/:id', async (req: any) => loadScan(await getCtx(req), req.params.id))

  app.get('/scans/:id/report', async (req: any, reply: any) => {
    const ctx = await getCtx(req)
    const scan = await loadScan(ctx, req.params.id)
    if (scan.status !== 'DONE') throw new HttpError(409, "Le rapport n'est disponible qu'une fois l'audit terminé")
    const fmt = String(req.query?.format ?? 'pdf')
    const file = `sentinelx-rapport-${scan.id}`
    await audit(req, ctx, 'report.download', `${scan.id} (${fmt})`)
    if (fmt === 'json') return reply.header('content-disposition', `attachment; filename="${file}.json"`).send(scan)
    if (fmt === 'csv') return reply.header('content-type', 'text/csv; charset=utf-8').header('content-disposition', `attachment; filename="${file}.csv"`).send(buildCsv(scan))
    const pdf = await buildPdf(scan, ctx.org.name)
    return reply.header('content-type', 'application/pdf').header('content-disposition', `attachment; filename="${file}.pdf"`).send(pdf)
  })

  // ================= VULNÉRABILITÉS =================
  app.get('/findings', async (req: any) => {
    const ctx = await getCtx(req)
    const q = req.query ?? {}
    const where: any = { orgId: ctx.orgId }
    if (SEVERITIES.includes(q.severity)) where.severity = q.severity
    if (FINDING_STATUS.includes(q.status)) where.status = q.status
    if (q.applicationId) where.applicationId = String(q.applicationId)
    const list = await prisma.finding.findMany({ where, orderBy: { createdAt: 'desc' }, take: 300, include: { scan: { select: { application: { select: { name: true } } } } } })
    const order = (s: string) => SEVERITIES.indexOf(s)
    return list.sort((a, b) => order(a.severity) - order(b.severity)).map((f) => ({ ...f, application: f.scan.application.name, scan: undefined }))
  })

  app.patch('/findings/:id', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, OPERATE)
    const status = String(req.body?.status ?? ''), note = str(req.body?.note, 500)
    if (!FINDING_STATUS.includes(status)) throw new HttpError(400, 'Statut invalide')
    if (status === 'FALSE_POSITIVE' && !note) throw new HttpError(400, 'Un faux positif doit être justifié')
    const r = await prisma.finding.updateMany({ where: { id: req.params.id, orgId: ctx.orgId }, data: { status, ...(note ? { note } : {}) } })
    if (!r.count) throw new HttpError(404, 'Vulnérabilité introuvable')
    await audit(req, ctx, 'finding.status', `${req.params.id} → ${status}`)
    return { ok: true }
  })

  // ================= MONITORING / NOTIFICATIONS =================
  app.get('/incidents', async (req: any) => {
    const ctx = await getCtx(req)
    return prisma.incident.findMany({ where: { orgId: ctx.orgId }, orderBy: { startedAt: 'desc' }, take: 100, include: { application: { select: { name: true } } } })
  })

  app.get('/notifications', async (req: any) => {
    const ctx = await getCtx(req)
    return prisma.notification.findMany({ where: { orgId: ctx.orgId }, orderBy: { createdAt: 'desc' }, take: 100 })
  })

  app.post('/notifications/read-all', async (req: any) => {
    const ctx = await getCtx(req)
    await prisma.notification.updateMany({ where: { orgId: ctx.orgId, read: false }, data: { read: true } })
    return { ok: true }
  })

  // ================= MEMBRES =================
  app.get('/members', async (req: any) => {
    const ctx = await getCtx(req)
    const list = await prisma.organizationMember.findMany({ where: { orgId: ctx.orgId }, include: { user: { select: { id: true, name: true, email: true, createdAt: true } } } })
    return list.map((m) => ({ id: m.id, role: m.role, ...m.user, memberId: m.id, self: m.userId === ctx.user.id }))
  })

  app.post('/members', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, ['ADMIN'])
    const b = req.body ?? {}
    const name = str(b.name, 80), email = str(b.email, 160).toLowerCase(), password = String(b.password ?? '')
    const role = ROLES.includes(b.role) ? b.role : 'READER'
    if (!name || !EMAIL.test(email)) throw new HttpError(400, 'Nom et e-mail valides requis')
    checkPassword(password)
    return withLock(ctx.orgId, async () => {
      const plan = planOf(ctx.org)
      if ((await prisma.organizationMember.count({ where: { orgId: ctx.orgId } })) >= plan.members) {
        throw new HttpError(402, `Quota atteint : ${plan.members} collaborateur(s) maximum avec la formule ${plan.label}`)
      }
      if (await prisma.user.findUnique({ where: { email } })) throw new HttpError(409, 'Un compte existe déjà avec cet e-mail')
      const user = await prisma.user.create({ data: { name, email, passwordHash: await hashPassword(password), memberships: { create: { orgId: ctx.orgId, role } } } })
      await audit(req, ctx, 'member.invite', `${email} (${role})`)
      return { id: user.id }
    })
  })

  async function adminCount(orgId: string) {
    return prisma.organizationMember.count({ where: { orgId, role: 'ADMIN' } })
  }

  app.patch('/members/:id', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, ['ADMIN'])
    const role = String(req.body?.role ?? '')
    if (!ROLES.includes(role)) throw new HttpError(400, 'Rôle invalide')
    const m = await prisma.organizationMember.findFirst({ where: { id: req.params.id, orgId: ctx.orgId } })
    if (!m) throw new HttpError(404, 'Membre introuvable')
    if (m.role === 'ADMIN' && role !== 'ADMIN' && (await adminCount(ctx.orgId)) <= 1) throw new HttpError(400, "L'organisation doit conserver au moins un administrateur")
    await prisma.organizationMember.update({ where: { id: m.id }, data: { role } })
    await audit(req, ctx, 'member.role', `${m.userId} → ${role}`)
    return { ok: true }
  })

  app.delete('/members/:id', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, ['ADMIN'])
    const m = await prisma.organizationMember.findFirst({ where: { id: req.params.id, orgId: ctx.orgId } })
    if (!m) throw new HttpError(404, 'Membre introuvable')
    if (m.userId === ctx.user.id) throw new HttpError(400, 'Vous ne pouvez pas vous retirer vous-même')
    if (m.role === 'ADMIN' && (await adminCount(ctx.orgId)) <= 1) throw new HttpError(400, "L'organisation doit conserver au moins un administrateur")
    await prisma.user.delete({ where: { id: m.userId } }) // supprime aussi l'adhésion et les sessions (cascade)
    await audit(req, ctx, 'member.remove', m.userId)
    return { ok: true }
  })

  // ================= ABONNEMENT =================
  app.get('/billing', async (req: any) => {
    const ctx = await getCtx(req)
    return { current: ctx.org.plan, plans: PLANS, usage: await usage(ctx.orgId) }
  })

  app.post('/billing/plan', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, ['ADMIN'])
    const plan = String(req.body?.plan ?? '')
    if (!PLANS[plan]) throw new HttpError(400, 'Formule inconnue')
    return withLock(ctx.orgId, async () => {
      const u = await usage(ctx.orgId), p = PLANS[plan]
      if (u.apps > p.apps || u.members > p.members) throw new HttpError(409, `Votre utilisation actuelle dépasse les limites de la formule ${p.label} (${p.apps} applications, ${p.members} collaborateurs)`)
      await prisma.organization.update({ where: { id: ctx.orgId }, data: { plan } })
      await audit(req, ctx, 'billing.plan_change', `${ctx.org.plan} → ${plan} (démonstration, sans paiement)`)
      return { ok: true }
    })
  })

  // ================= JOURNAL =================
  app.get('/audit-logs', async (req: any) => {
    const ctx = await getCtx(req)
    need(ctx, ['ADMIN'])
    return prisma.auditLog.findMany({ where: { orgId: ctx.orgId }, orderBy: { createdAt: 'desc' }, take: 100 })
  })
}

// Moteurs d'analyse : QA, sécurité (contrôles passifs non destructifs), performance.
// Toutes les requêtes sortantes passent par safeFetch (protection SSRF, section 14.3).
import { Agent, fetch as ufetch } from 'undici'
import dns from 'node:dns'
import net from 'node:net'
import tls from 'node:tls'
import { prisma, notify } from './core.js'

const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE_TARGETS === 'true' // mode laboratoire local uniquement
const UA = 'SentinelX-Scanner/0.1'

export function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number)
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || // inclut les métadonnées cloud 169.254.169.254
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0)) ||
      (a === 198 && (b === 18 || b === 19))
    )
  }
  const v = ip.toLowerCase()
  if (v.startsWith('::ffff:')) {
    const m = v.slice(7)
    return net.isIPv4(m) ? isPrivateIp(m) : true
  }
  return v === '::' || v === '::1' || /^f[cd]/.test(v) || /^fe[89ab]/.test(v) || v.startsWith('ff') || v.startsWith('64:ff9b')
}

/** Résolution DNS contrôlée : l'adresse réellement utilisée pour la connexion est vérifiée (pas de contournement par DNS). */
function guardedLookup(hostname: string, options: any, cb: any) {
  dns.lookup(hostname, options, (err: any, address: any, family: any) => {
    if (err) return cb(err, address, family)
    const list = Array.isArray(address) ? address.map((a: any) => a.address) : [address]
    if (!ALLOW_PRIVATE && list.some(isPrivateIp)) {
      return cb(new Error('Destination interne bloquée (protection SSRF)'), address, family)
    }
    cb(null, address, family)
  })
}

const agent = new Agent({
  connect: { lookup: guardedLookup as any, timeout: 8000 },
  headersTimeout: 12000,
  bodyTimeout: 12000,
})

export function assertAllowedUrl(raw: string | URL): URL {
  let u: URL
  try {
    u = typeof raw === 'string' ? new URL(raw) : raw
  } catch {
    throw new Error('URL invalide')
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('Seuls http et https sont autorisés')
  if (u.username || u.password) throw new Error("Les identifiants dans l'URL ne sont pas autorisés")
  const host = u.hostname.replace(/^\[|\]$/g, '')
  if (!ALLOW_PRIVATE) {
    if (net.isIP(host) && isPrivateIp(host)) throw new Error('Adresse interne bloquée (protection SSRF)')
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
      throw new Error('Nom d\'hôte interne bloqué (protection SSRF)')
    }
  }
  return u
}

export type Fetched = { url: string; status: number; headers: Headers; body: string; bytes: number; ttfb: number; total: number; chain: string[] }

/** Requête HTTP sécurisée : redirections suivies manuellement et revalidées, délai et taille limités. */
export async function safeFetch(rawUrl: string, opts: { readBody?: boolean; maxRedirects?: number; maxBytes?: number } = {}): Promise<Fetched> {
  const { readBody = true, maxRedirects = 5, maxBytes = 2_000_000 } = opts
  let url = assertAllowedUrl(rawUrl)
  const chain: string[] = []
  const t0 = performance.now()
  for (let i = 0; i <= maxRedirects; i++) {
    assertAllowedUrl(url)
    const res: any = await ufetch(url, {
      method: 'GET',
      redirect: 'manual',
      dispatcher: agent,
      headers: { 'user-agent': UA, accept: '*/*' },
      signal: AbortSignal.timeout(15000),
    })
    const ttfb = performance.now() - t0
    const loc = res.headers.get('location')
    if ([301, 302, 303, 307, 308].includes(res.status) && loc) {
      chain.push(`${res.status} ${url.href}`)
      await res.body?.cancel().catch(() => {})
      url = new URL(loc, url)
      continue
    }
    let body = ''
    let bytes = 0
    if (readBody && res.body) {
      const reader = res.body.getReader()
      const chunks: Uint8Array[] = []
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        bytes += value.length
        if (bytes > maxBytes) {
          await reader.cancel().catch(() => {})
          break
        }
        chunks.push(value)
      }
      body = Buffer.concat(chunks).toString('utf8')
    } else {
      await res.body?.cancel().catch(() => {})
    }
    return { url: url.href, status: res.status, headers: res.headers, body, bytes, ttfb, total: performance.now() - t0, chain }
  }
  throw new Error('Trop de redirections')
}

const errMsg = (e: any) => String(e?.cause?.message ?? e?.message ?? e).slice(0, 200)
const cut = (s: string, n = 300) => (s.length > n ? s.slice(0, n) + '…' : s)

// =============== MODULE QA ===============
type Test = { name: string; status: 'PASS' | 'FAIL'; detail: string; durationMs: number }

async function runQA(app: any): Promise<Test[]> {
  const out: Test[] = []
  const add = (name: string, ok: boolean, detail = '', ms = 0) => out.push({ name, status: ok ? 'PASS' : 'FAIL', detail: cut(detail, 600), durationMs: Math.round(ms) })

  let page: Fetched
  try {
    page = await safeFetch(app.url)
  } catch (e) {
    add('Page principale accessible', false, errMsg(e))
    return out
  }
  add('Page principale accessible', page.status < 400, `HTTP ${page.status} en ${Math.round(page.total)} ms`, page.total)
  const html = page.body
  const isHtml = (page.headers.get('content-type') ?? '').includes('html')
  if (!isHtml) {
    add('Réponse exploitable', true, `Type de contenu : ${page.headers.get('content-type') ?? 'inconnu'} (contrôles HTML ignorés)`)
    return out
  }
  add('Balise <title> renseignée', /<title[^>]*>\s*[^<\s]/i.test(html), 'Le titre de page est requis pour la navigation et le référencement')
  add('Langue déclarée sur <html>', /<html[^>]*\slang=/i.test(html), 'Attribut lang attendu sur la balise html')
  add('Meta viewport (affichage mobile)', /<meta[^>]+name=["']?viewport/i.test(html), 'Nécessaire pour un affichage responsive')

  const imgs = html.match(/<img\b[^>]*>/gi) ?? []
  const noAlt = imgs.filter((i) => !/\salt\s*=/i.test(i))
  add('Images avec texte alternatif', noAlt.length === 0, `${noAlt.length} image(s) sans attribut alt sur ${imgs.length}`)

  const forms = html.match(/<form\b[\s\S]*?<\/form>/gi) ?? []
  const required = (html.match(/<(input|select|textarea)\b[^>]*\srequired\b/gi) ?? []).length
  add('Formulaires détectés', true, `${forms.length} formulaire(s), ${required} champ(s) obligatoire(s) déclaré(s)`)

  // Liens et ressources : vérification non destructive (GET), limitée en volume
  const found = new Set<string>()
  for (const m of html.matchAll(/(?:href|src)\s*=\s*["']([^"'#\s]+)["']/gi)) {
    try {
      const u = new URL(m[1], page.url)
      if (u.protocol === 'http:' || u.protocol === 'https:') found.add(u.href)
    } catch {}
    if (found.size >= 30) break
  }
  const links = [...found]
  const broken: string[] = []
  const t0 = performance.now()
  let idx = 0
  await Promise.all(
    Array.from({ length: 5 }, async () => {
      while (idx < links.length) {
        const link = links[idx++]
        try {
          const r = await safeFetch(link, { readBody: false })
          if (r.status >= 400 && r.status !== 401 && r.status !== 403 && r.status !== 429) broken.push(`${r.status} ${link}`)
        } catch (e) {
          broken.push(`ERREUR ${link} (${errMsg(e)})`)
        }
      }
    }),
  )
  add(`Liens et ressources valides (${links.length} vérifiés)`, broken.length === 0, broken.length ? broken.slice(0, 8).join('\n') : 'Aucun lien cassé détecté', performance.now() - t0)
  return out
}

// =============== MODULE SÉCURITÉ (passif) ===============
type F = { severity: string; title: string; description: string; resource: string; evidence: string; recommendation: string }

function tlsInfo(host: string, port: number): Promise<any> {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, lookup: guardedLookup as any, timeout: 8000 }, () => {
      const c: any = s.getPeerCertificate()
      const out = { authorized: s.authorized, error: s.authorizationError ? String(s.authorizationError) : null, protocol: s.getProtocol(), validTo: c?.valid_to, subject: c?.subject?.CN, issuer: c?.issuer?.O ?? c?.issuer?.CN }
      s.end()
      resolve(out)
    })
    s.on('error', reject)
    s.on('timeout', () => s.destroy(new Error('Délai TLS dépassé')))
  })
}

async function runSecurity(app: any): Promise<{ findings: F[]; info: any }> {
  const f: F[] = []
  const add = (severity: string, title: string, description: string, resource: string, evidence: string, recommendation: string) =>
    f.push({ severity, title, description, resource, evidence: cut(evidence, 500), recommendation })
  const page = await safeFetch(app.url)
  const h = page.headers
  const u = new URL(page.url)
  const https = u.protocol === 'https:'
  const html = page.body
  const info: any = { finalUrl: page.url, status: page.status }
  const missing = (name: string) => `En-tête « ${name} » absent de la réponse HTTP ${page.status} de ${page.url}`

  // --- Transport ---
  if (!https) {
    add('HIGH', 'Application servie sans HTTPS', 'Les échanges ne sont pas chiffrés : identifiants et données peuvent être interceptés.', page.url, `URL finale après redirections : ${page.url}`, 'Activer HTTPS avec un certificat valide et rediriger tout le trafic HTTP vers HTTPS.')
  } else {
    if (!u.port) {
      try {
        const plain = await safeFetch(`http://${u.hostname}/`, { readBody: false })
        if (new URL(plain.url).protocol === 'http:') {
          add('MEDIUM', 'HTTP non redirigé vers HTTPS', 'La version HTTP du site répond sans rediriger vers HTTPS.', `http://${u.hostname}/`, `GET http://${u.hostname}/ → HTTP ${plain.status} sans redirection vers https`, 'Rediriger systématiquement (301) le trafic HTTP vers HTTPS.')
        }
      } catch {}
    }
    try {
      const t = await tlsInfo(u.hostname, Number(u.port) || 443)
      info.tls = t
      const days = t.validTo ? Math.floor((new Date(t.validTo).getTime() - Date.now()) / 86400_000) : null
      info.tls.daysLeft = days
      if (!t.authorized) add('HIGH', 'Certificat TLS non valide', 'Le certificat présenté ne peut pas être validé (chaîne, nom de domaine ou expiration).', u.host, `Erreur de validation : ${t.error} — sujet : ${t.subject}, émetteur : ${t.issuer}`, 'Installer un certificat valide couvrant ce nom de domaine avec la chaîne complète.')
      else if (days !== null && days < 30) add(days < 7 ? 'HIGH' : 'MEDIUM', 'Certificat TLS bientôt expiré', `Le certificat expire dans ${days} jour(s).`, u.host, `valid_to : ${t.validTo}`, 'Renouveler le certificat et automatiser le renouvellement.')
      if (t.protocol === 'TLSv1' || t.protocol === 'TLSv1.1') add('MEDIUM', 'Protocole TLS obsolète', 'Le serveur négocie une version de TLS dépréciée.', u.host, `Protocole négocié : ${t.protocol}`, 'Désactiver TLS 1.0 et 1.1, n\'autoriser que TLS 1.2 et 1.3.')
    } catch (e) {
      info.tlsError = errMsg(e)
    }
    if (!h.get('strict-transport-security')) add('MEDIUM', 'En-tête HSTS manquant', 'Sans HSTS, un navigateur peut être forcé à utiliser HTTP lors d\'une attaque de type downgrade.', page.url, missing('Strict-Transport-Security'), 'Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains')
    if (/(?:src|href)\s*=\s*["']http:\/\//i.test(html) && /<(script|img|iframe|link)\b[^>]*(?:src|href)\s*=\s*["']http:\/\//i.test(html)) {
      const m = html.match(/<(script|img|iframe|link)\b[^>]*(?:src|href)\s*=\s*["']http:\/\/[^"']+["'][^>]*>/i)
      add('MEDIUM', 'Contenu mixte (ressource HTTP sur page HTTPS)', 'Une ressource est chargée en clair depuis une page chiffrée.', page.url, m?.[0] ?? '', 'Charger toutes les ressources en HTTPS.')
    }
  }

  // --- En-têtes de sécurité ---
  const csp = h.get('content-security-policy')
  if (!csp) add('MEDIUM', 'Content-Security-Policy manquante', 'Sans CSP, l\'impact d\'une injection de script (XSS) n\'est pas limité par le navigateur.', page.url, missing('Content-Security-Policy'), 'Définir une politique CSP restrictive (default-src \'self\' au minimum).')
  if (!h.get('x-frame-options') && !(csp && /frame-ancestors/i.test(csp))) add('MEDIUM', 'Protection anti-clickjacking absente', 'La page peut être intégrée dans une iframe par un site tiers.', page.url, `${missing('X-Frame-Options')} ; pas de directive frame-ancestors dans la CSP`, 'Ajouter X-Frame-Options: DENY ou la directive CSP frame-ancestors \'none\'.')
  if (!h.get('x-content-type-options')) add('LOW', 'X-Content-Type-Options manquant', 'Le navigateur peut interpréter un fichier avec un type différent de celui annoncé.', page.url, missing('X-Content-Type-Options'), 'Ajouter : X-Content-Type-Options: nosniff')
  if (!h.get('referrer-policy')) add('LOW', 'Referrer-Policy manquante', 'Les URL internes peuvent être transmises à des sites tiers.', page.url, missing('Referrer-Policy'), 'Ajouter : Referrer-Policy: strict-origin-when-cross-origin')
  if (!h.get('permissions-policy')) add('INFO', 'Permissions-Policy manquante', 'Les fonctionnalités sensibles du navigateur (caméra, micro, géolocalisation) ne sont pas restreintes.', page.url, missing('Permissions-Policy'), 'Déclarer une Permissions-Policy limitant les fonctionnalités inutilisées.')

  // --- Divulgation d'informations ---
  const server = h.get('server')
  if (server && /\d/.test(server)) add('LOW', 'Version du serveur exposée', 'La version du serveur facilite la recherche de vulnérabilités connues.', page.url, `Server: ${server}`, 'Masquer la version dans l\'en-tête Server.')
  const powered = h.get('x-powered-by')
  if (powered) add('LOW', 'Technologie exposée (X-Powered-By)', 'La technologie utilisée est divulguée inutilement.', page.url, `X-Powered-By: ${powered}`, 'Supprimer l\'en-tête X-Powered-By.')
  if (h.get('access-control-allow-origin') === '*') add('INFO', 'CORS ouvert à toutes les origines', 'Toute origine peut lire les réponses publiques de cette ressource. À vérifier manuellement si des données sensibles sont exposées.', page.url, 'Access-Control-Allow-Origin: *', 'Restreindre les origines autorisées si la ressource n\'est pas publique.')

  // --- Cookies ---
  const cookies: string[] = (h as any).getSetCookie?.() ?? []
  for (const c of cookies.slice(0, 10)) {
    const name = c.split('=')[0]
    const sensitive = /sess|sid|token|auth|jwt/i.test(name)
    const lacks: string[] = []
    if (https && !/;\s*secure/i.test(c)) lacks.push('Secure')
    if (!/;\s*httponly/i.test(c)) lacks.push('HttpOnly')
    if (!/;\s*samesite/i.test(c)) lacks.push('SameSite')
    if (lacks.length) add(sensitive ? 'MEDIUM' : 'LOW', `Cookie « ${name} » sans attribut ${lacks.join(', ')}`, 'Les attributs de sécurité du cookie sont incomplets.', page.url, `Set-Cookie: ${c.replace(/=([^;]{6})[^;]*/, '=$1…')}`, 'Définir les attributs Secure, HttpOnly et SameSite sur les cookies.')
  }

  // --- Formulaires ---
  const forms = html.match(/<form\b[\s\S]*?<\/form>/gi) ?? []
  for (const form of forms.slice(0, 10)) {
    const tag = form.match(/<form\b[^>]*>/i)?.[0] ?? ''
    if (!https && /type\s*=\s*["']?password/i.test(form)) add('HIGH', 'Mot de passe transmis sans chiffrement', 'Un formulaire contenant un champ mot de passe est servi en HTTP.', page.url, cut(tag, 200), 'Servir et soumettre ce formulaire exclusivement en HTTPS.')
    if (/method\s*=\s*["']?post/i.test(tag) && !/name\s*=\s*["']?[^"'>\s]*(csrf|token|nonce|authenticity)/i.test(form)) {
      add('INFO', 'Jeton anti-CSRF non visible dans un formulaire POST', 'Aucun champ de type jeton n\'a été repéré. Constat non confirmé : la protection peut reposer sur un autre mécanisme (cookie SameSite, en-tête).', page.url, cut(tag, 200), 'Vérifier manuellement la protection CSRF de ce formulaire.')
    }
  }

  // --- Fichiers sensibles exposés (2 requêtes GET, lecture seule) ---
  const base = `${u.protocol}//${u.host}`
  try {
    const git = await safeFetch(`${base}/.git/HEAD`, { maxBytes: 2000 })
    if (git.status === 200 && /^ref:\s|^[0-9a-f]{40}/.test(git.body.trim())) add('HIGH', 'Dépôt Git exposé publiquement', 'Le dossier .git est accessible : le code source et son historique peuvent être reconstitués.', `${base}/.git/HEAD`, `HTTP 200 — contenu : ${cut(git.body.trim(), 80)}`, 'Bloquer l\'accès au dossier .git au niveau du serveur web.')
  } catch {}
  try {
    const env = await safeFetch(`${base}/.env`, { maxBytes: 5000 })
    if (env.status === 200 && !(env.headers.get('content-type') ?? '').includes('html') && /^[A-Z][A-Z0-9_]*\s*=/m.test(env.body)) {
      const keys = [...env.body.matchAll(/^([A-Z][A-Z0-9_]*)\s*=/gm)].map((m) => m[1]).slice(0, 8)
      add('CRITICAL', 'Fichier .env exposé publiquement', 'Le fichier de configuration est téléchargeable : il contient généralement des secrets.', `${base}/.env`, `HTTP 200 — clés présentes (valeurs masquées) : ${keys.join(', ')}`, 'Retirer le fichier de la racine web, bloquer son accès et renouveler tous les secrets qu\'il contient.')
    }
  } catch {}

  return { findings: f, info }
}

// =============== MODULE PERFORMANCE ===============
type Metric = { name: string; value: number; unit: string }

async function runPerf(app: any): Promise<{ metrics: Metric[]; score: number }> {
  const N = 10 // volume volontairement limité : mesure, pas test de charge
  const times: number[] = []
  const ttfbs: number[] = []
  let errors = 0
  let bytes = 0
  let totalBytes = 0
  const t0 = performance.now()
  for (let i = 0; i < N; i++) {
    try {
      const r = await safeFetch(app.url)
      if (r.status >= 500) errors++
      times.push(r.total)
      ttfbs.push(r.ttfb)
      bytes = r.bytes
      totalBytes += r.bytes
    } catch {
      errors++
    }
  }
  if (!times.length) throw new Error('Cible injoignable pendant la mesure de performance')
  const elapsed = (performance.now() - t0) / 1000
  const sorted = [...times].sort((a, b) => a - b)
  const pct = (p: number) => sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]
  const avg = times.reduce((a, b) => a + b, 0) / times.length
  const r1 = (n: number) => Math.round(n * 10) / 10
  const metrics: Metric[] = [
    { name: 'Average Response Time', value: r1(avg), unit: 'ms' },
    { name: 'P95 Response Time', value: r1(pct(95)), unit: 'ms' },
    { name: 'P99 Response Time', value: r1(pct(99)), unit: 'ms' },
    { name: 'Min Response Time', value: r1(sorted[0]), unit: 'ms' },
    { name: 'Max Response Time', value: r1(sorted[sorted.length - 1]), unit: 'ms' },
    { name: 'Time To First Byte (moyen)', value: r1(ttfbs.reduce((a, b) => a + b, 0) / ttfbs.length), unit: 'ms' },
    { name: 'Requests Per Second', value: r1(N / elapsed), unit: 'req/s' },
    { name: 'Error Rate', value: r1((errors / N) * 100), unit: '%' },
    { name: 'Throughput', value: r1(totalBytes / 1024 / elapsed), unit: 'Ko/s' },
    { name: 'Poids de la page (HTML)', value: r1(bytes / 1024), unit: 'Ko' },
  ]
  const score = Math.max(0, Math.min(100, Math.round(100 - (avg - 200) / 28 - (errors / N) * 50)))
  return { metrics, score }
}

// =============== ORCHESTRATION D'UNE CAMPAGNE ===============
const SEV_WEIGHT: Record<string, number> = { CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 3, INFO: 0 }

export async function runScan(scanId: string) {
  const scan = await prisma.scan.update({ where: { id: scanId }, data: { status: 'RUNNING', startedAt: new Date() }, include: { application: true } })
  const app = scan.application
  const orgId = scan.orgId
  const mods = scan.modules.split(',')
  const summary: any = {}
  const scores: number[] = []
  let ok = 0

  if (mods.includes('QA')) {
    try {
      const tests = await runQA(app)
      await prisma.testResult.createMany({ data: tests.map((t) => ({ ...t, orgId, scanId })) })
      const passed = tests.filter((t) => t.status === 'PASS').length
      summary.qa = { passed, failed: tests.length - passed, total: tests.length, rate: Math.round((passed / tests.length) * 100) }
      scores.push(summary.qa.rate)
      ok++
    } catch (e) {
      summary.qa = { error: errMsg(e) }
    }
  }
  if (mods.includes('SECURITY')) {
    try {
      const { findings, info } = await runSecurity(app)
      await prisma.finding.createMany({
        data: findings.map((x) => ({ ...x, orgId, scanId, applicationId: app.id, module: 'SECURITY', fingerprint: `${x.title}|${x.resource}` })),
      })
      const counts: any = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
      findings.forEach((x) => counts[x.severity]++)
      const penalty = findings.reduce((a, x) => a + SEV_WEIGHT[x.severity], 0)
      summary.security = { counts, total: findings.length, score: Math.max(0, 100 - penalty), info }
      scores.push(summary.security.score)
      ok++
      if (counts.CRITICAL > 0) await notify(orgId, 'CRITICAL_FINDING', `Vulnérabilité critique détectée sur ${app.name}`, `${counts.CRITICAL} vulnérabilité(s) critique(s)`, `/app/scans/${scanId}`)
    } catch (e) {
      summary.security = { error: errMsg(e) }
    }
  }
  if (mods.includes('PERFORMANCE')) {
    try {
      const { metrics, score } = await runPerf(app)
      await prisma.performanceMetric.createMany({ data: metrics.map((m) => ({ ...m, orgId, scanId })) })
      summary.performance = { score, avg: metrics[0].value, p95: metrics[1].value }
      scores.push(score)
      ok++
    } catch (e) {
      summary.performance = { error: errMsg(e) }
    }
  }

  const failed = ok === 0
  await prisma.scan.update({
    where: { id: scanId },
    data: {
      status: failed ? 'FAILED' : 'DONE',
      error: failed ? Object.values(summary).map((s: any) => s.error).filter(Boolean).join(' | ').slice(0, 400) : null,
      score: scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null,
      summary: JSON.stringify(summary),
      finishedAt: new Date(),
    },
  })
  await notify(orgId, failed ? 'SCAN_FAILED' : 'SCAN_DONE', failed ? `Audit en échec : ${app.name}` : `Audit terminé : ${app.name}`, failed ? 'La cible n\'a pas pu être analysée.' : 'Le rapport est disponible.', `/app/scans/${scanId}`)
}

export function launchScan(scanId: string) {
  setImmediate(() => {
    runScan(scanId).catch(async (e) => {
      await prisma.scan.update({ where: { id: scanId }, data: { status: 'FAILED', error: errMsg(e), finishedAt: new Date() } }).catch(() => {})
    })
  })
}

// =============== MONITORING (section 9) ===============
export async function checkApplication(app: any) {
  let up = false
  let code: number | null = null
  let ms: number | null = null
  let reason = ''
  try {
    const r = await safeFetch(app.url, { readBody: false })
    code = r.status
    ms = Math.round(r.total)
    up = r.status < 500
    if (!up) reason = `HTTP ${r.status}`
  } catch (e) {
    reason = errMsg(e)
  }
  await prisma.application.update({ where: { id: app.id }, data: { lastStatus: up ? 'UP' : 'DOWN', lastHttpCode: code, lastResponseMs: ms, lastCheckedAt: new Date() } })
  const open = await prisma.incident.findFirst({ where: { applicationId: app.id, orgId: app.orgId, status: 'OPEN' } })
  if (!up) {
    // Regroupement : un seul incident ouvert par application, on incrémente les occurrences
    if (open) await prisma.incident.update({ where: { id: open.id }, data: { occurrences: { increment: 1 } } })
    else {
      await prisma.incident.create({ data: { orgId: app.orgId, applicationId: app.id, title: `${app.name} indisponible (${reason})`.slice(0, 200) } })
      await notify(app.orgId, 'APP_DOWN', `Application indisponible : ${app.name}`, reason, '/app/monitoring')
    }
  } else if (open) {
    await prisma.incident.update({ where: { id: open.id }, data: { status: 'RESOLVED', resolvedAt: new Date() } })
    await notify(app.orgId, 'INCIDENT_RESOLVED', `Incident résolu : ${app.name}`, 'L\'application répond de nouveau.', '/app/monitoring')
  }
  return { up, code, ms, reason }
}

export function startMonitor(PLANS: Record<string, any>) {
  let busy = false
  let lastPurge = 0
  setInterval(async () => {
    if (busy) return
    busy = true
    try {
      const apps = await prisma.application.findMany({ where: { monitoring: true, authorized: true } })
      for (const a of apps) {
        const due = !a.lastCheckedAt || Date.now() - a.lastCheckedAt.getTime() >= a.monitorInterval * 60_000 - 5000
        if (due) await checkApplication(a).catch(() => {})
      }
      // Conservation de l'historique selon la formule
      if (Date.now() - lastPurge > 3600_000) {
        lastPurge = Date.now()
        const orgs = await prisma.organization.findMany()
        for (const o of orgs) {
          const days = (PLANS[o.plan] ?? PLANS.STARTER).historyDays
          await prisma.scan.deleteMany({ where: { orgId: o.id, createdAt: { lt: new Date(Date.now() - days * 86400_000) } } })
        }
      }
    } catch (e) {
      console.error('[monitor]', e)
    } finally {
      busy = false
    }
  }, 60_000)
}

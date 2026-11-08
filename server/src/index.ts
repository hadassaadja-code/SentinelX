import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import fstatic from '@fastify/static'
import fs from 'node:fs'
import path from 'node:path'
import { prisma, HttpError, ROOT, PLANS } from './core.js'
import routes from './routes.js'
import { startMonitor } from './engine.js'

const app = Fastify({ logger: { level: 'warn' }, bodyLimit: 100_000 })
await app.register(cookie)

// En-têtes de sécurité sur toutes les réponses
app.addHook('onSend', async (_req, reply) => {
  reply.header('X-Content-Type-Options', 'nosniff')
  reply.header('X-Frame-Options', 'DENY')
  reply.header('Referrer-Policy', 'strict-origin-when-cross-origin')
  reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
  reply.header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
})

// Protection CSRF : cookie SameSite=Strict + en-tête personnalisé obligatoire sur toute requête modifiante
app.addHook('preHandler', async (req) => {
  if (req.url.startsWith('/api') && !['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.headers['x-requested-with'] !== 'sentinelx') {
    throw new HttpError(403, 'Requête refusée (protection CSRF)')
  }
})

app.setErrorHandler((err: any, _req, reply) => {
  if (err instanceof HttpError) return reply.code(err.status).send({ error: err.message })
  if (err.statusCode && err.statusCode < 500) return reply.code(err.statusCode).send({ error: 'Requête invalide' })
  app.log.error(err)
  reply.code(500).send({ error: 'Erreur interne' }) // aucun détail technique renvoyé au client
})

await app.register(routes, { prefix: '/api' })

// Sert le frontend compilé (web/dist) : une seule adresse pour la démonstration
const dist = path.join(ROOT, '..', 'web', 'dist')
if (fs.existsSync(dist)) {
  await app.register(fstatic, { root: dist })
  app.setNotFoundHandler((req, reply) => {
    if (req.url.startsWith('/api')) return reply.code(404).send({ error: 'Introuvable' })
    return reply.sendFile('index.html')
  })
}

// Au démarrage : les audits interrompus par un arrêt du serveur sont marqués en échec
await prisma.scan.updateMany({ where: { status: { in: ['QUEUED', 'RUNNING'] } }, data: { status: 'FAILED', error: 'Audit interrompu par un redémarrage du serveur', finishedAt: new Date() } })
startMonitor(PLANS)

const port = Number(process.env.PORT) || 3000
await app.listen({ port, host: '127.0.0.1' })
console.log(`SentinelX est démarré : http://localhost:${port}`)

// Génération des rapports PDF et CSV (section 10.2)
import PDFDocument from 'pdfkit'

const SEV_FR: Record<string, string> = { CRITICAL: 'Critique', HIGH: 'Élevée', MEDIUM: 'Moyenne', LOW: 'Faible', INFO: 'Information' }
const SEV_COLOR: Record<string, string> = { CRITICAL: '#b91c1c', HIGH: '#c2410c', MEDIUM: '#a16207', LOW: '#1d4ed8', INFO: '#475569' }
const STATUS_FR: Record<string, string> = { DETECTED: 'Détectée', CONFIRMED: 'Confirmée', ASSIGNED: 'Assignée', IN_PROGRESS: 'En cours', FIXED: 'Corrigée', RETESTED: 'Retestée', CLOSED: 'Clôturée', FALSE_POSITIVE: 'Faux positif' }
const MODULE_FR: Record<string, string> = { QA: 'QA', SECURITY: 'Sécurité', PERFORMANCE: 'Performance' }
const fmtDate =(d: any) => (d ? new Date(d).toLocaleString('fr-FR') : '-')
// La police intégrée ne couvre que le jeu Latin-1 : on remplace le reste
const safe = (s: any) => String(s ?? '').replace(/[→]/g, '->').replace(/[…]/g, '...').replace(/[^\x09\x0A\x0D\x20-\x7E -ÿ]/g, '?')

export function buildCsv(scan: any): string {
  const esc = (v: any) => {
    let s = String(v ?? '')
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s // neutralise les formules dans les tableurs
    return `"${s.replace(/"/g, '""')}"`
  }
  const rows = [['type', 'gravite_ou_statut', 'titre', 'ressource', 'preuve_ou_detail', 'recommandation']]
  for (const f of scan.findings) rows.push(['vulnerabilite', f.severity, f.title, f.resource, f.evidence, f.recommendation])
  for (const t of scan.testResults) rows.push(['test_qa', t.status, t.name, scan.application.url, t.detail, ''])
  for (const m of scan.metrics) rows.push(['metrique', '', m.name, scan.application.url, `${m.value} ${m.unit}`, ''])
  return '﻿' + rows.map((r) => r.map(esc).join(';')).join('\r\n')
}

export function buildPdf(scan: any, orgName: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 50, info: { Title: `Rapport SentinelX - ${safe(scan.application.name)}` } })
    const chunks: Buffer[] = []
    doc.on('data', (c: Buffer) => chunks.push(c))
    doc.on('end', () => resolve(Buffer.concat(chunks)))
    doc.on('error', reject)

    const W = doc.page.width - 100
    const h2 = (t: string) => {
      if (doc.y > 700) doc.addPage()
      doc.moveDown(1).fillColor('#0f2339').font('Helvetica-Bold').fontSize(14).text(safe(t))
      doc.moveTo(50, doc.y + 2).lineTo(50 + W, doc.y + 2).strokeColor('#14a3a8').lineWidth(1.5).stroke()
      doc.moveDown(0.6).fillColor('#1f2937').font('Helvetica').fontSize(10)
    }
    const kv = (k: string, v: any) => doc.font('Helvetica-Bold').text(safe(k) + ' : ', { continued: true }).font('Helvetica').text(safe(v))

    // --- En-tête ---
    doc.fillColor('#0f2339').font('Helvetica-Bold').fontSize(24).text('SENTINELX')
    doc.fillColor('#14a3a8').fontSize(12).text("Rapport d'audit")
    doc.moveDown(1).fillColor('#1f2937').font('Helvetica').fontSize(10)
    const duration = scan.startedAt && scan.finishedAt ? `${Math.round((new Date(scan.finishedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000)} s` : '-'
    kv('Organisation', orgName)
    kv('Application', `${scan.application.name} (${scan.application.environment})`)
    kv('Cible', scan.application.url)
    kv('Date', fmtDate(scan.startedAt))
    kv('Durée', duration)
    kv('Modules exécutés', scan.modules.split(',').map((m: string) => MODULE_FR[m] ?? m).join(', '))
    kv('Score global', scan.score != null ? `${scan.score} / 100` : '-')
    kv('Référence', scan.id)

    const s = scan.summary ?? {}
    // --- Synthèse ---
    h2('Synthèse')
    if (s.qa) doc.text(safe(s.qa.error ? `QA : échec du module (${s.qa.error})` : `QA : ${s.qa.passed} test(s) réussi(s) sur ${s.qa.total} (${s.qa.rate} %)`))
    if (s.security) {
      const c = s.security.counts
      doc.text(safe(s.security.error ? `Sécurité : échec du module (${s.security.error})` : `Sécurité : ${s.security.total} constat(s) - Critique ${c.CRITICAL}, Élevée ${c.HIGH}, Moyenne ${c.MEDIUM}, Faible ${c.LOW}, Information ${c.INFO}`))
    }
    if (s.performance) doc.text(safe(s.performance.error ? `Performance : échec du module (${s.performance.error})` : `Performance : score ${s.performance.score}/100 - temps moyen ${s.performance.avg} ms, P95 ${s.performance.p95} ms`))
    if (scan.comparison) {
      const c = scan.comparison
      doc.moveDown(0.4).text(safe(`Comparaison avec l'audit du ${fmtDate(c.previousDate)} : ${c.fixed.length} corrigée(s), ${c.added.length} nouvelle(s), ${c.persistent} persistante(s).`))
    }

    // --- Vulnérabilités ---
    if (scan.modules.includes('SECURITY')) {
      h2(`Vulnérabilités et constats de sécurité (${scan.findings.length})`)
      if (!scan.findings.length) doc.text('Aucun constat relevé par les contrôles exécutés.')
      scan.findings.forEach((f: any, i: number) => {
        if (doc.y > 660) doc.addPage()
        doc.moveDown(0.5).font('Helvetica-Bold').fontSize(11).fillColor(SEV_COLOR[f.severity] ?? '#1f2937').text(safe(`${i + 1}. [${SEV_FR[f.severity] ?? f.severity}] ${f.title}`))
        doc.fillColor('#1f2937').fontSize(9.5).font('Helvetica')
        doc.text(safe(f.description))
        kv('Ressource', f.resource)
        kv('Preuve', f.evidence)
        kv('Recommandation', f.recommendation)
        kv('Statut', STATUS_FR[f.status] ?? f.status)
      })
      doc.fontSize(10)
    }

    // --- QA ---
    if (scan.testResults.length) {
      h2(`Résultats QA (${scan.testResults.length} tests)`)
      for (const t of scan.testResults) {
        if (doc.y > 720) doc.addPage()
        doc.font('Helvetica-Bold').fillColor(t.status === 'PASS' ? '#15803d' : '#b91c1c').text(t.status === 'PASS' ? 'RÉUSSI  ' : 'ÉCHEC  ', { continued: true })
        doc.fillColor('#1f2937').text(safe(t.name))
        if (t.detail) doc.font('Helvetica').fontSize(9).fillColor('#475569').text(safe(t.detail), { indent: 12 }).fontSize(10).fillColor('#1f2937')
      }
    }

    // --- Performance ---
    if (scan.metrics.length) {
      h2('Métriques de performance')
      for (const m of scan.metrics) kv(m.name, `${m.value} ${m.unit}`)
    }

    // --- Conclusion ---
    h2('Conclusion')
    const c = s.security?.counts
    const urgent = c ? c.CRITICAL + c.HIGH : 0
    doc.text(
      safe(
        urgent > 0
          ? `${urgent} constat(s) de gravité élevée ou critique nécessitent une correction prioritaire. Un nouvel audit est recommandé après correction.`
          : scan.modules.includes('SECURITY')
            ? "Aucun constat de gravité élevée ou critique n'a été relevé par les contrôles exécutés. Les constats de gravité inférieure restent à traiter."
            : 'Consultez le détail des modules exécutés ci-dessus.',
      ),
    )
    doc.moveDown(0.6).fontSize(8.5).fillColor('#64748b').text(safe("Périmètre : contrôles automatisés passifs et non destructifs, exécutés sur une cible déclarée autorisée. Ce rapport ne remplace pas un test d'intrusion complet ; l'absence de constat ne garantit pas l'absence de vulnérabilité."))
    doc.end()
  })
}

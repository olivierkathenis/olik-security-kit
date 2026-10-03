/** Runner CI non interactif, distinct du CLI historique. */
import { mkdir, readFile, writeFile, appendFile, stat } from 'node:fs/promises'
import { resolve, join } from 'node:path'
import { scanSecrets } from './secrets.js'
import { scanVulns } from './vuln-scan.js'
import { checkHeaders } from './headers.js'
import { options, runScanners, evaluate } from '../src/core/ci-report.js'

async function main() {
  const config = options({ scanType: process.env.SCAN_TYPE, minGrade: process.env.MIN_GRADE,
    failOnCritical: process.env.FAIL_ON_CRITICAL, url: process.env.AUDIT_URL })
  if (process.env.KIT_SHA && !/^[0-9a-f]{40}$/.test(process.env.KIT_SHA)) throw Error('SHA du kit invalide')
  const project = resolve(process.env.PROJECT_PATH || '.')
  if (!(await stat(project)).isDirectory()) throw Error('Projet absent')
  const directory = resolve(process.env.REPORT_DIR || 'security-audit-report')
  // Création exclusive : aucun rapport ancien/forgé du projet n'est réutilisé.
  await mkdir(directory, { recursive: false, mode: 0o700 })
  await runScanners(config, {
    secrets: () => scanSecrets(project, { strict: true }),
    vuln: () => scanVulns(project, { strict: true }),
    headers: () => checkHeaders(config.url, { strict: true })
  }, (name, report) => writeFile(join(directory, `scan-${name}.json`), JSON.stringify(report, null, 2), { flag: 'wx', mode: 0o600 }))
  const reports = await Promise.all(config.scanners.map(async name => {
    try { return JSON.parse(await readFile(join(directory, `scan-${name}.json`), 'utf8')) }
    catch { return { scanner: name, status: 'error' } }
  }))
  const result = evaluate(reports, config)
  result.kit_sha = process.env.KIT_SHA || null
  await writeFile(join(directory, 'summary.json'), JSON.stringify(result, null, 2), { flag: 'wx', mode: 0o600 })
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY,
    `## Olik Security Audit\n\nÉtat : ${result.complete ? 'terminé' : 'incomplet'}\n\nGrade : ${result.grade || 'non calculé'} · Minimum : ${config.minGrade}\n\nCRITICAL : ${result.counts.CRITICAL} · HIGH : ${result.counts.HIGH} · MEDIUM : ${result.counts.MEDIUM}\n`)
  console.log(JSON.stringify(result))
  return result.quality_pass ? 0 : 1
}

try { process.exitCode = await main() }
catch { console.error('Audit CI incomplet ; aucun grade valide produit.'); process.exitCode = 1 }

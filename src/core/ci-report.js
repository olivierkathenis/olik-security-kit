/** Contrat CI : seuls les champs severity structurés participent à la note. */
export const GRADES = ['A', 'B', 'C', 'D', 'F']
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export function options({ scanType = 'all', minGrade = 'C', failOnCritical = 'true', url = '' } = {}) {
  if (!['secrets', 'vuln', 'all'].includes(scanType) || !GRADES.includes(minGrade) ||
      !['true', 'false'].includes(failOnCritical) || typeof url !== 'string') throw Error('Paramètres CI invalides')
  if (url) {
    const parsed = new URL(url)
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) throw Error('URL HTTP(S) requise sans identifiants')
  }
  return { scanType, minGrade, failOnCritical: failOnCritical === 'true', url,
    scanners: scanType === 'all' ? ['secrets', 'vuln', ...(url ? ['headers'] : [])] : [scanType] }
}

export function scannerReport(scanner, findings) {
  if (!Array.isArray(findings) || findings.some(f => !f || !SEVERITIES.includes(f.severity))) throw Error('Findings structurés invalides')
  // Ne jamais exporter les valeurs des secrets ou extraits de code détectés.
  return { schema: 1, scanner, status: 'completed', findings: findings.map(f => {
    const result = { severity: f.severity }
    for (const key of ['file', 'pattern', 'check', 'fix']) if (typeof f[key] === 'string') result[key] = f[key]
    if (Number.isInteger(f.line) && f.line > 0) result.line = f.line
    return result
  }) }
}

export function evaluate(reports, config) {
  const errors = [], findings = []
  if (!Array.isArray(reports)) reports = []
  for (const scanner of config.scanners) {
    const matches = reports.filter(r => r?.scanner === scanner)
    const report = matches[0]
    if (matches.length !== 1 || report?.schema !== 1 || report.status !== 'completed' ||
        !Array.isArray(report.findings) || report.findings.some(f => !f || !SEVERITIES.includes(f.severity))) {
      errors.push({ scanner, code: 'scanner_incomplet' }); continue
    }
    findings.push(...report.findings)
  }
  if (reports.some(r => !config.scanners.includes(r?.scanner))) errors.push({ scanner: null, code: 'rapport_inattendu' })
  const counts = Object.fromEntries(SEVERITIES.map(s => [s, findings.filter(f => f.severity === s).length]))
  const complete = errors.length === 0
  let grade = null
  if (complete) grade = counts.CRITICAL ? 'F' : counts.HIGH ? 'D' : counts.MEDIUM >= 3 ? 'C' : counts.MEDIUM ? 'B' : 'A'
  const gradeOk = complete && GRADES.indexOf(grade) <= GRADES.indexOf(config.minGrade)
  return { schema: 1, complete, grade, min_grade: config.minGrade, counts, errors,
    quality_pass: gradeOk && !(config.failOnCritical && counts.CRITICAL > 0) }
}

export async function runScanners(config, scanners, writeReport) {
  for (const scanner of config.scanners) {
    let report
    try { report = scannerReport(scanner, await scanners[scanner]()) }
    catch { report = { schema: 1, scanner, status: 'error', findings: [], error: 'scanner_incomplet' } }
    // Une panne d'écriture doit interrompre le runner, jamais produire un grade A.
    await writeReport(scanner, report)
  }
}

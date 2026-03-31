import chalk from 'chalk'
import { writeFile } from 'fs/promises'

const SEVERITY_COLOR = {
  CRITICAL: chalk.bgRed.white.bold,
  HIGH: chalk.red.bold,
  MEDIUM: chalk.yellow,
  LOW: chalk.blue,
}

const SEVERITY_LABEL = {
  CRITICAL: '🔴 CRITIQUE',
  HIGH: '🟠 ÉLEVÉ',
  MEDIUM: '🟡 MOYEN',
  LOW: '🔵 FAIBLE',
}

function gradeColor(grade) {
  if (grade === 'A') return chalk.green.bold
  if (grade === 'B') return chalk.cyan.bold
  if (grade === 'C') return chalk.yellow.bold
  if (grade === 'D') return chalk.red
  return chalk.bgRed.white.bold
}

export function printReport(findings, score, grade, url) {
  console.log('\n' + chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
  console.log(chalk.bold('  RAPPORT DE SÉCURITÉ — Olik Security Kit'))
  if (url) console.log(chalk.dim('  ' + url))
  console.log(chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━') + '\n')

  const gc = gradeColor(grade)
  console.log(`  Score : ${gc(score + '/100')}   Grade : ${gc(grade)}\n`)

  if (findings.length === 0) {
    console.log(chalk.green('  ✓ Aucune anomalie détectée.\n'))
    return
  }

  const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] }
  for (const f of findings) {
    if (bySeverity[f.severity]) bySeverity[f.severity].push(f)
  }

  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
    const group = bySeverity[sev]
    if (group.length === 0) continue
    const col = SEVERITY_COLOR[sev]
    console.log(col(`  ▸ ${sev} (${group.length})`))
    for (const f of group) {
      console.log(`    ${chalk.bold(f.title)}`)
      if (f.detail) console.log(chalk.dim(`      ${f.detail}`))
      if (f.fix) console.log(chalk.green(`      Fix : ${f.fix}`))
    }
    console.log()
  }

  const counts = Object.fromEntries(
    Object.entries(bySeverity).map(([k, v]) => [k, v.length])
  )
  console.log(chalk.dim(
    `  Total : ${findings.length} finding(s) — ` +
    `C:${counts.CRITICAL} H:${counts.HIGH} M:${counts.MEDIUM} L:${counts.LOW}`
  ))
  console.log(chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━') + '\n')
}

export async function exportMarkdown(findings, score, grade, url, outputPath) {
  const date = new Date().toLocaleDateString('fr-BE', {
    day: '2-digit', month: '2-digit', year: 'numeric'
  })

  const LABEL = { CRITICAL: 'Critique', HIGH: 'Élevé', MEDIUM: 'Moyen', LOW: 'Faible' }
  const EMOJI = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' }

  const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] }
  for (const f of findings) {
    if (bySeverity[f.severity]) bySeverity[f.severity].push(f)
  }

  const gradeDesc = {
    A: 'Excellente posture de sécurité',
    B: 'Bonne posture, quelques points à corriger',
    C: 'Posture acceptable, corrections recommandées',
    D: 'Posture fragile, corrections prioritaires',
    F: 'Posture critique, corrections urgentes',
  }

  let md = `# Rapport de sécurité — ${url ?? 'Projet'}\n\n`
  md += `**Date** : ${date}  \n`
  md += `**Score** : ${score}/100 — **Grade ${grade}** (${gradeDesc[grade] ?? ''})\n\n`
  md += `---\n\n`

  if (findings.length === 0) {
    md += `## Résultat\n\nAucune anomalie détectée. Le projet respecte les standards de sécurité analysés.\n`
  } else {
    const counts = Object.fromEntries(
      Object.entries(bySeverity).map(([k, v]) => [k, v.length])
    )
    md += `## Résumé\n\n`
    md += `| Sévérité | Nombre |\n|----------|--------|\n`
    for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      if (counts[sev] > 0) {
        md += `| ${EMOJI[sev]} ${LABEL[sev]} | ${counts[sev]} |\n`
      }
    }
    md += `\n---\n\n`

    for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      const group = bySeverity[sev]
      if (group.length === 0) continue
      md += `## ${EMOJI[sev]} Priorité ${LABEL[sev]}\n\n`
      for (const f of group) {
        md += `### ${f.title}\n\n`
        if (f.module) md += `**Module** : ${f.module}  \n`
        if (f.detail) md += `**Détail** : ${f.detail}  \n`
        if (f.fix) md += `**Recommandation** : ${f.fix}\n`
        md += `\n`
      }
    }

    md += `---\n\n`
    md += `## Recommandations prioritaires\n\n`
    const top = findings
      .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
      .slice(0, 5)
    if (top.length === 0) {
      md += `Aucun problème critique ou élevé identifié.\n`
    } else {
      for (const f of top) {
        md += `- **${f.title}**`
        if (f.fix) md += ` : ${f.fix}`
        md += `\n`
      }
    }
  }

  md += `\n---\n\n*Rapport généré par [Olik Security Kit](https://github.com/olivierkathenis)*\n`

  await writeFile(outputPath, md, 'utf-8')
  return outputPath
}

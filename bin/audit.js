#!/usr/bin/env node
import { scanSecrets } from '../scripts/secrets.js'
import { checkHeaders } from '../scripts/headers.js'
import { scanVulns } from '../scripts/vuln-scan.js'
import { writeFile, copyFile, mkdir, access } from 'fs/promises'
import { join, resolve } from 'path'
import chalk from 'chalk'

const SEVERITY_ICON = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' }
const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

function spin(msg) {
  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
  let i = 0
  const id = setInterval(() => {
    process.stdout.write(`\r${frames[i++ % frames.length]} ${msg}`)
  }, 80)
  return () => {
    clearInterval(id)
    process.stdout.write('\r' + ' '.repeat(msg.length + 3) + '\r')
  }
}

function printFindings(findings, label) {
  if (findings.length === 0) {
    console.log(chalk.green(`✓ ${label} — aucun finding`))
    return
  }
  console.log(chalk.bold(`\n${label} — ${findings.length} finding(s)`))
  for (const f of findings) {
    const icon = SEVERITY_ICON[f.severity] ?? '⚪'
    const sev = chalk.bold(f.severity === 'CRITICAL' ? chalk.red(f.severity) : f.severity === 'HIGH' ? chalk.yellow(f.severity) : f.severity)
    const loc = f.file ? `${f.file}:${f.line}` : f.check ?? ''
    console.log(`  ${icon} [${sev}] ${f.pattern ?? f.check}`)
    if (loc) console.log(`     ${chalk.dim(loc)}`)
    if (f.match) console.log(`     "${f.match}"`)
    if (f.detail) console.log(`     ${f.detail}`)
    if (f.fix) console.log(`     ${chalk.cyan('→')} ${f.fix}`)
  }
}

function computeGrade(findings) {
  if (findings.some(f => f.severity === 'CRITICAL')) return 'F'
  if (findings.some(f => f.severity === 'HIGH')) return 'D'
  const mediums = findings.filter(f => f.severity === 'MEDIUM').length
  if (mediums >= 3) return 'C'
  if (mediums >= 1) return 'B'
  return 'A'
}

function gradeColor(grade) {
  if (grade === 'A') return chalk.green(grade)
  if (grade === 'B') return chalk.cyan(grade)
  if (grade === 'C') return chalk.yellow(grade)
  return chalk.red(grade)
}

async function generateMarkdown(allFindings, projectPath, url) {
  const date = new Date().toISOString().slice(0, 10)
  const grade = computeGrade(allFindings)
  const lines = [
    `# Rapport de sécurité — ${date}`,
    ``,
    `**Projet :** ${projectPath}`,
    url ? `**URL :** ${url}` : null,
    `**Grade :** ${grade}`,
    `**Total findings :** ${allFindings.length}`,
    ``,
    `## Findings`,
    ``,
  ].filter(l => l !== null)

  if (allFindings.length === 0) {
    lines.push('Aucun finding détecté.')
  } else {
    const sorted = [...allFindings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
    for (const f of sorted) {
      const loc = f.file ? `\`${f.file}:${f.line}\`` : f.check ?? ''
      lines.push(`### [${f.severity}] ${f.pattern ?? f.check}`)
      if (loc) lines.push(`**Localisation :** ${loc}`)
      if (f.match) lines.push(`**Match :** \`${f.match}\``)
      if (f.detail) lines.push(`**Détail :** ${f.detail}`)
      if (f.fix) lines.push(`**Fix :** ${f.fix}`)
      lines.push('')
    }
  }

  return lines.join('\n')
}

async function cmdSecrets(projectPath) {
  const stop = spin('Scan secrets...')
  const findings = await scanSecrets(projectPath)
  stop()
  printFindings(findings, 'Secrets')
  return findings
}

async function cmdHeaders(url) {
  const stop = spin(`Check headers : ${url}`)
  const findings = await checkHeaders(url)
  stop()
  printFindings(findings, 'Headers HTTP')
  return findings
}

async function cmdVuln(projectPath) {
  const stop = spin('Scan vulnérabilités SAST...')
  const findings = await scanVulns(projectPath)
  stop()
  printFindings(findings, 'Vulnérabilités SAST')
  return findings
}

async function cmdAll(projectPath, url) {
  console.log(chalk.bold('\nOlik Security Kit — Audit complet\n'))

  const secretFindings = await cmdSecrets(projectPath)
  const vulnFindings = await cmdVuln(projectPath)
  const headerFindings = url ? await cmdHeaders(url) : []

  const all = [...secretFindings, ...vulnFindings, ...headerFindings]
  const grade = computeGrade(all)

  console.log(chalk.bold(`\n${'─'.repeat(50)}`))
  console.log(`Grade global : ${gradeColor(grade)}`)
  console.log(`Total findings : ${all.length} (${all.filter(f => f.severity === 'CRITICAL').length} CRITICAL, ${all.filter(f => f.severity === 'HIGH').length} HIGH)`)
  console.log(chalk.bold('─'.repeat(50)))

  // Proposer export Markdown
  process.stdout.write('\nExporter le rapport en Markdown ? [o/N] ')
  process.stdin.resume()
  process.stdin.setEncoding('utf-8')
  process.stdin.once('data', async (data) => {
    process.stdin.pause()
    const answer = data.trim().toLowerCase()
    if (answer === 'o' || answer === 'oui' || answer === 'y') {
      const date = new Date().toISOString().slice(0, 10)
      const outPath = join(projectPath, `scans`, `audit-${date}.md`)
      await mkdir(join(projectPath, 'scans'), { recursive: true })
      const md = await generateMarkdown(all, projectPath, url)
      await writeFile(outPath, md, 'utf-8')
      console.log(chalk.green(`\nRapport sauvegardé : ${outPath}`))
    }
    process.exit(all.some(f => f.severity === 'CRITICAL') ? 2 : all.length > 0 ? 1 : 0)
  })
}

async function cmdInit() {
  const cwd = process.cwd()
  const gitHooksDir = join(cwd, '.git', 'hooks')

  try {
    await access(join(cwd, '.git'))
  } catch {
    console.error(chalk.red('Erreur : ce dossier n\'est pas un dépôt git.'))
    process.exit(1)
  }

  const kitDir = resolve(new URL(import.meta.url).pathname, '../..')
  const hookSrc = join(kitDir, 'hooks', 'pre-commit.sh')
  const hookDst = join(gitHooksDir, 'pre-commit')

  await mkdir(gitHooksDir, { recursive: true })
  await copyFile(hookSrc, hookDst)

  // chmod +x via spawn (cross-platform best effort)
  const { spawn } = await import('child_process')
  await new Promise((res) => {
    const ch = spawn('chmod', ['+x', hookDst], { stdio: 'ignore' })
    ch.on('close', res)
    ch.on('error', res) // silencieux sur Windows
  })

  console.log(chalk.green(`✓ Hook pre-commit installé : ${hookDst}`))
  console.log(chalk.dim('Le scan secrets sera lancé à chaque commit.'))
}

// ─── CLI router ───────────────────────────────────────────────────────────────

const [,, cmd, arg1, arg2] = process.argv

if (!cmd || cmd === '--help' || cmd === '-h') {
  console.log(`
${chalk.bold('Olik Security Kit')}

Usage :
  olik-security secrets [path]       Scan secrets dans le code source
  olik-security headers <url>        Check headers HTTP
  olik-security vuln [path]          SAST scan vulnérabilités
  olik-security all [path] [url]     Les 3 en séquence + rapport final
  olik-security init                 Installer le hook pre-commit
`)
  process.exit(0)
}

switch (cmd) {
  case 'secrets': {
    const findings = await cmdSecrets(resolve(arg1 ?? process.cwd()))
    process.exit(findings.some(f => f.severity === 'CRITICAL') ? 2 : findings.length > 0 ? 1 : 0)
    break
  }
  case 'headers': {
    if (!arg1) { console.error('Usage : olik-security headers <url>'); process.exit(1) }
    const findings = await cmdHeaders(arg1)
    process.exit(findings.some(f => f.severity === 'CRITICAL') ? 2 : findings.length > 0 ? 1 : 0)
    break
  }
  case 'vuln': {
    const findings = await cmdVuln(resolve(arg1 ?? process.cwd()))
    process.exit(findings.some(f => f.severity === 'CRITICAL') ? 2 : findings.length > 0 ? 1 : 0)
    break
  }
  case 'all': {
    await cmdAll(resolve(arg1 ?? process.cwd()), arg2 ?? null)
    break
  }
  case 'init': {
    await cmdInit()
    process.exit(0)
    break
  }
  default: {
    console.error(chalk.red(`Commande inconnue : ${cmd}`))
    console.error('Utiliser --help pour voir les commandes disponibles.')
    process.exit(1)
  }
}

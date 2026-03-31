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
  const frames = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
  let i = 0
  const id = setInterval(() => process.stdout.write(`\r${frames[i++ % frames.length]} ${msg}`), 80)
  return () => { clearInterval(id); process.stdout.write('\r' + ' '.repeat(msg.length + 3) + '\r') }
}

function printFindings(findings, label) {
  if (findings.length === 0) { console.log(chalk.green(`✓ ${label} — aucun finding`)); return }
  console.log(chalk.bold(`\n${label} — ${findings.length} finding(s)`))
  for (const f of findings) {
    const loc = f.file ? `${f.file}:${f.line}` : f.check ?? ''
    console.log(`  ${SEVERITY_ICON[f.severity] ?? '⚪'} [${f.severity}] ${f.pattern ?? f.check}`)
    if (loc) console.log(`     ${chalk.dim(loc)}`)
    if (f.match) console.log(`     "${f.match}"`)
    if (f.detail) console.log(`     ${f.detail}`)
    if (f.fix) console.log(`     ${chalk.cyan('→')} ${f.fix}`)
  }
}

function computeGrade(findings) {
  if (findings.some(f => f.severity === 'CRITICAL')) return 'F'
  if (findings.some(f => f.severity === 'HIGH')) return 'D'
  const m = findings.filter(f => f.severity === 'MEDIUM').length
  return m >= 3 ? 'C' : m >= 1 ? 'B' : 'A'
}

function gradeColor(g) { return g === 'A' ? chalk.green(g) : g === 'B' ? chalk.cyan(g) : g === 'C' ? chalk.yellow(g) : chalk.red(g) }

async function cmdSecrets(p) { const s = spin('Scan secrets...'); const f = await scanSecrets(p); s(); printFindings(f, 'Secrets'); return f }
async function cmdHeaders(url) { const s = spin(`Check headers : ${url}`); const f = await checkHeaders(url); s(); printFindings(f, 'Headers HTTP'); return f }
async function cmdVuln(p) { const s = spin('Scan vulnérabilités SAST...'); const f = await scanVulns(p); s(); printFindings(f, 'Vulnérabilités SAST'); return f }

async function cmdAll(projectPath, url) {
  console.log(chalk.bold('\nOlik Security Kit — Audit complet\n'))
  const all = [...await cmdSecrets(projectPath), ...await cmdVuln(projectPath), ...(url ? await cmdHeaders(url) : [])]
  const grade = computeGrade(all)
  console.log(chalk.bold(`\n${'─'.repeat(50)}`))
  console.log(`Grade global : ${gradeColor(grade)} — ${all.length} finding(s) (${all.filter(f=>f.severity==='CRITICAL').length} CRITICAL)`)
  console.log(chalk.bold('─'.repeat(50)))
  process.stdout.write('\nExporter le rapport en Markdown ? [o/N] ')
  process.stdin.resume(); process.stdin.setEncoding('utf-8')
  process.stdin.once('data', async (data) => {
    process.stdin.pause()
    if (/^(o|oui|y)$/i.test(data.trim())) {
      const date = new Date().toISOString().slice(0, 10)
      const outPath = join(projectPath, 'scans', `audit-${date}.md`)
      await mkdir(join(projectPath, 'scans'), { recursive: true })
      const lines = [`# Rapport sécurité — ${date}`, ``, `**Grade :** ${grade}  `, `**Findings :** ${all.length}`, ``]
      for (const f of [...all].sort((a,b) => SEVERITY_ORDER[a.severity]-SEVERITY_ORDER[b.severity])) {
        lines.push(`### [${f.severity}] ${f.pattern ?? f.check}`)
        if (f.file) lines.push(`**Fichier :** \`${f.file}:${f.line}\``)
        if (f.match) lines.push(`**Match :** \`${f.match}\``)
        if (f.fix) lines.push(`**Fix :** ${f.fix}`)
        lines.push('')
      }
      await writeFile(outPath, lines.join('\n'), 'utf-8')
      console.log(chalk.green(`\nRapport sauvegardé : ${outPath}`))
    }
    process.exit(all.some(f=>f.severity==='CRITICAL') ? 2 : all.length > 0 ? 1 : 0)
  })
}

async function cmdInit() {
  const cwd = process.cwd()
  try { await access(join(cwd, '.git')) } catch { console.error(chalk.red('Erreur : pas un dépôt git.')); process.exit(1) }
  const kitDir = resolve(new URL(import.meta.url).pathname, '../..')
  const hookDst = join(cwd, '.git', 'hooks', 'pre-commit')
  await mkdir(join(cwd, '.git', 'hooks'), { recursive: true })
  await copyFile(join(kitDir, 'hooks', 'pre-commit.sh'), hookDst)
  const { spawn } = await import('child_process')
  await new Promise(res => { const c = spawn('chmod', ['+x', hookDst], { stdio: 'ignore' }); c.on('close', res); c.on('error', res) })
  console.log(chalk.green(`✓ Hook pre-commit installé : ${hookDst}`))
}

const [,, cmd, arg1, arg2] = process.argv
if (!cmd || cmd === '--help' || cmd === '-h') {
  console.log(`\n${chalk.bold('Olik Security Kit')}\n\nUsage :\n  olik-security secrets [path]\n  olik-security headers <url>\n  olik-security vuln [path]\n  olik-security all [path] [url]\n  olik-security init\n`)
  process.exit(0)
}
switch (cmd) {
  case 'secrets': { const f = await cmdSecrets(resolve(arg1??process.cwd())); process.exit(f.some(f=>f.severity==='CRITICAL')?2:f.length>0?1:0); break }
  case 'headers': { if (!arg1){console.error('Usage : olik-security headers <url>');process.exit(1)} const f=await cmdHeaders(arg1); process.exit(f.some(f=>f.severity==='CRITICAL')?2:f.length>0?1:0); break }
  case 'vuln': { const f = await cmdVuln(resolve(arg1??process.cwd())); process.exit(f.some(f=>f.severity==='CRITICAL')?2:f.length>0?1:0); break }
  case 'all': { await cmdAll(resolve(arg1??process.cwd()), arg2??null); break }
  case 'init': { await cmdInit(); process.exit(0); break }
  default: { console.error(chalk.red(`Commande inconnue : ${cmd}`)); process.exit(1) }
}

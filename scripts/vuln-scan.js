import { readdir, readFile, stat } from 'fs/promises'
import { join, relative, extname } from 'path'
import { VULN_PATTERNS, detectStack } from '../config/frameworks.js'

const IGNORE_DIRS = new Set(['node_modules', 'vendor', '.git', '.next', 'dist', 'build', 'scans', 'coverage', 'var', 'migrations'])
const PHP_EXTENSIONS = new Set(['.php'])
const TS_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'])
const TEST_FILE_REGEX = /\.(test|spec)\.[^.]+$|__tests__/

export async function scanVulns(projectPath) {
  const findings = []
  const stack = await detectStack(projectPath)
  const hasPhp = stack.php || stack.symfony.detected
  const hasTs = stack.typescript || stack.nextjs.detected
  async function walk(dir) {
    let entries
    try { entries = await readdir(dir, { withFileTypes: true }) } catch { return }
    for (const entry of entries) {
      const fullPath = join(dir, entry.name)
      const relPath = relative(projectPath, fullPath)
      if (entry.isDirectory()) { if (IGNORE_DIRS.has(entry.name)) continue; await walk(fullPath); continue }
      if (!entry.isFile() || TEST_FILE_REGEX.test(relPath)) continue
      const ext = extname(entry.name).toLowerCase()
      let patterns = null
      if (PHP_EXTENSIONS.has(ext) && hasPhp) patterns = VULN_PATTERNS.php
      else if (TS_EXTENSIONS.has(ext) && hasTs) patterns = VULN_PATTERNS.ts
      if (!patterns) continue
      try {
        const fileStat = await stat(fullPath)
        if (fileStat.size > 500 * 1024) continue
        const content = await readFile(fullPath, 'utf-8')
        const lines = content.split('\n')
        for (const pattern of patterns) {
          for (let i = 0; i < lines.length; i++) {
            const match = lines[i].match(pattern.regex)
            if (!match) continue
            const idx = lines[i].indexOf(match[0])
            findings.push({ severity: pattern.severity, file: relPath, line: i + 1, pattern: pattern.name, context: lines[i].substring(Math.max(0, idx - 40), Math.min(lines[i].length, idx + match[0].length + 40)).trim(), fix: pattern.fix ?? null })
          }
        }
      } catch {}
    }
  }
  await walk(projectPath)
  return findings
}

if (process.argv[1].endsWith('vuln-scan.js')) {
  const projectPath = process.argv[2] ?? process.cwd()
  console.log(`Scan vulnérabilités SAST : ${projectPath}\n`)
  const stack = await detectStack(projectPath)
  console.log(`Stack : ${[stack.symfony.detected && `Symfony ${stack.symfony.version}`, stack.nextjs.detected && `Next.js ${stack.nextjs.version}`, stack.php && 'PHP', stack.typescript && 'TypeScript'].filter(Boolean).join(' ')}\n`)
  const findings = await scanVulns(projectPath)
  if (findings.length === 0) { console.log('✓ Aucune vulnérabilité SAST détectée.'); process.exit(0) }
  for (const f of findings) {
    const p = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : '🟡'
    console.log(`${p} [${f.severity}] ${f.pattern}\n   ${f.file}:${f.line}\n   contexte : "${f.context}"`)
    if (f.fix) console.log(`   → ${f.fix}`)
    console.log()
  }
  console.log(`Total : ${findings.length} finding(s)`)
  process.exit(findings.some(f => f.severity === 'CRITICAL') ? 2 : 1)
}

import { readdir, readFile, stat } from 'fs/promises'
import { join, relative, extname } from 'path'
import { VULN_PATTERNS, detectStack } from '../config/frameworks.js'

const IGNORE_DIRS = new Set([
  'node_modules', 'vendor', '.git', '.next', 'dist', 'build', 'scans', 'coverage',
  'var',          // Symfony generated cache/logs/sessions
  'migrations',   // SQL générée par Doctrine
])

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
    try {
      entries = await readdir(dir, { withFileTypes: true })
    } catch {
      return
    }

    for (const entry of entries) {
      const fullPath = join(dir, entry.name)
      const relPath = relative(projectPath, fullPath)

      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name)) continue
        await walk(fullPath)
        continue
      }

      if (!entry.isFile()) continue
      if (TEST_FILE_REGEX.test(relPath)) continue

      const ext = extname(entry.name).toLowerCase()
      let patterns = null

      if (PHP_EXTENSIONS.has(ext) && hasPhp) {
        patterns = VULN_PATTERNS.php
      } else if (TS_EXTENSIONS.has(ext) && hasTs) {
        patterns = VULN_PATTERNS.ts
      }

      if (!patterns) continue

      try {
        const fileStat = await stat(fullPath)
        if (fileStat.size > 500 * 1024) continue

        const content = await readFile(fullPath, 'utf-8')
        const lines = content.split('\n')

        for (const pattern of patterns) {
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i]
            const match = line.match(pattern.regex)
            if (!match) continue

            // Contexte : 80 chars autour du match
            const matchIndex = line.indexOf(match[0])
            const start = Math.max(0, matchIndex - 40)
            const end = Math.min(line.length, matchIndex + match[0].length + 40)
            const context = line.substring(start, end).trim()

            findings.push({
              severity: pattern.severity,
              file: relPath,
              line: i + 1,
              pattern: pattern.name,
              context,
              fix: pattern.fix ?? null,
            })
          }
        }
      } catch {
        // fichier illisible
      }
    }
  }

  await walk(projectPath)
  return findings
}

// CLI
if (process.argv[1].endsWith('vuln-scan.js')) {
  const projectPath = process.argv[2] ?? process.cwd()

  console.log(`Scan vulnérabilités SAST : ${projectPath}\n`)

  const stack = await detectStack(projectPath)
  console.log(`Stack détectée : ${stack.symfony.detected ? `Symfony ${stack.symfony.version}` : ''} ${stack.nextjs.detected ? `Next.js ${stack.nextjs.version}` : ''} ${stack.php ? 'PHP' : ''} ${stack.typescript ? 'TypeScript' : ''}`.trim())
  console.log()

  const findings = await scanVulns(projectPath)

  if (findings.length === 0) {
    console.log('✓ Aucune vulnérabilité SAST détectée.')
    process.exit(0)
  }

  for (const f of findings) {
    const prefix = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : '🟡'
    console.log(`${prefix} [${f.severity}] ${f.pattern}`)
    console.log(`   ${f.file}:${f.line}`)
    console.log(`   contexte : "${f.context}"`)
    if (f.fix) console.log(`   → ${f.fix}`)
    console.log()
  }

  console.log(`Total : ${findings.length} finding(s)`)
  process.exit(findings.some(f => f.severity === 'CRITICAL') ? 2 : 1)
}

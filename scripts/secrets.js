import { readdir, readFile, stat } from 'fs/promises'
import { join, relative, extname } from 'path'
import { SECRET_PATTERNS } from '../config/patterns.js'

const IGNORE_DIRS = new Set(['node_modules', '.git', 'vendor', '.next', 'dist', 'build', 'scans', 'coverage', 'translations', 'locales', 'lang', 'i18n'])
const IGNORE_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.pdf', '.lock', '.zip', '.tar', '.gz', '.7z'])
const FALSE_POSITIVE_PATTERNS = [
  /process\.env\./, /import\.meta\.env\./, /\$\{[A-Z_][A-Z0-9_]*\}/, /^[A-Z_][A-Z0-9_]*$/,
  /your_/i, /example/i, /changeme/i, /REPLACE_/i, /INSERT_/i, /TODO/i, /FIXME/i,
  /^xxx+$/i, /^yyy+$/i, /^zzz+$/i,
  /^symfony$/, /^root$/, /^admin$/, /^password$/i, /^secret$/i, /^test$/i,
  /^motdepasse$/i, /^mot_de_passe$/i,  // Placeholders français
  /user:pass@/i, /username:password/i, /db_user:db_pass/i, /DB_USER:DB_PASS/, /MY_SECRET_PASSWORD/i, /ChangeMe/, /!ChangeMe!/,
  /1234567890abcdef/, /abcdefghijklmnop/i,
  /MySecretPassword/i, /MyPassword/i, /SuperSecret/i, /Passw0rd/i,
]
const MAX_FILE_SIZE = 500 * 1024

function isFalsePositive(match) { return FALSE_POSITIVE_PATTERNS.some(p => p.test(match)) }

export async function loadIgnore(projectPath) {
  try {
    const raw = await readFile(join(projectPath, '.viceignore'), 'utf-8')
    return new Set(raw.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')))
  } catch { return new Set() }
}

function matchesIgnore(filePath, ignoreSet) {
  for (const pattern of ignoreSet) { if (filePath.includes(pattern)) return true }
  return false
}

export async function scanSecrets(projectPath) {
  const ignoreSet = await loadIgnore(projectPath)
  const findings = []
  async function walk(dir) {
    let entries
    try { entries = await readdir(dir, { withFileTypes: true }) } catch { return }
    for (const entry of entries) {
      const fullPath = join(dir, entry.name)
      const relPath = relative(projectPath, fullPath)
      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name) || matchesIgnore(relPath, ignoreSet)) continue
        await walk(fullPath)
        continue
      }
      if (!entry.isFile() || matchesIgnore(relPath, ignoreSet)) continue
      const ext = extname(entry.name).toLowerCase()
      if (IGNORE_EXTENSIONS.has(ext)) continue
      const isEnvFile = entry.name.startsWith('.env')
      try {
        const fileStat = await stat(fullPath)
        if (fileStat.size > MAX_FILE_SIZE) continue
        const content = await readFile(fullPath, 'utf-8')
        const lines = content.split('\n')
        const seen = new Set()
        for (const pattern of SECRET_PATTERNS) {
          if (isEnvFile && pattern.severity !== 'CRITICAL') continue
          for (let i = 0; i < lines.length; i++) {
            const match = lines[i].match(pattern.regex)
            if (!match) continue
            const matchValue = match[1] ?? match[0]
            if (isFalsePositive(matchValue)) continue
            const key = `${relPath}:${pattern.name}:${matchValue}`
            if (seen.has(key)) continue
            seen.add(key)
            findings.push({ severity: pattern.severity, file: relPath, line: i + 1, pattern: pattern.name, match: matchValue.substring(0, 40) })
          }
        }
      } catch {}
    }
  }
  await walk(projectPath)
  return findings
}

if (process.argv[1].endsWith('secrets.js')) {
  const projectPath = process.argv[2] ?? process.cwd()
  console.log(`Scan secrets : ${projectPath}\n`)
  const findings = await scanSecrets(projectPath)
  if (findings.length === 0) { console.log('✓ Aucun secret détecté.'); process.exit(0) }
  for (const f of findings) {
    const p = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : '🟡'
    console.log(`${p} [${f.severity}] ${f.pattern}\n   ${f.file}:${f.line} — "${f.match}"`)
  }
  console.log(`\nTotal : ${findings.length} finding(s)`)
  process.exit(findings.some(f => f.severity === 'CRITICAL') ? 2 : 1)
}

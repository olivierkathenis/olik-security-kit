import { SECURITY_HEADERS, LEAK_HEADERS } from '../config/headers.js'

const TIMEOUT_MS = 10_000

async function fetchHeaders(url) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'manual', signal: controller.signal })
    clearTimeout(timer)
    return { ok: true, status: res.status, headers: res.headers }
  } catch (err) { clearTimeout(timer); return { ok: false, error: err.message } }
}

function normalizeUrl(raw) {
  try { return new URL(raw).href } catch {
    try { return new URL('https://' + raw).href } catch { return null }
  }
}

export async function checkHeaders(rawUrl) {
  const findings = []
  const httpsUrl = rawUrl.startsWith('http://') ? rawUrl.replace('http://', 'https://') : normalizeUrl(rawUrl)
  const httpUrl = httpsUrl?.replace('https://', 'http://')
  if (!httpsUrl) { findings.push({ severity: 'CRITICAL', check: 'URL invalide', detail: rawUrl, fix: 'Fournir une URL valide' }); return findings }
  const httpsResult = await fetchHeaders(httpsUrl)
  if (!httpsResult.ok) { findings.push({ severity: 'CRITICAL', check: 'HTTPS indisponible', detail: `Impossible de joindre ${httpsUrl}`, fix: 'Activer HTTPS' }); return findings }
  if (httpUrl) {
    const httpResult = await fetchHeaders(httpUrl)
    if (httpResult.ok) {
      const isRedirect = httpResult.status >= 300 && httpResult.status < 400
      const location = httpResult.headers?.get('location') ?? ''
      if (!isRedirect || !location.startsWith('https://')) findings.push({ severity: 'HIGH', check: 'Redirection HTTP → HTTPS absente', detail: `HTTP ${httpResult.status}`, fix: 'Configurer 301 HTTP→HTTPS dans Nginx/Traefik' })
    }
  }
  const headers = httpsResult.headers
  for (const h of SECURITY_HEADERS) { if (!headers.get(h.name.toLowerCase())) findings.push({ severity: h.severity, check: `Header manquant : ${h.name}`, detail: h.description, fix: `Ajouter ${h.name} dans la config Nginx` }) }
  for (const leak of LEAK_HEADERS) {
    const value = headers.get(leak.name.toLowerCase())
    if (value) {
      const skip = leak.name === 'Server' && !/\/[\d.]/.test(value)
      if (!skip) findings.push({ severity: 'MEDIUM', check: `Header de fuite : ${leak.name}`, detail: `Valeur exposée : "${value}"`, fix: `Supprimer ${leak.name} dans la config serveur` })
    }
  }
  const setCookie = headers.get('set-cookie')
  if (setCookie) {
    for (const cookie of setCookie.split(',').map(c => c.trim())) {
      const name = cookie.split('=')[0]?.trim()
      if (!/HttpOnly/i.test(cookie)) findings.push({ severity: 'HIGH', check: `Cookie sans HttpOnly : ${name}`, detail: 'Accessible via JS — risque XSS', fix: `Ajouter HttpOnly` })
      if (!/Secure/i.test(cookie)) findings.push({ severity: 'MEDIUM', check: `Cookie sans Secure : ${name}`, detail: 'Peut être transmis en HTTP clair', fix: `Ajouter Secure` })
      if (!/SameSite/i.test(cookie)) findings.push({ severity: 'LOW', check: `Cookie sans SameSite : ${name}`, detail: 'Protection CSRF réduite', fix: `Ajouter SameSite=Lax` })
    }
  }
  return findings
}

if (process.argv[1].endsWith('headers.js')) {
  const url = process.argv[2]
  if (!url) { console.error('Usage : node scripts/headers.js <url>'); process.exit(1) }
  console.log(`Vérification des headers : ${url}\n`)
  const findings = await checkHeaders(url)
  if (findings.length === 0) { console.log('✓ Tous les headers de sécurité sont présents.'); process.exit(0) }
  for (const f of findings) {
    const p = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : f.severity === 'MEDIUM' ? '🟡' : '🔵'
    console.log(`${p} [${f.severity}] ${f.check}\n   ${f.detail}`)
    if (f.fix) console.log(`   → ${f.fix}`)
    console.log()
  }
  console.log(`Total : ${findings.length} finding(s)`)
  process.exit(findings.some(f => f.severity === 'CRITICAL') ? 2 : 1)
}

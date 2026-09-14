import { SECURITY_HEADERS, LEAK_HEADERS } from '../config/headers.js'

const TIMEOUT_MS = 10_000

// follow: true suit les redirects (jusqu'à 20) pour évaluer les headers de la
// page finale. Indispensable pour les sites dont la racine fait un 301 (locale
// /→/fr/, trailing-slash, www) : sinon on évalue la réponse 301, qui n'a
// légitimement aucun header de sécurité → faux positif « CSP manquant ».
// manual (défaut) reste requis pour la sonde HTTP→HTTPS qui inspecte le 301.
async function fetchHeaders(url, { follow = false, basicAuth = '' } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    // Credentials never reach HTTP or a different origin, including redirects.
    const origin = new URL(url).origin
    let target = new URL(url)
    for (let redirects = 0; redirects <= 20; redirects++) {
      if (basicAuth && (target.protocol !== 'https:' || target.origin !== origin || target.username || target.password)) {
        return { ok: false }
      }
      const res = await fetch(target.href, {
        method: 'GET', redirect: basicAuth ? 'manual' : follow ? 'follow' : 'manual',
        signal: controller.signal,
        ...(basicAuth ? { headers: { Authorization: `Basic ${Buffer.from(basicAuth).toString('base64')}` } } : {}),
      })
      const location = res.headers.get('location')
      if (basicAuth && follow && [301, 302, 303, 307, 308].includes(res.status) && location) {
        await res.body?.cancel()
        target = new URL(location, target)
        continue
      }
      await res.body?.cancel()
      return { ok: true, status: res.status, headers: res.headers }
    }
    return { ok: false }
  } catch { return { ok: false } } finally { clearTimeout(timer) }
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
  const basicAuth = process.env.OLIK_SECURITY_BASIC_AUTH ?? ''
  if (basicAuth && (!basicAuth.includes(':') || basicAuth.startsWith(':') || /[\r\n]/.test(basicAuth))) {
    return [{ severity: 'CRITICAL', check: 'Authentification audit invalide', detail: 'Secret BasicAuth mal formé.', fix: 'Configurer OLIK_SECURITY_BASIC_AUTH au format utilisateur:mot-de-passe' }]
  }
  const httpsResult = await fetchHeaders(httpsUrl, { follow: true, basicAuth })
  if (!httpsResult.ok) {
    // Un audit authentifié incomplet doit échouer, quel que soit min_grade.
    findings.push({ severity: basicAuth ? 'CRITICAL' : 'HIGH', check: 'HTTPS indisponible', detail: `Impossible de joindre ${httpsUrl}`, fix: 'Activer HTTPS ou vérifier que le site est déployé' })
    return findings
  }
  if ([401, 403].includes(httpsResult.status)) {
    return [{ severity: 'CRITICAL', check: 'Audit headers non authentifié', detail: `HTTP ${httpsResult.status} : la réponse ne permet pas d’auditer la page.`, fix: 'Vérifier le secret BasicAuth et les autorisations du staging' }]
  }
  if (basicAuth && (httpsResult.status < 200 || httpsResult.status >= 300)) {
    return [{ severity: 'CRITICAL', check: 'Audit headers sans page valide', detail: `HTTP ${httpsResult.status} : une réponse 2xx est requise pour l’audit authentifié.`, fix: 'Vérifier la disponibilité de la page et ses redirections' }]
  }
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
  // Do not expose credentials even if a server reflects them in a header.
  if (basicAuth) {
    const sensitive = [basicAuth, Buffer.from(basicAuth).toString('base64'), basicAuth.slice(basicAuth.indexOf(':') + 1)].filter(Boolean)
    for (const finding of findings) {
      for (const key of ['check', 'detail', 'fix']) {
        for (const value of sensitive) finding[key] = finding[key]?.split(value).join('[REDACTED]')
      }
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

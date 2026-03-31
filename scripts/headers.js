import { SECURITY_HEADERS, LEAK_HEADERS } from '../config/headers.js'

const TIMEOUT_MS = 10_000

async function fetchHeaders(url) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
    })
    clearTimeout(timer)
    return { ok: true, status: res.status, headers: res.headers, redirected: false }
  } catch (err) {
    clearTimeout(timer)
    return { ok: false, error: err.message }
  }
}

function normalizeUrl(raw) {
  try {
    const u = new URL(raw)
    return u.href
  } catch {
    // Essayer avec https:// si pas de protocole
    try {
      return new URL('https://' + raw).href
    } catch {
      return null
    }
  }
}

export async function checkHeaders(rawUrl) {
  const findings = []

  const httpsUrl = rawUrl.startsWith('http://') ? rawUrl.replace('http://', 'https://') : normalizeUrl(rawUrl)
  const httpUrl = httpsUrl?.replace('https://', 'http://')

  if (!httpsUrl) {
    findings.push({ severity: 'CRITICAL', check: 'URL invalide', detail: rawUrl, fix: 'Fournir une URL valide' })
    return findings
  }

  // --- HTTPS disponible ---
  const httpsResult = await fetchHeaders(httpsUrl)
  if (!httpsResult.ok) {
    findings.push({
      severity: 'CRITICAL',
      check: 'HTTPS indisponible',
      detail: `Impossible de joindre ${httpsUrl} (${httpsResult.error})`,
      fix: 'Activer HTTPS sur le serveur et configurer le certificat TLS',
    })
    return findings
  }

  // --- Redirection HTTP → HTTPS ---
  if (httpUrl) {
    const httpResult = await fetchHeaders(httpUrl)
    if (httpResult.ok) {
      const isRedirect = httpResult.status >= 300 && httpResult.status < 400
      const location = httpResult.headers?.get('location') ?? ''
      const redirectsToHttps = location.startsWith('https://')

      if (!isRedirect || !redirectsToHttps) {
        findings.push({
          severity: 'HIGH',
          check: 'Redirection HTTP → HTTPS absente',
          detail: `HTTP ${httpResult.status} — location: ${location || '(aucune)'}`,
          fix: 'Configurer une redirection 301 de HTTP vers HTTPS dans Nginx/Traefik',
        })
      }
    }
  }

  const headers = httpsResult.headers

  // --- Security headers requis ---
  for (const expected of SECURITY_HEADERS) {
    const value = headers.get(expected.name.toLowerCase())
    if (!value) {
      findings.push({
        severity: expected.severity,
        check: `Header manquant : ${expected.name}`,
        detail: expected.description,
        fix: `Ajouter le header ${expected.name} dans la config Nginx ou l'application`,
      })
    }
  }

  // --- Leak headers ---
  for (const leak of LEAK_HEADERS) {
    const value = headers.get(leak.name.toLowerCase())
    if (value) {
      const isServerWithVersion = leak.name === 'Server' && !/\/[\d.]/.test(value)
      if (!isServerWithVersion) {
        findings.push({
          severity: 'MEDIUM',
          check: `Header de fuite : ${leak.name}`,
          detail: `Valeur exposée : "${value}" — ${leak.description}`,
          fix: `Supprimer ou masquer le header ${leak.name} dans la config serveur`,
        })
      }
    }
  }

  // --- Cookie flags ---
  const setCookie = headers.get('set-cookie')
  if (setCookie) {
    const cookies = setCookie.split(',').map(c => c.trim())
    for (const cookie of cookies) {
      const cookieName = cookie.split('=')[0]?.trim()

      if (!/HttpOnly/i.test(cookie)) {
        findings.push({
          severity: 'HIGH',
          check: `Cookie sans HttpOnly : ${cookieName}`,
          detail: 'Un cookie sans HttpOnly est accessible via JavaScript — risque XSS',
          fix: `Ajouter le flag HttpOnly au cookie ${cookieName}`,
        })
      }
      if (!/Secure/i.test(cookie)) {
        findings.push({
          severity: 'MEDIUM',
          check: `Cookie sans Secure : ${cookieName}`,
          detail: 'Un cookie sans Secure peut être transmis en HTTP clair',
          fix: `Ajouter le flag Secure au cookie ${cookieName}`,
        })
      }
      if (!/SameSite/i.test(cookie)) {
        findings.push({
          severity: 'LOW',
          check: `Cookie sans SameSite : ${cookieName}`,
          detail: 'Absence de SameSite — protection CSRF réduite',
          fix: `Ajouter SameSite=Lax ou SameSite=Strict au cookie ${cookieName}`,
        })
      }
    }
  }

  return findings
}

// CLI
if (process.argv[1].endsWith('headers.js')) {
  const url = process.argv[2]
  if (!url) {
    console.error('Usage : node scripts/headers.js <url>')
    process.exit(1)
  }

  console.log(`Vérification des headers : ${url}\n`)

  const findings = await checkHeaders(url)

  if (findings.length === 0) {
    console.log('✓ Tous les headers de sécurité sont présents.')
    process.exit(0)
  }

  for (const f of findings) {
    const prefix = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : f.severity === 'MEDIUM' ? '🟡' : '🔵'
    console.log(`${prefix} [${f.severity}] ${f.check}`)
    console.log(`   ${f.detail}`)
    if (f.fix) console.log(`   → ${f.fix}`)
    console.log()
  }

  console.log(`Total : ${findings.length} finding(s)`)
  process.exit(findings.some(f => f.severity === 'CRITICAL') ? 2 : 1)
}

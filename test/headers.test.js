import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkHeaders } from '../scripts/headers.js'

// Headers de sécurité complets, servis par la page finale (200) après redirect.
const SECURE_PAGE_HEADERS = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy': "default-src 'self'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'geolocation=()',
}

// Faux fetch simulant un site dont la racine fait 301 -> /fr/ :
//  - https + 'follow' -> 200 de /fr/ AVEC tous les headers (page finale)
//  - https + 'manual' -> 301 SANS header de sécurité (réponse intermédiaire)
//  - http  + 'manual' -> 301 vers https (sonde HTTP->HTTPS OK)
//  - http  + 'follow' -> 200 sans Location (casserait la sonde -> détecte une régression)
function installFetchMock() {
  const original = globalThis.fetch
  globalThis.fetch = async (url, opts = {}) => {
    const u = new URL(url)
    if (u.protocol === 'https:') {
      if (opts.redirect === 'follow') return { status: 200, headers: new Headers(SECURE_PAGE_HEADERS) }
      return { status: 301, headers: new Headers({ location: 'https://example.test/fr/' }) }
    }
    if (opts.redirect === 'manual') return { status: 301, headers: new Headers({ location: 'https://example.test/' }) }
    return { status: 200, headers: new Headers({}) }
  }
  return () => { globalThis.fetch = original }
}

test('racine en 301 -> /fr/ porteur de la CSP : pas de faux positif CSP', async () => {
  const restore = installFetchMock()
  try {
    const findings = await checkHeaders('https://example.test/')
    const checks = findings.map(f => f.check)
    assert.ok(!checks.some(c => /Content-Security-Policy/i.test(c)), `CSP ne doit pas être signalée manquante. Findings: ${JSON.stringify(checks)}`)
    assert.ok(!checks.includes('HTTPS indisponible'), 'Le HTTPS doit être joignable.')
    assert.deepEqual(findings, [])
  } finally { restore() }
})

test("la sonde HTTP->HTTPS reste en 'manual' (le 301 est bien détecté)", async () => {
  const restore = installFetchMock()
  try {
    const findings = await checkHeaders('https://example.test/')
    assert.ok(!findings.some(f => f.check === 'Redirection HTTP → HTTPS absente'), "La redirection HTTP->HTTPS (301) doit être reconnue ; passer la sonde en 'follow' verrait un 200 sans Location et signalerait une absence à tort.")
  } finally { restore() }
})

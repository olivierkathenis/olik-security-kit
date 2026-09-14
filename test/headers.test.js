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

async function withBasicAuth(fetchMock, run, secret = 'audit:fixture-password') {
  const originalFetch = globalThis.fetch
  const originalSecret = process.env.OLIK_SECURITY_BASIC_AUTH
  globalThis.fetch = fetchMock
  process.env.OLIK_SECURITY_BASIC_AUTH = secret
  try { await run() } finally {
    globalThis.fetch = originalFetch
    if (originalSecret === undefined) delete process.env.OLIK_SECURITY_BASIC_AUTH
    else process.env.OLIK_SECURITY_BASIC_AUTH = originalSecret
  }
}

test('BasicAuth suit /fr/ et ne transmet aucun secret à la sonde HTTP', async () => {
  const requests = []
  await withBasicAuth(async (url, opts) => {
    requests.push({ url, opts })
    const u = new URL(url)
    assert.equal(opts.redirect, 'manual')
    if (u.protocol === 'http:') {
      assert.equal(opts.headers, undefined)
      return { status: 301, headers: new Headers({ location: 'https://example.test/' }) }
    }
    assert.equal(opts.headers.Authorization, `Basic ${Buffer.from('audit:fixture-password').toString('base64')}`)
    return u.pathname === '/' ? { status: 302, headers: new Headers({ location: '/fr/' }) }
      : { status: 200, headers: new Headers(SECURE_PAGE_HEADERS) }
  }, async () => {
    assert.deepEqual(await checkHeaders('https://example.test/'), [])
    assert.equal(requests.length, 3)
  })
})

for (const location of ['https://other.test/fr/', 'http://example.test/fr/', 'https://user:pass@example.test/fr/']) {
  test(`refuse redirect authentifié interdit : ${location}`, async () => {
    let count = 0
    await withBasicAuth(async () => {
      count++
      return { status: 302, headers: new Headers({ location }) }
    }, async () => {
      const findings = await checkHeaders('https://example.test/')
      assert.equal(count, 1)
      assert.equal(findings[0].check, 'HTTPS indisponible')
      assert.equal(findings[0].severity, 'CRITICAL')
    })
  })
}

for (const status of [401, 403]) {
  for (const secret of ['', 'audit:fixture-password']) {
    test(`HTTP ${status} avec secret ${secret ? 'présent' : 'absent'} échoue explicitement`, async () => {
      await withBasicAuth(async () => ({ status, headers: new Headers(SECURE_PAGE_HEADERS) }), async () => {
        const findings = await checkHeaders('https://example.test/')
        assert.equal(findings.length, 1)
        assert.equal(findings[0].severity, 'CRITICAL')
        assert.equal(findings[0].check, 'Audit headers non authentifié')
      }, secret)
    })
  }
}

test('boucle authentifiée limitée à 20 redirects', async () => {
  let count = 0
  await withBasicAuth(async () => {
    count++
    return { status: 302, headers: new Headers({ location: '/loop' }) }
  }, async () => {
    assert.equal((await checkHeaders('https://example.test/'))[0].check, 'HTTPS indisponible')
    assert.equal(count, 21)
  })
})

test('secret invalide refusé avant tout accès réseau', async () => {
  await withBasicAuth(async () => { assert.fail('aucun réseau attendu') }, async () => {
    assert.equal((await checkHeaders('https://example.test/'))[0].severity, 'CRITICAL')
  }, 'invalid')
})

test('un secret réfléchi par le serveur ne figure pas dans le rapport', async () => {
  const secret = 'audit:fixture-password'
  const encoded = Buffer.from(secret).toString('base64')
  await withBasicAuth(async (url) => new URL(url).protocol === 'http:'
    ? { status: 301, headers: new Headers({ location: 'https://example.test/' }) }
    : { status: 200, headers: new Headers({ ...SECURE_PAGE_HEADERS, 'x-powered-by': `${secret} ${encoded} fixture-password` }) }, async () => {
    const report = JSON.stringify(await checkHeaders('https://example.test/'))
    assert.ok(!report.includes(secret))
    assert.ok(!report.includes(encoded))
    assert.ok(!report.includes('fixture-password'))
    assert.ok(report.includes('[REDACTED]'))
  })
})

for (const status of [302, 404, 500]) {
  test(`HTTP ${status} avec headers valides échoue sous BasicAuth`, async () => {
    await withBasicAuth(async () => ({ status, headers: new Headers(SECURE_PAGE_HEADERS) }), async () => {
      const findings = await checkHeaders('https://example.test/')
      assert.equal(findings.length, 1)
      assert.equal(findings[0].severity, 'CRITICAL')
      assert.equal(findings[0].check, 'Audit headers sans page valide')
    })
  })
}

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { options, scannerReport, evaluate, runScanners } from '../src/core/ci-report.js'
import { scanSecrets } from '../scripts/secrets.js'
import { scanVulns } from '../scripts/vuln-scan.js'
import { checkHeaders } from '../scripts/headers.js'

const clean = name => scannerReport(name, [])

test('clean terminé : A ; CRITICAL : F et blocage, sans lecture de marqueurs textuels', () => {
  const config = options()
  assert.equal(evaluate([clean('secrets'), clean('vuln')], config).grade, 'A')
  const critical = scannerReport('secrets', [{ severity: 'CRITICAL', pattern: 'Erreur', match: 'ne pas publier' }])
  assert.equal(critical.findings[0].match, undefined)
  assert.equal(evaluate([critical, clean('vuln')], config).quality_pass, false)
  assert.equal(evaluate([critical, clean('vuln')], config).grade, 'F')
  const arbitrary = scannerReport('secrets', [{ severity: 'LOW', pattern: '[CRITICAL] [HIGH]', file: '[MEDIUM]' }])
  assert.equal(evaluate([arbitrary, clean('vuln')], config).grade, 'A')
  assert.equal(evaluate([critical, clean('vuln')], options({ minGrade: 'F', failOnCritical: 'false' })).quality_pass, true)
})

test('rapport absent, crash, doublon ou severity invalide : aucune note', async () => {
  const config = options()
  for (const reports of [[], [clean('secrets')], [clean('secrets'), clean('secrets')],
    [clean('secrets'), { schema: 1, scanner: 'vuln', status: 'completed', findings: [{ severity: 'UNKNOWN' }] }]]) {
    const result = evaluate(reports, config)
    assert.equal(result.complete, false); assert.equal(result.grade, null); assert.equal(result.quality_pass, false)
  }
  const reports = []
  await runScanners(config, { secrets: async () => { throw Error('[CRITICAL] message non fiable') }, vuln: async () => [] },
    async (_name, report) => reports.push(report))
  assert.equal(reports[0].status, 'error')
  assert.equal(evaluate(reports, config).grade, null)
  await assert.rejects(runScanners(config, { secrets: async () => [], vuln: async () => [] }, async () => { throw Error('disque') }))
})

test('scan_type/min_grade validés ; URL vide ne lance pas headers', async () => {
  for (const input of [{ scanType: 'invalid' }, { scanType: 'all; echo injection' }, { minGrade: 'Z' },
    { minGrade: "C'; process.exit(0)//" }, { failOnCritical: 'yes' }, { url: 'file:///etc/passwd' }, { url: 'https://u:p@example.test' }]) {
    assert.throws(() => options(input))
  }
  let called = false
  await runScanners(options(), { secrets: async () => [], vuln: async () => [], headers: async () => { called = true } }, async () => {})
  assert.equal(called, false)
  assert.deepEqual(options({ url: 'https://example.test' }).scanners, ['secrets', 'vuln', 'headers'])
})

test('mode strict remonte I/O et metadata cassée ; comportement CLI historique conservé', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'olik-kit-'))
  try {
    const absent = join(dir, 'absent')
    assert.deepEqual(await scanSecrets(absent), [])
    await assert.rejects(scanSecrets(absent, { strict: true }))
    await assert.rejects(scanVulns(absent, { strict: true }))
    await writeFile(join(dir, 'package.json'), 'JSON cassé')
    assert.deepEqual(await scanVulns(dir), [])
    await assert.rejects(scanVulns(dir, { strict: true }))
    await mkdir(join(dir, '.viceignore'))
    await assert.rejects(scanSecrets(dir, { strict: true }))
  } finally { await rm(dir, { recursive: true, force: true }) }
})

test('mode strict headers : panne HTTPS ou HTTP ne fournit pas de scan terminé', async () => {
  const original = globalThis.fetch
  try {
    globalThis.fetch = async () => { throw Error('offline') }
    await assert.rejects(checkHeaders('https://example.test', { strict: true }))
    assert.equal((await checkHeaders('https://example.test'))[0].severity, 'HIGH')
    globalThis.fetch = async url => {
      if (url.startsWith('http:')) throw Error('offline')
      return { status: 200, headers: new Headers() }
    }
    await assert.rejects(checkHeaders('https://example.test', { strict: true }))
  } finally { globalThis.fetch = original }
})

test('runner réel clean, secret factice et panne : rapports JSON et exit indépendants', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'olik-kit-run-'))
  const project = join(dir, 'project'); await mkdir(project)
  function run(name, extra = {}) {
    return spawnSync(process.execPath, [resolve('scripts/ci-audit.js')], { encoding: 'utf8', timeout: 5000,
      env: { ...process.env, SCAN_TYPE: 'all', AUDIT_URL: '', MIN_GRADE: 'C', FAIL_ON_CRITICAL: 'true',
        PROJECT_PATH: project, REPORT_DIR: join(dir, name), GITHUB_STEP_SUMMARY: '', ...extra } })
  }
  try {
    const passed = run('clean'); assert.equal(passed.status, 0, passed.stderr)
    assert.equal(JSON.parse(passed.stdout).grade, 'A')
    // Construction d'un jeton entièrement factice : pas de secret réel ni pattern complet dans ce test.
    await writeFile(join(project, 'config.txt'), ['ghp', '_', '9'.repeat(36)].join(''))
    const failed = run('critical'); assert.equal(failed.status, 1)
    assert.equal(JSON.parse(failed.stdout).grade, 'F')
    const report = JSON.parse(await readFile(join(dir, 'critical/scan-secrets.json'), 'utf8'))
    assert.equal(report.status, 'completed'); assert.equal(report.findings[0].severity, 'CRITICAL')
    assert.equal(report.findings[0].match, undefined)
    await writeFile(join(project, 'package.json'), '{')
    const crashed = run('crashed'); assert.equal(crashed.status, 1)
    assert.equal(JSON.parse(crashed.stdout).grade, null)
    assert.equal(JSON.parse(await readFile(join(dir, 'crashed/scan-vuln.json'), 'utf8')).status, 'error')
    assert.equal(run('bad-input', { SCAN_TYPE: 'invalid' }).status, 1)
    assert.equal(run('clean').status, 1) // Ancien rapport refusé, pas réutilisé.
  } finally { await rm(dir, { recursive: true, force: true }) }
})

test('workflow : SHA du reusable validé et checkout exact, inputs jamais insérés dans run', async () => {
  const yaml = await readFile('.github/workflows/audit.yml', 'utf8')
  assert.match(yaml, /KIT_SHA: \$\{\{ job\.workflow_sha \}\}/)
  assert.match(yaml, /ref: \$\{\{ steps\.identity\.outputs\.sha \}\}/)
  assert.doesNotMatch(yaml, /ref: main|continue-on-error|tee scan/)
  const body = yaml.match(/        run: \|\n([\s\S]*?)\n      - uses:/)[1].split('\n').map(line => line.slice(10)).join('\n')
  const dir = await mkdtemp(join(tmpdir(), 'olik-kit-identity-'))
  try {
    const env = { ...process.env, KIT_SHA: 'a'.repeat(40), KIT_REPOSITORY: 'olivierkathenis/olik-security-kit',
      SCAN_TYPE: 'all', MIN_GRADE: 'C', GITHUB_OUTPUT: join(dir, 'outputs') }
    assert.equal(spawnSync('bash', ['-e', '-c', body], { env }).status, 0)
    assert.match(await readFile(env.GITHUB_OUTPUT, 'utf8'), /^sha=a{40}\n$/)
    for (const change of [{ KIT_SHA: '' }, { KIT_SHA: 'main' }, { KIT_REPOSITORY: 'caller/repo' },
      { SCAN_TYPE: 'invalid' }, { MIN_GRADE: 'Z' }]) assert.notEqual(spawnSync('bash', ['-e', '-c', body], { env: { ...env, ...change } }).status, 0)
    const repo = join(dir, 'olik-security-kit')
    function git(args) {
      const result = spawnSync('git', args, { encoding: 'utf8' })
      assert.equal(result.status, 0, result.stderr)
      return result.stdout.trim()
    }
    git(['init', '--quiet', '--initial-branch=fixture', repo])
    const commit = () => git(['-C', repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
      'commit', '--allow-empty', '--quiet', '-m', 'fixture'])
    commit()
    const expected = git(['-C', repo, 'rev-parse', 'HEAD'])
    const check = yaml.match(/name: Vérifier les scripts effectivement récupérés[\s\S]*?        run: \|\n([\s\S]*?)\n      - uses:/)[1]
      .split('\n').map(line => line.slice(10)).join('\n')
    const checkoutEnv = { ...env, KIT_SHA: expected, GITHUB_STEP_SUMMARY: join(dir, 'summary') }
    assert.equal(spawnSync('bash', ['-e', '-c', check], { cwd: dir, env: checkoutEnv }).status, 0)
    commit() // Un autre checkout/SHA doit échouer même si la forme du SHA attendu est valide.
    assert.notEqual(spawnSync('bash', ['-e', '-c', check], { cwd: dir, env: checkoutEnv }).status, 0)
  } finally { await rm(dir, { recursive: true, force: true }) }
  // Les expressions ne sont présentes que dans env/with, jamais dans un bloc shell.
  for (const block of yaml.matchAll(/        run: \|\n((?:          .*\n)+)/g)) assert.doesNotMatch(block[1], /\$\{\{/)
})

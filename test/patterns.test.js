import { test } from 'node:test'
import assert from 'node:assert/strict'
import { SECRET_PATTERNS } from '../config/patterns.js'

// Cas reels de l'audit du 18/08/2026 (olik-prospection + olik-gestion).
// Valeurs volontairement fictives : meme FORME, pas les vrais secrets.
const DOIT_MATCHER = [
  ['Google API Key', 'API Key : `AIzaSy000000000000000000000000000000000`'],
  ['Google OAuth Client Secret', 'Client Secret : `GOCSPX-A0000000000000000000000`'],
  ['Telegram Bot Token', 'url: "https://api.telegram.org/bot8609076026:AAF0000000000000000000000000000000/sendMessage"'],
  ['Generic Token assignment', 'NOCODB_TOKEN = "emLs0000000000000000000000000000000000"'],
  // Forme markdown : separateur espace + backticks (invisible avant le 18/08).
  ['Generic Secret assignment', '  - Client Secret : `0-t8Q~kw000000000.se8qR0000000000000`'],
]

// Ce qui ne doit PAS declencher : un scanner bruyant ne sera pas utilise.
const NE_DOIT_PAS_MATCHER = [
  'MAILJET_API_KEY = os.environ.get("MAILJET_API_KEY", "")',
  'password: "[mot de passe purge le 17/08]"',
  'PGPASSWORD=$POSTGRES_PASSWORD psql ...',
  'client_secret: "<A_REMPLIR>"',
  'api_key = "your_api_key_here"',
]

function matche(ligne) {
  return SECRET_PATTERNS.filter(p => p.regex.test(ligne)).map(p => p.name)
}

for (const [nomAttendu, ligne] of DOIT_MATCHER) {
  test(`detecte : ${nomAttendu}`, () => {
    assert.ok(matche(ligne).includes(nomAttendu),
      `"${nomAttendu}" attendu, obtenu : ${JSON.stringify(matche(ligne))}`)
  })
}

test('les patterns fournisseur ne matchent pas les placeholders', () => {
  const FOURNISSEUR = ['Google API Key', 'Google OAuth Client Secret', 'Telegram Bot Token',
                       'OpenAI API Key', 'Anthropic API Key']
  for (const ligne of NE_DOIT_PAS_MATCHER) {
    const faux = matche(ligne).filter(n => FOURNISSEUR.includes(n))
    assert.deepEqual(faux, [], `faux positif sur : ${ligne}`)
  }
})

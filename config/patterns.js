export const SECRET_PATTERNS = [
  { name: 'Mailjet API Key', regex: /(?:mailjet[_-]?(?:api[_-]?)?key|MJ_APIKEY_PUBLIC)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/i, severity: 'CRITICAL' },
  { name: 'Mailjet Secret Key', regex: /(?:mailjet[_-]?(?:api[_-]?)?secret|MJ_APIKEY_PRIVATE)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/i, severity: 'CRITICAL' },
  { name: 'Brevo API Key', regex: /xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]+/, severity: 'CRITICAL' },
  { name: 'Coolify Token', regex: /(?:coolify[_-]?token|COOLIFY_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9-_]{40,})['"]?/i, severity: 'CRITICAL' },
  { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,}/, severity: 'CRITICAL' },
  { name: 'Private Key PEM', regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: 'CRITICAL' },
  { name: 'Database URL with credentials (MySQL)', regex: /mysql:\/\/[^:]+:([^@\s]{6,})@/i, severity: 'CRITICAL' },
  { name: 'Database URL with credentials (PostgreSQL)', regex: /postgresql:\/\/[^:]+:([^@\s]{6,})@/i, severity: 'CRITICAL' },
  { name: 'Bearer Token', regex: /Authorization\s*[=:]\s*['"]?Bearer\s+[A-Za-z0-9-._~+/]{20,}['"]?/i, severity: 'HIGH' },
  { name: 'Generic API Key assignment', regex: /(?:api[_\-\s]?key|apikey)\s*[=:]\s*['"`]([A-Za-z0-9-_]{20,})['"`]?/i, severity: 'HIGH' },
  { name: 'Generic Secret assignment', regex: /(?:secret[_\-\s]?key|app[_\-\s]?secret|client[_\-\s]?secret)\s*[=:]\s*['"`]([A-Za-z0-9\-_~.]{16,})['"`]?/i, severity: 'HIGH' },
  { name: 'Generic Password assignment', regex: /(?:password|passwd|db[_-]?pass)\s*[=:]\s*['"`]([^'"`]{8,})['"`]?/i, severity: 'MEDIUM' },
  // --- Ajouts 18/08/2026 : angles morts reveles par l'audit olik-prospection ---
  // Formats fournisseur : sans ambiguite, aucun faux positif attendu.
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/, severity: 'CRITICAL' },
  { name: 'Google OAuth Client Secret', regex: /GOCSPX-[A-Za-z0-9_-]{20,}/, severity: 'CRITICAL' },
  { name: 'Telegram Bot Token', regex: /\d{8,10}:AA[A-Za-z0-9_-]{30,}/, severity: 'CRITICAL' },  // pas de \b en tete : colle a "bot" dans les URLs api.telegram.org
  { name: 'OpenAI API Key', regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/, severity: 'CRITICAL' },
  { name: 'Anthropic API Key', regex: /\bsk-ant-[A-Za-z0-9_-]{20,}/, severity: 'CRITICAL' },
  // Affectation de token generique (NocoDB, n8n, API maison...) : non couvert par 'Generic Secret'.
  { name: 'Generic Token assignment', regex: /(?:^|[^A-Za-z])(?:[a-z]+[_\-\s])?(?:api[_\-\s]?)?token\s*[=:]\s*['"`]([A-Za-z0-9-_]{20,})['"`]?/i, severity: 'HIGH' },
];

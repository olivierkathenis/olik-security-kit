export const SECRET_PATTERNS = [
  {
    name: 'Mailjet API Key',
    regex: /(?:mailjet[_\-]?(?:api[_\-]?)?key|MJ_APIKEY_PUBLIC)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/i,
    severity: 'CRITICAL',
  },
  {
    name: 'Mailjet Secret Key',
    regex: /(?:mailjet[_\-]?(?:api[_\-]?)?secret|MJ_APIKEY_PRIVATE)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/i,
    severity: 'CRITICAL',
  },
  {
    name: 'Brevo API Key',
    regex: /xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]+/,
    severity: 'CRITICAL',
  },
  {
    name: 'Coolify Token',
    regex: /(?:coolify[_\-]?token|COOLIFY_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9\-_]{40,})['"]?/i,
    severity: 'CRITICAL',
  },
  {
    name: 'GitHub Token',
    regex: /gh[pousr]_[A-Za-z0-9_]{36,}/,
    severity: 'CRITICAL',
  },
  {
    name: 'Private Key PEM',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    severity: 'CRITICAL',
  },
  {
    name: 'Database URL with credentials (MySQL)',
    regex: /mysql:\/\/[^:]+:([^@\s]{6,})@/i,  // capture group 1 = mot de passe
    severity: 'CRITICAL',
  },
  {
    name: 'Database URL with credentials (PostgreSQL)',
    regex: /postgresql:\/\/[^:]+:([^@\s]{6,})@/i,  // capture group 1 = mot de passe
    severity: 'CRITICAL',
  },
  {
    name: 'Bearer Token',
    regex: /Authorization\s*[=:]\s*['"]?Bearer\s+[A-Za-z0-9\-._~+/]{20,}['"]?/i,
    severity: 'HIGH',
  },
  {
    name: 'Generic API Key assignment',
    regex: /(?:api[_\-]?key|apikey)\s*[=:]\s*['"]([A-Za-z0-9\-_]{20,})['"]?/i,
    severity: 'HIGH',
  },
  {
    name: 'Generic Secret assignment',
    regex: /(?:secret[_\-]?key|app[_\-]?secret|client[_\-]?secret)\s*[=:]\s*['"]([A-Za-z0-9\-_]{16,})['"]?/i,
    severity: 'HIGH',
  },
  {
    name: 'Generic Password assignment',
    regex: /(?:password|passwd|db[_\-]?pass)\s*[=:]\s*['"]([^'"]{8,})['"]?/i,
    severity: 'MEDIUM',
  },
];

export const SECURITY_HEADERS = [
  {
    name: 'Strict-Transport-Security',
    severity: 'CRITICAL',
    description: 'Force HTTPS — absent = downgrade attack possible',
  },
  {
    name: 'Content-Security-Policy',
    severity: 'HIGH',
    description: 'Limite les sources de contenu — absent = XSS facilite',
  },
  {
    name: 'X-Frame-Options',
    severity: 'MEDIUM',
    description: 'Protege contre le clickjacking (remplacable par CSP frame-ancestors)',
  },
  {
    name: 'X-Content-Type-Options',
    severity: 'MEDIUM',
    description: 'Empeche le MIME sniffing — valeur attendue : nosniff',
  },
  {
    name: 'Referrer-Policy',
    severity: 'LOW',
    description: 'Controle les infos transmises au referrer',
  },
  {
    name: 'Permissions-Policy',
    severity: 'LOW',
    description: 'Limite l\'acces aux APIs navigateur (camera, geolocation, etc.)',
  },
];

export const LEAK_HEADERS = [
  {
    name: 'X-Powered-By',
    description: 'Revele la technologie serveur (ex: PHP/8.2, Express)',
  },
  {
    name: 'Server',
    description: 'Revele le serveur et sa version (ex: nginx/1.25.3) — acceptable sans version',
  },
  {
    name: 'X-AspNet-Version',
    description: 'Revele la version ASP.NET',
  },
  {
    name: 'X-Generator',
    description: 'Revele le generateur de site (ex: Drupal, WordPress)',
  },
];

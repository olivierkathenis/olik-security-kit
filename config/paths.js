export const SENSITIVE_PATHS = [
  // Fichiers d'environnement
  { path: '/.env', severity: 'CRITICAL' },
  { path: '/.env.local', severity: 'CRITICAL' },
  { path: '/.env.production', severity: 'CRITICAL' },
  { path: '/.env.prod', severity: 'CRITICAL' },

  // Git
  { path: '/.git/config', severity: 'CRITICAL' },
  { path: '/.git/HEAD', severity: 'HIGH' },

  // Config et manifestes
  { path: '/config.json', severity: 'HIGH' },
  { path: '/package.json', severity: 'MEDIUM' },

  // Fichiers systeme
  { path: '/.DS_Store', severity: 'LOW' },
  { path: '/.htaccess', severity: 'MEDIUM' },

  // PHP
  { path: '/phpinfo.php', severity: 'HIGH' },

  // Symfony
  { path: '/_profiler', severity: 'HIGH' },
  { path: '/_wdt', severity: 'HIGH' },

  // API / Admin
  { path: '/api/', severity: 'MEDIUM' },
  { path: '/admin', severity: 'MEDIUM' },
  { path: '/graphql', severity: 'MEDIUM' },

  // Debug
  { path: '/debug', severity: 'MEDIUM' },

  // Standards web
  { path: '/.well-known/', severity: 'LOW' },
];

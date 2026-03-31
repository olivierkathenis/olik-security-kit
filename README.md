# olik-security-kit

Audit de sécurité automatisé pour les projets Symfony + Next.js.

## Installation

```bash
# Dépendance de développement dans un projet
npm install -D github:olivierkathenis/olik-security-kit

# Ou usage ponctuel sans installation
npx github:olivierkathenis/olik-security-kit secrets .
```

## Commandes CLI

| Commande | Description |
|----------|-------------|
| `olik-security secrets [path]` | Scan secrets dans le code source |
| `olik-security headers <url>` | Vérification des headers HTTP |
| `olik-security vuln [path]` | SAST scan vulnérabilités (PHP + TypeScript) |
| `olik-security all [path] [url]` | Les 3 en séquence + rapport final + export Markdown optionnel |
| `olik-security init` | Installe le hook pre-commit dans le projet courant |

Codes de sortie : `0` = OK, `1` = findings non-critiques, `2` = CRITICAL trouvé.

## Intégration CI

Appeler depuis n'importe quel repo via `workflow_call` :

```yaml
# .github/workflows/security.yml
name: Security

on: [push, pull_request]

jobs:
  audit:
    uses: olivierkathenis/olik-security-kit/.github/workflows/audit.yml@main
    with:
      scan_type: 'all'
      url: 'https://monsite.be'
      fail_on_critical: true
      min_grade: 'C'
```

### Inputs disponibles

| Input | Type | Défaut | Description |
|-------|------|--------|-------------|
| `scan_type` | string | `all` | `secrets`, `vuln`, ou `all` |
| `url` | string | _(vide)_ | URL pour le scan des headers |
| `fail_on_critical` | bool | `true` | Échouer si CRITICAL trouvé |
| `min_grade` | string | `C` | Grade minimum accepté (A/B/C/D/F) |

## Hook pre-commit

```bash
# Dans le projet à protéger
olik-security init
```

Installe `hooks/pre-commit.sh` dans `.git/hooks/pre-commit`. À chaque commit :
- Les fichiers staged sont scannés pour secrets
- CRITICAL → commit bloqué
- HIGH → warning, commit autorisé
- Timeout 30s maximum

## Configuration `vice.config.js`

Copier dans la racine du projet :

```js
// vice.config.js
export default {
  ignore: ['legacy/', 'migrations/'],
  headers: { url: 'https://monsite.be' },
  ci: { failOnCritical: true, minGrade: 'C' },
  extraPatterns: []
}
```

## Ajouter des patterns

Les patterns sont dans `config/patterns.js` (secrets) et `config/frameworks.js` (SAST).

Pour des patterns spécifiques au projet, utiliser `extraPatterns` dans `vice.config.js`.

# olik-security-kit

Audit de sécurité automatisé pour les projets Symfony + Next.js.

## Commandes CLI

| Commande | Description |
|----------|-------------|
| `olik-security secrets [path]` | Scan secrets dans le code source |
| `olik-security headers <url>` | Vérification des headers HTTP |
| `olik-security vuln [path]` | SAST scan vulnérabilités (PHP + TypeScript) |
| `olik-security all [path] [url]` | Les 3 en séquence + rapport final |
| `olik-security init` | Installe le hook pre-commit |

## Intégration CI

```yaml
jobs:
  audit:
    uses: olivierkathenis/olik-security-kit/.github/workflows/audit.yml@main
    with:
      scan_type: 'all'
      url: 'https://monsite.be'
      fail_on_critical: true
      min_grade: 'C'
```

## Ajouter des patterns

Les patterns sont dans `config/patterns.js` (secrets) et `config/frameworks.js` (SAST).

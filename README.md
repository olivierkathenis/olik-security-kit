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

## Staging protégé par BasicAuth

Stocker `utilisateur:mot-de-passe` dans un secret Actions du dépôt appelant
(`STAGING_BASIC_AUTH`), puis le transmettre explicitement au job réutilisable :

```yaml
    secrets:
      headers_basic_auth: ${{ secrets.STAGING_BASIC_AUTH }}
```

Le secret est exposé uniquement au step headers, via `OLIK_SECURITY_BASIC_AUTH`.
La CLI accepte cette même variable d’environnement, jamais un argument de mot de passe.
Le scanner conserve l’authentification sur les redirects HTTPS de même origine
(p. ex. `/` → `/fr/`) et refuse les redirects authentifiés vers une autre origine
ou vers HTTP. La sonde HTTP→HTTPS reste sans authentification.
Une réponse 401/403 produit un CRITICAL, y compris si le secret est absent.
Avec BasicAuth, seule une réponse finale 2xx permet l’audit des headers.
Les PR de forks et Dependabot ne reçoivent pas les secrets Actions usuels :
leur audit du staging protégé reste bloqué jusqu’à une exécution autorisée.
Ne pas utiliser `pull_request_target` pour contourner cette restriction.

Références : [secrets des workflows réutilisables](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows),
[redirections Fetch](https://fetch.spec.whatwg.org/#http-redirect-fetch).

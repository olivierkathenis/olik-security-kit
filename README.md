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

## Contrat CI

Pour figer une intégration, remplacer `@main` dans l'exemple par le SHA complet
du kit validé. Le workflow récupère ses scripts au `job.workflow_sha` du workflow
réutilisable, puis vérifie le HEAD effectivement récupéré ; aucun fallback sur main.
Ce contexte est documenté sur GitHub.com ; s'il est absent, l'audit échoue fermé.

Le runner `scripts/ci-audit.js` est distinct du CLI interactif. Il produit un JSON
par scanner dans un dossier neuf hors du projet, puis `summary.json`. `scan_type`
et `min_grade` sont validés. `all` avec URL vide exécute secrets et vuln seulement.
Les findings sont notés par leur champ `severity`, sans analyser les messages.
Les valeurs des secrets et extraits de code ne figurent pas dans les artefacts CI.

Scanner en erreur, rapport manquant/invalide ou lecture impossible : audit incomplet,
`grade: null`, `quality_pass: false`, processus en échec. Une erreur de préparation
ou une interruption avant résumé échoue également, sans grade valide. Des findings
peuvent fournir un audit terminé mais refusé par CRITICAL ou la note minimale.
Le mode strict CI remonte les erreurs I/O, de métadonnées et de sondes HTTP ; les
commandes CLI existantes conservent leur comportement. Les exclusions et la
détection par patterns restent les mêmes : un grade A n'est pas un audit exhaustif.

`npm test` couvre clean/CRITICAL, crash/incomplet/rapport manquant, inputs invalides,
URL vide, métadonnées cassées et validation du SHA. `kit-tests.yml` appelle aussi
le workflow réutilisable local au même commit pour éprouver ce contexte en CI.

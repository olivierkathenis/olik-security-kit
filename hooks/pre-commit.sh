#!/bin/bash
# VICE Security — pre-commit hook
# Scan les fichiers staged pour secrets
# Installé via : olik-security init

set -euo pipefail

TIMEOUT=30
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SECRETS_SCRIPT="$KIT_DIR/scripts/secrets.js"

# Récupérer les fichiers staged (non supprimés)
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR 2>/dev/null)

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

# Créer un fichier temporaire avec la liste des fichiers staged
TMP_DIR=$(mktemp -d)

# Copier les fichiers staged dans le répertoire temporaire (en préservant le chemin)
while IFS= read -r file; do
  if [ -f "$file" ]; then
    dest="$TMP_DIR/$file"
    mkdir -p "$(dirname "$dest")"
    cp "$file" "$dest"
  fi
done <<< "$STAGED_FILES"

# Lancer le scan avec timeout
OUTPUT=$(timeout "$TIMEOUT" node "$SECRETS_SCRIPT" "$TMP_DIR" 2>&1) || SCAN_EXIT=$?
rm -rf "$TMP_DIR"

SCAN_EXIT="${SCAN_EXIT:-0}"

# exit 2 = CRITICAL trouvé
if [ "$SCAN_EXIT" -eq 2 ]; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║  VICE Security — Secret CRITICAL détecté                ║"
  echo "║  Commit bloqué. Supprimer le secret avant de committer. ║"
  echo "╚══════════════════════════════════════════════════════════╝"
  echo ""
  echo "$OUTPUT"
  echo ""
  echo "Pour ignorer un faux positif, ajouter le chemin dans .viceignore"
  exit 1
fi

# exit 1 = HIGH trouvé — warning mais laisse passer
if [ "$SCAN_EXIT" -eq 1 ]; then
  echo ""
  echo "⚠  VICE Security — Avertissement : secret HIGH détecté (commit autorisé)"
  echo "$OUTPUT"
  echo ""
fi

# exit 124 = timeout
if [ "$SCAN_EXIT" -eq 124 ]; then
  echo "⚠  VICE Security — Timeout (${TIMEOUT}s dépassé), scan ignoré"
fi

exit 0

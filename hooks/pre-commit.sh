#!/bin/bash
# Olik Security Kit — pre-commit hook
# Installez via : olik-security init

set -euo pipefail
TIMEOUT=30
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR 2>/dev/null)
[ -z "$STAGED_FILES" ] && exit 0
TMP_DIR=$(mktemp -d)
while IFS= read -r file; do
  if [ -f "$file" ]; then
    dest="$TMP_DIR/$file"; mkdir -p "$(dirname "$dest")"; cp "$file" "$dest"
  fi
done <<< "$STAGED_FILES"
OUTPUT=$(timeout "$TIMEOUT" node "$KIT_DIR/scripts/secrets.js" "$TMP_DIR" 2>&1) || SCAN_EXIT=$?
rm -rf "$TMP_DIR"
SCAN_EXIT="${SCAN_EXIT:-0}"
if [ "$SCAN_EXIT" -eq 2 ]; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║  Olik Security — Secret CRITICAL détecté                ║"
  echo "║  Commit bloqué. Supprimer le secret avant de committer. ║"
  echo "╚══════════════════════════════════════════════════════════╝"
  echo "$OUTPUT"
  echo "Pour ignorer un faux positif : ajouter dans .viceignore"
  exit 1
fi
[ "$SCAN_EXIT" -eq 1 ] && echo "⚠  Olik Security — Avertissement : secret HIGH (commit autorisé)" && echo "$OUTPUT"
[ "$SCAN_EXIT" -eq 124 ] && echo "⚠  Olik Security — Timeout ${TIMEOUT}s, scan ignoré"
exit 0

#!/usr/bin/env sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
# Sauvegarde de LogSonar : base de données (copie cohérente, sans arrêt),
# clés de chiffrement et rapports.
#
#   ./scripts/backup.sh [dossier]        (par défaut : ./backups)
#
# Restauration : voir docs/EXPLOITATION.md
# Exemple cron (chaque nuit à 4 h, 14 sauvegardes conservées) :
#   0 4 * * * cd /opt/logsonar && ./scripts/backup.sh >/dev/null && ls -1t backups/logsonar-*.tar.gz | tail -n +15 | xargs -r rm
set -eu

CONTAINER=logsonar
DEST_ROOT=${1:-./backups}
STAMP=$(date +%Y-%m-%d_%H%M)
WORK=$(mktemp -d)
# Copie temporaire dans le volume de données : /tmp est un tmpfs (système de fichiers en
# lecture seule) que « docker cp » ne voit pas.
TMP_DB=/app/data/.backup-tmp.db
trap 'rm -rf "$WORK"; docker exec "$CONTAINER" rm -f "$TMP_DB" >/dev/null 2>&1 || true' EXIT

mkdir -p "$DEST_ROOT"

# Copie cohérente de SQLite pendant que LogSonar tourne
docker exec "$CONTAINER" python -c "
import sqlite3
src = sqlite3.connect('/app/data/logsonar.db')
dst = sqlite3.connect('$TMP_DB')
src.backup(dst)
dst.close()
"
docker cp "$CONTAINER:$TMP_DB" "$WORK/logsonar.db"

# Sans ces clés, les secrets enregistrés (clés API) et les sessions sont illisibles
docker cp "$CONTAINER:/app/data/.secret_key" "$WORK/.secret_key" 2>/dev/null || true
docker cp "$CONTAINER:/app/data/.jwt_secret" "$WORK/.jwt_secret" 2>/dev/null || true
docker cp "$CONTAINER:/app/data/reports" "$WORK/reports" 2>/dev/null || true

ARCHIVE="$DEST_ROOT/logsonar-$STAMP.tar.gz"
tar czf "$ARCHIVE" -C "$WORK" .
chmod 600 "$ARCHIVE"
echo "Sauvegarde : $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"

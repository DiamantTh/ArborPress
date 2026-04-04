#!/bin/sh
# ArborPress Container-Entrypoint
# Funktioniert in beiden Image-Varianten (UBI9 und Ubuntu LTS).
# Erwartet, dass die arborpress-CLI (installiert via pip install .) im PATH liegt.
set -e

# ── 1. Pflicht-Umgebungsvariable prüfen ──────────────────────────────
if [ -z "${ARBORPRESS_WEB__SECRET_KEY:-}" ]; then
    echo "[arborpress] FEHLER: ARBORPRESS_WEB__SECRET_KEY ist nicht gesetzt." >&2
    echo "[arborpress] Bitte einen sicheren Zufallswert setzen (z.B. openssl rand -base64 48)." >&2
    exit 1
fi

# ── 2. Auf Datenbankverbindung warten ────────────────────────────────
# DB_HOST und DB_PORT können optional direkt gesetzt werden.
# Sind sie ungesetzt, wird kein TCP-Wait durchgeführt (z.B. SQLite).
if [ -n "${DB_HOST:-}" ] && [ -n "${DB_PORT:-}" ]; then
    echo "[arborpress] Warte auf Datenbankverbindung ${DB_HOST}:${DB_PORT} …"
    WAIT_SECONDS=0
    MAX_WAIT=60
    until nc -z "${DB_HOST}" "${DB_PORT}" 2>/dev/null; do
        WAIT_SECONDS=$((WAIT_SECONDS + 2))
        if [ "${WAIT_SECONDS}" -ge "${MAX_WAIT}" ]; then
            echo "[arborpress] FEHLER: Datenbank nicht innerhalb von ${MAX_WAIT}s erreichbar." >&2
            exit 1
        fi
        sleep 2
    done
    echo "[arborpress] Datenbank erreichbar (${WAIT_SECONDS}s)."
fi

# ── 3. Datenbankmigrationen anwenden ────────────────────────────────
echo "[arborpress] Führe Datenbankmigrationen aus …"
arborpress db migrate

# ── 4. Server starten ────────────────────────────────────────────────
WORKERS="${ARBORPRESS_WORKERS:-2}"
echo "[arborpress] Starte Server mit ${WORKERS} Worker(n) …"
exec arborpress serve --workers "${WORKERS}"

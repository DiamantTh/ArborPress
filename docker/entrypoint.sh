#!/usr/bin/env bash
# ==============================================================
# ArborPress – Container-Entrypoint
# Führt folgende Schritte aus:
#   1. Pflicht-Konfiguration prüfen (Secret Key)
#   2. Datenbank-Erreichbarkeit abwarten (max. 60 Sek.)
#   3. DB-Schema erstellen / migrieren (idempotent)
#   4. ArborPress-Server starten
# ==============================================================
set -euo pipefail

# ──────────────────────────────────────────────────────────────
# 1. Sicherheits-Sanity-Check
# ──────────────────────────────────────────────────────────────
_secret="${ARBORPRESS_WEB__SECRET_KEY:-}"

if [[ -z "$_secret" || "$_secret" == "CHANGE_ME_IN_PRODUCTION"* || "$_secret" == "AENDERN_IM_PRODUKTIVBETRIEB"* ]]; then
    echo "[entrypoint] FEHLER: ARBORPRESS_WEB__SECRET_KEY ist nicht gesetzt oder enthält den Standard-Wert." >&2
    echo "[entrypoint]         Bitte .env aus .env.example erstellen und einen langen Zufallsstring setzen." >&2
    echo "[entrypoint]         Tipp:  openssl rand -base64 48" >&2
    exit 1
fi

if [[ "${#_secret}" -lt 32 ]]; then
    echo "[entrypoint] FEHLER: ARBORPRESS_WEB__SECRET_KEY muss mindestens 32 Zeichen lang sein." >&2
    exit 1
fi

# ──────────────────────────────────────────────────────────────
# 2. Datenbank-Verbindung abwarten (max. 60 Sekunden)
# ──────────────────────────────────────────────────────────────
_db_url="${ARBORPRESS_DB__URL:-}"

_wait_for_db() {
    if [[ -z "$_db_url" ]]; then
        echo "[entrypoint] Kein ARBORPRESS_DB__URL gesetzt – DB-Wartezeit wird übersprungen."
        return
    fi

    # Host und Port aus URL extrahieren
    local _host _port
    if [[ "$_db_url" == postgresql* ]]; then
        _host=$(echo "$_db_url" | sed -E 's|.*@([^:/]+)[:/].*|\1|')
        _port=$(echo "$_db_url" | sed -E 's|.*@[^:]+:([0-9]+)/.*|\1|; t; s|.*|5432|')
    elif [[ "$_db_url" == mysql* ]]; then
        _host=$(echo "$_db_url" | sed -E 's|.*@([^:/]+)[:/].*|\1|')
        _port=$(echo "$_db_url" | sed -E 's|.*@[^:]+:([0-9]+)/.*|\1|; t; s|.*|3306|')
    else
        echo "[entrypoint] SQLite oder unbekannter Treiber – DB-Wartezeit wird übersprungen."
        return
    fi

    local _attempts=0
    local _max=30

    echo "[entrypoint] Warte auf Datenbankserver ${_host}:${_port} ..."
    until python3 - <<EOF 2>/dev/null
import socket, sys
try:
    s = socket.create_connection(("${_host}", ${_port}), timeout=2)
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
EOF
    do
        _attempts=$((_attempts + 1))
        if [[ $_attempts -ge $_max ]]; then
            echo "[entrypoint] FEHLER: Datenbankserver nach ${_max} Versuchen nicht erreichbar." >&2
            exit 1
        fi
        echo "[entrypoint] Versuch ${_attempts}/${_max} – nächster Versuch in 2 Sek. ..."
        sleep 2
    done
    echo "[entrypoint] Datenbankserver erreichbar."
}

_wait_for_db

# ──────────────────────────────────────────────────────────────
# 3. DB-Schema anlegen / aktualisieren (überspringbar via Env)
# ──────────────────────────────────────────────────────────────
if [[ "${ARBORPRESS_SKIP_MIGRATE:-false}" != "true" ]]; then
    echo "[entrypoint] Erstelle / aktualisiere Datenbankschema ..."
    arborpress db migrate
    echo "[entrypoint] Schema-Migration abgeschlossen."
else
    echo "[entrypoint] ARBORPRESS_SKIP_MIGRATE=true – Migration übersprungen."
fi

# ──────────────────────────────────────────────────────────────
# 4. Server starten
#    Host/Port werden aus ARBORPRESS_WEB__HOST / ARBORPRESS_WEB__PORT gelesen.
#    Workers über ARBORPRESS_WORKERS steuerbar (Default: 2).
# ──────────────────────────────────────────────────────────────
_workers="${ARBORPRESS_WORKERS:-2}"
echo "[entrypoint] Starte ArborPress (Hypercorn, ${_workers} Worker) ..."
exec arborpress serve --workers "${_workers}"

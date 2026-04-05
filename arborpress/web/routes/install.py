"""Web-basierter Einrichtungsassistent (§14 install wizard).

Ablauf:
  1. Erster Start →  arborpress schreibt config/install.token
  2. Browser    →  GET  /install    – Formular (Token + Stammdaten)
  3. Abschicken →  POST /install    – Token prüfen, DB anlegen, Admin anlegen,
                                      Marker schreiben, Token löschen
  4. Weiterleitung → /auth/register – Admin registriert Passkey/Sicherheitsschlüssel

Token-Schutz:
  Der Token steht ausschließlich in der Datei; er wird NICHT als URL-Parameter
  oder Kommandozeilenargument übergeben.  Nur wer Zugriff auf das Dateisystem
  des Servers hat, kann die Installation abschließen.
  Timing-sicherer Vergleich (secrets.compare_digest).

Nach der Installation:
  • config/.installed  wird angelegt → alle weiteren Zugriffe auf /install → 404
  • config/install.token wird gelöscht
"""

from __future__ import annotations

import logging
import re
import secrets

from quart import Blueprint, abort, redirect, render_template, request, session, url_for

from arborpress.web.security import validate_csrf

log = logging.getLogger("arborpress.web.install")

install_bp = Blueprint("install", __name__, template_folder="../../templates")


# ---------------------------------------------------------------------------
# GET /install
# ---------------------------------------------------------------------------


@install_bp.get("/install")
async def install_page():
    from arborpress.core.config import is_installed
    if is_installed():
        abort(404)
    return await render_template("install.html")


# ---------------------------------------------------------------------------
# POST /install
# ---------------------------------------------------------------------------


@install_bp.post("/install")
async def install_submit():
    from arborpress.core.config import (
        install_token_path,
        installed_marker_path,
        is_installed,
    )

    if is_installed():
        abort(404)

    await validate_csrf()

    form = await request.form
    token_in        = form.get("token", "").strip()
    site_name       = form.get("site_name", "").strip()
    admin_user      = form.get("admin_username", "").strip()
    admin_email     = form.get("admin_email", "").strip() or None
    admin_dn        = form.get("admin_display_name", "").strip() or None

    # ── Token-Prüfung ───────────────────────────────────────────────────────
    token_file = install_token_path()
    if not token_file.exists():
        log.error("install.token fehlt – manuelle Anlage nötig oder bereits installiert")
        abort(403)

    expected = token_file.read_text(encoding="utf-8").strip()
    if not secrets.compare_digest(token_in, expected):
        return await render_template(
            "install.html",
            errors=["Ungültiger Installations-Token."],
            form=form,
        ), 400

    # ── Eingaben validieren ─────────────────────────────────────────────────
    errors: list[str] = []
    if not site_name or len(site_name) > 128:
        errors.append("Blog-Name ist erforderlich (max. 128 Zeichen).")
    if not admin_user or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]|[a-z0-9]", admin_user):
        errors.append(
            "Benutzername ungültig – nur Kleinbuchstaben, Ziffern, Punkt, Bindestrich,"
            " Unterstrich (max. 64 Zeichen, muss mit Buchstabe/Ziffer beginnen und enden)."
        )
    if admin_email and len(admin_email) > 256:
        errors.append("E-Mail-Adresse zu lang.")

    if errors:
        return await render_template("install.html", errors=errors, form=form), 400

    # ── Installation durchführen ────────────────────────────────────────────
    try:
        import arborpress.models  # noqa: F401 – Modelle registrieren
        from arborpress.core.db import create_all_tables, get_db_session
        from arborpress.core.site_settings import save_section
        from arborpress.models.user import AccountType, User, UserRole
        from sqlalchemy import select

        # 1. DB-Schema anlegen
        await create_all_tables()

        # 2. Admin-User anlegen (idempotent)
        async for db in get_db_session():
            result = await db.execute(select(User).where(User.username == admin_user))
            if result.scalar_one_or_none() is None:
                user = User(
                    username=admin_user,
                    display_name=admin_dn or admin_user,
                    email=admin_email,
                    account_type=AccountType.PUBLIC,
                    role=UserRole("admin"),
                )
                db.add(user)
                await db.commit()

        # 3. Site-Titel setzen
        async for db in get_db_session():
            await save_section("general", {"site_title": site_name}, db, by="install")

        # 4. Installations-Marker schreiben, Token löschen
        marker = installed_marker_path()
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("installed\n", encoding="utf-8")
        if token_file.exists():
            token_file.unlink()

        log.info("Installation abgeschlossen. Admin: %r, Site: %r", admin_user, site_name)

    except Exception as exc:
        log.error("Installationsfehler: %s", exc, exc_info=True)
        return await render_template(
            "install.html",
            errors=[f"Interner Fehler bei der Installation: {exc}"],
            form=form,
        ), 500

    # Benutzernamen in Session für das Register-Formular vorbelegen
    session["install_prefill_user"] = admin_user
    return redirect(url_for("auth.register_page"))

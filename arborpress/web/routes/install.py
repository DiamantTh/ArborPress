"""Web-based setup wizard (§14 install wizard).

Flow:
  1. First start → arborpress writes config/install.token
  2. Browser    → GET  /install    – form (token + base data)
  3. Submit     → POST /install    – verify token, create DB, create admin,
                                      write marker, delete token
  4. Redirect   → /auth/register  – admin registers passkey/security key

Token protection:
  The token lives exclusively in the file; it is NOT passed as a URL parameter
  or command-line argument.  Only someone with filesystem access to the server
  can complete the installation.
  Timing-safe comparison (secrets.compare_digest).

After installation:
  • config/.installed  is created → all further requests to /install → 404
  • config/install.token is deleted
"""

from __future__ import annotations

import logging
import secrets

from quart import Blueprint, abort, redirect, render_template, request, session, url_for

from arborpress.core.validators import is_valid_email, is_valid_username
from arborpress.web.security import validate_csrf

log = logging.getLogger("arborpress.web.install")

install_bp = Blueprint("install", __name__, template_folder="../../templates")


# ---------------------------------------------------------------------------
# Rate-Limit helper  (§10 – brute-force protection on the install endpoint)
# ---------------------------------------------------------------------------

async def _check_install_rate_limit() -> bool:
    """Returns False (= blocked) when the IP exceeds 10 POSTs/minute."""
    from arborpress.web.ratelimit import check_rate_limit
    ip = request.remote_addr or "unknown"
    return check_rate_limit(f"install:{ip}", "10/minute")


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

    # §10 Rate-limit: max. 10 install attempts per IP per minute
    if not await _check_install_rate_limit():
        from quart import Response
        return Response("Too many requests", status=429, headers={"Retry-After": "60"})

    await validate_csrf()

    form = await request.form
    token_in        = form.get("token", "").strip()
    site_name       = form.get("site_name", "").strip()
    admin_user      = form.get("admin_username", "").strip()
    admin_email     = form.get("admin_email", "").strip() or None
    admin_dn        = form.get("admin_display_name", "").strip() or None

    # ── Token check ───────────────────────────────────────────────────────────────
    token_file = install_token_path()
    if not token_file.exists():
        log.error("install.token missing – manual creation needed or already installed")
        abort(403)

    expected = token_file.read_text(encoding="utf-8").strip()
    if not secrets.compare_digest(token_in, expected):
        return await render_template(
            "install.html",
            errors=["Invalid installation token."],
            form=form,
        ), 400

    # ── Validate input ───────────────────────────────────────────────────────────
    errors: list[str] = []
    if not site_name or len(site_name) > 128:
        errors.append("Blog name is required (max. 128 characters).")
    if not admin_user or not is_valid_username(admin_user):
        errors.append(
            "Invalid username – letters, digits, dot, hyphen,"
            " underscore only (max. 32 characters, must start and end with letter/digit)."
        )
    if admin_email and not is_valid_email(admin_email):
        errors.append("Invalid e-mail address.")

    if errors:
        return await render_template("install.html", errors=errors, form=form), 400

    # ── Run installation ────────────────────────────────────────────────────────────
    try:
        import arborpress.models  # noqa: F401 – register models
        from arborpress.core.db import create_all_tables, get_db_session
        from arborpress.core.site_settings import save_section
        from arborpress.models.user import AccountType, User, UserRole
        from sqlalchemy import func, select

        # 1. Create DB schema
        await create_all_tables()

        # 2. Create admin user (idempotent)
        async for db in get_db_session():
            result = await db.execute(select(User).where(func.lower(User.username) == admin_user.lower()))
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

        # 3. Set site title
        async for db in get_db_session():
            await save_section("general", {"site_title": site_name}, db, by="install")

        # 4. Write installation marker, delete token
        marker = installed_marker_path()
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("installed\n", encoding="utf-8")
        if token_file.exists():
            token_file.unlink()

        log.info("Installation complete. Admin: %r, site: %r", admin_user, site_name)

        # 5. DB-Capabilities detektieren und Scheduler starten (kein Neustart nötig)
        import asyncio as _asyncio

        from arborpress.core.db import get_engine as _get_engine
        from arborpress.core.db_capabilities import (
            detect_capabilities as _detect_caps,
            set_capabilities as _set_caps,
        )
        from arborpress.core.scheduler import run_scheduler as _run_scheduler

        try:
            _set_caps(await _detect_caps(_get_engine()))
        except Exception as _exc:
            log.warning("DB-Capability-Detection nach Install fehlgeschlagen: %s", _exc)

        _asyncio.ensure_future(_run_scheduler())

    except Exception as exc:
        log.error("Installation error: %s", exc, exc_info=True)
        return await render_template(
            "install.html",
            errors=[f"Internal error during installation: {exc}"],
            form=form,
        ), 500

    # Pre-fill username in session for the register form
    session["install_prefill_user"] = admin_user
    return redirect(url_for("auth.register_page"))

"""Seed-Daten: Beispiel-Posts, -Seiten, Impressum, Datenschutz (§14).

Wird von `arborpress init --seed` oder `arborpress db seed` aufgerufen.
Idempotent: Prüft vor dem Einfügen, ob Daten bereits vorhanden sind.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("arborpress.seed")

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _uid() -> str:
    return str(uuid.uuid4())


def _short_id() -> str:
    return secrets.token_urlsafe(8)[:10]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _md_to_html(md: str) -> str:
    """Einfaches Markdown→HTML ohne externe Bibliothek (Fallback)."""
    try:
        import markdown  # type: ignore
        return markdown.markdown(md, extensions=["fenced_code", "tables", "toc"])
    except ImportError:
        # Minimaler Fallback: Absätze
        paras = md.strip().split("\n\n")
        return "\n".join(f"<p>{p.replace(chr(10), '<br>')}</p>" for p in paras)


# ---------------------------------------------------------------------------
# Seed-Inhalte
# ---------------------------------------------------------------------------

_POST_1_SLUG = "willkommen-bei-arborpress"
_POST_1_TITLE = "Willkommen bei ArborPress"
_POST_1_MD = """\
# Willkommen bei ArborPress

Schön, dass du dabei bist! **ArborPress** ist eine selbstgehostete Blogging-Plattform,
die du vollständig kontrollierst – ohne Tracking, ohne fremde Server, ohne Kompromisse.

## Was kann ArborPress?

- **WebAuthn-Login** – passwortlose Anmeldung mit Hardwaretoken oder Gerätesensor
- **ActivityPub-Federation** – deine Beiträge erscheinen im Fediverse (Mastodon, Misskey …)
- **Mehrsprachigkeit** – Beiträge in verschiedenen Sprachen veröffentlichen
- **Volltextsuche** – dank PostgreSQL `pg_fts` oder MariaDB FULLTEXT
- **Plugins** – das System lässt sich einfach erweitern

## Erste Schritte

1. Melde dich unter `/auth/register` an und richte deinen WebAuthn-Schlüssel ein
2. Erstelle deinen ersten echten Beitrag im [Admin-Bereich](/admin/)
3. Passe das Theme in `config.toml` unter `[web] theme = "dark"` an

> "Das Web gehört allen." – Tim Berners-Lee

Viel Spaß beim Schreiben!
"""

_POST_2_SLUG = "markdown-referenz"
_POST_2_TITLE = "Markdown-Formatierungsreferenz"
_POST_2_MD = """\
# Markdown-Formatierungsreferenz

Dieser Beitrag zeigt alle unterstützten Formatierungen auf einen Blick.

## Überschriften

# H1 – Seitenüberschrift
## H2 – Abschnittsüberschrift
### H3 – Unterabschnitt

## Textformatierung

**Fett**, *kursiv*, ~~durchgestrichen~~, `Inline-Code`, [Link](https://arborpress.dev)

## Listen

- Erster Punkt
- Zweiter Punkt
  - Eingerückt
- Dritter Punkt

1. Nummerierter Punkt
2. Noch einer

## Zitat

> Das ist ein Blockzitat über mehrere Zeilen.
> Es kann mehrere Absätze enthalten.

## Code-Block

```python
def hello(name: str) -> str:
    return f"Hallo, {name}!"

print(hello("Welt"))
```

## Tabelle

| Spalte A | Spalte B | Spalte C |
|----------|----------|----------|
| Wert 1   | Wert 2   | Wert 3   |
| Alpha    | Beta     | Gamma    |

## Bild

![Platzhalter](https://picsum.photos/seed/arborpress/720/360)

---

*Letztes Update: automatisch beim Init eingefügt.*
"""

_IMPRESSUM_SLUG = "imprint"
_IMPRESSUM_TITLE = "Impressum"
_IMPRESSUM_MD = """\
# Imprint

**Angaben gemäß § 5 TMG**

Muster Max  
Musterstraße 1  
12345 Musterstadt  
Deutschland

**Kontakt:**  
E-Mail: kontakt@beispiel.de  
Telefon: +49 (0)123 456789

**Verantwortlich für den Inhalt nach § 55 Abs. 2 RStV:**  
Muster Max  
Musterstraße 1  
12345 Musterstadt

---

## Haftungsausschluss

### Haftung für Inhalte

Die Inhalte dieser Seite wurden mit größter Sorgfalt erstellt. Für die Richtigkeit,
Vollständigkeit und Aktualität der Inhalte übernehmen wir keine Gewähr.
Als Diensteanbieter sind wir gemäß § 7 Abs. 1 TMG für eigene Inhalte auf
diesen Seiten nach den allgemeinen Gesetzen verantwortlich.

### Haftung für Links

Unser Angebot enthält Links zu externen Websites Dritter, auf deren Inhalte wir
keinen Einfluss haben. Deshalb können wir für diese fremden Inhalte auch keine
Gewähr übernehmen.

### Urheberrecht

Die durch die Seitenbetreiber erstellten Inhalte und Werke auf diesen Seiten
unterliegen dem deutschen Urheberrecht.

> **Hinweis:** Bitte passe diese Angaben deinen tatsächlichen Daten an.
> Das Impressum dient nur als Vorlage.
"""

_PRIVACY_SLUG = "privacy"
_PRIVACY_TITLE = "Datenschutzerklärung"
_PRIVACY_MD = """\
# Privacy Policy

## 1. Verantwortlicher

Verantwortlich für die Datenverarbeitung auf dieser Website:

Muster Max  
Musterstraße 1  
12345 Musterstadt  
E-Mail: datenschutz@beispiel.de

## 2. Erhebung und Verarbeitung personenbezogener Daten

### Server-Logfiles

Beim Besuch unserer Website werden automatisch Informationen in sogenannten
Server-Logfiles gespeichert, die Ihr Browser übermittelt:

- Browsertyp und -version
- Betriebssystem
- Referrer-URL
- Hostname des zugreifenden Rechners
- Uhrzeit der Serveranfrage
- IP-Adresse (anonymisiert)

Diese Daten werden nicht mit anderen Datenquellen zusammengeführt.
Grundlage ist Art. 6 Abs. 1 lit. f DSGVO.

### Cookies

Diese Website verwendet ausschließlich technisch notwendige Cookies (Session-Cookie
für eingeloggte Benutzer). Es werden keine Tracking- oder Werbe-Cookies eingesetzt.

## 3. Kontaktformular / E-Mail

Wenn Sie uns per E-Mail kontaktieren, werden Ihre Angaben zur Bearbeitung der
Anfrage und für mögliche Anschlussfragen gespeichert. Grundlage: Art. 6 Abs. 1
lit. b DSGVO (Vertragserfüllung) oder Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse).

## 4. Benutzerkonten (WebAuthn)

Bei der Registrierung wird ein kryptographischer öffentlicher Schlüssel (WebAuthn
Credential) gespeichert. Es werden keine Passwörter gespeichert. Biometrische Daten
werden ausschließlich lokal auf Ihrem Gerät verarbeitet und verlassen es nicht.

Gespeicherte Daten: Benutzername, öffentlicher Schlüssel, Zeitpunkt der Registrierung
und letzten Anmeldung.

Grundlage: Art. 6 Abs. 1 lit. b DSGVO.

## 5. Ihre Rechte

Sie haben gemäß DSGVO folgende Rechte:

- **Recht auf Auskunft** (Art. 15 DSGVO)
- **Recht auf Berichtigung** (Art. 16 DSGVO)
- **Recht auf Löschung** (Art. 17 DSGVO)
- **Recht auf Einschränkung der Verarbeitung** (Art. 18 DSGVO)
- **Recht auf Datenübertragbarkeit** (Art. 20 DSGVO)
- **Widerspruchsrecht** (Art. 21 DSGVO)

Zur Ausübung Ihrer Rechte wenden Sie sich an: datenschutz@beispiel.de

Sie haben außerdem das Recht, sich bei einer Datenschutz-Aufsichtsbehörde zu
beschweren.

## 6. Keine Weitergabe an Dritte

Personenbezogene Daten werden nicht an Dritte weitergegeben, sofern keine gesetzliche
Verpflichtung besteht.

## 7. Federation (ActivityPub)

Falls die Federation aktiviert ist, werden veröffentlichte Beiträge an follower
in anderen Fediverse-Instanzen übermittelt. Dies umfasst Beitragstitel, Inhalt,
Veröffentlichungszeitpunkt und Autorenname. Die Übermittlung basiert auf Art. 6
Abs. 1 lit. b DSGVO (Nutzungsvertrag).

---

> **Hinweis:** Bitte passe diese Datenschutzerklärung deinen tatsächlichen
> Verarbeitungsaktivitäten an. Dieser Text ist eine Vorlage und ersetzt keine
> Rechtsberatung.

*Stand: {{ date }}*
"""


# ---------------------------------------------------------------------------
# Seed-Funktion
# ---------------------------------------------------------------------------


async def seed_database(db: AsyncSession, *, force: bool = False) -> dict[str, int]:
    """Fügt Beispielinhalte ein.

    Args:
        db:    Aktive AsyncSession
        force: Wenn True, wird auch bei vorhandenen Daten neu eingefügt

    Returns:
        Dict mit eingefügten Datensätzen pro Tabelle.
    """
    from arborpress.models.content import Page, PageType, Post, PostStatus, Tag

    inserted: dict[str, int] = {"posts": 0, "pages": 0, "tags": 0}

    # ---- Tags ----
    existing_tags = (await db.execute(select(Tag))).scalars().all()
    tag_slugs = {t.slug for t in existing_tags}
    seed_tags = [
        Tag(slug="neuigkeiten", label="Neuigkeiten", lang="de"),
        Tag(slug="tutorial",    label="Tutorial",    lang="de"),
        Tag(slug="meta",        label="Meta",        lang="de"),
    ]
    created_tags: dict[str, Tag] = {}
    for tag in seed_tags:
        if not force and tag.slug in tag_slugs:
            # Tag existiert schon – referenzieren
            for et in existing_tags:
                if et.slug == tag.slug:
                    created_tags[tag.slug] = et
            continue
        db.add(tag)
        created_tags[tag.slug] = tag
        inserted["tags"] += 1

    await db.flush()

    # ---- Posts ----
    if force or not (await db.execute(select(Post).where(Post.slug == _POST_1_SLUG))).scalar_one_or_none():
        post1 = Post(
            id=_uid(),
            short_id=_short_id(),
            slug=_POST_1_SLUG,
            title=_POST_1_TITLE,
            body_md=_POST_1_MD,
            body_html=_md_to_html(_POST_1_MD),
            excerpt="Entdecke ArborPress – eine selbstgehostete Blogging-Plattform "
                    "mit WebAuthn-Login, ActivityPub und voller Kontrolle über deine Daten.",
            status=PostStatus.PUBLISHED,
            lang="de",
            published_at=_now(),
        )
        tags_for_post1 = [created_tags[s] for s in ("neuigkeiten", "meta") if s in created_tags]
        post1.tags = tags_for_post1
        db.add(post1)
        inserted["posts"] += 1

    if force or not (await db.execute(select(Post).where(Post.slug == _POST_2_SLUG))).scalar_one_or_none():
        post2 = Post(
            id=_uid(),
            short_id=_short_id(),
            slug=_POST_2_SLUG,
            title=_POST_2_TITLE,
            body_md=_POST_2_MD,
            body_html=_md_to_html(_POST_2_MD),
            excerpt="Alle unterstützten Formatierungen auf einen Blick: "
                    "Überschriften, Listen, Code-Blöcke, Tabellen und mehr.",
            status=PostStatus.PUBLISHED,
            lang="de",
            published_at=_now(),
        )
        tags_for_post2 = [created_tags[s] for s in ("tutorial", "meta") if s in created_tags]
        post2.tags = tags_for_post2
        db.add(post2)
        inserted["posts"] += 1

    # ---- System-Seiten ----
    date_str = _now().strftime("%B %Y")

    async def _upsert_page(slug: str, title: str, md: str, ptype: PageType) -> None:
        existing = (await db.execute(select(Page).where(Page.slug == slug))).scalar_one_or_none()
        if existing and not force:
            return
        md_rendered = md.replace("{{ date }}", date_str)
        if existing:
            existing.title = title
            existing.body_md = md_rendered
            existing.body_html = _md_to_html(md_rendered)
        else:
            page = Page(
                id=_uid(),
                slug=slug,
                title=title,
                body_md=md_rendered,
                body_html=_md_to_html(md_rendered),
                page_type=ptype,
                lang="de",
                is_published=True,
                show_in_footer=True,
                noindex=(ptype == PageType.IMPRESSUM),
            )
            db.add(page)
            inserted["pages"] += 1

    await _upsert_page(_IMPRESSUM_SLUG, _IMPRESSUM_TITLE, _IMPRESSUM_MD, PageType.IMPRESSUM)  # /page/imprint
    await _upsert_page(_PRIVACY_SLUG,   _PRIVACY_TITLE,   _PRIVACY_MD,  PageType.PRIVACY)    # /page/privacy

    await db.commit()
    log.info("Seed abgeschlossen: %s", inserted)
    return inserted

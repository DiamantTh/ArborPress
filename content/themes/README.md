# Eigene Themes für ArborPress

Dieser Ordner enthält benutzerdefinierte Themes, die beim Start von ArborPress automatisch
erkannt und im Admin-Bereich unter **Einstellungen → Theme** zur Auswahl angeboten werden.

## Verzeichnisstruktur

Jedes Theme benötigt einen eigenen Unterordner mit mindestens einer `theme.toml`:

```
themes/
  mein-theme/
    theme.toml          ← Pflicht: Metadaten und Konfiguration
    static/
      css/
        style.css       ← Haupt-CSS (wird via /static/themes/<id>/css/style.css eingebunden)
      js/
        app.js          ← Optionales JavaScript
      fonts/            ← Optionale Web-Fonts
      images/
        preview.png     ← Vorschaubild (empfohlen: 800×600 px)
    templates/          ← Optionale Template-Überschreibungen (nur öffentliche Seiten!)
      post.html
      index.html
```

## theme.toml – Minimales Beispiel

```toml
[theme]
id          = "mein-theme"          # Eindeutige ID (lowercase, nur a-z 0-9 -)
name        = "Mein Theme"
version     = "1.0.0"
author      = "Dein Name"
description = "Ein individuelles Theme für mein Blog."
license     = "MIT"

[theme.features]
dark_mode_toggle  = false
code_highlight    = true
reading_time      = true
table_of_contents = false

[assets]
css   = ["css/style.css"]     # Wird zusätzlich zu style.css eingebunden
js    = ["js/app.js"]
fonts = []

[overrides]
# Öffentliche Templates überschreiben (NIE Login/Sicherheits-Templates!)
templates = ["post.html", "index.html"]
```

## Wichtige Hinweise

- **Sicherheit**: Templates dürfen niemals Admin- oder Login-Seiten überschreiben.
  ArborPress blockiert Überschreibungen für geschützte Templates automatisch.
- **IDs**: Theme-IDs müssen eindeutig sein. Eingebaute IDs (`default`, `dark`, `minimal`)
  werden von eigenen Themes mit gleicher ID überschrieben.
- **CSS-Einbindung**: `static/css/style.css` wird immer automatisch als Haupt-CSS geladen,
  sofern die Datei existiert.
- **Aktivierung**: Nach dem Hinzufügen eines Themes den Server neu starten.
  Dann im Admin unter **Einstellungen → Theme** auswählen und speichern.

## Eingebaute Themes

ArborPress enthält folgende Built-in-Themes (unter `arborpress/themes/`):

| ID        | Name        | Beschreibung                      |
|-----------|-------------|-----------------------------------|
| `default` | Standard    | Helles, minimalistisches Layout   |
| `dark`    | Dunkel      | Dark-Mode-Variante                |
| `minimal` | Minimal     | Noch reduzierter, nur Typography  |

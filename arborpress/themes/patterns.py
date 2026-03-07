"""Hintergrundmuster-Definitionen für ArborPress-Themes.

Kachelbare SVG-Polygonmuster als data: URI.
Platzhalter:
  {c}  – URL-encodierte Farbe (z. B. %23818cf8 für #818cf8)
  {o}  – Deckkraft als float (z. B. 0.07)
"""

from __future__ import annotations

# SVG-Pattern-Templates (kachelfähig, inline data: URI kompatibel)
PATTERN_TEMPLATES: dict[str, str] = {
    "hexagon": (
        "<svg xmlns='http://www.w3.org/2000/svg' width='36' height='30'>"
        "<polygon points='18,1 31,8 31,22 18,29 5,22 5,8' "
        "fill='none' stroke='{c}' stroke-width='0.9' stroke-opacity='{o}'/></svg>"
    ),
    "diamond": (
        "<svg xmlns='http://www.w3.org/2000/svg' width='28' height='28'>"
        "<polygon points='14,1 27,14 14,27 1,14' "
        "fill='none' stroke='{c}' stroke-width='0.8' stroke-opacity='{o}'/></svg>"
    ),
    "diamond-lg": (
        "<svg xmlns='http://www.w3.org/2000/svg' width='42' height='42'>"
        "<polygon points='21,1 41,21 21,41 1,21' "
        "fill='none' stroke='{c}' stroke-width='0.9' stroke-opacity='{o}'/></svg>"
    ),
    "triangle": (
        "<svg xmlns='http://www.w3.org/2000/svg' width='28' height='24'>"
        "<polygon points='14,1 27,23 1,23' "
        "fill='none' stroke='{c}' stroke-width='0.9' stroke-opacity='{o}'/></svg>"
    ),
    "triangle-sm": (
        "<svg xmlns='http://www.w3.org/2000/svg' width='22' height='20'>"
        "<polygon points='11,1 21,19 1,19' "
        "fill='none' stroke='{c}' stroke-width='0.8' stroke-opacity='{o}'/></svg>"
    ),
    "chevron": (
        "<svg xmlns='http://www.w3.org/2000/svg' width='32' height='24'>"
        "<polyline points='1,1 16,12 1,23' fill='none' "
        "stroke='{c}' stroke-width='0.9' stroke-opacity='{o}' stroke-linejoin='round'/></svg>"
    ),
    "star": (
        "<svg xmlns='http://www.w3.org/2000/svg' width='38' height='37'>"
        "<polygon points='19,6 29,24 9,24' fill='none' "
        "stroke='{c}' stroke-width='0.8' stroke-opacity='{o}'/>"
        "<polygon points='19,30 29,12 9,12' fill='none' "
        "stroke='{c}' stroke-width='0.8' stroke-opacity='{o}'/></svg>"
    ),
    "dots": (
        "<svg xmlns='http://www.w3.org/2000/svg' width='24' height='24'>"
        "<circle cx='12' cy='12' r='1.2' fill='{c}' fill-opacity='{o}'/></svg>"
    ),
    "cross": (
        "<svg xmlns='http://www.w3.org/2000/svg' width='24' height='24'>"
        "<line x1='12' y1='1' x2='12' y2='23' "
        "stroke='{c}' stroke-width='0.6' stroke-opacity='{o}'/>"
        "<line x1='1' y1='12' x2='23' y2='12' "
        "stroke='{c}' stroke-width='0.6' stroke-opacity='{o}'/></svg>"
    ),
}

PATTERN_LABELS: dict[str, str] = {
    "auto":        "Theme-Standard",
    "none":        "Kein Muster",
    "hexagon":     "Hexagone",
    "diamond":     "Rauten",
    "diamond-lg":  "Rauten (groß)",
    "triangle":    "Dreiecke",
    "triangle-sm": "Dreiecke (klein)",
    "chevron":     "Chevron",
    "star":        "Sternmuster",
    "dots":        "Punkte",
    "cross":       "Kreuzgitter",
}

# Reihenfolge für Admin-UI
PATTERN_ORDER = [
    "auto", "none", "hexagon", "diamond", "diamond-lg",
    "triangle", "triangle-sm", "chevron", "star", "dots", "cross",
]


def make_pattern_url(pattern_id: str, color: str, opacity: float = 0.07) -> str:
    """Erzeugt eine ``data:image/svg+xml``-URL für das gegebene Pattern.

    Args:
        pattern_id: Schlüssel aus :data:`PATTERN_TEMPLATES` oder ``"none"``/``"auto"``.
                    ``"auto"`` gibt ``""`` zurück (Theme-eigene Variable bleibt aktiv).
        color:      Hex-Farbe, z. B. ``"#818cf8"`` oder ``"818cf8"``.
        opacity:    Deckkraft der Linien/Füllung (0–1).

    Returns:
        CSS-``url(...)``-Wert oder ``"none"`` oder leerer String.
    """
    if pattern_id == "auto":
        return ""   # kein Override – Theme-eigene --bg-pattern-Variable gilt
    if pattern_id == "none" or pattern_id not in PATTERN_TEMPLATES:
        return "none"
    rgb = color.lstrip("#")
    encoded_color = f"%23{rgb}"
    svg = PATTERN_TEMPLATES[pattern_id].format(c=encoded_color, o=opacity)
    return f'url("data:image/svg+xml,{svg}")'


def preview_svg(pattern_id: str, color: str = "#818cf8", size: int = 48) -> str:
    """Gibt ein ``<svg>``-Element für die Admin-UI-Vorschau zurück."""
    if pattern_id in ("auto", "none"):
        return (
            f"<svg xmlns='http://www.w3.org/2000/svg' width='{size}' height='{size}'>"
            "<rect width='100%' height='100%' fill='none'/>"
            "</svg>"
        )
    rgb = color.lstrip("#")
    encoded_color = f"%23{rgb}"
    template = PATTERN_TEMPLATES.get(pattern_id, "")
    # Einfaches Preview: Pattern dreimal kacheln → 3×3 Grid im SVG
    svg_tile = template.format(c=encoded_color, o=0.9)
    # Tile-Dimensions aus Template ablesen (sehr einfach)
    import re as _re
    m = _re.search(r"width='(\d+)'\s+height='(\d+)'", svg_tile)
    if not m:
        return svg_tile
    tw, th = int(m.group(1)), int(m.group(2))
    # Viewbox-Ausschnitt: 2×2 Kacheln
    vw, vh = tw * 2, th * 2
    inner = svg_tile.replace(
        f"width='{tw}' height='{th}'", ""
    ).replace("<svg xmlns='http://www.w3.org/2000/svg'", "").replace("</svg>", "")
    tiles = ""
    for row in range(3):
        for col in range(3):
            tiles += f"<g transform='translate({col * tw},{row * th})'>{inner}</g>"
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{size}' height='{size}' "
        f"viewBox='0 0 {vw} {vh}'>{tiles}</svg>"
    )

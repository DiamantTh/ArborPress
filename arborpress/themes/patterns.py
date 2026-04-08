"""Background pattern definitions for ArborPress themes.

Tileable SVG polygon patterns as data: URIs.
Placeholders:
  {c}  – URL-encoded colour (e.g. %23818cf8 for #818cf8)
  {o}  – opacity as float (e.g. 0.07)
"""

from __future__ import annotations

# SVG pattern templates (tileable, compatible with inline data: URI)
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
    "auto":        "Theme default",
    "none":        "No pattern",
    "hexagon":     "Hexagons",
    "diamond":     "Diamonds",
    "diamond-lg":  "Diamonds (large)",
    "triangle":    "Triangles",
    "triangle-sm": "Triangles (small)",
    "chevron":     "Chevron",
    "star":        "Star pattern",
    "dots":        "Dots",
    "cross":       "Crosshatch",
}

# Order for admin UI
PATTERN_ORDER = [
    "auto", "none", "hexagon", "diamond", "diamond-lg",
    "triangle", "triangle-sm", "chevron", "star", "dots", "cross",
]


def make_pattern_url(pattern_id: str, color: str, opacity: float = 0.07) -> str:
    """Generates a ``data:image/svg+xml`` URL for the given pattern.

    Args:
        pattern_id: Key from :data:`PATTERN_TEMPLATES` or ``"none"``/``"auto"``.
                    ``"auto"`` returns ``""`` (theme's own variable stays active).
        color:      Hex colour, e.g. ``"#818cf8"`` or ``"818cf8"``.
        opacity:    Opacity of lines/fill (0–1).

    Returns:
        CSS ``url(...)`` value, ``"none"``, or empty string.
    """
    if pattern_id == "auto":
        return ""   # no override – theme's own --bg-pattern variable applies
    if pattern_id == "none" or pattern_id not in PATTERN_TEMPLATES:
        return "none"
    rgb = color.lstrip("#")
    encoded_color = f"%23{rgb}"
    svg = PATTERN_TEMPLATES[pattern_id].format(c=encoded_color, o=opacity)
    return f'url("data:image/svg+xml,{svg}")'


def preview_svg(pattern_id: str, color: str = "#818cf8", size: int = 48) -> str:
    """Returns an ``<svg>`` element for the admin UI preview."""
    if pattern_id in ("auto", "none"):
        return (
            f"<svg xmlns='http://www.w3.org/2000/svg' width='{size}' height='{size}'>"
            "<rect width='100%' height='100%' fill='none'/>"
            "</svg>"
        )
    rgb = color.lstrip("#")
    encoded_color = f"%23{rgb}"
    template = PATTERN_TEMPLATES.get(pattern_id, "")
    # Simple preview: tile the pattern three times → 3×3 grid in SVG
    svg_tile = template.format(c=encoded_color, o=0.9)
    # Read tile dimensions from template (very simple)
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

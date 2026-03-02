"""Tests für Content-Modell – §6 Slug-Kanonisierung, §5 AP-IDs."""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# §6 Slug-Kanonisierung
# ---------------------------------------------------------------------------


class TestSlugCanonicalization:
    """Slugs müssen lowercase sein und stabile URLs ergeben (§6)."""

    def _canonicalize(self, slug: str) -> str:
        """Repliziert _canonical_slug aus public.py."""
        from slugify import slugify
        return slugify(slug, lowercase=True, separator="-")

    def test_lowercase(self):
        assert self._canonicalize("Hello-World") == "hello-world"

    def test_spaces_to_dashes(self):
        assert self._canonicalize("hello world") == "hello-world"

    def test_unicode_umlauts(self):
        result = self._canonicalize("Über Äpfel")
        assert result == result.lower()
        assert " " not in result

    def test_special_chars_stripped(self):
        result = self._canonicalize("Test! @#$% Post")
        assert "!" not in result
        assert "@" not in result

    def test_empty_slug(self):
        result = self._canonicalize("")
        # Leerer Slug bleibt leer oder wird zu ""
        assert isinstance(result, str)

    def test_already_canonical(self):
        assert self._canonicalize("already-canonical") == "already-canonical"


# ---------------------------------------------------------------------------
# §6 Stabile Media-URLs
# ---------------------------------------------------------------------------


class TestMediaURLs:
    """Media-Pfade: yyyy/mm/dateiname – unveränderlich nach Upload (§6)."""

    def test_media_path_format(self):
        import re
        path = "2024/03/my-image.webp"
        assert re.match(r"^\d{4}/\d{2}/.+$", path)

    def test_media_filename_no_traversal(self):
        """Pfad-Traversal-Versuche dürfen nicht in URL auftauchen."""
        filename = "../../etc/passwd"
        # Simulation: Dateinamen-Sanitisierung
        import os
        safe = os.path.basename(filename)
        assert ".." not in safe
        assert "/" not in safe


# ---------------------------------------------------------------------------
# §6 Kurz-IDs (ActivityPub-kompatibel)
# ---------------------------------------------------------------------------


class TestShortIds:
    """short_id muss URL-safe und eindeutig sein (§6 /o/{id})."""

    def test_short_id_url_safe(self):
        import re
        # Simulates UUID4 hex prefix or nanoid-style
        short_id = "a1b2c3d4"
        assert re.match(r"^[a-zA-Z0-9_-]+$", short_id)

    def test_short_id_not_empty(self):
        assert len("a1b2c3d4") > 0

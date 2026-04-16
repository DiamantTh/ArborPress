"""Shared break-glass password tools.

Focus:
- long passphrases over arbitrary symbol rules
- zxcvbn-backed quality checks
- keyboard-friendly generators for UI and CLI
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import secrets

from zxcvbn import zxcvbn

SAFE_RANDOM_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-._"

_XKCD_WORDS = (
    "acorn", "anchor", "apricot", "aster", "aurora", "badger", "bamboo", "bayou",
    "beacon", "birch", "blossom", "bluejay", "bramble", "breeze", "brook", "cabin",
    "cactus", "canary", "canyon", "caramel", "cedar", "comet", "coral", "copper",
    "cricket", "crimson", "dahlia", "dawn", "delta", "ember", "falcon", "fable",
    "fern", "field", "firefly", "fjord", "forest", "foxglove", "garden", "glacier",
    "granite", "grove", "harbor", "hazel", "heather", "heron", "horizon", "ivy",
    "juniper", "kettle", "lagoon", "lantern", "lavender", "leaf", "lemur", "lilac",
    "linen", "lotus", "maple", "marble", "meadow", "meteor", "mist", "monarch",
    "morning", "moss", "nectar", "north", "oasis", "olive", "opal", "orchard",
    "otter", "owl", "pebble", "pepper", "petal", "pine", "planet", "plume",
    "prairie", "quartz", "quill", "raven", "reef", "river", "robin", "saffron",
    "sage", "sailor", "sandbar", "scarlet", "shadow", "silver", "skyline", "solstice",
    "sparrow", "spruce", "starling", "stone", "stream", "summit", "sunrise", "sunset",
    "thicket", "thistle", "timber", "trail", "trident", "tulip", "valley", "velvet",
    "violet", "vista", "walnut", "waterfall", "willow", "windmill", "winter", "wren",
    "amber", "atlas", "barley", "bonfire", "caper", "cloud", "cobalt", "cosmos",
    "drift", "elm", "feather", "flint", "harvest", "island", "lark", "moonbeam",
    "nightfall", "ocean", "orchid", "pearl", "rainfall", "rosewood", "seabird", "starlight",
)


@dataclass(slots=True)
class PasswordAssessment:
    score: int
    warning: str
    suggestions: list[str]
    guesses_log10: float
    crack_times_display: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _clean_user_inputs(user_inputs: list[str] | tuple[str, ...] | None) -> list[str]:
    if not user_inputs:
        return []
    cleaned: list[str] = []
    for item in user_inputs:
        value = item.strip()
        if value:
            cleaned.append(value)
    return cleaned


def assess_password_strength(
    password: str,
    *,
    user_inputs: list[str] | tuple[str, ...] | None = None,
) -> PasswordAssessment:
    result = zxcvbn(password, user_inputs=_clean_user_inputs(user_inputs))
    feedback = result.get("feedback") or {}
    return PasswordAssessment(
        score=int(result.get("score", 0)),
        warning=str(feedback.get("warning") or ""),
        suggestions=[str(item) for item in feedback.get("suggestions") or []],
        guesses_log10=float(result.get("guesses_log10", 0.0)),
        crack_times_display=dict(result.get("crack_times_display") or {}),
    )


def validate_password_policy(
    password: str,
    *,
    min_length: int,
    max_length: int,
    min_score: int,
    user_inputs: list[str] | tuple[str, ...] | None = None,
) -> PasswordAssessment:
    length = len(password)
    if length < min_length:
        raise ValueError(f"Password must be at least {min_length} characters long.")
    if length > max_length:
        raise ValueError(f"Password must be at most {max_length} characters long.")
    if password != password.strip():
        raise ValueError("Password must not start or end with whitespace.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in password):
        raise ValueError("Password must not contain control characters.")

    assessment = assess_password_strength(password, user_inputs=user_inputs)
    if assessment.score < min_score:
        hint = assessment.warning or "; ".join(assessment.suggestions[:2])
        message = (
            f"Password is too easy to guess (zxcvbn score {assessment.score}/4, "
            f"need at least {min_score}/4)."
        )
        if hint:
            message = f"{message} {hint}"
        raise ValueError(message)
    return assessment


def generate_random_password(*, length: int = 24) -> str:
    if length < 16:
        raise ValueError("Random password length must be at least 16 characters.")
    return "".join(secrets.choice(SAFE_RANDOM_ALPHABET) for _ in range(length))


def generate_xkcd_passphrase(*, word_count: int = 5, delimiter: str = "-") -> str:
    if word_count < 4:
        raise ValueError("XKCD passphrases must contain at least 4 words.")
    if word_count > 10:
        raise ValueError("XKCD passphrases must contain at most 10 words.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in delimiter):
        raise ValueError("Delimiter must not contain control characters.")
    words = [secrets.choice(_XKCD_WORDS) for _ in range(word_count)]
    return delimiter.join(words)
"""Shared break-glass password tools.

Focus:
- strong random passwords and wordlist passphrases as equal generator options
- zxcvbn-backed quality checks
- keyboard-friendly output for UI and CLI
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import lru_cache
from importlib import resources
import secrets

from zxcvbn import zxcvbn

SAFE_RANDOM_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-._"

DEFAULT_DICEWARE_WORDS = 6
DEFAULT_RANDOM_PASSWORD_LENGTH = 24


@dataclass(slots=True)
class PasswordAssessment:
    score: int
    warning: str
    suggestions: list[str]
    guesses_log10: float
    crack_times_display: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@lru_cache(maxsize=1)
def _load_eff_large_words() -> tuple[str, ...]:
    wordlist_path = resources.files("arborpress.auth").joinpath("data/eff_large_wordlist.txt")
    words: list[str] = []
    with wordlist_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2:
                raise RuntimeError("Invalid EFF wordlist entry encountered.")
            _, word = parts
            words.append(word)
    if len(words) != 7776:
        raise RuntimeError("EFF large wordlist must contain exactly 7776 entries.")
    return tuple(words)


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
    check_hibp: bool = False,
    hibp_max_count: int = 0,
    hibp_timeout: float = 3.0,
    hibp_fail_open: bool = True,
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

    if check_hibp:
        # Local import to keep zxcvbn import path light and to avoid a
        # hard httpx dependency when HIBP is disabled.
        from arborpress.auth.hibp import enforce_hibp_policy

        enforce_hibp_policy(
            password,
            max_count=hibp_max_count,
            timeout=hibp_timeout,
            fail_open=hibp_fail_open,
        )
    return assessment


def generate_random_password(*, length: int = DEFAULT_RANDOM_PASSWORD_LENGTH) -> str:
    if length < 16:
        raise ValueError("Random password length must be at least 16 characters.")
    return "".join(secrets.choice(SAFE_RANDOM_ALPHABET) for _ in range(length))


def generate_diceware_passphrase(*, word_count: int = DEFAULT_DICEWARE_WORDS, delimiter: str = "-") -> str:
    if word_count < 4:
        raise ValueError("Diceware passphrases must contain at least 4 words.")
    if word_count > 10:
        raise ValueError("Diceware passphrases must contain at most 10 words.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in delimiter):
        raise ValueError("Delimiter must not contain control characters.")
    words = [secrets.choice(_load_eff_large_words()) for _ in range(word_count)]
    return delimiter.join(words)


def generate_xkcd_passphrase(*, word_count: int = DEFAULT_DICEWARE_WORDS, delimiter: str = "-") -> str:
    """Backward-compatible alias for the Diceware-style wordlist generator."""
    return generate_diceware_passphrase(word_count=word_count, delimiter=delimiter)
"""Conservative report redaction, not a complete secret-detection guarantee."""

import re

_SENSITIVE_KEYS = frozenset(
    {
        "token",
        "password",
        "secret",
        "api_key",
        "client_secret",
        "authorization",
        "private_key",
        "openai_api_key",
        "anthropic_api_key",
    }
)


def sensitive_key(key: object) -> bool:
    return isinstance(key, str) and key.casefold().replace("-", "_") in _SENSITIVE_KEYS


_PATTERNS = [
    re.compile(
        r"""(?i)(?:token|api[_-]?key|password|secret|authorization)["']?\s*[:=]\s*["'][^"'\r\n]{8,}["']"""
    ),
    re.compile(
        r"(?im)^\s*(?:token|api[_-]?key|password|secret|authorization)\s*[:=]\s*[A-Za-z0-9_/-]{12,}\s*$"
    ),
    re.compile(r"(?:gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{12,})"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*"),
    re.compile(r"https?://[^/\s]+:[^@\s]+@[^\s]+"),
]


def sanitize(text: str) -> tuple[str, bool]:
    redacted = False
    for pattern in _PATTERNS:
        text, count = pattern.subn("[REDACTED]", text)
        redacted |= count > 0
    # Strip terminal controls; preserve newlines/tabs as quoted data in renderers.
    text = "".join(
        c if c in "\n\t" or (ord(c) >= 32 and not 127 <= ord(c) < 160) else f"\\u{ord(c):04x}"
        for c in text
    )
    return text, redacted

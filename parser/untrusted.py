"""Detection of instruction-like text inside log fields.

Log fields such as userAgent, roleSessionName, tags or descriptions are
attacker-controlled. IdentityTrace never executes them; this module only
*labels* them so analysts and the AI layer know a field tries to talk to a
reader. The label is informational and never changes detection results.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

_PATTERNS = [
    r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)",
    r"disregard\s+(all\s+|the\s+)?(previous|prior|above|instructions|rules)",
    r"\byou\s+are\s+now\b",
    r"\bsystem\s*prompt\b",
    r"^\s*(system|assistant)\s*:",
    r"</?\s*(system|instructions?|untrusted_log_data)\s*>",
    r"mark\s+(this|the|all)\s+(incident|alert|finding|event)s?\s+as\s+(benign|resolved|false\s+positive|closed)",
    r"(delete|remove|suppress|close)\s+(all\s+)?(findings|alerts|incidents|logs)",
    r"do\s+not\s+(report|alert|flag|escalate)",
    r"\bthis\s+(change|activity)\s+is\s+(approved|authorized|legitimate)\b.*\b(close|ignore|benign)",
]
_REGEX = re.compile("|".join(f"(?:{p})" for p in _PATTERNS), re.IGNORECASE | re.MULTILINE)


def looks_like_instruction(text: str) -> bool:
    return bool(_REGEX.search(text))


def _walk(value: Any, path: str, depth: int) -> Iterator[tuple[str, str]]:
    if depth > 8:
        return
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, inner in value.items():
            yield from _walk(inner, f"{path}.{key}" if path else str(key), depth + 1)
    elif isinstance(value, list):
        for i, inner in enumerate(value[:200]):
            yield from _walk(inner, f"{path}[{i}]", depth + 1)


def find_instruction_like_fields(record: Any) -> list[str]:
    """Return JSON paths of string fields that contain instruction-like text."""
    return [path for path, text in _walk(record, "", 0) if looks_like_instruction(text)]

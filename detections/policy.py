"""Static analysis of IAM policy documents found in request parameters."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import unquote

_ACCOUNT_RE = re.compile(r"arn:aws:iam::(\d{12}):")


def load_policy(document: Any) -> dict[str, Any] | None:
    if isinstance(document, dict):
        return document
    if not isinstance(document, str) or not document.strip():
        return None
    for candidate in (document, unquote(document)):
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(policy: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not policy:
        return []
    return [s for s in _as_list(policy.get("Statement")) if isinstance(s, dict)]


def broad_grants(policy: dict[str, Any] | None, sensitive_services: set[str]) -> list[str]:
    """Return human-readable reasons why a policy grants unusually wide permissions."""
    reasons: list[str] = []
    for st in statements(policy):
        if st.get("Effect") != "Allow":
            continue
        resources = [str(r) for r in _as_list(st.get("Resource"))]
        wildcard_resource = "*" in resources or not resources
        if "NotAction" in st:
            reasons.append("Allow mit NotAction (erlaubt alles außer einer Ausnahmeliste)")
            continue
        for action in (str(a) for a in _as_list(st.get("Action"))):
            if action == "*":
                reasons.append("Action \"*\" (alle Aktionen aller Dienste)")
            elif action.endswith(":*") and action.split(":", 1)[0].lower() in sensitive_services and wildcard_resource:
                reasons.append(f"Action \"{action}\" auf Resource \"*\"")
    return sorted(set(reasons))


def has_full_admin(policy: dict[str, Any] | None) -> bool:
    return any(r.startswith("Action \"*\"") or r.startswith("Allow mit NotAction") for r in broad_grants(policy, set()))


def untrusted_principals(policy: dict[str, Any] | None, trusted_accounts: set[str]) -> list[str]:
    """Principals in a trust policy that are public or belong to untrusted accounts."""
    found: list[str] = []
    for st in statements(policy):
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal")
        if principal == "*":
            found.append("*")
            continue
        if not isinstance(principal, dict):
            continue
        for value in _as_list(principal.get("AWS")):
            value = str(value)
            if value == "*":
                found.append("*")
                continue
            match = _ACCOUNT_RE.search(value)
            account = match.group(1) if match else (value if value.isdigit() else None)
            if account and account not in trusted_accounts:
                found.append(value)
    return found

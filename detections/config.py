from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

PRIVILEGED_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/AWSOrganizationsFullAccess",
}

# Services where wildcard permissions effectively mean control over identities or evidence.
SENSITIVE_SERVICES = {"iam", "sts", "organizations", "kms", "cloudtrail", "secretsmanager", "guardduty", "config"}


@dataclass
class DetectionConfig:
    privileged_managed_policies: set[str] = field(default_factory=lambda: set(PRIVILEGED_MANAGED_POLICIES))
    sensitive_services: set[str] = field(default_factory=lambda: set(SENSITIVE_SERVICES))
    # Principals that are sensitive regardless of observed activity (entity keys, e.g. "user:break-glass-admin").
    sensitive_principals: set[str] = field(default_factory=set)
    # Name fragments that mark a user or role as sensitive.
    sensitive_name_patterns: list[str] = field(default_factory=lambda: ["admin", "break-glass", "breakglass", "root"])
    # Accounts trusted in role trust policies. Empty = only the account the event happened in.
    trusted_account_ids: set[str] = field(default_factory=set)
    burst_window_minutes: int = 30
    burst_min_events: int = 3
    burst_min_rules: int = 2
    # Correlation
    incident_split_hours: float = 6.0
    context_before_minutes: int = 120
    context_after_minutes: int = 360

    @classmethod
    def from_file(cls, path: str | Path) -> "DetectionConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        cfg = cls()
        for key, value in data.items():
            if not hasattr(cfg, key):
                raise ValueError(f"Unknown config key: {key}")
            current = getattr(cfg, key)
            setattr(cfg, key, set(value) if isinstance(current, set) else value)
        return cfg

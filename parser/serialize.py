"""JSON serialization helpers for dataclasses with datetimes."""

from __future__ import annotations

import dataclasses
from datetime import datetime
from enum import Enum
from typing import Any


def to_jsonable(value: Any, *, include_raw: bool = True) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        out = {}
        for f in dataclasses.fields(value):
            if f.name == "raw" and not include_raw:
                continue
            out[f.name] = to_jsonable(getattr(value, f.name), include_raw=include_raw)
        return out
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): to_jsonable(v, include_raw=include_raw) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v, include_raw=include_raw) for v in value]
    return value

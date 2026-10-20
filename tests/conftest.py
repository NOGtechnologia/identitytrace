from __future__ import annotations

import json
from itertools import count
from pathlib import Path
from typing import Any

import pytest

from correlation.pipeline import analyze

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "examples" / "synthetic_cloudtrail.json"
TRUTH = ROOT / "examples" / "ground_truth.json"
ACCOUNT = "111122223333"
_ids = count(1)


def user(name: str, key: str = "AKIATESTKEY00000001") -> dict[str, Any]:
    return {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}", "accountId": ACCOUNT,
            "accessKeyId": key, "userName": name}


def role(name: str, session: str = "s1") -> dict[str, Any]:
    return {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{name}/{session}",
            "accountId": ACCOUNT, "accessKeyId": "ASIATEST",
            "sessionContext": {"sessionIssuer": {"type": "Role", "userName": name,
                                                 "arn": f"arn:aws:iam::{ACCOUNT}:role/{name}"}}}


def rec(name: str, identity: dict[str, Any], *, source: str = "iam.amazonaws.com", time: str = "2026-09-15T12:00:00Z",
        params: dict[str, Any] | None = None, response: dict[str, Any] | None = None, ip: str = "10.0.0.1",
        error: str | None = None, read_only: bool = False, **extra: Any) -> dict[str, Any]:
    record = {"eventVersion": "1.10", "eventID": f"evt-{next(_ids)}", "eventTime": time, "eventSource": source,
              "eventName": name, "userIdentity": identity, "sourceIPAddress": ip, "userAgent": "test",
              "requestParameters": params, "responseElements": response, "readOnly": read_only,
              "recipientAccountId": ACCOUNT}
    if error:
        record["errorCode"] = error
    record.update(extra)
    return record


def policy(actions: Any, resource: str = "*") -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}]})


@pytest.fixture(scope="session")
def demo_result():
    return analyze(DATASET)


@pytest.fixture(scope="session")
def truth() -> dict[str, Any]:
    return json.loads(TRUTH.read_text(encoding="utf-8"))

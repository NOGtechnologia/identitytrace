"""The Claude adapter is tested with a fake client; no network, no API key."""

import json
from types import SimpleNamespace

import anthropic
import pytest

from ai.assistant import OUTPUT_SCHEMA, AnalysisUnavailable, ClaudeAnalyst, analyze_incident


class FakeMessages:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def make_analyst(response):
    analyst = object.__new__(ClaudeAnalyst)
    analyst._anthropic = anthropic
    analyst.model = "claude-opus-5-5"
    analyst.name = "anthropic:claude-opus-5-5"
    analyst.client = SimpleNamespace(beta=SimpleNamespace(messages=FakeMessages(response)))
    return analyst


def response(text, stop_reason="end_turn"):
    return SimpleNamespace(stop_reason=stop_reason, content=[SimpleNamespace(type="text", text=text)])


def test_request_shape_and_validation(demo_result):
    inc = next(i for i in demo_result.incidents if "IT-006" in i.rule_ids)
    eid = inc.timeline[0].event_id
    body = {"summary": "s", "facts": [{"text": "f", "event_ids": [eid, "fake"]}], "hypotheses": [],
            "uncertainties": [], "investigation_steps": [], "remediation_suggestions": [], "manipulation_indicators": []}
    analyst = make_analyst(response(json.dumps(body)))
    out = analyze_incident(demo_result, inc.incident_id, analyst)
    call = analyst.client.beta.messages.calls[0]
    assert call["model"] == "claude-opus-5-5"
    assert call["output_config"]["format"]["schema"] == OUTPUT_SCHEMA
    assert "tools" not in call, "the model must not get tools"
    assert "<untrusted_log_data>" in call["messages"][0]["content"]
    assert out["facts"] == [{"text": "f", "event_ids": [eid]}]
    assert out["provider"] == "anthropic:claude-opus-5-5"


@pytest.mark.parametrize("resp, message", [
    (response("", "refusal"), "abgelehnt"),
    (response("{", "max_tokens"), "abgeschnitten"),
    (response("kein json"), "kein gültiges JSON"),
])
def test_failures_become_analysis_unavailable(demo_result, resp, message):
    inc = demo_result.incidents[0]
    with pytest.raises(AnalysisUnavailable, match=message):
        analyze_incident(demo_result, inc.incident_id, make_analyst(resp))

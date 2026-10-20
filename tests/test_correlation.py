from detections.models import Severity


def _incident_with_rules(result, *rules):
    return [i for i in result.incidents if set(rules) <= set(i.rule_ids)]


def test_account_takeover_chain_is_one_incident(demo_result, truth):
    s08 = {lab["event_id"] for lab in truth["labels"] if lab["scenario"] == "S08"}
    matches = [i for i in demo_result.incidents if s08 & {t.event_id for t in i.timeline}]
    assert len(matches) == 1, "S08 must not be split into several incidents"
    inc = matches[0]
    assert s08 <= {t.event_id for t in inc.timeline}, "all attacker steps incl. secret/data access belong to the timeline"
    assert {"IT-001", "IT-002", "IT-003", "IT-004", "IT-006"} <= set(inc.rule_ids)
    assert inc.severity == Severity.CRITICAL
    assert "Rechteausweitung → neuer Zugang → Zugriff auf sensible Daten" in inc.patterns
    assert "user:backup-operator" in inc.actors and "user:ci-deployer" in inc.actors


def test_timeline_is_chronological_and_marks_triggers(demo_result):
    for inc in demo_result.incidents:
        times = [t.timestamp for t in inc.timeline]
        assert times == sorted(times)
        assert any(t.kind == "detection" for t in inc.timeline)


def test_facts_inferences_gaps_are_separated(demo_result):
    inc = _incident_with_rules(demo_result, "IT-003", "IT-006")[0]
    timeline_ids = {t.event_id for t in inc.timeline}
    assert all(f.event_ids and set(f.event_ids) <= timeline_ids for f in inc.facts)
    assert all(i.confidence in {"hoch", "mittel", "niedrig"} for i in inc.inferences)
    key_inference = [i for i in inc.inferences if "AKIA5BACKUPOPNEW077" in i.text]
    assert key_inference and "GetSecretValue" in key_inference[0].text
    new_ip = [i for i in inc.inferences if "203.0.113.77" in i.text]
    assert new_ip, "an unusual source IP for the actor must be called out"
    assert any("PutEventSelectors" in g.text for g in inc.gaps), "logging change must be listed as a blind spot"


def test_gap_in_data_is_reported_for_overlapping_incident(demo_result):
    # S04 stops logging at 14:05; the dataset has a gap starting late that evening (context window: +6 h).
    inc = _incident_with_rules(demo_result, "IT-004")
    texts = " ".join(g.text for i in inc for g in i.gaps)
    assert "unvollständig oder fehlerhaft" in texts


def test_failed_attempt_is_called_out(demo_result):
    inc = [i for i in demo_result.incidents if "user:intern-readonly" in i.actors][0]
    assert any("abgelehnt" in s.text for s in inc.inferences)


def test_separate_scenarios_stay_separate(demo_result):
    actors = [tuple(i.actors) for i in demo_result.incidents]
    assert len(actors) == len(set(actors))
    assert len(demo_result.incidents) == 9

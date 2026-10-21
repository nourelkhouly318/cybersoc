import pytest

from cybersoc.common.schema import CaseFile, Evidence, Finding, Verdict
from cybersoc.critic.rules import review


def _ev():
    return [Evidence(source="unsw-nb15", ref="flow:42", detail="sttl=254, 30 dst ports in 1s")]


def test_confidence_bounds():
    with pytest.raises(ValueError):
        Finding(agent="a", claim="x", verdict=Verdict.MALICIOUS, confidence=1.5)


def test_unsupported_malicious_claim_is_rejected():
    f = Finding(agent="anomaly", claim="port scan", verdict=Verdict.MALICIOUS, confidence=0.9)
    case = review(CaseFile(alert_id="a1", findings=[f]))
    assert case.accepted_findings() == []
    assert "no evidence" in case.reviews[0].reason


def test_low_confidence_is_rejected():
    f = Finding(agent="ti", claim="known bad IP", verdict=Verdict.SUSPICIOUS,
                confidence=0.3, evidence=_ev())
    case = review(CaseFile(alert_id="a2", findings=[f]))
    assert case.accepted_findings() == []


def test_supported_finding_is_accepted():
    f = Finding(agent="network", claim="port scan", verdict=Verdict.MALICIOUS,
                confidence=0.8, evidence=_ev(), mitre_techniques=["T1046"])
    case = review(CaseFile(alert_id="a3", findings=[f]))
    assert case.accepted_findings() == [f]


def test_conflict_is_flagged_for_escalation():
    bad = Finding(agent="anomaly", claim="scan", verdict=Verdict.MALICIOUS,
                  confidence=0.8, evidence=_ev())
    ok = Finding(agent="ti", claim="internal scanner", verdict=Verdict.BENIGN, confidence=0.9)
    case = review(CaseFile(alert_id="a4", findings=[bad, ok]))
    assert all("escalate" in r.reason for r in case.reviews)
    assert case.requires_human_approval

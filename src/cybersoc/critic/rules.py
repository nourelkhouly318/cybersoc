"""First, deterministic layer of the verification/critic agent.

Before any LLM-based challenge, the critic rejects findings that fail cheap,
checkable rules. The LLM critic (Milestone II) runs only on what survives.
"""
from __future__ import annotations

from cybersoc.common.schema import CaseFile, CriticReview, Verdict

MIN_CONFIDENCE = 0.5


def review(case: CaseFile) -> CaseFile:
    verdicts = {f.verdict for f in case.findings if f.verdict is not Verdict.INCONCLUSIVE}
    conflicting = Verdict.BENIGN in verdicts and Verdict.MALICIOUS in verdicts
    for f in case.findings:
        if not f.is_supported:
            case.reviews.append(CriticReview(f.id, False, "non-benign claim cites no evidence"))
        elif f.verdict is not Verdict.BENIGN and f.confidence < MIN_CONFIDENCE:
            case.reviews.append(
                CriticReview(f.id, False, f"confidence {f.confidence:.2f} below {MIN_CONFIDENCE}")
            )
        elif conflicting:
            case.reviews.append(
                CriticReview(f.id, True, "accepted, but agents disagree: escalate to analyst")
            )
        else:
            case.reviews.append(CriticReview(f.id, True, "evidence present"))
    return case

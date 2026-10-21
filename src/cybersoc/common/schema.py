"""Shared message schema between CyberSOC agents.

Every specialist agent returns `Finding` objects. The orchestrator merges them
into a `CaseFile`, and the critic agent reviews the case file before anything
reaches the analyst. Keeping one schema is what lets the critic check whether a
conclusion is actually backed by evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Evidence:
    """A pointer to raw data that supports a claim (flow id, log line, IOC hit)."""

    source: str  # e.g. "unsw-nb15", "zeek-conn", "threat-intel:abuseipdb"
    ref: str  # record id / log offset / indicator value
    detail: str  # short human-readable description of what the record shows


@dataclass
class Finding:
    agent: str
    claim: str
    verdict: Verdict
    confidence: float  # 0..1, agent's own estimate
    severity: Severity = Severity.INFO
    evidence: list[Evidence] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)  # e.g. ["T1046"]
    meta: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid4().hex[:12])
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")

    @property
    def is_supported(self) -> bool:
        """A non-benign claim with no evidence is unsupported by definition."""
        return self.verdict is Verdict.BENIGN or len(self.evidence) > 0


@dataclass
class CriticReview:
    finding_id: str
    accepted: bool
    reason: str


@dataclass
class CaseFile:
    alert_id: str
    findings: list[Finding] = field(default_factory=list)
    reviews: list[CriticReview] = field(default_factory=list)
    final_verdict: Verdict = Verdict.INCONCLUSIVE
    risk_score: float = 0.0  # 0..100
    recommended_actions: list[str] = field(default_factory=list)
    requires_human_approval: bool = True  # high-impact actions always need sign-off

    def accepted_findings(self) -> list[Finding]:
        rejected = {r.finding_id for r in self.reviews if not r.accepted}
        return [f for f in self.findings if f.id not in rejected]

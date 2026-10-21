"""Base class for specialist agents.

Each MVP agent (network/log analysis, anomaly detection, threat intelligence,
incident investigation) subclasses `Agent` and implements `analyze`. The LLM
call, if any, happens inside `analyze`; the orchestration framework only sees
the typed `Finding` output.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from cybersoc.common.schema import Finding


class Agent(ABC):
    name: str = "agent"

    @abstractmethod
    def analyze(self, alert: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        """Inspect one alert plus shared context; return zero or more findings."""

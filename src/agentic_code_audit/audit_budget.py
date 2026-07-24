from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class AuditMode(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"

    @classmethod
    def normalize(cls, value: str | None) -> "AuditMode":
        raw = (value or cls.STANDARD.value).strip().lower()
        if raw == "full":
            raw = cls.STANDARD.value
        try:
            return cls(raw)
        except ValueError as exc:
            allowed = ", ".join(item.value for item in cls)
            raise ValueError(f"invalid audit mode '{value}', expected one of: {allowed}") from exc


@dataclass(frozen=True)
class AuditBudget:
    """Mode budget.

    max_anchors, max_slices, max_candidates and max_findings are legacy API
    fields. A value of 0 means mining evidence collection and final finding
    output are unbounded; LLM and dynamic-verification budgets still apply.
    """

    mode: str
    max_anchors: int
    max_slices: int
    max_candidates: int
    max_findings: int
    max_llm_calls: int
    enable_config_audit: bool
    weak_signal_min_confidence: float
    max_dynamic_verifications: int = 0

    @classmethod
    def for_mode(cls, value: str | None) -> "AuditBudget":
        mode = AuditMode.normalize(value)
        if mode == AuditMode.QUICK:
            return cls(
                mode=mode.value,
                max_anchors=0,
                max_slices=0,
                max_candidates=0,
                max_findings=0,
                max_llm_calls=8,
                enable_config_audit=False,
                weak_signal_min_confidence=0.55,
                max_dynamic_verifications=2,
            )
        if mode == AuditMode.DEEP:
            return cls(
                mode=mode.value,
                max_anchors=0,
                max_slices=0,
                max_candidates=0,
                max_findings=0,
                max_llm_calls=60,
                enable_config_audit=False,
                weak_signal_min_confidence=0.35,
                max_dynamic_verifications=10,
            )
        return cls(
            mode=AuditMode.STANDARD.value,
            max_anchors=0,
            max_slices=0,
            max_candidates=0,
            max_findings=0,
            max_llm_calls=20,
            enable_config_audit=False,
            weak_signal_min_confidence=0.45,
            max_dynamic_verifications=5,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BudgetUsage:
    anchors: int = 0
    anchors_before_budget: int = 0
    config_anchors_suppressed: int = 0
    weak_signal_anchors_suppressed: int = 0
    slices: int = 0
    candidates: int = 0
    aggregated_candidates: int = 0
    findings: int = 0
    llm_calls: int = 0
    config_audit_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

"""Schemas components extracted from the original Moirae runner."""
from typing import Literal
from pydantic import BaseModel, Field


RiskLevel = Literal["none", "low", "medium", "high", "unknown"]


class StageFinding(BaseModel):
    label: str = Field(description="Short finding label appropriate to the current Agent's evidence role.")
    severity: RiskLevel = Field(description="Finding severity.")
    evidence: str = Field(description="Concrete observed evidence with identifiers available to the current Agent.")
    interpretation: str = Field(description="Why this evidence matters for benign/malicious judgment.")


class VisionAgentResult(BaseModel):
    sample_hash: str
    screens_reviewed: list[int] = Field(default_factory=list)
    phishing_or_impersonation_signals: list[StageFinding] = Field(default_factory=list)
    coercive_or_deceptive_ui_signals: list[StageFinding] = Field(default_factory=list)
    benign_ui_signals: list[str] = Field(default_factory=list)
    risk_level: RiskLevel
    summary: str


class UIEventAgentResult(BaseModel):
    sample_hash: str
    screens_or_events_reviewed: list[str] = Field(default_factory=list)
    state_event_findings: list[StageFinding] = Field(default_factory=list)
    suspicious_transitions: list[str] = Field(default_factory=list)
    permission_or_external_focus_findings: list[str] = Field(default_factory=list)
    silent_or_deceptive_trigger_candidates: list[str] = Field(default_factory=list)
    risk_level: RiskLevel
    summary: str


class APIAgentResult(BaseModel):
    sample_hash: str
    events_reviewed: list[int] = Field(default_factory=list)
    api_findings: list[StageFinding] = Field(default_factory=list)
    high_risk_api_calls: list[str] = Field(default_factory=list)
    data_leakage_or_abuse_signals: list[str] = Field(default_factory=list)
    benign_or_empty_trace_notes: list[str] = Field(default_factory=list)
    risk_level: RiskLevel
    summary: str


class AndroidMalwareAnalysisOutput(BaseModel):
    apk_name: str = Field(description="APK name or sample hash.")
    is_malicious: bool = Field(description="Whether the APK should be judged malicious.")
    threat_category: str = Field(
        alias="threat_category(Malicious family)",
        description=(
            "Malicious family/category such as SMS, Banking, Adware, "
            "Ransomware, Scareware, Trojan, another evidence-grounded family, or Benign."
        ),
    )
    confidence_score: int = Field(description="Confidence score from 0 to 100.", ge=0, le=100)
    reason: str = Field(description="Concise final reason grounded in observed evidence.")
    evidence_chain: list[str] = Field(
        description="Numbered evidence chain, e.g. '1. [Intent Mismatch] ...'.",
        min_length=1,
    )



from typing import Literal

from pydantic import BaseModel, Field


SeverityLevel = Literal[
    "informational",
    "low",
    "medium",
    "high",
    "critical",
]

ConfidenceLevel = Literal[
    "low",
    "medium",
    "high",
]


class EvidenceItem(BaseModel):
    title: str = Field(
        description="Short title describing the important evidence."
    )
    description: str = Field(
        description="Explanation of why this evidence matters."
    )
    event_references: list[str] = Field(
        default_factory=list,
        description=(
            "Timestamps, line numbers, event IDs, usernames, IP addresses, "
            "hostnames, or other references found directly in the supplied data."
        ),
    )


class MitreTechnique(BaseModel):
    technique_id: str = Field(
        description=(
            "MITRE ATT&CK technique identifier when reasonably supported, "
            "or 'Unconfirmed' when there is insufficient evidence."
        )
    )
    technique_name: str
    explanation: str


class IncidentAssessment(BaseModel):
    title: str = Field(
        description="Concise incident title."
    )

    severity: SeverityLevel

    confidence: ConfidenceLevel

    summary: str = Field(
        description=(
            "Evidence-grounded summary of what may have happened. "
            "Clearly distinguish observations from conclusions."
        )
    )

    timeline: list[str] = Field(
        default_factory=list,
        description="Chronological sequence of important observed events.",
    )

    evidence: list[EvidenceItem] = Field(
        default_factory=list,
    )

    possible_attack_path: list[str] = Field(
        default_factory=list,
        description=(
            "Likely sequence of attacker actions. Every uncertain action "
            "must be presented as a possibility, not a confirmed fact."
        ),
    )

    mitre_attack: list[MitreTechnique] = Field(
        default_factory=list,
    )

    affected_assets: list[str] = Field(
        default_factory=list,
    )

    affected_accounts: list[str] = Field(
        default_factory=list,
    )

    indicators: list[str] = Field(
        default_factory=list,
        description=(
            "Relevant IP addresses, domains, file hashes, processes, "
            "commands, usernames, or hostnames present in the input."
        ),
    )

    investigation_steps: list[str] = Field(
        default_factory=list,
    )

    containment_actions: list[str] = Field(
        default_factory=list,
    )

    limitations: list[str] = Field(
        default_factory=list,
        description=(
            "Missing context, uncertain conclusions, and information "
            "needed to confirm the assessment."
        ),
    )
from __future__ import annotations

from django.db import transaction

from analyzer.models import Investigation
from analyzer.schemas import IncidentAssessment


class InvestigationService:
    """
    Handles creation of saved ThreatLens investigations.
    """

    @staticmethod
    @transaction.atomic
    def create_investigation(
        *,
        raw_events: str,
        assessment: IncidentAssessment,
    ) -> Investigation:
        normalized_events = raw_events.strip()

        if not normalized_events:
            raise ValueError(
                "Raw security events are required."
            )

        return Investigation.objects.create(
            title=assessment.title,
            severity=assessment.severity,
            confidence=assessment.confidence,
            summary=assessment.summary,
            raw_events=normalized_events,
            analysis=assessment.model_dump(mode="json"),
        )
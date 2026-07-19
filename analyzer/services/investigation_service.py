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
        input_source: str = Investigation.InputSource.PASTED,
        source_filename: str = "",
        source_content_type: str = "",
        source_size_bytes: int | None = None,
        source_event_count: int | None = None,
    ) -> Investigation:
        normalized_events = raw_events.strip()

        if not normalized_events:
            raise ValueError(
                "Raw security events are required."
            )

        valid_input_sources = {
            choice
            for choice, _label
            in Investigation.InputSource.choices
        }

        if input_source not in valid_input_sources:
            raise ValueError(
                "Invalid investigation input source."
            )

        return Investigation.objects.create(
            title=assessment.title,
            severity=assessment.severity,
            confidence=assessment.confidence,
            summary=assessment.summary,
            raw_events=normalized_events,
            input_source=input_source,
            source_filename=source_filename,
            source_content_type=source_content_type,
            source_size_bytes=source_size_bytes,
            source_event_count=source_event_count,
            analysis=assessment.model_dump(mode="json"),
        )
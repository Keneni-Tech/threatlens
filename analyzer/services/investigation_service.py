from __future__ import annotations

from dataclasses import dataclass

from django.core.files.uploadedfile import UploadedFile
from django.db import transaction

from analyzer.models import Investigation
from analyzer.schemas import IncidentAssessment
from analyzer.services.event_file_parser import EventFileParser


@dataclass(frozen=True, slots=True)
class InvestigationInput:
    raw_events: str
    input_source: str
    source_filename: str = ""
    source_content_type: str = ""
    source_size_bytes: int | None = None
    source_event_count: int | None = None


class InvestigationService:
    """
    Handles creation of saved ThreatLens investigations.
    """

    @staticmethod
    def prepare_input(
        *,
        pasted_events: str,
        uploaded_file: UploadedFile | None,
    ) -> InvestigationInput:
        if uploaded_file is not None:
            parsed_file = EventFileParser().parse(uploaded_file)

            return InvestigationInput(
                raw_events=parsed_file.text,
                input_source=(
                    Investigation.InputSource.UPLOADED_FILE
                ),
                source_filename=parsed_file.filename,
                source_content_type=parsed_file.content_type,
                source_size_bytes=parsed_file.size_bytes,
                source_event_count=parsed_file.event_count,
            )

        normalized_events = pasted_events.strip()

        if not normalized_events:
            raise ValueError("Raw security events are required.")

        event_count = sum(
            1
            for line in normalized_events.splitlines()
            if line.strip()
        )

        return InvestigationInput(
            raw_events=normalized_events,
            input_source=Investigation.InputSource.PASTED,
            source_event_count=event_count,
        )

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

        investigation = Investigation(
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

        investigation.full_clean()
        investigation.save()

        return investigation

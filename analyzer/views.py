from __future__ import annotations


import re
from io import BytesIO

from django.http import FileResponse

import logging

from django.db.models import Count
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods

from analyzer.forms import IncidentAnalysisForm, SAMPLE_SECURITY_EVENTS
from analyzer.models import Investigation
from analyzer.services.incident_analyzer import (
    IncidentAnalysisError,
    IncidentAnalyzer,
)
from analyzer.services.investigation_service import (
    InvestigationService,
)


from analyzer.services.pdf_report_service import (
    InvestigationPDFReportService,
    PDFReportError,
)

from analyzer.services.event_file_parser import (
    EventFileParseError,
    EventFileParser,
    EventFileValidationError,
)

logger = logging.getLogger(__name__)


@require_http_methods(["GET"])
def investigation_list(request: HttpRequest) -> HttpResponse:
    investigations = Investigation.objects.all()

    severity_counts = {
        item["severity"]: item["total"]
        for item in (
            Investigation.objects
            .values("severity")
            .annotate(total=Count("id"))
        )
    }

    context = {
        "investigations": investigations,
        "total_investigations": investigations.count(),
        "critical_count": severity_counts.get(
            Investigation.Severity.CRITICAL,
            0,
        ),
        "high_count": severity_counts.get(
            Investigation.Severity.HIGH,
            0,
        ),
        "medium_count": severity_counts.get(
            Investigation.Severity.MEDIUM,
            0,
        ),
    }

    return render(
        request,
        "analyzer/investigation_list.html",
        context,
    )

@require_http_methods(["GET", "POST"])
def investigation_create(
    request: HttpRequest,
) -> HttpResponse:
    analysis_error = None

    if request.method == "POST":
        form = IncidentAnalysisForm(
            request.POST,
            request.FILES,
        )

        if form.is_valid():
            pasted_events = form.cleaned_data[
                "security_events"
            ]

            uploaded_file = form.cleaned_data[
                "event_file"
            ]

            input_source = (
                Investigation.InputSource.PASTED
            )

            source_filename = ""
            source_content_type = ""
            source_size_bytes = None
            source_event_count = None

            try:
                if uploaded_file:
                    parsed_file = EventFileParser().parse(
                        uploaded_file
                    )

                    security_events = parsed_file.text

                    input_source = (
                        Investigation
                        .InputSource
                        .UPLOADED_FILE
                    )

                    source_filename = (
                        parsed_file.filename
                    )

                    source_content_type = (
                        parsed_file.content_type
                    )

                    source_size_bytes = (
                        parsed_file.size_bytes
                    )

                    source_event_count = (
                        parsed_file.event_count
                    )

                else:
                    security_events = pasted_events

                    source_event_count = len(
                        [
                            line
                            for line
                            in security_events.splitlines()
                            if line.strip()
                        ]
                    )

                analyzer = IncidentAnalyzer()

                assessment = analyzer.analyze(
                    security_events,
                )

                investigation = (
                    InvestigationService
                    .create_investigation(
                        raw_events=security_events,
                        assessment=assessment,
                        input_source=input_source,
                        source_filename=source_filename,
                        source_content_type=(
                            source_content_type
                        ),
                        source_size_bytes=(
                            source_size_bytes
                        ),
                        source_event_count=(
                            source_event_count
                        ),
                    )
                )

                return redirect(investigation)

            except (
                EventFileValidationError,
                EventFileParseError,
            ) as exc:
                form.add_error(
                    "event_file",
                    str(exc),
                )

            except IncidentAnalysisError as exc:
                analysis_error = str(exc)

            except Exception:
                logger.exception(
                    "ThreatLens failed to create "
                    "the investigation."
                )

                analysis_error = (
                    "ThreatLens could not complete and save "
                    "the investigation."
                )

    else:
        form = IncidentAnalysisForm()

    context = {
        "form": form,
        "analysis_error": analysis_error,
        "sample_security_events": SAMPLE_SECURITY_EVENTS,
    }

    return render(
        request,
        "analyzer/investigation_create.html",
        context,
    )

@require_http_methods(["GET"])
def investigation_detail(
    request: HttpRequest,
    investigation_id,
) -> HttpResponse:
    investigation = get_object_or_404(
        Investigation,
        id=investigation_id,
    )

    context = {
        "investigation": investigation,
        "analysis": investigation.analysis,
    }

    return render(
        request,
        "analyzer/investigation_detail.html",
        context,
    )

@require_http_methods(["GET"])
def investigation_pdf(
    request: HttpRequest,
    investigation_id,
) -> FileResponse | HttpResponse:
    investigation = get_object_or_404(
        Investigation,
        id=investigation_id,
    )

    try:
        pdf_content = InvestigationPDFReportService(
            investigation
        ).generate()

    except PDFReportError:
        logger.exception(
            "PDF report generation failed for investigation %s.",
            investigation.id,
        )

        return render(
            request,
            "analyzer/report_error.html",
            {
                "investigation": investigation,
            },
            status=500,
        )

    safe_title = re.sub(
        r"[^A-Za-z0-9_-]+",
        "-",
        investigation.title,
    ).strip("-")

    if not safe_title:
        safe_title = "investigation"

    filename = (
        f"threatlens-{safe_title[:60]}-"
        f"{str(investigation.id)[:8]}.pdf"
    )

    pdf_file = BytesIO(pdf_content)

    return FileResponse(
        pdf_file,
        as_attachment=True,
        filename=filename,
        content_type="application/pdf",
    )


from __future__ import annotations

import logging
import re
from io import BytesIO

from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import (
    FileResponse,
    HttpRequest,
    HttpResponse,
    JsonResponse,
)
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from analyzer.forms import (
    IncidentAnalysisForm,
    InvestigationFilterForm,
    SAMPLE_SECURITY_EVENTS,
)
from analyzer.models import Investigation
from analyzer.services.dashboard_service import (
    InvestigationDashboardService,
)
from analyzer.services.demo_service import DemoCaseService
from analyzer.services.event_file_parser import (
    EventFileParseError,
    EventFileValidationError,
)
from analyzer.services.health_service import HealthCheckService
from analyzer.services.incident_analyzer import (
    IncidentAnalysisError,
    IncidentAnalyzer,
)
from analyzer.services.investigation_service import InvestigationService
from analyzer.services.pdf_report_service import (
    InvestigationPDFReportService,
    PDFReportError,
)

logger = logging.getLogger(__name__)


@require_http_methods(["GET"])
def investigation_list(
    request: HttpRequest,
) -> HttpResponse:
    filter_form = InvestigationFilterForm(
        request.GET or None
    )

    if filter_form.is_valid():
        cleaned_filters = (
            filter_form.cleaned_data
        )
    else:
        cleaned_filters = {}

    investigations = (
        InvestigationDashboardService
        .build_queryset(
            cleaned_filters=cleaned_filters,
        )
    )

    metrics = (
        InvestigationDashboardService
        .build_metrics()
    )

    paginator = Paginator(
        investigations,
        8,
    )

    page_obj = paginator.get_page(
        request.GET.get("page")
    )

    active_filter_count = sum(
        bool(cleaned_filters.get(field))
        for field in (
            "search",
            "severity",
            "confidence",
            "input_source",
        )
    )

    selected_sort = (
        cleaned_filters.get("sort")
        or InvestigationFilterForm
        .SortChoice
        .NEWEST
    )

    context = {
        "filter_form": filter_form,
        "page_obj": page_obj,
        "investigations": (
            page_obj.object_list
        ),
        "metrics": metrics,
        "recent_activity": (
            InvestigationDashboardService
            .get_recent_activity(
                limit=5,
            )
        ),
        "active_filter_count": (
            active_filter_count
        ),
        "selected_sort": selected_sort,
        "result_count": paginator.count,
        "demo_mode_enabled": (
            settings.THREATLENS_DEMO_MODE
),

    }

    return render(
        request,
        "analyzer/investigation_list.html",
        context,
    )


def _render_error(
    request: HttpRequest,
    *,
    status: int,
) -> HttpResponse:
    return render(
        request,
        f"analyzer/errors/{status}.html",
        {
            "request_id": getattr(
                request,
                "request_id",
                "-",
            ),
        },
        status=status,
    )


def bad_request(
    request: HttpRequest,
    exception: Exception | None = None,
) -> HttpResponse:
    return _render_error(request, status=400)


def permission_denied(
    request: HttpRequest,
    exception: Exception | None = None,
) -> HttpResponse:
    return _render_error(request, status=403)


def page_not_found(
    request: HttpRequest,
    exception: Exception | None = None,
) -> HttpResponse:
    return _render_error(request, status=404)


def server_error(
    request: HttpRequest,
) -> HttpResponse:
    return _render_error(request, status=500)


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

            try:
                prepared_input = (
                    InvestigationService.prepare_input(
                        pasted_events=pasted_events,
                        uploaded_file=uploaded_file,
                    )
                )

                analyzer = IncidentAnalyzer()

                assessment = analyzer.analyze(
                    prepared_input.raw_events,
                )

                investigation = (
                    InvestigationService
                    .create_investigation(
                        raw_events=prepared_input.raw_events,
                        assessment=assessment,
                        input_source=(
                            prepared_input.input_source
                        ),
                        source_filename=(
                            prepared_input.source_filename
                        ),
                        source_content_type=(
                            prepared_input.source_content_type
                        ),
                        source_size_bytes=(
                            prepared_input.source_size_bytes
                        ),
                        source_event_count=(
                            prepared_input.source_event_count
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
                request_id = getattr(
                    request,
                    "request_id",
                    "-",
                )

                logger.exception(
                    "ThreatLens failed to create investigation."
                )

                analysis_error = (
                    "ThreatLens could not complete this investigation. "
                    f"Reference ID: {request_id}"
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
                "request_id": getattr(
                    request,
                    "request_id",
                    "-",
                ),
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


@require_http_methods(["GET"])
@never_cache
def health_check(
    request: HttpRequest,
) -> JsonResponse:
    result = HealthCheckService.check()

    status_code = (
        200
        if result.status == "ok"
        else 503
    )

    return JsonResponse(
        result.as_dict(),
        status=status_code,
    )


@require_http_methods(["POST"])
def create_demo_investigation(
    request: HttpRequest,
) -> HttpResponse:
    if not settings.THREATLENS_DEMO_MODE:
        return HttpResponse(
            "Demo mode is disabled.",
            status=403,
        )

    try:
        result = DemoCaseService.create_or_get()

    except PermissionError:
        return HttpResponse(
            "Demo mode is disabled.",
            status=403,
        )

    if result.created:
        messages.success(
            request,
            "The guided demonstration case was created.",
        )

    else:
        messages.info(
            request,
            "The existing guided demonstration case was opened.",
        )

    return redirect(result.investigation)


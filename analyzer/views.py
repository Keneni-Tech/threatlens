import logging

from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from analyzer.forms import IncidentAnalysisForm, SAMPLE_SECURITY_EVENTS
from analyzer.services.incident_analyzer import (
    IncidentAnalysisError,
    IncidentAnalyzer,
)


logger = logging.getLogger(__name__)


@require_http_methods(["GET", "POST"])
def analyze_incident(request):
    assessment = None
    analysis_error = None

    if request.method == "POST":
        form = IncidentAnalysisForm(request.POST)

        if form.is_valid():
            security_events = form.cleaned_data["security_events"]

            try:
                analyzer = IncidentAnalyzer()
                assessment = analyzer.analyze(security_events)

            except IncidentAnalysisError as exc:
                analysis_error = str(exc)

    else:
        form = IncidentAnalysisForm()

    context = {
        "form": form,
        "assessment": assessment,
        "analysis_error": analysis_error,
        "sample_security_events": SAMPLE_SECURITY_EVENTS,
    }

    return render(
        request,
        "analyzer/analyze.html",
        context,
    )
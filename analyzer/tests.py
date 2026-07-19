from __future__ import annotations

from io import BytesIO
import uuid
from django.http import FileResponse
from pypdf import PdfReader

from analyzer.services.pdf_report_service import (
    InvestigationPDFReportService,
    PDFReportError,
)

from analyzer.forms import IncidentAnalysisForm

from unittest.mock import Mock, patch

from django.test import TestCase
from django.urls import reverse

from analyzer.models import Investigation
from analyzer.schemas import IncidentAssessment
from analyzer.services.investigation_service import (
    InvestigationService,
)

from django.core.files.uploadedfile import (
    SimpleUploadedFile,
)

from analyzer.services.event_file_parser import (
    EventFileParseError,
    EventFileParser,
    EventFileValidationError,
)

from datetime import timedelta

from django.utils import timezone

from analyzer.forms import InvestigationFilterForm
from analyzer.services.dashboard_service import (
    InvestigationDashboardService,
)

def build_assessment() -> IncidentAssessment:
    return IncidentAssessment(
        title="Possible administrator account compromise",
        severity="high",
        confidence="high",
        summary=(
            "Repeated authentication failures were followed by a "
            "successful administrator login."
        ),
        timeline=[
            "Multiple authentication failures occurred.",
            "A successful administrator login followed.",
        ],
        evidence=[
            {
                "title": "Repeated login failures",
                "description": (
                    "Several failed authentication events targeted "
                    "the same administrator account."
                ),
                "event_references": [
                    "administrator",
                    "198.51.100.24",
                ],
            }
        ],
        possible_attack_path=[
            "Possible password guessing activity.",
            "Possible unauthorized account access.",
        ],
        mitre_attack=[
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "explanation": (
                    "Repeated authentication failures may indicate "
                    "password guessing."
                ),
            }
        ],
        affected_assets=[
            "web-server-01",
        ],
        affected_accounts=[
            "administrator",
        ],
        indicators=[
            "198.51.100.24",
        ],
        investigation_steps=[
            "Review authentication logs for the source IP.",
        ],
        containment_actions=[
            "Temporarily disable the affected administrator account.",
        ],
        limitations=[
            "The available event dataset is limited.",
        ],
    )
def create_investigation(
    *,
    title: str,
    severity: str,
    confidence: str = Investigation.Confidence.HIGH,
    summary: str = "Example security investigation.",
    raw_events: str = "event=example",
    input_source: str = Investigation.InputSource.PASTED,
    source_filename: str = "",
) -> Investigation:
    return Investigation.objects.create(
        title=title,
        severity=severity,
        confidence=confidence,
        summary=summary,
        raw_events=raw_events,
        input_source=input_source,
        source_filename=source_filename,
        analysis={
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "summary": summary,
            "timeline": [],
            "evidence": [],
            "possible_attack_path": [],
            "mitre_attack": [],
            "affected_assets": [],
            "affected_accounts": [],
            "indicators": [],
            "investigation_steps": [],
            "containment_actions": [],
            "limitations": [],
        },
    )

class InvestigationModelTests(TestCase):
    def test_get_absolute_url(self):
        investigation = Investigation.objects.create(
            title="Test investigation",
            severity=Investigation.Severity.HIGH,
            confidence=Investigation.Confidence.HIGH,
            summary="Test summary.",
            raw_events="Example security events.",
            analysis={},
        )

        self.assertEqual(
            investigation.get_absolute_url(),
            reverse(
                "analyzer:investigation_detail",
                kwargs={
                    "investigation_id": investigation.id,
                },
            ),
        )


class InvestigationServiceTests(TestCase):
    def test_create_investigation_saves_assessment(self):
        assessment = build_assessment()

        investigation = (
            InvestigationService.create_investigation(
                raw_events="Example event data.",
                assessment=assessment,
            )
        )

        self.assertEqual(
            Investigation.objects.count(),
            1,
        )

        self.assertEqual(
            investigation.title,
            assessment.title,
        )

        self.assertEqual(
            investigation.analysis["severity"],
            "high",
        )

        self.assertEqual(
            investigation.raw_events,
            "Example event data.",
        )

        self.assertEqual(
            investigation.input_source,
            Investigation.InputSource.PASTED,
        )

        self.assertEqual(
            investigation.source_filename,
            "",
        )

class InvestigationViewTests(TestCase):
    def test_list_page_displays_saved_investigation(self):
        investigation = Investigation.objects.create(
            title="Saved investigation",
            severity=Investigation.Severity.MEDIUM,
            confidence=Investigation.Confidence.MEDIUM,
            summary="Saved summary.",
            raw_events="Saved events.",
            analysis={},
        )

        response = self.client.get(
            reverse("analyzer:investigation_list")
        )

        self.assertEqual(response.status_code, 200)

        self.assertContains(
            response,
            investigation.title,
        )

    def test_detail_page_displays_investigation(self):
        assessment = build_assessment()

        investigation = (
            InvestigationService.create_investigation(
                raw_events="Example event data.",
                assessment=assessment,
            )
        )

        response = self.client.get(
            investigation.get_absolute_url()
        )

        self.assertEqual(response.status_code, 200)

        self.assertContains(
            response,
            assessment.title,
        )

        self.assertContains(
            response,
            "198.51.100.24",
        )

    @patch("analyzer.views.IncidentAnalyzer")
    def test_create_view_saves_and_redirects(
        self,
        analyzer_class,
    ):
        analyzer = Mock()

        analyzer.analyze.return_value = build_assessment()

        analyzer_class.return_value = analyzer

        response = self.client.post(
            reverse("analyzer:investigation_create"),
            {
                "security_events": (
                    "Repeated failed authentication attempts were "
                    "followed by a successful administrator login."
                ),
            },
        )

        investigation = Investigation.objects.get()

        self.assertRedirects(
            response,
            investigation.get_absolute_url(),
        )

        analyzer.analyze.assert_called_once()

    def test_create_page_rejects_empty_input(self):
        response = self.client.post(
            reverse("analyzer:investigation_create"),
            {
                "security_events": "",
            },
        )

        self.assertEqual(response.status_code, 200)

        self.assertContains(
            response,
            "Paste security events or upload an event file.",
        )

    @patch("analyzer.views.IncidentAnalyzer")
    def test_create_view_analyzes_uploaded_json_file(
        self,
        analyzer_class,
    ):
        analyzer = Mock()
        analyzer.analyze.return_value = build_assessment()
        analyzer_class.return_value = analyzer

        uploaded_file = SimpleUploadedFile(
            "authentication-events.json",
            (
                b'[{"event":"login_failure","user":"admin"},'
                b'{"event":"login_success","user":"admin"}]'
            ),
            content_type="application/json",
        )

        response = self.client.post(
            reverse("analyzer:investigation_create"),
            {
                "event_file": uploaded_file,
            },
        )

        investigation = Investigation.objects.get()

        self.assertRedirects(
            response,
            investigation.get_absolute_url(),
        )

        self.assertEqual(
            investigation.input_source,
            Investigation.InputSource.UPLOADED_FILE,
        )

        self.assertEqual(
            investigation.source_filename,
            "authentication-events.json",
        )

        self.assertEqual(
            investigation.source_content_type,
            "application/json",
        )

        self.assertEqual(
            investigation.source_event_count,
            2,
        )

        self.assertIn(
            "login_failure",
            investigation.raw_events,
        )

        analyzer.analyze.assert_called_once_with(
            investigation.raw_events
        )


@patch("analyzer.views.IncidentAnalyzer")
def test_create_view_analyzes_uploaded_csv_file(
    self,
    analyzer_class,
):
    analyzer = Mock()
    analyzer.analyze.return_value = build_assessment()
    analyzer_class.return_value = analyzer

    uploaded_file = SimpleUploadedFile(
        "events.csv",
        (
            b"timestamp,event,user\n"
            b"2026-07-18T10:00:00Z,"
            b"login_failure,administrator\n"
        ),
        content_type="text/csv",
    )

    response = self.client.post(
        reverse("analyzer:investigation_create"),
        {
            "event_file": uploaded_file,
        },
    )

    investigation = Investigation.objects.get()

    self.assertRedirects(
        response,
        investigation.get_absolute_url(),
    )

    self.assertEqual(
        investigation.source_event_count,
        1,
    )

    self.assertEqual(
        investigation.source_filename,
        "events.csv",
    )


@patch("analyzer.views.IncidentAnalyzer")
def test_invalid_uploaded_file_does_not_call_ai(
    self,
    analyzer_class,
):
    uploaded_file = SimpleUploadedFile(
        "events.json",
        b'{"event": invalid}',
        content_type="application/json",
    )

    response = self.client.post(
        reverse("analyzer:investigation_create"),
        {
            "event_file": uploaded_file,
        },
    )

    self.assertEqual(
        response.status_code,
        200,
    )

    self.assertContains(
        response,
        "The uploaded JSON file is invalid",
    )

    self.assertEqual(
        Investigation.objects.count(),
        0,
    )

    analyzer_class.assert_not_called()


@patch("analyzer.views.IncidentAnalyzer")
def test_pasted_input_records_pasted_source(
    self,
    analyzer_class,
):
    analyzer = Mock()
    analyzer.analyze.return_value = build_assessment()
    analyzer_class.return_value = analyzer

    response = self.client.post(
        reverse("analyzer:investigation_create"),
        {
            "security_events": (
                "event=login_failure user=administrator\n"
                "event=login_success user=administrator"
            ),
        },
    )

    investigation = Investigation.objects.get()

    self.assertRedirects(
        response,
        investigation.get_absolute_url(),
    )

    self.assertEqual(
        investigation.input_source,
        Investigation.InputSource.PASTED,
    )

    self.assertEqual(
        investigation.source_filename,
        "",
    )

    self.assertEqual(
        investigation.source_event_count,
        2,
    )
class InvestigationPDFReportServiceTests(TestCase):
    def setUp(self):
        self.assessment = build_assessment()

        self.investigation = (
            InvestigationService.create_investigation(
                raw_events=(
                    "Repeated login failures followed by a "
                    "successful administrator login."
                ),
                assessment=self.assessment,
            )
        )

    def test_generate_returns_valid_pdf(self):
        pdf_content = InvestigationPDFReportService(
            self.investigation
        ).generate()

        self.assertTrue(
            pdf_content.startswith(b"%PDF"),
        )

        reader = PdfReader(
            BytesIO(pdf_content)
        )

        self.assertGreaterEqual(
            len(reader.pages),
            1,
        )

    def test_generated_pdf_contains_investigation_content(self):
        pdf_content = InvestigationPDFReportService(
            self.investigation
        ).generate()

        reader = PdfReader(
            BytesIO(pdf_content)
        )

        extracted_text = "\n".join(
            page.extract_text() or ""
            for page in reader.pages
        )

        self.assertIn(
            "Possible administrator account compromise",
            extracted_text,
        )

        self.assertIn(
            "Executive Summary",
            extracted_text,
        )

        self.assertIn(
            "Recommended Containment Actions",
            extracted_text,
        )

    def test_report_escapes_markup_characters(self):
        self.investigation.title = (
            "PowerShell <script> & account activity"
        )

        self.investigation.summary = (
            "Observed command text containing < and > characters."
        )

        self.investigation.save(
            update_fields=[
                "title",
                "summary",
                "updated_at",
            ]
        )

        pdf_content = InvestigationPDFReportService(
            self.investigation
        ).generate()

        self.assertTrue(
            pdf_content.startswith(b"%PDF"),
        )

    
class InvestigationPDFViewTests(TestCase):
    def setUp(self):
        self.investigation = (
            InvestigationService.create_investigation(
                raw_events="Example security events.",
                assessment=build_assessment(),
            )
        )

        self.url = reverse(
            "analyzer:investigation_pdf",
            kwargs={
                "investigation_id": self.investigation.id,
            },
        )

    def test_pdf_view_returns_downloadable_pdf(self):
        response = self.client.get(self.url)

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertIsInstance(
            response,
            FileResponse,
        )

        self.assertEqual(
            response["Content-Type"],
            "application/pdf",
        )

        self.assertIn(
            "attachment;",
            response["Content-Disposition"],
        )

        response_content = b"".join(
            response.streaming_content
        )

        self.assertTrue(
            response_content.startswith(b"%PDF"),
        )

    def test_pdf_view_returns_404_for_unknown_case(self):
        import uuid

        response = self.client.get(
            reverse(
                "analyzer:investigation_pdf",
                kwargs={
                    "investigation_id": uuid.uuid4(),
                },
            )
        )

        self.assertEqual(
            response.status_code,
            404,
        )

    @patch(
        "analyzer.views.InvestigationPDFReportService.generate"
    )
    def test_pdf_view_handles_generation_error(
        self,
        generate_mock,
    ):
        generate_mock.side_effect = PDFReportError(
            "Report generation failed."
        )

        response = self.client.get(self.url)

        self.assertEqual(
            response.status_code,
            500,
        )

        self.assertContains(
            response,
            "ThreatLens could not generate this report.",
            status_code=500,
        )

    

def test_pdf_view_returns_404_for_unknown_case(self):
    response = self.client.get(
        reverse(
            "analyzer:investigation_pdf",
            kwargs={
                "investigation_id": uuid.uuid4(),
            },
        )
    )

    self.assertEqual(
        response.status_code,
        404,
    )

class EventFileParserTests(TestCase):
    def setUp(self):
        self.parser = EventFileParser(
            max_upload_bytes=1024 * 1024,
            max_parsed_characters=50_000,
        )

    def test_parse_text_file(self):
        uploaded_file = SimpleUploadedFile(
            "events.log",
            (
                b"event=login_failure user=admin\n"
                b"event=login_success user=admin\n"
            ),
            content_type="text/plain",
        )

        result = self.parser.parse(uploaded_file)

        self.assertEqual(
            result.filename,
            "events.log",
        )

        self.assertEqual(
            result.event_count,
            2,
        )

        self.assertIn(
            "login_failure",
            result.text,
        )

    def test_parse_json_array(self):
        uploaded_file = SimpleUploadedFile(
            "events.json",
            (
                b'[{"event": "login_failure"}, '
                b'{"event": "login_success"}]'
            ),
            content_type="application/json",
        )

        result = self.parser.parse(uploaded_file)

        self.assertEqual(
            result.event_count,
            2,
        )

        self.assertIn(
            '"login_failure"',
            result.text,
        )

    def test_parse_jsonl(self):
        uploaded_file = SimpleUploadedFile(
            "events.jsonl",
            (
                b'{"event":"login_failure"}\n'
                b'{"event":"login_success"}\n'
            ),
            content_type="application/json",
        )

        result = self.parser.parse(uploaded_file)

        self.assertEqual(
            result.event_count,
            2,
        )

        self.assertEqual(
            len(result.text.splitlines()),
            2,
        )

    def test_parse_csv(self):
        uploaded_file = SimpleUploadedFile(
            "events.csv",
            (
                b"timestamp,event,user\n"
                b"2026-07-18T10:00:00Z,"
                b"login_failure,admin\n"
                b"2026-07-18T10:01:00Z,"
                b"login_success,admin\n"
            ),
            content_type="text/csv",
        )

        result = self.parser.parse(uploaded_file)

        self.assertEqual(
            result.event_count,
            2,
        )

        self.assertIn(
            '"event": "login_failure"',
            result.text,
        )

    def test_rejects_unsupported_extension(self):
        uploaded_file = SimpleUploadedFile(
            "events.exe",
            b"not an executable",
            content_type="application/octet-stream",
        )

        with self.assertRaises(
            EventFileValidationError
        ):
            self.parser.parse(uploaded_file)

    def test_rejects_oversized_file(self):
        parser = EventFileParser(
            max_upload_bytes=10,
        )

        uploaded_file = SimpleUploadedFile(
            "events.log",
            b"this file is larger than ten bytes",
            content_type="text/plain",
        )

        with self.assertRaises(
            EventFileValidationError
        ):
            parser.parse(uploaded_file)

    def test_rejects_binary_content(self):
        uploaded_file = SimpleUploadedFile(
            "events.log",
            b"event\x00binary",
            content_type="text/plain",
        )

        with self.assertRaises(
            EventFileValidationError
        ):
            self.parser.parse(uploaded_file)

    def test_rejects_invalid_json(self):
        uploaded_file = SimpleUploadedFile(
            "events.json",
            b'{"event": invalid}',
            content_type="application/json",
        )

        with self.assertRaises(
            EventFileParseError
        ):
            self.parser.parse(uploaded_file)

    def test_rejects_non_object_jsonl_record(self):
        uploaded_file = SimpleUploadedFile(
            "events.jsonl",
            b'{"event":"login"}\n["invalid"]\n',
            content_type="application/json",
        )

        with self.assertRaises(
            EventFileParseError
        ):
            self.parser.parse(uploaded_file)

class IncidentAnalysisFormTests(TestCase):
    def test_requires_input(self):
        form = IncidentAnalysisForm(
            data={},
            files={},
        )

        self.assertFalse(
            form.is_valid()
        )

        self.assertIn(
            "Paste security events or upload an event file.",
            form.non_field_errors(),
        )

    def test_accepts_pasted_events(self):
        form = IncidentAnalysisForm(
            data={
                "security_events": (
                    "event=login_failure user=admin"
                ),
            },
        )

        self.assertTrue(
            form.is_valid(),
            form.errors,
        )

    def test_accepts_uploaded_file(self):
        uploaded_file = SimpleUploadedFile(
            "events.log",
            b"event=login_failure user=admin",
            content_type="text/plain",
        )

        form = IncidentAnalysisForm(
            data={},
            files={
                "event_file": uploaded_file,
            },
        )

        self.assertTrue(
            form.is_valid(),
            form.errors,
        )

    def test_rejects_paste_and_file_together(self):
        uploaded_file = SimpleUploadedFile(
            "events.log",
            b"event=login_failure user=admin",
            content_type="text/plain",
        )

        form = IncidentAnalysisForm(
            data={
                "security_events": (
                    "event=login_success user=admin"
                ),
            },
            files={
                "event_file": uploaded_file,
            },
        )

        self.assertFalse(
            form.is_valid()
        )

        self.assertIn(
            "Use one input method at a time",
            str(form.non_field_errors()),
        )
class InvestigationFilterFormTests(TestCase):
    def test_default_filter_form_is_valid(self):
        form = InvestigationFilterForm(
            data={}
        )

        self.assertTrue(
            form.is_valid(),
            form.errors,
        )

    def test_rejects_invalid_severity(self):
        form = InvestigationFilterForm(
            data={
                "severity": "extreme",
            }
        )

        self.assertFalse(
            form.is_valid()
        )

        self.assertIn(
            "severity",
            form.errors,
        )

    def test_rejects_invalid_sort_option(self):
        form = InvestigationFilterForm(
            data={
                "sort": "unknown",
            }
        )

        self.assertFalse(
            form.is_valid()
        )

        self.assertIn(
            "sort",
            form.errors,
        )


class InvestigationDashboardServiceTests(TestCase):
    def setUp(self):
        self.critical = create_investigation(
            title="Critical account compromise",
            severity=(
                Investigation.Severity.CRITICAL
            ),
            summary=(
                "Administrator account compromise "
                "from suspicious source."
            ),
            raw_events=(
                "user=administrator "
                "source_ip=198.51.100.24"
            ),
        )

        self.high = create_investigation(
            title="PowerShell execution",
            severity=(
                Investigation.Severity.HIGH
            ),
            confidence=(
                Investigation.Confidence.MEDIUM
            ),
            input_source=(
                Investigation
                .InputSource
                .UPLOADED_FILE
            ),
            source_filename="powershell-events.json",
        )

        self.low = create_investigation(
            title="Routine service login",
            severity=(
                Investigation.Severity.LOW
            ),
            confidence=(
                Investigation.Confidence.LOW
            ),
        )

    def test_metrics_count_severities(self):
        metrics = (
            InvestigationDashboardService
            .build_metrics()
        )

        self.assertEqual(
            metrics.total,
            3,
        )

        self.assertEqual(
            metrics.critical,
            1,
        )

        self.assertEqual(
            metrics.high,
            1,
        )

        self.assertEqual(
            metrics.low,
            1,
        )

        self.assertEqual(
            metrics.high_priority,
            2,
        )

    def test_metrics_count_input_sources(self):
        metrics = (
            InvestigationDashboardService
            .build_metrics()
        )

        self.assertEqual(
            metrics.uploaded,
            1,
        )

        self.assertEqual(
            metrics.pasted,
            2,
        )

    def test_search_matches_title(self):
        queryset = (
            InvestigationDashboardService
            .build_queryset(
                cleaned_filters={
                    "search": "PowerShell",
                }
            )
        )

        self.assertEqual(
            list(queryset),
            [self.high],
        )

    def test_search_matches_raw_events(self):
        queryset = (
            InvestigationDashboardService
            .build_queryset(
                cleaned_filters={
                    "search": "198.51.100.24",
                }
            )
        )

        self.assertEqual(
            list(queryset),
            [self.critical],
        )

    def test_filter_by_severity(self):
        queryset = (
            InvestigationDashboardService
            .build_queryset(
                cleaned_filters={
                    "severity": (
                        Investigation
                        .Severity
                        .CRITICAL
                    ),
                }
            )
        )

        self.assertEqual(
            list(queryset),
            [self.critical],
        )

    def test_filter_by_confidence(self):
        queryset = (
            InvestigationDashboardService
            .build_queryset(
                cleaned_filters={
                    "confidence": (
                        Investigation
                        .Confidence
                        .MEDIUM
                    ),
                }
            )
        )

        self.assertEqual(
            list(queryset),
            [self.high],
        )

    def test_filter_by_uploaded_source(self):
        queryset = (
            InvestigationDashboardService
            .build_queryset(
                cleaned_filters={
                    "input_source": (
                        Investigation
                        .InputSource
                        .UPLOADED_FILE
                    ),
                }
            )
        )

        self.assertEqual(
            list(queryset),
            [self.high],
        )

    def test_sort_highest_severity_first(self):
        queryset = (
            InvestigationDashboardService
            .build_queryset(
                cleaned_filters={
                    "sort": (
                        InvestigationFilterForm
                        .SortChoice
                        .SEVERITY_DESC
                    ),
                }
            )
        )

        self.assertEqual(
            list(queryset),
            [
                self.critical,
                self.high,
                self.low,
            ],
        )

    def test_sort_lowest_severity_first(self):
        queryset = (
            InvestigationDashboardService
            .build_queryset(
                cleaned_filters={
                    "sort": (
                        InvestigationFilterForm
                        .SortChoice
                        .SEVERITY_ASC
                    ),
                }
            )
        )

        self.assertEqual(
            list(queryset),
            [
                self.low,
                self.high,
                self.critical,
            ],
        )

    def test_severity_percentages_total_one_hundred(self):
        metrics = (
            InvestigationDashboardService
            .build_metrics()
        )

        total_percentage = sum(
            item.percentage
            for item
            in metrics.severity_distribution
        )

        self.assertAlmostEqual(
            total_percentage,
            100.0,
            places=1,
        )
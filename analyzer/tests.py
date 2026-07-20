from __future__ import annotations

from datetime import timedelta
from io import BytesIO
import re
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.contrib.staticfiles import finders
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.http import FileResponse, HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from pypdf import PdfReader
from pydantic import ValidationError

from analyzer.forms import (
    IncidentAnalysisForm,
    InvestigationFilterForm,
)
from analyzer.middleware import RequestIDMiddleware
from analyzer.models import Investigation
from analyzer.schemas import IncidentAssessment
from analyzer.services.dashboard_service import (
    InvestigationDashboardService,
)
from analyzer.services.demo_service import DEMO_CASE_TITLE, DemoCaseService
from analyzer.services.event_file_parser import (
    EventFileParseError,
    EventFileParser,
    EventFileValidationError,
)
from analyzer.services.health_service import (
    HealthCheckService,
)
from analyzer.services.incident_analyzer import (
    IncidentAnalysisError,
    IncidentAnalyzer,
)
from analyzer.services.investigation_service import InvestigationService
from analyzer.services.pdf_report_service import (
    InvestigationPDFReportService,
    PDFReportError,
)


@override_settings(
    STORAGES={
        "default": {
            "BACKEND": (
                "django.core.files.storage.FileSystemStorage"
            ),
        },
        "staticfiles": {
            "BACKEND": (
                "django.contrib.staticfiles.storage."
                "StaticFilesStorage"
            ),
        },
    }
)
class RenderedTemplateTestCase(TestCase):
    """Render templates without requiring a collected asset manifest."""


class RequestIDMiddlewareTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_generates_request_id(self):
        def get_response(request):
            self.assertTrue(
                request.request_id
            )

            return HttpResponse("ok")

        middleware = RequestIDMiddleware(
            get_response
        )

        request = self.factory.get("/")

        response = middleware(request)

        self.assertIn(
            "X-Request-ID",
            response,
        )

    def test_preserves_valid_supplied_request_id(self):
        supplied_id = "test-request-123"

        def get_response(request):
            self.assertEqual(
                request.request_id,
                supplied_id,
            )

            return HttpResponse("ok")

        middleware = RequestIDMiddleware(
            get_response
        )

        request = self.factory.get(
            "/",
            HTTP_X_REQUEST_ID=supplied_id,
        )

        response = middleware(request)

        self.assertEqual(
            response["X-Request-ID"],
            supplied_id,
        )

    def test_replaces_request_id_with_unsafe_characters(self):
        supplied_id = "attacker controlled value"
        middleware = RequestIDMiddleware(
            lambda request: HttpResponse("ok")
        )

        response = middleware(
            self.factory.get(
                "/",
                HTTP_X_REQUEST_ID=supplied_id,
            )
        )

        self.assertNotEqual(
            response["X-Request-ID"],
            supplied_id,
        )


class HealthCheckTests(TestCase):
    def test_health_service_reports_available_database(self):
        result = HealthCheckService.check()

        self.assertEqual(
            result.status,
            "ok",
        )

        self.assertEqual(
            result.database,
            "available",
        )

    def test_health_endpoint_returns_json(self):
        response = self.client.get(
            reverse("analyzer:health_check")
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        payload = response.json()

        self.assertEqual(
            payload["status"],
            "ok",
        )

        self.assertEqual(
            payload["database"],
            "available",
        )

        self.assertIn(
            "X-Request-ID",
            response,
        )

        self.assertEqual(
            response["Cache-Control"],
            "max-age=0, no-cache, no-store, "
            "must-revalidate, private",
        )

    def test_responses_include_security_headers(self):
        response = self.client.get(
            reverse("analyzer:health_check")
        )

        self.assertIn(
            "default-src 'self'",
            response["Content-Security-Policy"],
        )
        self.assertIn(
            "script-src 'self'",
            response["Content-Security-Policy"],
        )
        self.assertEqual(
            response["X-Content-Type-Options"],
            "nosniff",
        )
        self.assertEqual(
            response["X-Frame-Options"],
            "DENY",
        )


class IncidentAnalyzerTests(TestCase):
    def test_returns_parsed_structured_assessment(self):
        assessment = build_assessment()
        client = Mock()
        client.responses.parse.return_value = SimpleNamespace(
            output_parsed=assessment,
            output=[],
            _request_id="req_test",
        )
        analyzer = IncidentAnalyzer(
            model="gpt-5.6",
            client=client,
        )

        result = analyzer.analyze("event=login_failure")

        self.assertIs(result, assessment)
        client.responses.parse.assert_called_once()
        call = client.responses.parse.call_args
        self.assertEqual(call.kwargs["model"], "gpt-5.6")
        self.assertIs(
            call.kwargs["text_format"],
            IncidentAssessment,
        )
        self.assertIn(
            "untrusted security-event data",
            call.kwargs["input"][1]["content"],
        )

    @override_settings(
        THREATLENS_MAX_PARSED_CHARACTERS=10
    )
    def test_rejects_input_over_analysis_limit(self):
        client = Mock()
        analyzer = IncidentAnalyzer(client=client)

        with self.assertRaisesMessage(
            IncidentAnalysisError,
            "10-character analysis limit",
        ):
            analyzer.analyze("x" * 11)

        client.responses.parse.assert_not_called()

    def test_reports_structured_output_refusal(self):
        client = Mock()
        client.responses.parse.return_value = SimpleNamespace(
            output_parsed=None,
            output=[
                SimpleNamespace(
                    content=[
                        SimpleNamespace(type="refusal"),
                    ]
                )
            ],
            _request_id="req_refusal",
        )
        analyzer = IncidentAnalyzer(client=client)

        with self.assertRaisesMessage(
            IncidentAnalysisError,
            "could not analyze this input safely",
        ):
            analyzer.analyze("event=example")

    @override_settings(
        OPENAI_API_KEY="test-key",
        THREATLENS_ANALYSIS_TIMEOUT_SECONDS=42,
        OPENAI_MAX_RETRIES=1,
    )
    @patch("analyzer.services.incident_analyzer.OpenAI")
    def test_configures_client_timeout_and_retries(
        self,
        openai_class,
    ):
        IncidentAnalyzer()

        openai_class.assert_called_once_with(
            api_key="test-key",
            timeout=42,
            max_retries=1,
        )


@override_settings(
    THREATLENS_DEMO_MODE=True
)
class DemoCaseServiceTests(TestCase):
    def test_creates_demo_case(self):
        result = DemoCaseService.create_or_get()

        self.assertTrue(
            result.created
        )

        self.assertEqual(
            result.investigation.title,
            DEMO_CASE_TITLE,
        )

        self.assertEqual(
            result.investigation.severity,
            Investigation.Severity.CRITICAL,
        )

        self.assertEqual(
            result.investigation.source_event_count,
            6,
        )

        self.assertIn(
            "T1059.001",
            {
                item["technique_id"]
                for item in (
                    result.investigation
                    .analysis["mitre_attack"]
                )
            },
        )

    def test_demo_case_is_idempotent(self):
        first = DemoCaseService.create_or_get()
        second = DemoCaseService.create_or_get()

        self.assertTrue(
            first.created
        )

        self.assertFalse(
            second.created
        )

        self.assertEqual(
            first.investigation.id,
            second.investigation.id,
        )

        self.assertEqual(
            Investigation.objects.count(),
            1,
        )

    def test_seed_demo_management_command(self):
        call_command("seed_demo")

        self.assertEqual(
            Investigation.objects.filter(
                title=DEMO_CASE_TITLE,
            ).count(),
            1,
        )
class DemoCaseViewTests(RenderedTemplateTestCase):
    @override_settings(
        THREATLENS_DEMO_MODE=True
    )
    def test_demo_post_creates_and_redirects(self):
        response = self.client.post(
            reverse(
                "analyzer:create_demo_investigation"
            )
        )

        investigation = Investigation.objects.get(
            title=DEMO_CASE_TITLE
        )

        self.assertRedirects(
            response,
            investigation.get_absolute_url(),
        )

    @override_settings(
        THREATLENS_DEMO_MODE=True
    )
    def test_demo_endpoint_rejects_get(self):
        response = self.client.get(
            reverse(
                "analyzer:create_demo_investigation"
            )
        )

        self.assertEqual(
            response.status_code,
            405,
        )

    @override_settings(
        THREATLENS_DEMO_MODE=False
    )
    def test_disabled_demo_mode_returns_403(self):
        response = self.client.post(
            reverse(
                "analyzer:create_demo_investigation"
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

        self.assertEqual(
            Investigation.objects.count(),
            0,
        )

class ErrorPageTests(RenderedTemplateTestCase):
    @override_settings(DEBUG=False)
    def test_custom_404_page(self):
        response = self.client.get(
            "/resource-that-does-not-exist/"
        )

        self.assertEqual(
            response.status_code,
            404,
        )

        self.assertContains(
            response,
            "This ThreatLens resource does not exist.",
            status_code=404,
        )

        self.assertIn(
            "X-Request-ID",
            response,
        )


class TemplateMarkupTests(RenderedTemplateTestCase):
    def setUp(self):
        self.investigation = (
            InvestigationService.create_investigation(
                raw_events=(
                    "<script>alert('unsafe')</script>"
                ),
                assessment=build_assessment(),
            )
        )

    def test_base_landmarks_and_current_navigation(self):
        response = self.client.get(
            reverse("analyzer:investigation_list")
        )

        self.assertContains(
            response,
            'href="#main-content"',
        )
        self.assertContains(
            response,
            'id="main-content"',
        )
        self.assertContains(
            response,
            'aria-current="page"',
        )
        self.assertNotContains(response, "<<div")

    def test_create_form_uses_accessible_tabs_and_csrf(self):
        response = self.client.get(
            reverse("analyzer:investigation_create")
        )

        self.assertContains(response, 'role="tablist"')
        self.assertContains(response, 'role="tab"', count=2)
        self.assertContains(response, 'role="tabpanel"', count=2)
        self.assertContains(response, "csrfmiddlewaretoken")
        self.assertContains(
            response,
            'src="/static/analyzer/app.js"',
        )
        self.assertNotContains(
            response,
            'id="upload-panel"\n                    hidden',
        )

    def test_frontend_assets_are_discoverable(self):
        self.assertIsNotNone(
            finders.find("analyzer/app.css")
        )
        self.assertIsNotNone(
            finders.find("analyzer/app.js")
        )

    @override_settings(
        THREATLENS_MAX_INPUT_CHARACTERS=10
    )
    def test_invalid_field_exposes_accessible_error_state(self):
        response = self.client.post(
            reverse("analyzer:investigation_create"),
            {
                "security_events": "x" * 11,
            },
        )

        self.assertContains(response, 'aria-invalid="true"')
        self.assertContains(
            response,
            'id="security-events-errors"',
        )
        self.assertContains(response, 'role="alert"')

    def test_detail_escapes_submitted_events(self):
        response = self.client.get(
            self.investigation.get_absolute_url()
        )

        self.assertNotContains(
            response,
            "<script>alert('unsafe')</script>",
        )
        self.assertContains(
            response,
            "&lt;script&gt;alert(&#x27;unsafe&#x27;)"
            "&lt;/script&gt;",
        )
        self.assertContains(response, "<time datetime=")

    def test_primary_pages_do_not_render_duplicate_ids(self):
        responses = [
            self.client.get(
                reverse("analyzer:investigation_list")
            ),
            self.client.get(
                reverse("analyzer:investigation_create")
            ),
            self.client.get(
                self.investigation.get_absolute_url()
            ),
        ]

        for response in responses:
            ids = re.findall(
                rb'\sid="([^"]+)"',
                response.content,
            )

            self.assertEqual(
                len(ids),
                len(set(ids)),
                response.request["PATH_INFO"],
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
    def test_prepare_input_normalizes_pasted_events(self):
        prepared = InvestigationService.prepare_input(
            pasted_events=" event=one \n\n event=two ",
            uploaded_file=None,
        )

        self.assertEqual(
            prepared.raw_events,
            "event=one \n\n event=two",
        )
        self.assertEqual(
            prepared.input_source,
            Investigation.InputSource.PASTED,
        )
        self.assertEqual(prepared.source_event_count, 2)

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

    def test_assessment_rejects_title_over_model_limit(self):
        with self.assertRaises(ValidationError):
            IncidentAssessment(
                **{
                    **build_assessment().model_dump(),
                    "title": "x" * 256,
                }
            )


class InvestigationViewTests(RenderedTemplateTestCase):
    def test_create_rejects_multiple_uploaded_files(self):
        response = self.client.post(
            reverse("analyzer:investigation_create"),
            {
                "event_file": [
                    SimpleUploadedFile(
                        "first.log",
                        b"event=first",
                        content_type="text/plain",
                    ),
                    SimpleUploadedFile(
                        "second.log",
                        b"event=second",
                        content_type="text/plain",
                    ),
                ],
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertContains(
            response,
            "ThreatLens could not process that request.",
            status_code=400,
        )

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
class InvestigationPDFViewTests(RenderedTemplateTestCase):
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
        response = self.client.get(
            reverse(
                "analyzer:investigation_pdf",
                kwargs={
                    "investigation_id": "00000000-0000-0000-0000-000000000000",
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
        self.assertContains(
            response,
            "Reference ID:",
            status_code=500,
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

    def test_accepts_content_type_with_charset_parameter(self):
        uploaded_file = SimpleUploadedFile(
            "events.csv",
            b"event,user\nlogin_failure,admin\n",
            content_type="text/csv; charset=utf-8",
        )

        result = self.parser.parse(uploaded_file)

        self.assertEqual(result.event_count, 1)

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

    @override_settings(
        THREATLENS_MAX_INPUT_CHARACTERS=10
    )
    def test_rejects_oversized_pasted_events(self):
        form = IncidentAnalysisForm(
            data={
                "security_events": "x" * 11,
            },
        )

        self.assertFalse(form.is_valid())
        self.assertIn(
            "10-character limit",
            str(form.errors["security_events"]),
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

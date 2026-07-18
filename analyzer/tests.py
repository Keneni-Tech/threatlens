from __future__ import annotations

from unittest.mock import Mock, patch

from django.test import TestCase
from django.urls import reverse

from analyzer.models import Investigation
from analyzer.schemas import IncidentAssessment
from analyzer.services.investigation_service import (
    InvestigationService,
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
            "Paste security-event data before analyzing.",
        )
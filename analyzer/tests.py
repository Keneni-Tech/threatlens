from unittest.mock import Mock, patch

from django.test import TestCase
from django.urls import reverse

from analyzer.schemas import IncidentAssessment


class AnalyzeIncidentViewTests(TestCase):
    def setUp(self):
        self.url = reverse("analyzer:analyze")

    def test_get_displays_analysis_form(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ThreatLens")
        self.assertContains(response, "Analyze incident")

    def test_empty_submission_displays_validation_error(self):
        response = self.client.post(
            self.url,
            {"security_events": ""},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            "Paste security-event data before analyzing.",
        )

    @patch("analyzer.views.IncidentAnalyzer")
    def test_valid_submission_displays_assessment(
        self,
        analyzer_class,
    ):
        analyzer = Mock()

        analyzer.analyze.return_value = IncidentAssessment(
            title="Possible account compromise",
            severity="high",
            confidence="high",
            summary="Authentication failures preceded a suspicious login.",
            timeline=[
                "Multiple authentication failures occurred.",
                "A successful login followed.",
            ],
            evidence=[],
            possible_attack_path=[],
            mitre_attack=[],
            affected_assets=["web-server-01"],
            affected_accounts=["administrator"],
            indicators=["198.51.100.24"],
            investigation_steps=[
                "Review authentication logs.",
            ],
            containment_actions=[
                "Temporarily disable the affected account.",
            ],
            limitations=[
                "The submitted dataset is limited.",
            ],
        )

        analyzer_class.return_value = analyzer

        response = self.client.post(
            self.url,
            {
                "security_events": (
                    "Repeated login failures followed by a successful login."
                ),
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Possible account compromise")
        self.assertContains(response, "High confidence")
        self.assertContains(response, "198.51.100.24")

        analyzer.analyze.assert_called_once()
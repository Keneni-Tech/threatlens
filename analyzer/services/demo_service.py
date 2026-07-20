from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings

from analyzer.models import Investigation


DEMO_CASE_TITLE = (
    "Possible administrator account compromise"
)

DEMO_RAW_EVENTS = """\
2026-07-18T14:02:11Z host=web-server-01 event=login_failure user=administrator source_ip=198.51.100.24
2026-07-18T14:02:18Z host=web-server-01 event=login_failure user=administrator source_ip=198.51.100.24
2026-07-18T14:02:27Z host=web-server-01 event=login_failure user=administrator source_ip=198.51.100.24
2026-07-18T14:03:04Z host=web-server-01 event=login_success user=administrator source_ip=198.51.100.24
2026-07-18T14:04:31Z host=web-server-01 event=process_start user=administrator process=powershell.exe command="-EncodedCommand SQBFAFgA"
2026-07-18T14:05:44Z host=web-server-01 event=outbound_connection process=powershell.exe destination_ip=203.0.113.51 destination_port=443
"""


@dataclass(frozen=True, slots=True)
class DemoCaseResult:
    investigation: Investigation
    created: bool


class DemoCaseService:
    """
    Create or return a deterministic demonstration investigation.

    This does not call OpenAI and therefore produces a fast,
    repeatable competition demonstration.
    """

    @staticmethod
    def create_or_get() -> DemoCaseResult:
        if not getattr(
            settings,
            "THREATLENS_DEMO_MODE",
            False,
        ):
            raise PermissionError(
                "ThreatLens demo mode is disabled."
            )

        investigation, created = (
            Investigation.objects.get_or_create(
                title=DEMO_CASE_TITLE,
                summary=(
                    "Repeated administrator authentication failures "
                    "were followed by a successful login, encoded "
                    "PowerShell execution, and an outbound network "
                    "connection from the affected server."
                ),
                defaults={
                    "severity": (
                        Investigation.Severity.CRITICAL
                    ),
                    "confidence": (
                        Investigation.Confidence.HIGH
                    ),
                    "raw_events": DEMO_RAW_EVENTS,
                    "input_source": (
                        Investigation.InputSource.PASTED
                    ),
                    "source_event_count": 6,
                    "analysis": {
                        "title": DEMO_CASE_TITLE,
                        "severity": "critical",
                        "confidence": "high",
                        "summary": (
                            "Repeated administrator authentication "
                            "failures were followed by a successful "
                            "login, encoded PowerShell execution, "
                            "and an outbound network connection."
                        ),
                        "timeline": [
                            (
                                "14:02 UTC — Multiple failed "
                                "administrator authentication attempts "
                                "originated from 198.51.100.24."
                            ),
                            (
                                "14:03 UTC — The same source completed "
                                "a successful administrator login."
                            ),
                            (
                                "14:04 UTC — Encoded PowerShell ran "
                                "under the administrator account."
                            ),
                            (
                                "14:05 UTC — PowerShell initiated an "
                                "outbound TLS connection to "
                                "203.0.113.51."
                            ),
                        ],
                        "evidence": [
                            {
                                "title": (
                                    "Authentication failure sequence"
                                ),
                                "description": (
                                    "Three failures targeted the same "
                                    "administrator account immediately "
                                    "before a successful login."
                                ),
                                "event_references": [
                                    "198.51.100.24",
                                    "administrator",
                                ],
                            },
                            {
                                "title": (
                                    "Encoded PowerShell execution"
                                ),
                                "description": (
                                    "PowerShell was launched with an "
                                    "encoded command after the login."
                                ),
                                "event_references": [
                                    "powershell.exe",
                                    "-EncodedCommand",
                                ],
                            },
                            {
                                "title": (
                                    "Post-execution network activity"
                                ),
                                "description": (
                                    "The PowerShell process connected "
                                    "to an external documentation-safe "
                                    "IP address over port 443."
                                ),
                                "event_references": [
                                    "203.0.113.51",
                                    "443",
                                ],
                            },
                        ],
                        "possible_attack_path": [
                            (
                                "Password guessing or credential "
                                "validation targeted the administrator."
                            ),
                            (
                                "The attacker may have obtained access "
                                "to the privileged account."
                            ),
                            (
                                "Encoded PowerShell may have been used "
                                "for payload execution."
                            ),
                            (
                                "The outbound connection may represent "
                                "command-and-control communication."
                            ),
                        ],
                        "mitre_attack": [
                            {
                                "technique_id": "T1110",
                                "technique_name": "Brute Force",
                                "explanation": (
                                    "Repeated authentication failures "
                                    "preceded the successful login."
                                ),
                            },
                            {
                                "technique_id": "T1059.001",
                                "technique_name": (
                                    "PowerShell"
                                ),
                                "explanation": (
                                    "An encoded PowerShell command "
                                    "executed after account access."
                                ),
                            },
                            {
                                "technique_id": "T1071.001",
                                "technique_name": (
                                    "Web Protocols"
                                ),
                                "explanation": (
                                    "The process initiated an outbound "
                                    "connection over TCP port 443."
                                ),
                            },
                        ],
                        "affected_assets": [
                            "web-server-01",
                        ],
                        "affected_accounts": [
                            "administrator",
                        ],
                        "indicators": [
                            "198.51.100.24",
                            "203.0.113.51",
                            "powershell.exe",
                            "-EncodedCommand",
                        ],
                        "investigation_steps": [
                            (
                                "Review complete authentication history "
                                "for the administrator account."
                            ),
                            (
                                "Decode and inspect the PowerShell "
                                "command in an isolated environment."
                            ),
                            (
                                "Collect process, network, and endpoint "
                                "telemetry from web-server-01."
                            ),
                            (
                                "Search the environment for both IP "
                                "addresses and related process activity."
                            ),
                        ],
                        "containment_actions": [
                            (
                                "Disable or reset the affected "
                                "administrator account."
                            ),
                            (
                                "Isolate web-server-01 while preserving "
                                "volatile evidence."
                            ),
                            (
                                "Block the observed external indicators "
                                "after validating business impact."
                            ),
                            (
                                "Revoke active sessions and credentials "
                                "associated with the account."
                            ),
                        ],
                        "limitations": [
                            (
                                "This is a fictional demonstration "
                                "scenario."
                            ),
                            (
                                "No endpoint memory capture, full "
                                "command content, or identity-provider "
                                "history was provided."
                            ),
                        ],
                    },
                },
            )
        )

        return DemoCaseResult(
            investigation=investigation,
            created=created,
        )
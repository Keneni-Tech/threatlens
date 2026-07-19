
from __future__ import annotations

from django import forms
from django.conf import settings
from django.core.files.uploadedfile import UploadedFile


SAMPLE_SECURITY_EVENTS = """2026-07-18T14:02:11Z host=web-server-01 event=login_failure user=administrator source_ip=198.51.100.24
2026-07-18T14:02:18Z host=web-server-01 event=login_failure user=administrator source_ip=198.51.100.24
2026-07-18T14:02:27Z host=web-server-01 event=login_failure user=administrator source_ip=198.51.100.24
2026-07-18T14:03:04Z host=web-server-01 event=login_success user=administrator source_ip=198.51.100.24
2026-07-18T14:04:31Z host=web-server-01 event=process_start user=administrator process=powershell.exe command="-EncodedCommand SQBFAFgA"
"""


class IncidentAnalysisForm(forms.Form):
    security_events = forms.CharField(
        required=False,
        label="Paste security events",
        widget=forms.Textarea(
            attrs={
                "rows": 18,
                "placeholder": (
                    "Paste sanitized logs, alerts, authentication "
                    "events, endpoint telemetry, or cloud audit events..."
                ),
                "spellcheck": "false",
                "autocomplete": "off",
            }
        ),
    )

    event_file = forms.FileField(
        required=False,
        label="Upload an event file",
        widget=forms.ClearableFileInput(
            attrs={
                "accept": (
                    ".txt,.log,.json,.jsonl,.csv,"
                    "text/plain,application/json,text/csv"
                ),
            }
        ),
        help_text=(
            "Supported types: TXT, LOG, JSON, JSONL, and CSV."
        ),
    )

    def clean_event_file(
        self,
    ) -> UploadedFile | None:
        uploaded_file = self.cleaned_data.get(
            "event_file"
        )

        if not uploaded_file:
            return None

        maximum_bytes = getattr(
            settings,
            "THREATLENS_MAX_UPLOAD_BYTES",
            5 * 1024 * 1024,
        )

        if uploaded_file.size > maximum_bytes:
            maximum_mb = maximum_bytes / (1024 * 1024)

            raise forms.ValidationError(
                f"The uploaded file exceeds the "
                f"{maximum_mb:g} MB limit."
            )

        return uploaded_file

    def clean(self):
        cleaned_data = super().clean()

        security_events = (
            cleaned_data.get("security_events")
            or ""
        ).strip()

        event_file = cleaned_data.get("event_file")

        if not security_events and not event_file:
            raise forms.ValidationError(
                "Paste security events or upload an event file."
            )

        if security_events and event_file:
            raise forms.ValidationError(
                "Use one input method at a time: "
                "either paste events or upload a file."
            )

        cleaned_data["security_events"] = security_events

        return cleaned_data
    
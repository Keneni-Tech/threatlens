from django import forms
from django.conf import settings


SAMPLE_SECURITY_EVENTS = """\
2026-07-18T14:02:11Z host=web-server-01 event=authentication_failure \
user=administrator src_ip=198.51.100.24 message="Invalid password"

2026-07-18T14:02:18Z host=web-server-01 event=authentication_failure \
user=administrator src_ip=198.51.100.24 message="Invalid password"

2026-07-18T14:02:27Z host=web-server-01 event=authentication_failure \
user=administrator src_ip=198.51.100.24 message="Invalid password"

2026-07-18T14:03:02Z host=web-server-01 event=authentication_success \
user=administrator src_ip=198.51.100.24 message="Successful administrative login"

2026-07-18T14:05:44Z host=web-server-01 event=process_creation \
user=administrator process=powershell.exe \
command_line="powershell.exe -NoProfile -EncodedCommand REDACTED"
"""


class IncidentAnalysisForm(forms.Form):
    security_events = forms.CharField(
        label="Security events",
        min_length=20,
        max_length=settings.THREATLENS_MAX_INPUT_CHARACTERS,
        strip=True,
        widget=forms.Textarea(
            attrs={
                "rows": 18,
                "placeholder": (
                    "Paste JSON, authentication events, firewall events, "
                    "process logs, or other sanitized security data..."
                ),
                "spellcheck": "false",
                "autocomplete": "off",
            }
        ),
        error_messages={
            "required": "Paste security-event data before analyzing.",
            "min_length": (
                "Provide additional event details so ThreatLens can analyze it."
            ),
            "max_length": (
                "The submitted security data is too large for this demo."
            ),
        },
    )
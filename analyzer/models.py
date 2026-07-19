from __future__ import annotations

import uuid

from django.db import models
from django.urls import reverse


class Investigation(models.Model):
    class Severity(models.TextChoices):
        INFORMATIONAL = "informational", "Informational"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Confidence(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    title = models.CharField(
        max_length=255,
    )

    severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        db_index=True,
    )

    confidence = models.CharField(
        max_length=20,
        choices=Confidence.choices,
        db_index=True,
    )
    class InputSource(models.TextChoices):
        PASTED = "pasted", "Pasted text"
        UPLOADED_FILE = "uploaded_file", "Uploaded file"

    summary = models.TextField()

    raw_events = models.TextField(
        help_text="Sanitized security-event data submitted for analysis.",
    )
    input_source = models.CharField(
        max_length=20,
        choices=InputSource.choices,
        default=InputSource.PASTED,
        db_index=True,
    )

    source_filename = models.CharField(
        max_length=255,
        blank=True,
    )

    source_content_type = models.CharField(
        max_length=100,
        blank=True,
    )

    source_size_bytes = models.PositiveIntegerField(
        null=True,
        blank=True,
    )

    source_event_count = models.PositiveIntegerField(
        null=True,
        blank=True,
    )

    analysis = models.JSONField(
        help_text="Structured AI incident assessment.",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["severity", "-created_at"],
                name="inv_severity_created_idx",
            ),
            models.Index(
                fields=["confidence", "-created_at"],
                name="inv_conf_created_idx",
            ),
        ]

    def __str__(self) -> str:
        return self.title

    def get_absolute_url(self) -> str:
        return reverse(
            "analyzer:investigation_detail",
            kwargs={"investigation_id": self.id},
        )
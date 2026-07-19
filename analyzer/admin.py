from django.contrib import admin

from analyzer.models import Investigation


@admin.register(Investigation)
class InvestigationAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "severity",
        "confidence",
        "input_source",
        "source_event_count",
        "created_at",
    )

    list_filter = (
        "severity",
        "confidence",
        "input_source",
        "created_at",
    )

    search_fields = (
        "title",
        "summary",
        "raw_events",
        "source_filename",
    )

    readonly_fields = (
        "id",
        "input_source",
        "source_filename",
        "source_content_type",
        "source_size_bytes",
        "source_event_count",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        (
            "Investigation",
            {
                "fields": (
                    "id",
                    "title",
                    "severity",
                    "confidence",
                    "summary",
                )
            },
        ),
        (
            "Input source",
            {
                "fields": (
                    "input_source",
                    "source_filename",
                    "source_content_type",
                    "source_size_bytes",
                    "source_event_count",
                    "raw_events",
                )
            },
        ),
        (
            "Structured assessment",
            {
                "fields": (
                    "analysis",
                )
            },
        ),
        (
            "Timestamps",
            {
                "fields": (
                    "created_at",
                    "updated_at",
                )
            },
        ),
    )

    ordering = (
        "-created_at",
    )
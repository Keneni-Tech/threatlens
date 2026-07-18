from django.contrib import admin

from analyzer.models import Investigation


@admin.register(Investigation)
class InvestigationAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "severity",
        "confidence",
        "created_at",
        "updated_at",
    )

    list_filter = (
        "severity",
        "confidence",
        "created_at",
    )

    search_fields = (
        "title",
        "summary",
        "raw_events",
    )

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )

    ordering = (
        "-created_at",
    )
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.db.models import Count, Q, QuerySet
from django.utils import timezone

from analyzer.forms import InvestigationFilterForm
from analyzer.models import Investigation


@dataclass(frozen=True, slots=True)
class SeverityMetric:
    value: str
    label: str
    count: int
    percentage: float


@dataclass(frozen=True, slots=True)
class DashboardMetrics:
    total: int
    critical: int
    high: int
    medium: int
    low: int
    informational: int
    uploaded: int
    pasted: int
    last_7_days: int
    high_priority: int
    severity_distribution: tuple[SeverityMetric, ...]


class InvestigationDashboardService:
    """
    Build dashboard metrics and filtered investigation querysets.
    """

    SEVERITY_RANK = {
        Investigation.Severity.CRITICAL: 5,
        Investigation.Severity.HIGH: 4,
        Investigation.Severity.MEDIUM: 3,
        Investigation.Severity.LOW: 2,
        Investigation.Severity.INFORMATIONAL: 1,
    }

    SORT_MAPPING = {
        InvestigationFilterForm.SortChoice.NEWEST: (
            "-created_at",
        ),
        InvestigationFilterForm.SortChoice.OLDEST: (
            "created_at",
        ),
        InvestigationFilterForm.SortChoice.TITLE_ASC: (
            "title",
            "-created_at",
        ),
    }

    @classmethod
    def build_queryset(
        cls,
        *,
        cleaned_filters: dict[str, Any],
    ) -> QuerySet[Investigation]:
        queryset = Investigation.objects.all()

        search = (
            cleaned_filters.get("search")
            or ""
        ).strip()

        severity = (
            cleaned_filters.get("severity")
            or ""
        )

        confidence = (
            cleaned_filters.get("confidence")
            or ""
        )

        input_source = (
            cleaned_filters.get("input_source")
            or ""
        )

        sort = (
            cleaned_filters.get("sort")
            or InvestigationFilterForm.SortChoice.NEWEST
        )

        if search:
            queryset = queryset.filter(
                Q(title__icontains=search)
                | Q(summary__icontains=search)
                | Q(raw_events__icontains=search)
                | Q(source_filename__icontains=search)
                | Q(analysis__icontains=search)
            )

        if severity:
            queryset = queryset.filter(
                severity=severity
            )

        if confidence:
            queryset = queryset.filter(
                confidence=confidence
            )

        if input_source:
            queryset = queryset.filter(
                input_source=input_source
            )

        if sort in {
            InvestigationFilterForm
            .SortChoice
            .SEVERITY_DESC,
            InvestigationFilterForm
            .SortChoice
            .SEVERITY_ASC,
        }:
            queryset = cls._sort_by_severity(
                queryset,
                descending=(
                    sort
                    == InvestigationFilterForm
                    .SortChoice
                    .SEVERITY_DESC
                ),
            )

        else:
            queryset = queryset.order_by(
                *cls.SORT_MAPPING.get(
                    sort,
                    ("-created_at",),
                )
            )

        return queryset

    @classmethod
    def build_metrics(
        cls,
    ) -> DashboardMetrics:
        now = timezone.now()
        seven_days_ago = now - timedelta(days=7)

        aggregate_values = (
            Investigation.objects.aggregate(
                total=Count("id"),
                critical=Count(
                    "id",
                    filter=Q(
                        severity=(
                            Investigation
                            .Severity
                            .CRITICAL
                        )
                    ),
                ),
                high=Count(
                    "id",
                    filter=Q(
                        severity=(
                            Investigation
                            .Severity
                            .HIGH
                        )
                    ),
                ),
                medium=Count(
                    "id",
                    filter=Q(
                        severity=(
                            Investigation
                            .Severity
                            .MEDIUM
                        )
                    ),
                ),
                low=Count(
                    "id",
                    filter=Q(
                        severity=(
                            Investigation
                            .Severity
                            .LOW
                        )
                    ),
                ),
                informational=Count(
                    "id",
                    filter=Q(
                        severity=(
                            Investigation
                            .Severity
                            .INFORMATIONAL
                        )
                    ),
                ),
                uploaded=Count(
                    "id",
                    filter=Q(
                        input_source=(
                            Investigation
                            .InputSource
                            .UPLOADED_FILE
                        )
                    ),
                ),
                pasted=Count(
                    "id",
                    filter=Q(
                        input_source=(
                            Investigation
                            .InputSource
                            .PASTED
                        )
                    ),
                ),
                last_7_days=Count(
                    "id",
                    filter=Q(
                        created_at__gte=seven_days_ago
                    ),
                ),
                high_priority=Count(
                    "id",
                    filter=Q(
                        severity__in=[
                            Investigation
                            .Severity
                            .CRITICAL,
                            Investigation
                            .Severity
                            .HIGH,
                        ]
                    ),
                ),
            )
        )

        total = aggregate_values["total"] or 0

        severity_items = [
            (
                value,
                label,
                aggregate_values.get(value) or 0,
            )
            for value, label
            in Investigation.Severity.choices
        ]

        percentages = [
            cls._percentage(count, total)
            for _, _, count in severity_items
        ]

        if total > 0:
            rounded_total = sum(percentages)
            if rounded_total != 100.0:
                percentages[-1] = round(
                    percentages[-1] + (100.0 - rounded_total),
                    1,
                )

        severity_distribution = tuple(
            SeverityMetric(
                value=value,
                label=label,
                count=count,
                percentage=percentage,
            )
            for (value, label, count), percentage
            in zip(severity_items, percentages)
        )

        return DashboardMetrics(
            total=total,
            critical=(
                aggregate_values["critical"]
                or 0
            ),
            high=aggregate_values["high"] or 0,
            medium=(
                aggregate_values["medium"]
                or 0
            ),
            low=aggregate_values["low"] or 0,
            informational=(
                aggregate_values["informational"]
                or 0
            ),
            uploaded=(
                aggregate_values["uploaded"]
                or 0
            ),
            pasted=(
                aggregate_values["pasted"]
                or 0
            ),
            last_7_days=(
                aggregate_values["last_7_days"]
                or 0
            ),
            high_priority=(
                aggregate_values["high_priority"]
                or 0
            ),
            severity_distribution=(
                severity_distribution
            ),
        )

    @staticmethod
    def get_recent_activity(
        *,
        limit: int = 5,
    ) -> QuerySet[Investigation]:
        return (
            Investigation.objects
            .order_by("-created_at")[:limit]
        )

    @classmethod
    def _sort_by_severity(
        cls,
        queryset: QuerySet[Investigation],
        *,
        descending: bool,
    ) -> QuerySet[Investigation]:
        from django.db.models import (
            Case,
            IntegerField,
            Value,
            When,
        )

        conditions = [
            When(
                severity=severity,
                then=Value(rank),
            )
            for severity, rank
            in cls.SEVERITY_RANK.items()
        ]

        queryset = queryset.annotate(
            severity_rank=Case(
                *conditions,
                default=Value(0),
                output_field=IntegerField(),
            )
        )

        if descending:
            return queryset.order_by(
                "-severity_rank",
                "-created_at",
            )

        return queryset.order_by(
            "severity_rank",
            "-created_at",
        )

    @staticmethod
    def _percentage(
        value: int,
        total: int,
    ) -> float:
        if total <= 0:
            return 0.0

        return round(
            (value / total) * 100,
            1,
        )
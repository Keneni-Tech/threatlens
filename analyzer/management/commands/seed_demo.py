from __future__ import annotations

from django.core.management.base import (
    BaseCommand,
    CommandError,
)

from analyzer.services.demo_service import (
    DemoCaseService,
)


class Command(BaseCommand):
    help = (
        "Create the deterministic ThreatLens demonstration case."
    )

    def handle(
        self,
        *args,
        **options,
    ):
        try:
            result = DemoCaseService.create_or_get()

        except PermissionError as exc:
            raise CommandError(str(exc)) from exc

        if result.created:
            self.stdout.write(
                self.style.SUCCESS(
                    "ThreatLens demonstration case created."
                )
            )

        else:
            self.stdout.write(
                self.style.WARNING(
                    "ThreatLens demonstration case already exists."
                )
            )

        self.stdout.write(
            f"Case ID: {result.investigation.id}"
        )
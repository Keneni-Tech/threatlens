from __future__ import annotations

import logging
from dataclasses import asdict, dataclass

from django.db import connection
from django.utils import timezone


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class HealthCheckResult:
    status: str
    database: str
    timestamp: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


class HealthCheckService:
    @staticmethod
    def check() -> HealthCheckResult:
        database_status = "available"
        overall_status = "ok"

        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()

        except Exception:
            logger.exception("ThreatLens database health check failed.")
            database_status = "unavailable"
            overall_status = "degraded"

        return HealthCheckResult(
            status=overall_status,
            database=database_status,
            timestamp=timezone.now().isoformat(),
        )

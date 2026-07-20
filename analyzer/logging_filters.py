from __future__ import annotations

import logging

from analyzer.request_context import get_request_id


class RequestIDLogFilter(logging.Filter):
    def filter(
        self,
        record: logging.LogRecord,
    ) -> bool:
        record.request_id = get_request_id()
        return True
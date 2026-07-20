from __future__ import annotations

import uuid
from collections.abc import Callable
from re import fullmatch

from django.http import HttpRequest, HttpResponse

from analyzer.request_context import (
    reset_request_id,
    set_request_id,
)


class RequestIDMiddleware:
    """
    Attach a request ID to each request and response.

    A valid client-supplied ID is reused when present. Otherwise,
    ThreatLens generates a UUID.
    """

    HEADER_NAME = "HTTP_X_REQUEST_ID"
    RESPONSE_HEADER_NAME = "X-Request-ID"
    MAX_REQUEST_ID_LENGTH = 100

    def __init__(
        self,
        get_response: Callable[
            [HttpRequest],
            HttpResponse,
        ],
    ) -> None:
        self.get_response = get_response

    def __call__(
        self,
        request: HttpRequest,
    ) -> HttpResponse:
        supplied_request_id = (
            request.META
            .get(self.HEADER_NAME, "")
            .strip()
        )

        if (
            supplied_request_id
            and len(supplied_request_id)
            <= self.MAX_REQUEST_ID_LENGTH
            and fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]*",
                supplied_request_id,
            )
        ):
            request_id = supplied_request_id

        else:
            request_id = str(uuid.uuid4())

        request.request_id = request_id

        token = set_request_id(request_id)

        try:
            response = self.get_response(request)

            response[
                self.RESPONSE_HEADER_NAME
            ] = request_id

            return response

        finally:
            reset_request_id(token)

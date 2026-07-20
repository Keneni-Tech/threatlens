from __future__ import annotations

from contextvars import ContextVar


_current_request_id: ContextVar[str] = ContextVar(
    "threatlens_request_id",
    default="-",
)


def set_request_id(
    request_id: str,
):
    return _current_request_id.set(request_id)


def reset_request_id(token) -> None:
    _current_request_id.reset(token)


def get_request_id() -> str:
    return _current_request_id.get()
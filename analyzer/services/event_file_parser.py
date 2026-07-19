from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.files.uploadedfile import UploadedFile


class EventFileValidationError(ValueError):
    """
    Raised when an uploaded security-event file is unsafe or unsupported.
    """


class EventFileParseError(ValueError):
    """
    Raised when ThreatLens cannot parse an otherwise supported file.
    """


@dataclass(frozen=True, slots=True)
class ParsedEventFile:
    filename: str
    extension: str
    content_type: str
    size_bytes: int
    event_count: int
    text: str


class EventFileParser:
    """
    Validate and normalize supported security-event files.

    Supported extensions:

    - .txt
    - .log
    - .json
    - .jsonl
    - .csv

    Uploaded files are parsed in memory and are not persisted to disk.
    """

    DEFAULT_MAX_UPLOAD_BYTES = 5 * 1024 * 1024
    DEFAULT_MAX_PARSED_CHARACTERS = 200_000

    SUPPORTED_EXTENSIONS = {
        ".txt",
        ".log",
        ".json",
        ".jsonl",
        ".csv",
    }

    TEXT_CONTENT_TYPES = {
        "text/plain",
        "application/octet-stream",
    }

    JSON_CONTENT_TYPES = {
        "application/json",
        "text/json",
        "application/octet-stream",
        "text/plain",
    }

    CSV_CONTENT_TYPES = {
        "text/csv",
        "application/csv",
        "application/vnd.ms-excel",
        "application/octet-stream",
        "text/plain",
    }

    def __init__(
        self,
        *,
        max_upload_bytes: int | None = None,
        max_parsed_characters: int | None = None,
    ) -> None:
        self.max_upload_bytes = (
            max_upload_bytes
            if max_upload_bytes is not None
            else getattr(
                settings,
                "THREATLENS_MAX_UPLOAD_BYTES",
                self.DEFAULT_MAX_UPLOAD_BYTES,
            )
        )

        self.max_parsed_characters = (
            max_parsed_characters
            if max_parsed_characters is not None
            else getattr(
                settings,
                "THREATLENS_MAX_PARSED_CHARACTERS",
                self.DEFAULT_MAX_PARSED_CHARACTERS,
            )
        )

        configured_extensions = getattr(
            settings,
            "THREATLENS_ALLOWED_UPLOAD_EXTENSIONS",
            self.SUPPORTED_EXTENSIONS,
        )

        self.allowed_extensions = {
            str(extension).lower()
            for extension in configured_extensions
        }

    def parse(
        self,
        uploaded_file: UploadedFile,
    ) -> ParsedEventFile:
        self._validate_file_metadata(uploaded_file)

        filename = Path(uploaded_file.name).name
        extension = Path(filename).suffix.lower()
        content_type = (
            uploaded_file.content_type
            or "application/octet-stream"
        ).lower()

        raw_content = self._read_upload(uploaded_file)
        decoded_content = self._decode_text(raw_content)

        if extension in {".txt", ".log"}:
            self._validate_content_type(
                content_type,
                self.TEXT_CONTENT_TYPES,
                extension,
            )

            normalized_text, event_count = self._parse_plain_text(
                decoded_content
            )

        elif extension == ".json":
            self._validate_content_type(
                content_type,
                self.JSON_CONTENT_TYPES,
                extension,
            )

            normalized_text, event_count = self._parse_json(
                decoded_content
            )

        elif extension == ".jsonl":
            self._validate_content_type(
                content_type,
                self.JSON_CONTENT_TYPES,
                extension,
            )

            normalized_text, event_count = self._parse_jsonl(
                decoded_content
            )

        elif extension == ".csv":
            self._validate_content_type(
                content_type,
                self.CSV_CONTENT_TYPES,
                extension,
            )

            normalized_text, event_count = self._parse_csv(
                decoded_content
            )

        else:
            raise EventFileValidationError(
                f"Unsupported file extension: {extension or 'none'}."
            )

        normalized_text = normalized_text.strip()

        if not normalized_text:
            raise EventFileParseError(
                "The uploaded file did not contain usable security events."
            )

        if len(normalized_text) > self.max_parsed_characters:
            raise EventFileValidationError(
                "The parsed file is too large. "
                f"The maximum is "
                f"{self.max_parsed_characters:,} characters."
            )

        return ParsedEventFile(
            filename=filename,
            extension=extension,
            content_type=content_type,
            size_bytes=uploaded_file.size,
            event_count=event_count,
            text=normalized_text,
        )

    def _validate_file_metadata(
        self,
        uploaded_file: UploadedFile,
    ) -> None:
        if not uploaded_file:
            raise EventFileValidationError(
                "No event file was provided."
            )

        filename = Path(uploaded_file.name).name

        if not filename:
            raise EventFileValidationError(
                "The uploaded file must have a valid filename."
            )

        extension = Path(filename).suffix.lower()

        if extension not in self.allowed_extensions:
            allowed = ", ".join(
                sorted(self.allowed_extensions)
            )

            raise EventFileValidationError(
                f"Unsupported file type. Allowed types: {allowed}."
            )

        if uploaded_file.size <= 0:
            raise EventFileValidationError(
                "The uploaded file is empty."
            )

        if uploaded_file.size > self.max_upload_bytes:
            maximum_mb = (
                self.max_upload_bytes
                / (1024 * 1024)
            )

            raise EventFileValidationError(
                "The uploaded file is too large. "
                f"The maximum size is {maximum_mb:g} MB."
            )

    @staticmethod
    def _validate_content_type(
        content_type: str,
        allowed_content_types: set[str],
        extension: str,
    ) -> None:
        if content_type not in allowed_content_types:
            raise EventFileValidationError(
                f"The reported content type '{content_type}' "
                f"does not match a supported {extension} file."
            )

    def _read_upload(
        self,
        uploaded_file: UploadedFile,
    ) -> bytes:
        chunks: list[bytes] = []
        bytes_read = 0

        try:
            for chunk in uploaded_file.chunks():
                bytes_read += len(chunk)

                if bytes_read > self.max_upload_bytes:
                    raise EventFileValidationError(
                        "The uploaded file exceeded the maximum "
                        "size while it was being read."
                    )

                chunks.append(chunk)

        except EventFileValidationError:
            raise

        except Exception as exc:
            raise EventFileParseError(
                "ThreatLens could not read the uploaded file."
            ) from exc

        return b"".join(chunks)

    @staticmethod
    def _decode_text(raw_content: bytes) -> str:
        if b"\x00" in raw_content:
            raise EventFileValidationError(
                "The uploaded file appears to contain binary data."
            )

        encodings = (
            "utf-8-sig",
            "utf-8",
            "utf-16",
        )

        for encoding in encodings:
            try:
                return raw_content.decode(encoding)

            except UnicodeDecodeError:
                continue

        raise EventFileParseError(
            "The file encoding is unsupported. "
            "Use UTF-8 or UTF-16 text."
        )

    @staticmethod
    def _parse_plain_text(
        content: str,
    ) -> tuple[str, int]:
        lines = [
            line.strip()
            for line in content.splitlines()
            if line.strip()
        ]

        return "\n".join(lines), len(lines)

    @classmethod
    def _parse_json(
        cls,
        content: str,
    ) -> tuple[str, int]:
        try:
            data = json.loads(content)

        except json.JSONDecodeError as exc:
            raise EventFileParseError(
                "The uploaded JSON file is invalid. "
                f"Error near line {exc.lineno}, "
                f"column {exc.colno}."
            ) from exc

        if isinstance(data, list):
            event_count = len(data)

        elif isinstance(data, dict):
            event_count = 1

        else:
            raise EventFileParseError(
                "The JSON root must be an object or an array."
            )

        normalized = json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )

        return normalized, event_count

    @classmethod
    def _parse_jsonl(
        cls,
        content: str,
    ) -> tuple[str, int]:
        events: list[Any] = []

        for line_number, raw_line in enumerate(
            content.splitlines(),
            start=1,
        ):
            line = raw_line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

            except json.JSONDecodeError as exc:
                raise EventFileParseError(
                    "Invalid JSONL data on "
                    f"line {line_number}: {exc.msg}."
                ) from exc

            if not isinstance(event, dict):
                raise EventFileParseError(
                    "Each JSONL line must contain a JSON object. "
                    f"Line {line_number} contains "
                    f"{type(event).__name__}."
                )

            events.append(event)

        if not events:
            raise EventFileParseError(
                "The JSONL file contains no events."
            )

        normalized_lines = [
            json.dumps(
                event,
                ensure_ascii=False,
                sort_keys=True,
            )
            for event in events
        ]

        return "\n".join(normalized_lines), len(events)

    @classmethod
    def _parse_csv(
        cls,
        content: str,
    ) -> tuple[str, int]:
        stream = io.StringIO(
            content,
            newline="",
        )

        try:
            sample = content[:4096]

            dialect = csv.Sniffer().sniff(
                sample,
                delimiters=",;\t|",
            )

        except csv.Error:
            dialect = csv.excel

        try:
            reader = csv.DictReader(
                stream,
                dialect=dialect,
            )

            if not reader.fieldnames:
                raise EventFileParseError(
                    "The CSV file must contain a header row."
                )

            fieldnames = [
                str(field).strip()
                for field in reader.fieldnames
                if field is not None
            ]

            if not fieldnames:
                raise EventFileParseError(
                    "The CSV header does not contain valid columns."
                )

            events: list[dict[str, str]] = []

            for row_number, row in enumerate(
                reader,
                start=2,
            ):
                if None in row:
                    raise EventFileParseError(
                        "The CSV file has more values than headers "
                        f"on row {row_number}."
                    )

                normalized_row = {
                    str(key).strip(): (
                        str(value).strip()
                        if value is not None
                        else ""
                    )
                    for key, value in row.items()
                    if key is not None
                }

                if any(normalized_row.values()):
                    events.append(normalized_row)

        except EventFileParseError:
            raise

        except csv.Error as exc:
            raise EventFileParseError(
                "The uploaded CSV file is invalid."
            ) from exc

        if not events:
            raise EventFileParseError(
                "The CSV file contains no event rows."
            )

        normalized = json.dumps(
            events,
            indent=2,
            ensure_ascii=False,
        )

        return normalized, len(events)
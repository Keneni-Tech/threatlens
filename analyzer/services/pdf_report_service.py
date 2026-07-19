from __future__ import annotations

import logging
from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from analyzer.models import Investigation


logger = logging.getLogger(__name__)


class PDFReportError(Exception):
    """Raised when ThreatLens cannot generate an investigation report."""


class InvestigationPDFReportService:
    """
    Generate an executive PDF report for a saved investigation.

    The PDF is created entirely in memory and returned as bytes.
    """

    PAGE_WIDTH, PAGE_HEIGHT = LETTER

    COLOR_BACKGROUND = colors.HexColor("#071019")
    COLOR_SURFACE = colors.HexColor("#0D1824")
    COLOR_SURFACE_LIGHT = colors.HexColor("#F4F7FA")
    COLOR_TEXT = colors.HexColor("#17212B")
    COLOR_MUTED = colors.HexColor("#5B6B79")
    COLOR_BORDER = colors.HexColor("#D7E0E7")
    COLOR_ACCENT = colors.HexColor("#117A6D")
    COLOR_ACCENT_LIGHT = colors.HexColor("#DDF4EF")
    COLOR_WHITE = colors.white

    SEVERITY_COLORS = {
        Investigation.Severity.INFORMATIONAL: colors.HexColor("#2563EB"),
        Investigation.Severity.LOW: colors.HexColor("#16836F"),
        Investigation.Severity.MEDIUM: colors.HexColor("#A16207"),
        Investigation.Severity.HIGH: colors.HexColor("#C2410C"),
        Investigation.Severity.CRITICAL: colors.HexColor("#B91C1C"),
    }

    def __init__(self, investigation: Investigation) -> None:
        self.investigation = investigation
        self.analysis = investigation.analysis or {}
        self.styles = self._build_styles()

    def generate(self) -> bytes:
        """
        Build and return the complete PDF file as bytes.
        """

        output = BytesIO()

        try:
            document = SimpleDocTemplate(
                output,
                pagesize=LETTER,
                rightMargin=0.65 * inch,
                leftMargin=0.65 * inch,
                topMargin=0.8 * inch,
                bottomMargin=0.7 * inch,
                title=self.investigation.title,
                author="ThreatLens",
                subject="AI-assisted security incident investigation",
                creator="ThreatLens",
            )

            story = self._build_story()

            document.build(
                story,
                onFirstPage=self._draw_page,
                onLaterPages=self._draw_page,
            )

            return output.getvalue()

        except Exception as exc:
            logger.exception(
                "Failed to generate PDF for investigation %s.",
                self.investigation.id,
            )

            raise PDFReportError(
                "ThreatLens could not generate the PDF report."
            ) from exc

        finally:
            output.close()

    def _build_story(self) -> list[Any]:
        story: list[Any] = []

        story.extend(self._build_cover_section())
        story.extend(self._build_executive_summary())
        story.extend(self._build_incident_overview())
        story.extend(self._build_timeline())
        story.extend(self._build_evidence())
        story.extend(self._build_attack_path())
        story.extend(self._build_mitre_mapping())
        story.extend(self._build_assets_and_indicators())
        story.extend(self._build_investigation_steps())
        story.extend(self._build_containment_actions())
        story.extend(self._build_limitations())
        story.extend(self._build_methodology_notice())

        return story

    def _build_cover_section(self) -> list[Any]:
        severity = self.investigation.get_severity_display()
        confidence = self.investigation.get_confidence_display()

        severity_color = self.SEVERITY_COLORS.get(
            self.investigation.severity,
            self.COLOR_MUTED,
        )

        metadata = [
            [
                self._paragraph("Severity", "metadata_label"),
                self._paragraph(
                    severity,
                    "metadata_value",
                    text_color=severity_color,
                ),
                self._paragraph("Confidence", "metadata_label"),
                self._paragraph(confidence, "metadata_value"),
            ],
            [
                self._paragraph("Case ID", "metadata_label"),
                self._paragraph(
                    str(self.investigation.id),
                    "metadata_value_small",
                ),
                self._paragraph("Created", "metadata_label"),
                self._paragraph(
                    self.investigation.created_at.strftime(
                        "%B %d, %Y at %I:%M %p"
                    ),
                    "metadata_value_small",
                ),
            ],
        ]

        metadata_table = Table(
            metadata,
            colWidths=[
                0.8 * inch,
                1.55 * inch,
                0.9 * inch,
                2.6 * inch,
            ],
            hAlign="LEFT",
        )

        metadata_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), self.COLOR_SURFACE_LIGHT),
                    ("BOX", (0, 0), (-1, -1), 0.7, self.COLOR_BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.4, self.COLOR_BORDER),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 9),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )

        return [
            Spacer(1, 0.15 * inch),
            Paragraph(
                "THREATLENS",
                self.styles["report_brand"],
            ),
            Paragraph(
                "AI-Assisted Security Incident Report",
                self.styles["report_subtitle"],
            ),
            Spacer(1, 0.28 * inch),
            Paragraph(
                self._safe(self.investigation.title),
                self.styles["report_title"],
            ),
            Spacer(1, 0.22 * inch),
            metadata_table,
            Spacer(1, 0.3 * inch),
            HRFlowable(
                width="100%",
                thickness=1,
                color=self.COLOR_BORDER,
            ),
            Spacer(1, 0.18 * inch),
        ]

    def _build_executive_summary(self) -> list[Any]:
        return self._section(
            "Executive Summary",
            [
                Paragraph(
                    self._safe(self.investigation.summary),
                    self.styles["body"],
                )
            ],
        )

    def _build_incident_overview(self) -> list[Any]:
        affected_assets = self._string_list("affected_assets")
        affected_accounts = self._string_list("affected_accounts")
        indicators = self._string_list("indicators")
        input_source = (
            self.investigation.get_input_source_display()
        )

        source_filename = (
            self.investigation.source_filename
            or "Not applicable"
        )

        source_event_count = (
            str(self.investigation.source_event_count)
            if self.investigation.source_event_count is not None
            else "Unknown"
        )

        [
            self._paragraph(
                "Input source",
                "table_heading",
            ),
            self._paragraph(
                input_source,
                "table_body",
            ),
        ],
        [
            self._paragraph(
                "Source filename",
                "table_heading",
            ),
            self._paragraph(
                source_filename,
                "table_body",
            ),
        ],
        [
            self._paragraph(
                "Parsed events",
                "table_heading",
            ),
            self._paragraph(
                source_event_count,
                "table_body",
            ),
        ],
        rows = [
            [
                self._paragraph("Affected assets", "table_heading"),
                self._paragraph(
                    self._join_or_default(
                        affected_assets,
                        "No affected assets confirmed.",
                    ),
                    "table_body",
                ),
            ],
            [
                self._paragraph("Affected accounts", "table_heading"),
                self._paragraph(
                    self._join_or_default(
                        affected_accounts,
                        "No affected accounts confirmed.",
                    ),
                    "table_body",
                ),
            ],
            [
                self._paragraph("Observed indicators", "table_heading"),
                self._paragraph(
                    self._join_or_default(
                        indicators,
                        "No useful indicators extracted.",
                    ),
                    "table_body",
                ),
            ],
        ]

        table = Table(
            rows,
            colWidths=[1.55 * inch, 5.0 * inch],
            hAlign="LEFT",
            repeatRows=0,
        )

        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), self.COLOR_ACCENT_LIGHT),
                    ("BACKGROUND", (1, 0), (1, -1), self.COLOR_SURFACE_LIGHT),
                    ("BOX", (0, 0), (-1, -1), 0.6, self.COLOR_BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.4, self.COLOR_BORDER),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 9),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )

        return self._section(
            "Incident Overview",
            [table],
        )

    def _build_timeline(self) -> list[Any]:
        return self._list_section(
            "Incident Timeline",
            self._string_list("timeline"),
            "No reliable timeline was identified.",
            numbered=True,
        )

    def _build_attack_path(self) -> list[Any]:
        return self._list_section(
            "Possible Attack Path",
            self._string_list("possible_attack_path"),
            "Insufficient evidence was available to construct an attack path.",
            numbered=True,
        )

    def _build_evidence(self) -> list[Any]:
        evidence = self.analysis.get("evidence") or []

        if not isinstance(evidence, list) or not evidence:
            return self._section(
                "Important Evidence",
                [
                    Paragraph(
                        "No strong evidence items were identified.",
                        self.styles["muted"],
                    )
                ],
            )

        items: list[Any] = []

        for index, item in enumerate(evidence, start=1):
            if not isinstance(item, dict):
                continue

            title = self._safe(
                str(item.get("title") or f"Evidence item {index}")
            )

            description = self._safe(
                str(
                    item.get("description")
                    or "No evidence description was provided."
                )
            )

            references = item.get("event_references") or []

            block: list[Any] = [
                Paragraph(
                    f"{index}. {title}",
                    self.styles["item_heading"],
                ),
                Paragraph(
                    description,
                    self.styles["body"],
                ),
            ]

            if isinstance(references, list) and references:
                reference_text = ", ".join(
                    self._safe(str(reference))
                    for reference in references
                    if reference
                )

                if reference_text:
                    block.append(
                        Paragraph(
                            f"<b>References:</b> {reference_text}",
                            self.styles["reference"],
                        )
                    )

            items.append(
                KeepTogether(
                    [
                        *block,
                        Spacer(1, 0.12 * inch),
                    ]
                )
            )

        if not items:
            items.append(
                Paragraph(
                    "No usable evidence items were found.",
                    self.styles["muted"],
                )
            )

        return self._section(
            "Important Evidence",
            items,
        )

    def _build_mitre_mapping(self) -> list[Any]:
        techniques = self.analysis.get("mitre_attack") or []

        if not isinstance(techniques, list) or not techniques:
            return self._section(
                "MITRE ATT&CK Mapping",
                [
                    Paragraph(
                        "No reliable MITRE ATT&CK mapping was identified.",
                        self.styles["muted"],
                    )
                ],
            )

        rows: list[list[Any]] = [
            [
                self._paragraph("Technique", "table_heading"),
                self._paragraph("Name", "table_heading"),
                self._paragraph("Assessment basis", "table_heading"),
            ]
        ]

        for technique in techniques:
            if not isinstance(technique, dict):
                continue

            rows.append(
                [
                    self._paragraph(
                        str(
                            technique.get("technique_id")
                            or "Unconfirmed"
                        ),
                        "table_body",
                    ),
                    self._paragraph(
                        str(
                            technique.get("technique_name")
                            or "Unconfirmed technique"
                        ),
                        "table_body",
                    ),
                    self._paragraph(
                        str(
                            technique.get("explanation")
                            or "No explanation provided."
                        ),
                        "table_body",
                    ),
                ]
            )

        if len(rows) == 1:
            return self._section(
                "MITRE ATT&CK Mapping",
                [
                    Paragraph(
                        "No usable technique mappings were found.",
                        self.styles["muted"],
                    )
                ],
            )

        table = Table(
            rows,
            colWidths=[
                1.05 * inch,
                1.7 * inch,
                3.8 * inch,
            ],
            repeatRows=1,
            hAlign="LEFT",
        )

        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), self.COLOR_ACCENT),
                    ("TEXTCOLOR", (0, 0), (-1, 0), self.COLOR_WHITE),
                    ("BACKGROUND", (0, 1), (-1, -1), self.COLOR_SURFACE_LIGHT),
                    ("BOX", (0, 0), (-1, -1), 0.6, self.COLOR_BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.4, self.COLOR_BORDER),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )

        return self._section(
            "MITRE ATT&CK Mapping",
            [table],
        )

    def _build_assets_and_indicators(self) -> list[Any]:
        indicators = self._string_list("indicators")
        assets = self._string_list("affected_assets")
        accounts = self._string_list("affected_accounts")

        content: list[Any] = []

        content.extend(
            self._subsection_list(
                "Observed Indicators",
                indicators,
                "No useful indicators were extracted.",
            )
        )

        content.extend(
            self._subsection_list(
                "Affected Assets",
                assets,
                "No affected assets were confirmed.",
            )
        )

        content.extend(
            self._subsection_list(
                "Affected Accounts",
                accounts,
                "No affected accounts were confirmed.",
            )
        )

        return self._section(
            "Scope and Indicators",
            content,
        )

    def _build_investigation_steps(self) -> list[Any]:
        return self._list_section(
            "Recommended Investigation Steps",
            self._string_list("investigation_steps"),
            "No investigation steps were generated.",
            numbered=True,
        )

    def _build_containment_actions(self) -> list[Any]:
        actions = self._string_list("containment_actions")

        content: list[Any] = []

        if actions:
            content.append(
                Table(
                    [
                        [
                            Paragraph(
                                "Priority",
                                self.styles["table_heading"],
                            ),
                            Paragraph(
                                "Recommended containment action",
                                self.styles["table_heading"],
                            ),
                        ],
                        *[
                            [
                                Paragraph(
                                    str(index),
                                    self.styles["priority_number"],
                                ),
                                Paragraph(
                                    self._safe(action),
                                    self.styles["table_body"],
                                ),
                            ]
                            for index, action in enumerate(actions, start=1)
                        ],
                    ],
                    colWidths=[0.7 * inch, 5.85 * inch],
                    repeatRows=1,
                    style=TableStyle(
                        [
                            (
                                "BACKGROUND",
                                (0, 0),
                                (-1, 0),
                                colors.HexColor("#9F2F2F"),
                            ),
                            (
                                "TEXTCOLOR",
                                (0, 0),
                                (-1, 0),
                                self.COLOR_WHITE,
                            ),
                            (
                                "BACKGROUND",
                                (0, 1),
                                (-1, -1),
                                colors.HexColor("#FFF5F5"),
                            ),
                            (
                                "BOX",
                                (0, 0),
                                (-1, -1),
                                0.6,
                                self.COLOR_BORDER,
                            ),
                            (
                                "INNERGRID",
                                (0, 0),
                                (-1, -1),
                                0.4,
                                self.COLOR_BORDER,
                            ),
                            (
                                "VALIGN",
                                (0, 0),
                                (-1, -1),
                                "TOP",
                            ),
                            (
                                "ALIGN",
                                (0, 1),
                                (0, -1),
                                "CENTER",
                            ),
                            (
                                "LEFTPADDING",
                                (0, 0),
                                (-1, -1),
                                8,
                            ),
                            (
                                "RIGHTPADDING",
                                (0, 0),
                                (-1, -1),
                                8,
                            ),
                            (
                                "TOPPADDING",
                                (0, 0),
                                (-1, -1),
                                8,
                            ),
                            (
                                "BOTTOMPADDING",
                                (0, 0),
                                (-1, -1),
                                8,
                            ),
                        ]
                    ),
                )
            )
        else:
            content.append(
                Paragraph(
                    "No containment actions were generated.",
                    self.styles["muted"],
                )
            )

        return self._section(
            "Recommended Containment Actions",
            content,
        )

    def _build_limitations(self) -> list[Any]:
        return self._list_section(
            "Limitations and Missing Evidence",
            self._string_list("limitations"),
            "No analysis limitations were recorded.",
            numbered=False,
        )

    def _build_methodology_notice(self) -> list[Any]:
        return [
            PageBreak(),
            Paragraph(
                "Methodology and Responsible Use",
                self.styles["section_heading"],
            ),
            Paragraph(
                (
                    "This report was generated by ThreatLens from the "
                    "security-event data supplied for this investigation. "
                    "The analysis is AI-assisted and should support, not "
                    "replace, review by a qualified security professional."
                ),
                self.styles["body"],
            ),
            Spacer(1, 0.12 * inch),
            Paragraph(
                (
                    "Severity, confidence, attack-path conclusions, and "
                    "MITRE ATT&CK mappings may be incomplete or incorrect "
                    "when the source data is limited, inaccurate, altered, "
                    "or missing contextual information."
                ),
                self.styles["body"],
            ),
            Spacer(1, 0.12 * inch),
            Paragraph(
                (
                    "Containment recommendations should be evaluated against "
                    "the organization's incident-response procedures, legal "
                    "requirements, business impact, and evidence-preservation "
                    "needs before implementation."
                ),
                self.styles["body"],
            ),
            Spacer(1, 0.25 * inch),
            HRFlowable(
                width="100%",
                thickness=1,
                color=self.COLOR_BORDER,
            ),
            Spacer(1, 0.15 * inch),
            Paragraph(
                (
                    f"ThreatLens Case ID: "
                    f"{self._safe(str(self.investigation.id))}"
                ),
                self.styles["reference"],
            ),
        ]

    def _section(
        self,
        title: str,
        content: list[Any],
    ) -> list[Any]:
        return [
            Paragraph(
                self._safe(title),
                self.styles["section_heading"],
            ),
            Spacer(1, 0.06 * inch),
            *content,
            Spacer(1, 0.24 * inch),
        ]

    def _list_section(
        self,
        title: str,
        items: list[str],
        empty_message: str,
        *,
        numbered: bool,
    ) -> list[Any]:
        if not items:
            content: list[Any] = [
                Paragraph(
                    self._safe(empty_message),
                    self.styles["muted"],
                )
            ]
        else:
            content = [
                self._make_list(
                    items,
                    numbered=numbered,
                )
            ]

        return self._section(title, content)

    def _subsection_list(
        self,
        title: str,
        items: list[str],
        empty_message: str,
    ) -> list[Any]:
        content: list[Any] = [
            Paragraph(
                self._safe(title),
                self.styles["subsection_heading"],
            )
        ]

        if items:
            content.append(
                self._make_list(
                    items,
                    numbered=False,
                )
            )
        else:
            content.append(
                Paragraph(
                    self._safe(empty_message),
                    self.styles["muted"],
                )
            )

        content.append(Spacer(1, 0.14 * inch))

        return content

    def _make_list(
        self,
        items: list[str],
        *,
        numbered: bool,
    ) -> ListFlowable:
        list_items = [
            ListItem(
                Paragraph(
                    self._safe(item),
                    self.styles["list_body"],
                ),
                leftIndent=12,
            )
            for item in items
        ]

        return ListFlowable(
            list_items,
            bulletType="1" if numbered else "bullet",
            start="1",
            leftIndent=20,
            bulletFontName="Helvetica-Bold",
            bulletFontSize=9,
            bulletColor=self.COLOR_ACCENT,
            spaceAfter=4,
        )

    def _draw_page(
        self,
        canvas: Canvas,
        document: SimpleDocTemplate,
    ) -> None:
        canvas.saveState()

        canvas.setFillColor(self.COLOR_BACKGROUND)
        canvas.rect(
            0,
            self.PAGE_HEIGHT - 0.48 * inch,
            self.PAGE_WIDTH,
            0.48 * inch,
            fill=1,
            stroke=0,
        )

        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(self.COLOR_WHITE)
        canvas.drawString(
            0.65 * inch,
            self.PAGE_HEIGHT - 0.31 * inch,
            "ThreatLens",
        )

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#C3D1DC"))
        canvas.drawRightString(
            self.PAGE_WIDTH - 0.65 * inch,
            self.PAGE_HEIGHT - 0.31 * inch,
            "AI-Assisted Security Incident Report",
        )

        canvas.setStrokeColor(self.COLOR_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(
            0.65 * inch,
            0.52 * inch,
            self.PAGE_WIDTH - 0.65 * inch,
            0.52 * inch,
        )

        canvas.setFillColor(self.COLOR_MUTED)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(
            0.65 * inch,
            0.33 * inch,
            "Confidential - Defensive security analysis",
        )

        canvas.drawRightString(
            self.PAGE_WIDTH - 0.65 * inch,
            0.33 * inch,
            f"Page {document.page}",
        )

        canvas.restoreState()

    def _build_styles(self) -> dict[str, ParagraphStyle]:
        styles = getSampleStyleSheet()

        return {
            "report_brand": ParagraphStyle(
                "ThreatLensBrand",
                parent=styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=10,
                leading=12,
                textColor=self.COLOR_ACCENT,
                spaceAfter=4,
                letterSpacing=1.8,
            ),
            "report_subtitle": ParagraphStyle(
                "ThreatLensSubtitle",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=10,
                leading=13,
                textColor=self.COLOR_MUTED,
            ),
            "report_title": ParagraphStyle(
                "ThreatLensTitle",
                parent=styles["Title"],
                fontName="Helvetica-Bold",
                fontSize=24,
                leading=29,
                textColor=self.COLOR_TEXT,
                alignment=TA_LEFT,
                spaceAfter=8,
            ),
            "section_heading": ParagraphStyle(
                "ThreatLensSectionHeading",
                parent=styles["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=15,
                leading=19,
                textColor=self.COLOR_TEXT,
                spaceBefore=5,
                spaceAfter=7,
                keepWithNext=True,
            ),
            "subsection_heading": ParagraphStyle(
                "ThreatLensSubsectionHeading",
                parent=styles["Heading3"],
                fontName="Helvetica-Bold",
                fontSize=11,
                leading=14,
                textColor=self.COLOR_ACCENT,
                spaceBefore=4,
                spaceAfter=6,
                keepWithNext=True,
            ),
            "body": ParagraphStyle(
                "ThreatLensBody",
                parent=styles["BodyText"],
                fontName="Helvetica",
                fontSize=9.5,
                leading=14,
                textColor=self.COLOR_TEXT,
                spaceAfter=6,
            ),
            "list_body": ParagraphStyle(
                "ThreatLensListBody",
                parent=styles["BodyText"],
                fontName="Helvetica",
                fontSize=9.25,
                leading=13.5,
                textColor=self.COLOR_TEXT,
                spaceAfter=3,
            ),
            "muted": ParagraphStyle(
                "ThreatLensMuted",
                parent=styles["BodyText"],
                fontName="Helvetica-Oblique",
                fontSize=9,
                leading=13,
                textColor=self.COLOR_MUTED,
            ),
            "item_heading": ParagraphStyle(
                "ThreatLensItemHeading",
                parent=styles["Heading3"],
                fontName="Helvetica-Bold",
                fontSize=10.5,
                leading=14,
                textColor=self.COLOR_ACCENT,
                spaceAfter=4,
                keepWithNext=True,
            ),
            "reference": ParagraphStyle(
                "ThreatLensReference",
                parent=styles["BodyText"],
                fontName="Helvetica",
                fontSize=8,
                leading=11,
                textColor=self.COLOR_MUTED,
            ),
            "metadata_label": ParagraphStyle(
                "MetadataLabel",
                parent=styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=10,
                textColor=self.COLOR_MUTED,
            ),
            "metadata_value": ParagraphStyle(
                "MetadataValue",
                parent=styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=9,
                leading=11,
                textColor=self.COLOR_TEXT,
            ),
            "metadata_value_small": ParagraphStyle(
                "MetadataValueSmall",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=7.4,
                leading=9.5,
                textColor=self.COLOR_TEXT,
            ),
            "table_heading": ParagraphStyle(
                "TableHeading",
                parent=styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=10,
                textColor=self.COLOR_TEXT,
            ),
            "table_body": ParagraphStyle(
                "TableBody",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=8,
                leading=11,
                textColor=self.COLOR_TEXT,
            ),
            "priority_number": ParagraphStyle(
                "PriorityNumber",
                parent=styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=10,
                leading=12,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#9F2F2F"),
            ),
        }

    def _paragraph(
        self,
        text: str,
        style_name: str,
        *,
        text_color: colors.Color | None = None,
    ) -> Paragraph:
        style = self.styles[style_name]

        if text_color is not None:
            style = ParagraphStyle(
                f"{style.name}Dynamic",
                parent=style,
                textColor=text_color,
            )

        return Paragraph(
            self._safe(text),
            style,
        )

    def _string_list(self, key: str) -> list[str]:
        value = self.analysis.get(key) or []

        if not isinstance(value, list):
            return []

        return [
            str(item).strip()
            for item in value
            if item is not None and str(item).strip()
        ]

    @staticmethod
    def _join_or_default(
        values: list[str],
        default: str,
    ) -> str:
        if not values:
            return default

        return ", ".join(values)

    @staticmethod
    def _safe(value: Any) -> str:
        """
        Escape content before placing it in ReportLab Paragraph markup.
        """

        if value is None:
            return ""

        return escape(
            str(value),
            entities={
                "'": "&apos;",
                '"': "&quot;",
            },
        )
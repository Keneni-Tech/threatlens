# ThreatLens Devpost Demo Script

Target duration: 2 minutes 50 seconds. Devpost requires the public
YouTube demonstration to be shorter than three minutes.

## Before recording

- Open the deployed application and wait for Render to finish waking up.
- Confirm **Run guided demo**, the case detail, and PDF export all work.
- Use only the fictional guided-demo data.
- Use a clean browser window around 1440 × 900 at 100% zoom.
- Hide bookmarks, notifications, personal tabs, API keys, and account data.
- Prepare the dashboard, guided case, and new-case page in separate tabs.
- Record at 1080p with clear microphone audio.

Do not run **Load sample** during the public demonstration unless the
deployment has a protected OpenAI API key. The deterministic guided demo
is the primary judging path and consumes no API credits.

## 0:00–0:10 — Introduction

Show the ThreatLens dashboard or project title.

> Hello, and welcome to ThreatLens, my OpenAI Build Week submission in the
> Developer Tools track. ThreatLens helps security analysts investigate
> complex event data with AI-assisted, evidence-focused analysis.

## 0:10–0:23 — Problem

Show the dashboard.

> Security analysts often receive disconnected logs and alerts. Turning
> those events into a coherent, reviewable incident assessment takes time
> and can produce inconsistent documentation.

## 0:23–0:40 — Solution

Keep the dashboard visible and briefly point to its main metrics.

> ThreatLens is an AI-assisted incident investigation platform built with
> Django, GPT-5.6, the OpenAI Responses API, and strict Pydantic structured
> outputs. It converts sanitized event data into evidence, a timeline,
> severity, MITRE ATT&CK mappings, and response recommendations while
> keeping the analyst responsible for every decision.

## 0:40–0:56 — Investigation workspace

Show the severity cards, recent activity, and search filters.

> The dashboard summarizes investigation posture and lets analysts search,
> filter, sort, and revisit saved cases. The interface is server-rendered,
> responsive, and designed to remain clear during an active investigation.

## 0:56–1:40 — Guided investigation

Select **Run guided demo** and scroll deliberately through the detail page.

> The guided demo creates a deterministic fictional investigation without
> consuming API credits, giving judges a safe and repeatable way to test the
> complete product. The result includes severity and confidence, an
> executive summary, evidence-linked findings, a chronological timeline,
> and a possible attack path. ThreatLens maps observed behavior to MITRE
> ATT&CK and separates indicators, affected assets, containment actions,
> recommendations, and limitations so analysts can distinguish evidence
> from model-assisted conclusions.

Do not attempt to read every field. Pause briefly over evidence, timeline,
MITRE ATT&CK, recommendations, and limitations.

## 1:40–2:03 — Input and GPT-5.6 workflow

Open **New case**, show the paste and upload tabs, and do not submit.

> Analysts can paste sanitized logs or upload TXT, LOG, JSON, JSONL, and CSV
> files. ThreatLens validates and normalizes the input, treats log content
> as untrusted evidence, and sends the bounded analysis request to GPT-5.6
> through the Responses API. The response must pass a strict Pydantic schema
> before an investigation is saved. Timeouts, refusals, malformed output,
> and provider failures are handled explicitly.

## 2:03–2:18 — Reporting

Return to the guided case and select **Download PDF report**.

> Analysts can export an executive PDF from the saved, validated result.
> Exporting does not make another OpenAI request, so the report remains
> consistent with the reviewed investigation.

## 2:18–2:42 — Codex and engineering

Return to the investigation summary or briefly show the GitHub repository.

> I used Codex throughout Build Week to review the Django architecture,
> separate parsing and analysis services, strengthen upload and deployment
> security, improve accessibility and responsive behavior, expand automated
> tests, and prepare the Render deployment. GPT-5.6 provides the structured
> security reasoning; Codex accelerated the engineering and quality-review
> workflow around it.

## 2:42–2:50 — Close

Finish on the investigation summary.

> ThreatLens helps analysts move from raw event evidence to an organized,
> reviewable, and reportable assessment while preserving human oversight.

## Recording and upload checklist

1. Record one dry run and keep the final cut below 2:55.
2. Remove long page loads, cursor mistakes, and silent transitions.
3. Keep narration audible and avoid background music that competes with it.
4. Export as MP4 at 1080p and 30 frames per second.
5. Upload to YouTube with visibility set to **Public**.
6. Add the live application and GitHub repository links to the description.
7. Enable or correct captions.
8. Open the final YouTube link in a signed-out browser before submitting it.

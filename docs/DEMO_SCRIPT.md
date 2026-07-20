# ThreatLens Demonstration Script

Target duration: three to four minutes.

## Before recording or presenting

- Set `THREATLENS_DEMO_MODE=True`.
- Run `python manage.py seed_demo`.
- Use only the fictional data in `samples/`.
- Confirm the dashboard, case detail, and PDF export load.
- Keep the deterministic demo as the primary path; a live API call is
  optional.
- Use a browser window near 1440 × 900 with no unrelated tabs or
  personal bookmarks visible.

## 1. Frame the problem — 20 seconds

“Security analysts often receive disconnected logs and alerts. Turning
those events into a coherent, reviewable incident assessment takes time
and can produce inconsistent documentation.”

## 2. Introduce ThreatLens — 20 seconds

“ThreatLens is an AI-assisted investigation workspace built with Django,
GPT-5.6, and Pydantic structured outputs. It organizes sanitized event
data into evidence, timeline, severity, MITRE ATT&CK mappings, response
recommendations, and explicit limitations.”

Emphasize that ThreatLens supports analyst decisions and never executes
containment actions.

## 3. Dashboard — 30 seconds

Open `/` and show:

- total and high-priority investigations
- severity distribution
- paste-versus-upload metrics
- recent activity
- search, filters, sorting, and pagination

Mention that the dashboard is server-rendered and remains usable without
a frontend framework.

## 4. Deterministic guided demo — 75 seconds

Select **Run guided demo**.

Explain that this path:

- uses fixed fictional evidence
- is repeatable
- consumes no API credits
- exercises the same saved-case, detail, search, and PDF workflows

On the detail page, point out:

1. Critical severity and high confidence
2. Executive summary and input provenance
3. Evidence references and chronological timeline
4. Possible attack path
5. MITRE ATT&CK mappings
6. Indicators, affected asset, and affected account
7. Investigation and containment recommendations
8. Limitations and missing evidence

## 5. Input workflow — 40 seconds

Open **New case**.

Show both tabs:

- pasted, sanitized events
- TXT, LOG, JSON, JSONL, or CSV upload

Optionally select a file from `samples/`. Mention the upload and parsing
limits, the prompt-injection boundary, the loading state, and strict
structured-output validation.

Avoid making a live API request during the core demonstration. If live
analysis is shown, prepare a fallback by keeping the guided case open in
another tab.

## 6. Reporting — 25 seconds

Return to the guided case and select **Download PDF report**.

Explain that the executive PDF is generated from the saved validated
investigation and does not make another OpenAI request.

## 7. Engineering close — 25 seconds

Summarize:

- focused Django services and server-rendered accessibility
- OpenAI Responses API with strict Pydantic output
- retry, timeout, refusal, and provider-error handling
- deterministic no-credit demo
- upload validation, CSP, request IDs, and deployment checks
- human review and stated limitations

Closing line:

“ThreatLens helps analysts move from raw event evidence to an organized,
reviewable, and reportable assessment while preserving human oversight.”

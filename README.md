# ThreatLens

> AI-powered security incident investigation built with Django and OpenAI.

ThreatLens helps security analysts transform raw security events into structured investigations using modern AI. Instead of manually reviewing thousands of log lines, analysts receive an evidence-based incident assessment with timelines, MITRE ATT&CK mappings, indicators, and recommended next steps.

---

## Features

* AI-powered incident analysis
* Severity and confidence scoring
* Evidence extraction
* Timeline reconstruction
* MITRE ATT&CK technique mapping
* Indicators of Compromise (IOCs)
* Investigation recommendations
* Containment recommendations
* Executive-ready incident summaries
- Paste raw security events for AI-assisted investigation
- Upload TXT, LOG, JSON, JSONL, and CSV event files
- Validate and normalize structured security-event data
- Reject oversized, binary, malformed, and unsupported uploads
- Preserve investigation input provenance and parsed event counts
- Generate downloadable executive PDF reports
- Competition-ready security investigation dashboard
- Severity and investigation-posture metrics
- Visual severity distribution
- Full-text investigation search
- Severity, confidence, and input-source filtering
- Severity, date, and title sorting
- Paginated investigation history
- Recent investigation activity
- Responsive dashboard design

---

## Investigation Dashboard

The ThreatLens dashboard summarizes saved investigations and provides:

- total and high-priority case counts
- severity distribution
- recent activity
- file-upload and pasted-input totals
- search across titles, summaries, source files, structured analysis,
  and raw event data
- severity, confidence, and input-source filters
- stable paginated investigation history

The dashboard uses Django server-side filtering and pagination and does
not require a JavaScript frontend framework.

## Technology Stack

* Python 3.13
* Django 6
* OpenAI Responses API
* Pydantic Structured Outputs
* SQLite (development)
* Bootstrap 5

---

## Project Status

🚧 Active development for **OpenAI Build Week 2026**.

Current milestone:

* Project initialization
* Django application
* AI incident analysis
* Structured security assessments

Upcoming milestones:

* PDF executive reports
* Investigation history
* IOC extraction improvements
* Multi-format log ingestion

---

## Getting Started

Clone the repository:

```bash
git clone git@github.com:Keneni-Tech/threatlens.git
cd threatlens
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

Windows

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file from `.env.example` and configure your OpenAI API key.

Run:

```bash
python manage.py migrate
python manage.py runserver
```

---

## Security Notice

Only upload sanitized or fictional security events.

Never upload:

* Passwords
* API keys
* Private keys
* Customer secrets
* Sensitive personal information

## Upload Security

ThreatLens limits uploaded event files to 5 MB and supports only TXT,
LOG, JSON, JSONL, and CSV input. Uploaded files are parsed in memory
and are not permanently stored as files in the current MVP.

Users should submit only fictional or sanitized data and must never
upload passwords, API keys, authentication tokens, private keys, or
unnecessary personal information.

---

## License

MIT License.

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

---

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

---

## License

MIT License.

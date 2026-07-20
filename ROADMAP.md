# ThreatLens Roadmap

## Build Week MVP — complete

- Django incident-investigation workflow
- GPT-5.6 Responses API integration
- Strict Pydantic structured outputs
- Paste and multi-format file ingestion
- Severity, confidence, evidence, timeline, and MITRE ATT&CK mapping
- Saved investigation history with search, filters, sorting, and pagination
- Executive PDF reports
- Deterministic no-credit guided demo
- Request IDs, health check, security headers, and deployment configuration
- Responsive and accessible server-rendered interface
- Automated tests, dependency auditing, and CI

## Production foundation

- Application authentication and investigation ownership
- PostgreSQL and tested backup/restore procedures
- Background analysis jobs with progress and cancellation
- Data-retention and deletion controls
- Rate limiting and per-user quotas
- Centralized error monitoring and CSP reporting
- Object storage where retained source artifacts are required

## Analyst workflow

- Investigation notes and analyst disposition
- Visual and filterable timelines
- Comparison and linking of related investigations
- Export formats for downstream case-management tools
- Configurable investigation templates and organization guidance
- Enrichment from approved threat-intelligence sources

## Integrations and scale

- SIEM and alert-platform ingestion
- Enterprise identity and role-based access control
- Organization workspaces and tenant isolation
- PostgreSQL search or a dedicated search index
- Auditable API and webhook integrations
- Deployment profiles for managed cloud platforms

Roadmap items are directional and should preserve human review, evidence
traceability, and safe handling of sensitive security data.

# ThreatLens Security Policy

## Supported versions

ThreatLens is currently an MVP without versioned releases. Security fixes
are applied to the latest commit on `main`.

## Reporting a vulnerability

Do not open a public issue or include sensitive details in a public pull
request.

Use [GitHub private vulnerability reporting](https://github.com/Keneni-Tech/threatlens/security/advisories/new)
when available. Include:

- affected commit or environment
- vulnerability description and likely impact
- minimal reproduction steps or proof of concept
- relevant request IDs without submitted event content
- suggested mitigation, if known

Give the maintainer reasonable time to investigate and coordinate a fix
before public disclosure. Do not access data that does not belong to you,
degrade a running service, or use social engineering while testing.

## Data handling

ThreatLens is intended for defensive investigation of fictional,
sanitized, or properly authorized security data.

Never submit:

- passwords or authentication tokens
- API keys or private keys
- customer secrets
- unnecessary personally identifiable information
- production evidence without authorization and an approved data path

ThreatLens stores normalized submitted events and the resulting
assessment in its database. Uploaded source files are parsed during the
request and are not retained as files.

## Security boundaries

The current MVP:

- has no application-level investigation authentication or tenant
  isolation
- uses SQLite by default
- sends live analysis input to the configured OpenAI API project
- provides AI-generated decision support that requires human review
- does not execute investigation or containment recommendations

Do not expose the application publicly with sensitive evidence without
adding access control and an appropriate production database. Review
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) before deployment.

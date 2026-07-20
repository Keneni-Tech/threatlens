# ThreatLens Sample Security Events

This directory contains fictional, sanitized security-event files for
testing ThreatLens.

Supported examples:

- `authentication-events.log`
- `authentication-events.json`
- `authentication-events.jsonl`
- `authentication-events.csv`

The IP address `198.51.100.24` is used only as documentation-safe
example data. `203.0.113.51` is also reserved for documentation. These
files do not contain real credentials, customer records, or production
security events.

To test:

1. Start ThreatLens.
2. Open `/investigations/new/`.
3. Select **Upload file**.
4. Upload one of the sample files.
5. Select **Analyze and save investigation**.

Live analysis requires a configured OpenAI API key and may consume API
credits. For a deterministic test without an API call, enable
`THREATLENS_DEMO_MODE=True` and run:

```bash
python manage.py seed_demo
```

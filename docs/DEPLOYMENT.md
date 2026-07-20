# ThreatLens Deployment Checklist

ThreatLens can be deployed with Gunicorn and WhiteNoise on a Linux-based
application host. The current SQLite MVP is intended for one controlled
application instance.

## Required environment

Set at minimum:

```dotenv
DJANGO_SECRET_KEY=<unique random value of at least 50 characters>
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=threatlens.example.com
DJANGO_CSRF_TRUSTED_ORIGINS=https://threatlens.example.com
DJANGO_SECURE_SSL_REDIRECT=True
THREATLENS_DEMO_MODE=False
OPENAI_API_KEY=<production API key>
OPENAI_MODEL=gpt-5.6
```

Generate a Django secret locally:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Do not reuse development, CI, or example secrets.

## Startup

The checked-in `Procfile` invokes:

```bash
bash start.sh
```

The startup script applies migrations, collects versioned static assets,
and then replaces itself with Gunicorn. Its worker, thread, and timeout
settings can be overridden with:

- `WEB_CONCURRENCY`
- `GUNICORN_THREADS`
- `GUNICORN_TIMEOUT`
- `PORT`

## Reverse proxy

Terminate TLS at a trusted load balancer or reverse proxy.

Set `DJANGO_TRUST_X_FORWARDED_PROTO=True` only if the proxy removes any
client-supplied `X-Forwarded-Proto` value and supplies the authoritative
protocol value itself.

Enforce a request-body limit slightly above
`THREATLENS_MAX_UPLOAD_BYTES`. Django validates the file after upload
handling begins, so application validation is not a substitute for a
proxy-level limit.

## HSTS

The default production HSTS duration is one hour. Increase it only after
confirming HTTPS behavior. Enable `DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS`
only when every subdomain is HTTPS-only. Enable preload only after
reviewing the browser preload requirements and long-lived consequences.

## Release verification

Run against production configuration:

```bash
python manage.py check --deploy
python manage.py migrate --noinput
python manage.py collectstatic --noinput
python manage.py test
python -m pip check
```

Then verify:

- `/health/` returns HTTP 200 and `"status": "ok"`
- static CSS and JavaScript load with hashed asset names
- HTTP redirects to HTTPS
- the response includes `Content-Security-Policy` and `X-Request-ID`
- a fictional pasted event can be analyzed
- a saved investigation can be exported as PDF
- logs do not contain submitted event data or secrets

## Production limitations

ThreatLens currently has no application-level investigation
authentication, authorization, ownership, or tenant isolation. Do not
make it publicly reachable with sensitive evidence. Put it behind a
trusted access control layer or add application authentication before
multi-user use.

SQLite also limits safe horizontal scaling. Move to PostgreSQL and run
migrations as a release task before introducing multiple application
instances.

## Backup and recovery

For the SQLite MVP, back up `db.sqlite3` from a stopped application or
through a storage snapshot that guarantees consistency. Treat backups as
sensitive because they contain submitted event data and AI assessments.
Test restoration before relying on the backup process.

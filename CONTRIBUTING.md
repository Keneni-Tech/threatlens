# Contributing to ThreatLens

Thank you for helping improve ThreatLens. Contributions should preserve
its evidence-focused, human-in-the-loop security workflow and existing
Django architecture.

## Development setup

```bash
python -m venv .venv
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Copy `.env.example` to `.env`, apply migrations, and run the development
server:

```bash
python manage.py migrate
python manage.py runserver
```

Use only fictional or sanitized sample events. A working OpenAI key is
not required for the tests or guided demo.

## Before submitting a pull request

Run:

```bash
python manage.py check
python manage.py makemigrations --check
python manage.py test
python manage.py collectstatic --noinput
python -m pip check
node --check analyzer/static/analyzer/app.js
```

If a model change intentionally requires migrations, create and commit
the migration before rerunning `makemigrations --check`.

## Pull request expectations

- Keep changes focused and incremental.
- Explain the user problem and the chosen solution.
- Add or update tests for behavior changes and regressions.
- Include before-and-after screenshots for visible UI changes.
- Update README or supporting documentation when commands,
  configuration, architecture, or behavior changes.
- Do not commit `.env`, API keys, submitted evidence, generated PDFs,
  SQLite databases, or collected static files.
- Avoid unrelated formatting or refactoring in the same pull request.

## Code guidelines

- Follow PEP 8 and use type hints where they improve clarity.
- Keep views focused on HTTP orchestration and domain behavior in
  services.
- Validate external input at the boundary.
- Preserve Django template autoescaping.
- Keep JavaScript progressively enhanced and keyboard accessible.
- Prefer clear names and small functions over clever abstractions.
- Log operational context and request IDs, never raw security events or
  secrets.

## Security reports

Do not open a public issue for a suspected vulnerability. Follow
[`SECURITY.md`](SECURITY.md).

By participating, contributors agree to follow the
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

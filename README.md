# mini-SIEM

A learning project for security event processing and monitoring, built with
Python 3.14+, FastAPI, PostgreSQL 18, SQLAlchemy 2, and Alembic.

Currently implemented: JWT authentication, refresh/logout, role-based access,
Docker setup, migrations, and automated tests. Event ingestion, search, detection
rules, and alert investigation are the next milestones.

## Quick start

Requires Docker Compose. For a new setup:

```bash
cp .env.example .env
openssl rand -hex 32
```

Paste the generated value into `JWT_SECRET_KEY` in `.env`, then run:

```bash
docker compose up --build
```

The backend waits for PostgreSQL and runs migrations automatically.
Open [Swagger UI](http://localhost:8000/docs) to try the API.

For an existing setup, update `APP_NAME=mini-SIEM` in `.env`; it overrides the
application default. Keep the existing `POSTGRES_DB` to preserve access to your
database. Changing that setting does not rename or migrate a database.

Ports bind to localhost. Set `BACKEND_PORT` or `POSTGRES_PORT` in `.env` if the
defaults (`8000` and `5432`) are occupied.

## Local development

Requires Python 3.14+, uv, and PostgreSQL. Configure `.env` as above, then:

```bash
uv sync --locked
docker compose up -d postgres  # Optional: use Docker for the database only.
uv run alembic upgrade head
uv run fastapi dev app/main.py
```

For a native PostgreSQL installation, create the database first with
`createdb -h localhost -p 5432 -U postgres mini_siem`. Match `.env` if using
other connection settings. The local server uses port `8000`; change it with
`--port`, rather than `BACKEND_PORT`.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | API process health (does not check the database) |
| POST | `/api/v1/auth/register` | Register a regular user |
| POST | `/api/v1/auth/login` | Login with username or email |
| POST | `/api/v1/auth/token` | OAuth2-compatible login for Swagger UI |
| POST | `/api/v1/auth/refresh` | Rotate tokens with a refresh Bearer token |
| POST | `/api/v1/auth/logout` | Revoke the session with either Bearer token |
| GET | `/api/v1/auth/me` | Get the current user |
| GET | `/api/v1/auth/admin-only` | Require an admin role |

Use Swagger UI to register, then authorize with the same credentials. Refresh
rotation invalidates the previous token pair. No admin user is seeded.

## Checks

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv lock --check
```

The default suite includes PostgreSQL migration and concurrency checks. They
skip when `TEST_POSTGRES_URL` is unset; the other tests use isolated SQLite.
To run everything, use a disposable PostgreSQL test database with schema creation
rights:

```bash
TEST_POSTGRES_URL='postgresql+psycopg2://user:password@localhost:5432/test_db' \
  uv run pytest -W error
```

Run only PostgreSQL checks with `uv run pytest tests/test_postgres.py`. Each
check applies its own migrations in a temporary schema and removes it afterward.

GitHub Actions runs lint, formatting, and the full test suite on every pull
request using Python 3.14 and a temporary PostgreSQL 18 service. The workflow is
in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) and also supports manual
runs. No application secrets are needed. After the first run, require the
`Tests and lint` status check in your default branch's protection rule or ruleset
to block merging failing PRs.

Create schema changes with `uv run alembic revision --autogenerate -m "describe change"`.
Review migrations before applying them. The username constraint migration rejects
existing usernames containing `@`; rename those accounts before upgrading.

## Roadmap and limitations

See the [detailed MVP roadmap](docs/MVP_ROADMAP.md) for the current project
assessment, implementation milestones, security concepts, acceptance criteria,
and future development priorities.

1. Authenticated event ingestion, source-scoped idempotency, UTC timestamps,
   filtered/paginated queries, and a synthetic event generator.
2. Five failed logins for one account within ten minutes: detection, alert
   deduplication, investigation, and acknowledgement.
3. Workers, richer correlation, and a UI when needed.

Keep the MVP a modular monolith with separate routes, schemas, business logic,
and persistence. Avoid additional messaging infrastructure initially.

The current Compose database uses an anonymous volume. After `docker compose down`,
a new `up` does not automatically reuse it; use a named volume for persistent
work. `docker compose down --volumes` deletes database data. Migration downgrades
can also delete data; back up anything valuable.

Before public deployment, configure HTTPS, request-size limits, rate limits,
least-privilege database access, and separate secrets. Never log credentials or
tokens. Password reset and email verification are not implemented.

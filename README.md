# FastAPI Template

FastAPI starter project with PostgreSQL, SQLAlchemy, Alembic migrations, JWT
authentication, password hashing, refresh tokens, logout token revocation, CORS,
Docker, and role-based admin protection.

## Stack

- Python 3.14+
- FastAPI
- PostgreSQL 18
- SQLAlchemy 2
- Alembic
- Pydantic Settings
- PyJWT
- pwdlib with Argon2
- uv
- Ruff

## Requirements

- Python 3.14+
- uv
- PostgreSQL for local development, or Docker Compose for the full stack

## Local Setup

Install dependencies:

```bash
uv sync
```

Copy the example configuration and replace the blank JWT secret:

```bash
cp .env.example .env
openssl rand -hex 32
```

The resulting `.env` should contain:

```env
APP_NAME=fastapi-template
ENVIRONMENT=development
BACKEND_PORT=8000
ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:8000","http://127.0.0.1:3000","http://127.0.0.1:8000"]

POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=fastapi_template

JWT_SECRET_KEY=<paste-the-generated-secret>
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=30
```

`JWT_SECRET_KEY` is required for secure token signing. Use a long random value
for local development and a separate secret in every deployed environment.
Access-token lifetime must not exceed refresh-token lifetime.
Supported signing algorithms are `HS256` (default), `HS384`, and `HS512`.
Keys must contain at least 32 characters and at least 32, 48, or 64 UTF-8 bytes,
respectively; blank keys are rejected. Asymmetric algorithms require a separate
public/private-key configuration and are not supported by this template.

`ALLOWED_ORIGINS` is a JSON list of explicit origins. Wildcard `*` is rejected
because CORS credentials are enabled. `BACKEND_PORT` only controls the published
Docker host port; for a local server, use the FastAPI CLI's `--port` option.
Both configured port numbers must be between 1 and 65535. Unknown `.env` entries
remain errors so configuration typos are caught at startup.

## Database

### Native PostgreSQL

Create the configured local database if it does not exist:

```bash
createdb -h localhost -p 5432 -U postgres fastapi_template
```

Run migrations:

```bash
uv run alembic upgrade head
```

The username constraint migration rejects existing usernames containing `@`.
Review and rename those accounts before upgrading; the migration does not
silently change user identities. Back up any database that contains valuable data
before migrations. Downgrading to `base` removes all application tables and the
`user_role` enum; do not run it against a database you want to preserve.

Create a migration after model changes:

```bash
uv run alembic revision --autogenerate -m "describe change"
```

### Docker PostgreSQL

To create only the project database on localhost, set `JWT_SECRET_KEY` in
`.env`, then run:

```bash
docker compose up -d postgres
```

The default host port is `5432`. If it is already occupied, choose another
localhost port without changing the container port:

```env
POSTGRES_PORT=5434
```

The backend always uses PostgreSQL's internal Compose port `5432`.

## Run Locally

Start the development server:

```bash
uv run fastapi dev app/main.py
```

The API runs at `http://localhost:8000`. Interactive docs are available at
`http://localhost:8000/docs`.

Check the health endpoint:

```bash
curl http://localhost:8000/
```

## Docker

Build and run the API with PostgreSQL:

```bash
docker compose up --build
```

Compose reads `JWT_SECRET_KEY` from `.env` and refuses to start the backend when
it is missing, preventing accidental use of a public default signing key.

The backend waits for PostgreSQL to become healthy, runs Alembic migrations,
then starts FastAPI on `http://localhost:8000`.

Docker Compose starts a non-root `backend` service and a PostgreSQL 18 service.
Both published ports bind only to `127.0.0.1`. The backend connects through the
internal Compose hostname:

```env
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=fastapi_template
```

PostgreSQL is exposed to localhost on `POSTGRES_PORT`, defaulting to `5432`.
The API is exposed on `BACKEND_PORT`, defaulting to `8000`.

The PostgreSQL image stores data in an anonymous Docker volume and is intended
here for disposable local development. After `docker compose down`, a subsequent
`up` does not automatically reuse that volume. Use a named volume and backups
when persistence is required.

Stop and remove the containers:

```bash
docker compose down
```

For disposable data, `docker compose down --volumes` also removes the anonymous
database volume. This deletes the database contents.

Check service health and logs:

```bash
docker compose ps
docker compose logs backend postgres
```

## Authentication

Register a user:

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "exampleuser",
    "first_name": "Example",
    "last_name": "User",
    "password": "password123456"
  }'
```

Login with an email or username:

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user@example.com&password=password123456"
```

Use the OAuth2-compatible token endpoint from Swagger UI:

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user@example.com&password=password123456"
```

Call an authenticated endpoint:

```bash
curl http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer <access-token>"
```

Rotate a session with a refresh token. The old access and refresh tokens are
revoked, and a new token pair is returned:

```bash
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -H "Authorization: Bearer <refresh-token>"
```

Logout by revoking the session associated with the presented access or refresh
token. Both tokens in the pair are invalidated:

```bash
curl -X POST http://localhost:8000/api/v1/auth/logout \
  -H "Authorization: Bearer <access-or-refresh-token>"
```

Refresh rotation is single-use: concurrent requests using the same refresh
token allow only one success; the other returns `401`. Clients should serialize
refresh requests. A successful refresh starts a new session with a fresh refresh
lifetime. Logout revokes only the presented pair, not other logins or a newer
pair created by an earlier refresh. Authorization checks the user's current
database role and active status, rather than trusting the role stored in the JWT.

Malformed, expired, or revoked tokens return `401` with a Bearer challenge.
Session expiry must cover token expiry so expired-blocklist cleanup cannot
restore access to a still-valid token. Cleanup runs on refresh/logout; expired
rows can remain during idle periods.

## API Routes

```text
GET  /                              Health-style root response
POST /api/v1/auth/register          Create a regular user and return token pair
POST /api/v1/auth/login             Return the user and token pair
POST /api/v1/auth/token             Return an OAuth2-compatible token pair
POST /api/v1/auth/refresh           Rotate a refresh token and return a new token pair
POST /api/v1/auth/logout            Revoke the presented token's entire session
GET  /api/v1/auth/me                Return the current user
GET  /api/v1/auth/admin-only        Require an admin user
```

Newly registered users use the `regular` role. The base migration creates the
users and token blocklist tables; it does not seed an admin user.

## Registration Validation

```text
email       Max 255 characters
username    1-100 ASCII letters, digits, underscores, or hyphens
password    8-128 characters
first_name  1-30 characters after trimming surrounding whitespace
last_name   1-30 characters after trimming surrounding whitespace
```

Email addresses are validated and normalized to lowercase before storage and
login. Usernames cannot contain `@`, preventing ambiguous login identifiers.

## Quality

Run Ruff:

```bash
uv run ruff check .
uv run ruff format --check .
```

Run the test suite:

```bash
uv run pytest
```

The default suite uses an isolated in-memory SQLite database and test settings;
it does not connect to the configured application database. HTTP tests cover
registration, login, authorization, refresh/logout, malformed JWTs, and CORS.
`httpx2` is a development dependency used by Starlette's test client.

Run PostgreSQL-specific migration and concurrency checks against a **test**
database with permission to create schemas:

```bash
TEST_POSTGRES_URL='postgresql+psycopg2://user:password@localhost:5432/test_db' \
  uv run pytest tests/postgres_checks.py -W error
```

These explicitly invoked checks create a unique schema per test and remove it
afterward. They verify upgrade/downgrade/upgrade, model-to-migration alignment,
and simultaneous registration and refresh requests. The repository has no
dedicated static type checker or packaging build configured.

Update and inspect dependencies:

```bash
uv lock --upgrade
uv tree --outdated --depth 1
```

Review dependency updates before committing them; `uv lock --upgrade` updates
the full lockfile. To check the existing lockfile without upgrading, run
`uv lock --check`.

## Deployment Boundaries

This is a starter, not a complete production security configuration. Before
public exposure, configure HTTPS, trusted proxy handling, request/body limits,
and rate limits for registration, login, and refresh at your gateway or shared
application infrastructure. Unknown-user login attempts still verify a dummy
password hash, but that does not prevent brute force or resource exhaustion.
Registration intentionally reports duplicate identifiers with `409`.

Use separate signing secrets and least-privilege database credentials for each
environment. Secret fields are omitted from settings representations and text
validation errors; do not log settings dictionaries, tokens, or passwords.
There is no password reset, email verification, or logout-all-sessions endpoint.
`GET /` checks that the API process responds; it does not check database health.

## Project Layout

```text
app/main.py                       FastAPI application and middleware
app/api/router.py                 API router registration
app/api/v1/auth.py                Auth routes
app/api/v1/schemas/               Request and response schemas
app/core/security.py              Password hashing and JWT logic
app/core/settings.py              Environment settings
app/db/deps.py                    Database session dependency
app/db/models/base_model.py       Shared model fields
app/db/models/user.py             User model and roles
app/db/models/token_blocklist.py  Revoked token model
alembic/versions/                 Alembic migrations
docker-compose.yml                Backend and PostgreSQL services
Dockerfile                        Backend image
docker/entrypoint.sh              Migrations and container process startup
tests/                             Authentication and settings regression tests
tests/postgres_checks.py           Explicit PostgreSQL migration and race checks
```

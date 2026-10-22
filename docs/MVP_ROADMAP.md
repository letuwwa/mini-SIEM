# mini-SIEM: MVP and development roadmap

Reviewed: 22 October 2026. This is a proposed implementation plan based on the repository, not a claim that the features below already exist.

## 1. What you are building

A SIEM (Security Information and Event Management system) collects records from other systems, makes those records searchable, identifies suspicious patterns, and helps people investigate them.

Your first product should answer four questions:

1. What happened?
2. Where, when, and to which account did it happen?
3. Why does the system consider it suspicious?
4. What did the investigator decide?

**Recommended MVP:** a single-organization API that monitors authentication activity from one application, detects repeated failed logins, and supports alert investigation through Swagger or an API client. Start in a private lab. A dashboard is optional for this API MVP.

Do not promise comprehensive attack detection. This MVP demonstrates one useful detection and the complete workflow around it.

### Vocabulary you will need

| Term | Meaning | Example |
| --- | --- | --- |
| Event | A record of something that happened | One failed login |
| Source | A system producing events | A demo application's authentication service |
| Collector | Software that reads events and sends them to the SIEM | A script forwarding JSON log lines |
| Normalization | Translating different source formats into a shared format | Mapping `login_failure` to `authentication.failed` |
| Detection rule | A condition that identifies a suspicious pattern | Five failures for one account in ten minutes |
| Correlation | Relating multiple events using shared attributes and time | Grouping failures by source and account |
| Alert | A detection result that someone should investigate | Suspected password guessing against account `alice` |
| Triage | Reviewing an alert and deciding what it means | Check whether a user simply forgot their password |
| False positive | A rule correctly matches its conditions, but the activity is benign | A legitimate user repeatedly mistypes a password |
| Incident | An investigated security problem requiring response | Confirmed unauthorized account access |
| Retention | How long records are kept before deletion | A configurable 14-day lab event history |
| Idempotency | Retrying an operation does not repeat its effect | Sending the same event twice stores it once |

An event is an observation. An alert is a reason to investigate. An alert does not prove an attack, and an IP address does not identify a person.

## 2. Current repository assessment

| Area | Current evidence | Assessment |
| --- | --- | --- |
| API foundation | `app/main.py`, `app/api/router.py` | FastAPI and versioned routing exist; only the authentication router is registered |
| Human authentication | `app/api/v1/auth.py`, `app/core/security.py` | Registration, password hashing, JWT access/refresh tokens, rotation, logout, active-user checks |
| Authorization | `UserRole`, `require_admin` | Admin/regular roles and an example restricted endpoint; SIEM permissions still need design |
| Event persistence | `app/db/models/security_event.py`, event migration | Model and migration exist, including source/event uniqueness, two timestamps, JSONB metadata, and query indexes |
| Event workflow | No event routes or request schemas | Ingestion and search are still to build |
| Detection and investigation | No rule, alert, evidence, or investigation models/routes | Still to build |
| Development infrastructure | Docker, Compose, Alembic, lockfile, CI | Useful foundation for incremental development |
| Tests | Auth/settings tests and optional PostgreSQL tests | Covers existing infrastructure; future SIEM behavior needs its own tests |
| Persistence operations | Compose has no explicit named database volume | Make volume ownership explicit before using valuable data |
| Health | `/` reports process status | Does not establish database or detector readiness |

Keep the existing event model as a starting point. In particular, `actor_user_id` represents an account in the monitored system; it is not a foreign key to a SIEM user's account.

The PostgreSQL integration tests cover migration/model alignment, event storage, and concurrent authentication writes. They require `TEST_POSTGRES_URL`; SQLite checks cannot establish PostgreSQL behavior.

## 3. Scope and architecture decisions

### Required for the lab MVP

- One organization, one supported event format, one real lab source.
- Authenticated source identity, bounded ingestion, safe retries.
- Searchable events with consistent timestamps and validated fields.
- One tested detection rule and durable detection processing.
- Persisted alerts with evidence, status, and investigator notes.
- Documented access permissions, operational visibility, retention, and restore procedure.
- A repeatable demonstration using normal, suspicious, and duplicate events.

### Defer until after the MVP

- Multi-organization SaaS, billing, and tenant administration.
- Arbitrary rule languages, user-supplied SQL/Python, and comprehensive Sigma support.
- Kafka, distributed stream processing, Elasticsearch/OpenSearch, and microservices.
- Machine learning, behavioral baselines, geolocation, and threat-intelligence feeds.
- Automated account lockouts, IP blocking, or other response actions.
- Full case management, multiple notification channels, and elaborate dashboards.

These can be useful later. Add them when a measured requirement justifies their operational cost.

### Recommended architecture

```text
Demo application / collector
        |
        | source credential + normalized JSON
        v
FastAPI ingestion service
        |
        | one database transaction
        v
PostgreSQL: event + pending detection job
        |
        v
Detector command/process from the same codebase
        |
        v
PostgreSQL: alert + evidence + processing result
        |
        v
Authenticated analyst -> event / alert / investigation APIs
```

Use a modular monolith: one codebase with separate responsibilities. A detector process from that codebase does not require a new service architecture or message broker.

Suggested boundaries:

```text
app/api/v1/              HTTP routes and request/response schemas
app/api/v1/services/     ingestion, querying, investigation, permission checks
app/detection/           rule definitions and evaluation
app/db/models/           persisted entities
app/workers/             durable job processing entry point
scripts/                 source simulator and collector
tests/                   behavioral and PostgreSQL integration checks
```

Keep route handlers short. They validate input and permissions, call application logic, and translate results to HTTP. Keep rule evaluation callable without an HTTP request so it can be tested and replayed.

## 4. Implementation milestones

Follow these in order. Each milestone has an observable completion condition.

### Milestone 0 — Define the scenario and keep lab data safe

**Why:** log formats and detection rules are easier to design around a specific question than around “detect cyberattacks.”

Tasks:

1. Write the first user story: “As an analyst, I can investigate repeated failed logins against an account in my demo application.”
2. Define the supported event types: `authentication.failed` and `authentication.succeeded`. Start with failures; successes provide investigation context.
3. Define an initial permission matrix: administrators manage users/sources; regular users are analysts; sources can only submit their own events. Treat everyone with analyst access as trusted to read this single organization's events.
4. Add a named PostgreSQL volume, documenting migration of any existing anonymous volume before changing Compose. Recreating the service without migrating data can appear to lose the old database.
5. Provide an explicit, local administrative bootstrap command. The current API creates regular users and does not seed an administrator. Avoid a default admin password.
6. Decide how registration works: open registration is convenient for local learning; a private pilot should use controlled account creation.

**Done when:** the scenario and permissions are written down, an administrator can be created, and data survives a normal service recreation using the intended volume.

### Milestone 1 — Trusted sources and a normalized event contract

**Security concept:** authentication answers who sent the request. Authorization answers what that sender may do. Source authentication establishes which producer sent a record; it cannot prove the producer's record is truthful.

Tasks:

1. Add a `sources` table with a stable ID, display name, enabled state, creation time, and last accepted event time.
2. Add source credentials with a public lookup identifier and a securely generated random secret. Store a one-way verifier, show the full credential once, and support revocation/rotation. Keep secrets out of URLs and logs.
3. Make source identity come from the verified credential. A collector must not choose another source by editing the JSON body.
4. Introduce `source_id` on events with a foreign key and a unique constraint on `(source_id, event_id)`. Plan the backfill/migration from the existing `source` string; do not silently reinterpret old values.
5. Add an event request schema. Reuse the current fields where appropriate and document their meaning.

Example proposed request, with source identity provided by the request credential:

```json
{
  "schema_version": 1,
  "event_id": "demo-auth-000123",
  "event_type": "authentication.failed",
  "occurred_at": "2026-10-22T09:00:00Z",
  "severity": "info",
  "actor_user_id": "alice",
  "actor_ip": "192.0.2.20",
  "metadata": {
    "reason": "invalid_credentials",
    "service": "demo-app"
  }
}
```

6. Validate IP addresses, field lengths, supported event types, object-shaped metadata, and timezone-aware timestamps. Normalize accepted timestamps to UTC. The current database column types alone do not provide all this validation.
7. Require a stable external account identifier for events eligible for the account-based rule. Unknown-account failures may still be stored; do not group all missing identities together.
8. Set limits: an initial lab choice is 100 events per batch and 256 KiB per request, enforced at the request boundary before parsing an oversized body. These are starting configuration choices, not universal SIEM limits.
9. Allowlist supported metadata fields for the first integration. Exclude passwords, tokens, cookies, and API keys. A generic `metadata` dictionary can otherwise become a secret collection mechanism. Retain only sanitized source evidence, with an explicit access policy.

The event's producer severity describes that observation. A failed login can be `info` while an alert about many failures is `medium`; derive alert severity from your rule rather than trusting the producer to set it.

**Done when:** a valid credential can submit only for its own source; a revoked credential fails; malformed input fails clearly; secrets are excluded by the supported schema.

### Milestone 2 — Durable ingestion and a simulator

**Security concept:** logs are evidence. Duplicated or silently lost evidence produces misleading investigations.

Tasks:

1. Implement single-event ingestion first, then a bounded batch endpoint once that behavior works.
2. Return success only after the database transaction commits. If persistence fails, return a retryable server error without claiming the event was accepted.
3. Enforce idempotency using the database uniqueness constraint, including concurrent submissions. A “check then insert” alone has a race condition.
4. For the same source and event ID: an identical normalized payload returns the existing event; different content returns a conflict. Do not overwrite the earlier record.
5. Compare stable normalized content for duplicates. Exclude server-generated IDs and ingestion timestamps; normalize equivalent timestamp/IP representations before comparison.
6. For the first batch API, use atomic behavior: validate the whole batch, then commit all new records together. Return counts/IDs for new records and identical duplicates; a conflicting reused ID rejects the batch without partial writes. Document duplicates inside a single batch too.
7. Create a simulator with fixed fixtures: normal activity, five failures, multiple accounts, multiple sources, a success after failures, duplicate retries, and delayed delivery. A retry must reuse the original event ID.
8. Add database-backed HTTP tests for accepted events, malformed input, source isolation, duplicate races, and failed transactions.

Suggested routes:

| Method | Route | Caller |
| --- | --- | --- |
| POST | `/api/v1/sources` | Administrator |
| POST | `/api/v1/sources/{id}/credentials` | Administrator |
| DELETE | `/api/v1/sources/{id}/credentials/{credential_id}` | Administrator |
| POST | `/api/v1/events` | Authenticated source |
| POST | `/api/v1/events/batch` | Authenticated source |

**Done when:** the simulator can send the same dataset repeatedly without changing the number or content of stored events, and concurrent retries behave correctly in PostgreSQL.

### Milestone 3 — Event search and evidence retrieval

**Security concept:** a detection is useful only when an analyst can inspect the underlying activity and surrounding context.

Tasks:

1. Implement `GET /api/v1/events` and `GET /api/v1/events/{id}` for authenticated analysts/admins.
2. Support filters for time range, source, event type, severity, external account, and IP. Use explicit indexed filters before adding unrestricted text search.
3. Define time boundaries, for example `start <= occurred_at < end`, and enforce a maximum search interval. Use a recent default range.
4. Support deterministic ordering and cursor pagination using both a timestamp and unique ID. A timestamp alone is not unique. Document that late events can alter event-time search results; ordinary pagination is not a historical snapshot.
5. Cap page size and set query timeouts. Use parameterized SQLAlchemy expressions and an allowlist for sort fields.
6. Return both `occurred_at` and `ingested_at`. The first is when the source says the event happened; the second is when your database received it. Their difference helps identify clock and delivery problems.
7. Preserve events as immutable through ordinary APIs. Corrections should be separately recorded; retention is a controlled administrative operation.
8. Test realistic query plans on seeded PostgreSQL data. The existing indexes are a good start; add composite indexes only for demonstrated access patterns.

**Done when:** an analyst can reconstruct an account's timeline, retrieve individual evidence records, and page through equal-timestamp results without pagination-induced duplicates or gaps on an unchanged dataset.

### Milestone 4 — One detection rule with reliable processing

**Security concept:** repeated authentication failures can indicate password guessing, but users and broken integrations also produce them. The threshold is a hypothesis to test and tune.

Initial rule specification:

```text
ID: repeated_failed_logins
Version: 1
Input: authentication.failed events with a non-empty external account ID
Group: source_id + actor_user_id
Condition: at least 5 distinct events within a sliding 10-minute window
Window: [window_end - 10 minutes, window_end]
Alert severity: medium (initial lab choice)
Evidence: triggering event IDs, timestamps, account, source, observed IPs
```

Group by account and source, allowing multiple IPs. Grouping only by IP would change the question and could combine unrelated users behind a shared public address. This rule suggests possible password guessing, related to [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/); it does not cover every brute-force variant.

Tasks:

1. Implement the rule as ordinary versioned application code with validated threshold/window configuration. A general rule editor is unnecessary initially.
2. Specify event-time behavior before coding. Recommended lab policy: use `occurred_at`; store older events for search but automatically evaluate only events delivered within a documented 24-hour lateness horizon. Reject or quarantine timestamps more than two minutes in the future. These limits are configurable design choices.
3. Handle out-of-order delivery within that horizon. An older arriving failure can complete a window ending at a later event already stored. Re-evaluate affected later windows as well as the window ending at the new event. Test this explicitly.
4. When detection is introduced, persist a pending detection job in the same transaction as each new event. A duplicate submission must not create another job. Existing events need an explicit backfill command if they should be evaluated.
5. Run a single detector command/process initially. Poll pending jobs, retry failures with backoff, record attempts/errors, and expose failed jobs for operator inspection. Use a lock to prevent overlapping detector instances; introduce row claiming/leases only when parallel workers are needed.
6. Commit alert/evidence changes and successful job completion together. A crash before commit should leave the job retryable; a crash after commit should not duplicate the alert. Do not use only in-memory tasks or FastAPI background callbacks for this guarantee.
7. Add alert deduplication separate from event deduplication. Define a detection episode for each rule/version/source/account: update its alert while matching failures continue, and permit a new episode after ten minutes without a matching failure. Keep episode timing separate from analyst status; closing an alert must not cause the next retry to create another one.
8. Give each episode a persisted identity and enforce uniqueness for its alert in the database. Late arrivals that connect previously separate episodes need a documented merge/update policy; do not silently emit an additional alert for the same evaluated activity.
9. Save rule version, threshold, window, matched count, evaluation time, and triggering evidence on the alert. A future rule edit must not erase the explanation for an old alert.
10. Create tests for four/five/six failures, exact time boundaries, cross-source/account separation, missing identities, duplicates, restarts, delayed events, the lateness cutoff, and alert deduplication.

**Done when:** five distinct qualifying failures produce one explainable alert, repeated delivery or worker retries do not produce extra alerts, and a restart resumes pending work.

### Milestone 5 — Alert investigation and an audit trail

**Security concept:** detection brings activity to a person's attention. Investigation determines whether it needs action and records the reasoning.

Suggested minimal entities:

| Entity | Purpose |
| --- | --- |
| `Alert` | Rule/version, source/account, severity, status, detection episode, time range, summary |
| `AlertEvidence` | Links alerts to event records; preserves the triggering explanation |
| `AlertActivity` | Append-only status changes and notes with analyst and timestamp |
| `AuditEntry` | Administrative actions such as credential revocation and source changes |

Tasks:

1. Add `GET /alerts`, `GET /alerts/{id}`, and `GET /alerts/{id}/events` under `/api/v1`.
2. Add `PATCH /alerts/{id}` for allowed status changes and `POST /alerts/{id}/notes` for investigator notes. Validate fields and prevent arbitrary property updates.
3. Use `new -> acknowledged -> closed`. At closure, require a resolution such as `benign`, `suspicious`, or `confirmed_incident`, plus an explanatory note. “Closed” alone does not explain the decision.
4. Record the user, time, old/new status, and note. Use a version check or equivalent concurrency control so two analysts do not silently overwrite each other's changes.
5. Keep the original trigger explanation stable while allowing later related evidence to be appended. An alert needs enough context to explain why it fired even after retention removes some events.
6. Record administrative changes in a separate audit trail. The source that submits events must not be able to edit alerts, investigator decisions, or administrative records.
7. Add a short investigation guide: inspect failures, compare account/IP patterns, look for nearby successful logins, check known tests/outages, and document the conclusion. A success after failures increases concern but still requires context.

**Done when:** an analyst can open an alert, inspect its evidence and nearby successes, acknowledge it, and close it with a decision whose history remains visible.

### Milestone 6 — One actual source integration

**Why:** synthetic events verify your algorithm, but an integration exposes parser mistakes, missing identities, clock differences, and unreliable delivery.

Tasks:

1. Instrument a small lab application to emit successful and failed authentication events. Start with structured JSON; add Linux SSH or Windows logs later when you can validate their exact formats and meaning.
2. Add a collector that transforms source records into the normalized schema. Keep parser logic specific to the supported source/version.
3. Preserve stable event IDs across retries and persist a file offset/checkpoint or pending spool. Advance it only after acknowledged ingestion so a collector restart does not silently discard records.
4. Use bounded retries and backoff. Treat authentication/schema errors differently from temporary server errors. Record rejected events without exposing credentials or sensitive payloads.
5. Keep the account namespace explicit. Two unrelated systems can both have an `alice`; correlating them later needs a separate identity-mapping decision.
6. Validate client IP provenance. Do not trust arbitrary `X-Forwarded-For` headers; configure trusted proxies before using forwarded addresses.

**Done when:** harmless failed logins against your own demo application travel through the collector and create an investigable SIEM alert without manually inserting database rows.

### Milestone 7 — Operate and validate the complete MVP

**Security concept:** silence may mean “nothing suspicious happened,” or it may mean collection/detection stopped. A monitoring product needs to reveal that difference.

Tasks:

1. Separate process liveness from readiness. Add a database readiness check and visible detector heartbeat/backlog age.
2. Track accepted/rejected/duplicate events, source last-seen time, ingestion delay, pending/failed jobs, processing latency, and alerts created. An authenticated status endpoint and structured logs are sufficient initially.
3. Add configurable retention and bounded cleanup. A proposed lab default is 14 days, chosen for convenience rather than compliance. Preserve alert explanations and clearly mark expired evidence; define foreign-key behavior before deleting events.
4. Add scheduled blocklist cleanup: the current code removes expired entries during session revocation, so quiet deployments need an independent cleanup path.
5. Document backup and restore, then restore into a disposable database and verify events, alerts, credentials, and migrations. A volume is persistence, not a backup.
6. Set an explicit small pilot capacity target and measure it. Example goal: 10 events/second for 30 minutes, one million seeded searchable events, first-page filtered search p95 below one second, and detector delay below 30 seconds on documented hardware. These are proposed acceptance targets, not measured capabilities.
7. Test database unavailability, detector crashes, collector restart, duplicate retries, and oversized inputs. An acknowledged committed event should survive the documented restart/recovery workflow.
8. Write a runbook explaining startup, administrative bootstrap, credential rotation, stuck jobs, retention, backup restoration, and what “healthy” looks like.

**Done when:** the entire demo below is repeatable and failures are visible, recoverable, and documented.

## 5. Before exposing the API beyond the lab

Treat this as a separate release gate. Completing a local demonstration does not establish internet-facing readiness.

- Terminate HTTPS correctly and restrict database/network access.
- Configure authentication and ingestion rate limits, body limits, and request/query timeouts.
- Use controlled account provisioning and an account recovery path; add MFA/SSO when required by the deployment's users and risk.
- Remove default database credentials. Use a restricted runtime database role and a separate migration identity with schema privileges.
- Store deployment secrets outside source control; define credential rotation and backup access controls.
- Review every source, event, alert, and administration endpoint for permission enforcement. Credentialed CORS is not authorization.
- Protect logs, metadata, exports, backups, and operational endpoints from unauthorized access.
- Validate restore procedures, resource limits, dependency maintenance, and failure monitoring in the deployment environment.

The logging field, sanitization, and access-control recommendations follow the themes in the [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html). The collection, analysis, and retention lifecycle is also covered by [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final). This roadmap is an engineering proposal, not a compliance assessment.

## 6. Final MVP acceptance walkthrough

1. Start the application from documented configuration and apply migrations.
2. Bootstrap an administrator, create an analyst and a source, and issue a source credential.
3. Send four distinct failures for one external account within ten minutes: no alert.
4. Send the fifth distinct failure: one alert with linked evidence appears within the agreed detector delay.
5. Resend those records: event counts and alert counts remain unchanged.
6. Send failures for another source/account: they do not contribute to the first group.
7. Deliver a qualifying event out of order: the documented late-arrival policy works.
8. Search the account timeline, including a nearby successful login.
9. Acknowledge the alert and close it with a reason and note; inspect the audit history.
10. Revoke the source credential: new submissions using it fail.
11. Restart the API, collector, and detector: stored data remains and pending processing resumes.
12. Restore a backup in a disposable environment and retrieve the same event/alert evidence.

This is the release checklist. “All endpoints return 200” is not sufficient.

## 7. Ordered development backlog

Use each row as a small issue or group of related pull requests. Rows depend on the relevant earlier contracts/models.

| Order | Deliverable | Main proof |
| --- | --- | --- |
| 1 | Scenario, permission matrix, admin bootstrap, database volume plan | Reproducible setup and persistent lab data |
| 2 | Source/credential models and migration | Revocation and source-isolation tests |
| 3 | Event schema and single-event ingestion | Validation, transaction, and duplicate tests |
| 4 | Bounded atomic batch endpoint and simulator | Repeatable datasets and stable retry IDs |
| 5 | Event search/detail routes | Filter boundaries, permissions, pagination |
| 6 | Alert/evidence/job models and migration | Constraints and migration alignment |
| 7 | Pure rule evaluator with documented time policy | Boundary, late-event, and grouping tests |
| 8 | Durable detector command and deduplication | Crash/retry tests in PostgreSQL |
| 9 | Investigation routes and audit history | Complete analyst workflow |
| 10 | Demo app integration and checkpointed collector | Real source-to-alert demonstration |
| 11 | Health, retention, backup/restore, capacity test | Operational acceptance walkthrough |
| 12 | Deployment controls when moving beyond the lab | Deployment-specific release review |

Avoid estimating all of this as a short weekend task. Integration, time semantics, and recovery will take iteration, particularly while learning. Use milestone completion evidence to update your schedule.

## 8. Future development after the MVP

| Priority | Feature | Why add it / prerequisite |
| --- | --- | --- |
| Next | Failures followed by a success | Builds on the same event vocabulary; indicates possible account compromise |
| Next | One IP failing against many accounts | Introduces distinct-account aggregation; potentially useful for password spraying, with shared-IP caveats |
| Next | Alert assignment, saved filters, small analyst UI | Reduces investigation effort after APIs are stable |
| Next | One reliable notification channel | Add durable delivery, retries, and rate limits after alert quality is acceptable |
| Later | Linux SSH or Windows authentication connector | Adds source diversity; requires tested parsing and identity mapping |
| Later | Rule configuration/version history and historical replay | Allows controlled tuning; replay should be previewable without flooding live alerts |
| Later | Source silence alerts and richer operational dashboards | Detects collection failures; needs expected source activity/heartbeat definitions |
| Later | Retention tiers, partitioning, archive storage | Add when measured database size/query/cleanup performance requires it |
| Later | Threat intelligence and enrichment | Adds context; requires data provenance, update policy, and false-positive review |
| Much later | Multiple organizations | Requires isolation in every query, job, credential, constraint, cache, and test |
| Much later | Automated response | Requires authorization, safeguards, rollback, and evidence that detections are reliable |

Measure detection quality as well as throughput: review benign alerts, test known suspicious scenarios, and record blind spots. No alert does not establish that an environment is secure.

## 9. Learning path alongside implementation

1. **During ingestion:** learn authentication versus authorization, least privilege, input validation, HTTP retries, database transactions, and idempotency. Exercise: explain why a source must not select its own identity in the payload.
2. **During search:** learn authentication log anatomy, account/IP namespaces, UTC, clock skew, and event time versus receipt time. Exercise: reconstruct one account's timeline when records arrive late.
3. **During detection:** learn password guessing, spraying, credential stuffing, false positives, and rule blind spots. [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/) describes the related attacker techniques. Exercise: explain which variants the first rule misses.
4. **During investigation:** practice writing a short conclusion supported by specific events. Exercise: distinguish “the threshold fired” from “unauthorized access was confirmed.”
5. **During operations:** learn backup versus persistence, queue recovery, monitoring gaps, retention, and resource exhaustion. Exercise: stop the detector, restart it, and prove that accepted events were processed.

Use systems you own or have explicit permission to test. The simulator and your demo application are enough to learn these concepts without targeting other systems.

The most valuable first achievement is a trustworthy path from one observed action to one explainable investigation decision.

import base64
import json
from datetime import UTC, datetime
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.v1.schemas.security_event import (
    SecurityEventCreate,
    SecurityEventFilters,
    SecurityEventPage,
    SecurityEventRead,
)
from app.db.models import EventSeverity, SecurityEvent


class EventConflictError(Exception):
    """A producer reused an event ID with different content."""


class InvalidCursorError(Exception):
    """The pagination cursor is malformed."""


class EventCursor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    occurred_at: AwareDatetime
    id: UUID


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def event_values(payload: SecurityEventCreate) -> dict:
    values = payload.model_dump(mode="json", exclude={"occurred_at", "metadata"})
    values["occurred_at"] = payload.occurred_at
    values["event_metadata"] = payload.metadata
    return values


def check_duplicate(event: SecurityEvent, values: dict) -> None:
    for field, value in values.items():
        stored = getattr(event, field)
        if field == "occurred_at":
            stored = as_utc(stored)
        if field == "event_metadata":
            # JSON booleans and numbers differ even though Python equates True and 1.
            stored = json.dumps(stored, sort_keys=True, allow_nan=False)
            value = json.dumps(value, sort_keys=True, allow_nan=False)
        if stored != value:
            raise EventConflictError


def ingest_event(
    db: Session, payload: SecurityEventCreate
) -> tuple[SecurityEvent, bool]:
    """Persist once, including concurrent retries protected by DB uniqueness."""
    query = select(SecurityEvent).where(
        SecurityEvent.source == payload.source,
        SecurityEvent.event_id == payload.event_id,
    )
    values = event_values(payload)
    existing = db.scalar(query)
    if existing is not None:
        check_duplicate(existing, values)
        return existing, False

    event = SecurityEvent(**values)
    db.add(event)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(query)
        if existing is None:
            # Do not disguise unrelated persistence failures as duplicate IDs.
            raise
        check_duplicate(existing, values)
        return existing, False
    db.refresh(event)
    return event, True


def list_events(db: Session, filters: SecurityEventFilters) -> SecurityEventPage:
    query = select(SecurityEvent)
    for field in ("source", "event_type", "severity", "actor_user_id", "actor_ip"):
        value = getattr(filters, field)
        if value is not None:
            value = value.value if isinstance(value, EventSeverity) else str(value)
            query = query.where(getattr(SecurityEvent, field) == value)
    if filters.occurred_from is not None:
        query = query.where(SecurityEvent.occurred_at >= filters.occurred_from)
    if filters.occurred_to is not None:
        query = query.where(SecurityEvent.occurred_at < filters.occurred_to)
    if filters.cursor is not None:
        try:
            decoded = base64.b64decode(filters.cursor, altchars=b"-_", validate=True)
            cursor = EventCursor.model_validate_json(decoded)
        except ValueError as exc:
            raise InvalidCursorError from exc
        occurred_at = cursor.occurred_at.astimezone(UTC)
        query = query.where(
            or_(
                SecurityEvent.occurred_at < occurred_at,
                and_(
                    SecurityEvent.occurred_at == occurred_at,
                    SecurityEvent.id < cursor.id,
                ),
            )
        )
    query = query.order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.id.desc())
    events = list(db.scalars(query.limit(filters.limit + 1)))
    has_more = len(events) > filters.limit
    events = events[: filters.limit]
    next_cursor = None
    if has_more:
        last = events[-1]
        cursor = EventCursor(occurred_at=as_utc(last.occurred_at), id=last.id)
        next_cursor = base64.urlsafe_b64encode(
            cursor.model_dump_json().encode()
        ).decode()
    return SecurityEventPage(
        items=[SecurityEventRead.model_validate(event) for event in events],
        next_cursor=next_cursor,
    )

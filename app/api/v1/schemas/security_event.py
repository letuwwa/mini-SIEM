import json
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.db.models import EventSeverity

EventIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)
]
EventType = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)
]


class SecurityEventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: EventIdentifier
    source: EventIdentifier
    event_type: EventType
    occurred_at: AwareDatetime
    severity: EventSeverity = EventSeverity.INFO
    actor_user_id: EventIdentifier | None = None
    actor_ip: IPvAnyAddress | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator("metadata")
    @classmethod
    def bound_metadata(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        # Reject non-standard JSON numbers as well as oversized metadata.
        encoded = json.dumps(value, allow_nan=False).encode()
        if len(encoded) > 16_384:
            raise ValueError("Metadata must not exceed 16384 JSON-encoded bytes")
        return value


class SecurityEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    event_id: str
    source: str
    event_type: str
    occurred_at: datetime
    ingested_at: datetime
    severity: EventSeverity
    actor_user_id: str | None
    actor_ip: str | None
    metadata: dict[str, JsonValue] = Field(validation_alias="event_metadata")

    @field_validator("occurred_at", "ingested_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        # SQLite drops timezone information; application writes are always UTC.
        return (
            value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        )


class SecurityEventPage(BaseModel):
    items: list[SecurityEventRead]
    next_cursor: str | None = None


class SecurityEventFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: EventIdentifier | None = None
    event_type: EventType | None = None
    severity: EventSeverity | None = None
    actor_user_id: EventIdentifier | None = None
    actor_ip: IPvAnyAddress | None = None
    occurred_from: AwareDatetime | None = None
    occurred_to: AwareDatetime | None = None
    limit: int = Field(default=50, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=512)

    @field_validator("occurred_from", "occurred_to")
    @classmethod
    def normalize_time(cls, value: datetime | None) -> datetime | None:
        return value.astimezone(UTC) if value is not None else None

    @model_validator(mode="after")
    def validate_time_range(self) -> SecurityEventFilters:
        if (
            self.occurred_from is not None
            and self.occurred_to is not None
            and self.occurred_from >= self.occurred_to
        ):
            raise ValueError("occurred_from must be earlier than occurred_to")
        return self

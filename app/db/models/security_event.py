import enum
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Enum,
    Index,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base_model import BaseModel


class EventSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    """A producer event; actor IDs are external identities, not application users.

    occurred_at is producer event time; ingested_at is database insertion time.
    Supply timezone-aware datetimes; request validation belongs to the API schema.
    """

    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_security_events_severity",
        ),
        UniqueConstraint(
            "source", "event_id", name="uq_security_events_source_event_id"
        ),
        Index("ix_security_events_occurred_at", "occurred_at"),
        Index("ix_security_events_source_time", "source", "occurred_at"),
        Index("ix_security_events_type_time", "event_type", "occurred_at"),
        Index(
            "ix_security_events_source_actor_time",
            "source",
            "actor_user_id",
            "occurred_at",
        ),
    )

    event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    severity: Mapped[EventSeverity] = mapped_column(
        Enum(
            EventSeverity,
            name="event_severity",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
            validate_strings=True,
        ),
        nullable=False,
    )
    actor_user_id: Mapped[str | None] = mapped_column(String(255))
    actor_ip: Mapped[str | None] = mapped_column(String(45))
    # DeclarativeBase reserves the Python attribute name "metadata".
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSON().with_variant(JSONB(), "postgresql"),
        default=dict,
        server_default=text("'{}'"),
        nullable=False,
    )

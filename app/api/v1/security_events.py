from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.v1.schemas.security_event import (
    SecurityEventCreate,
    SecurityEventFilters,
    SecurityEventPage,
    SecurityEventRead,
)
from app.api.v1.services import (
    EventConflictError,
    InvalidCursorError,
    ingest_event,
    list_events,
)
from app.core.security import get_current_user, require_admin
from app.db.deps import get_db
from app.db.models import SecurityEvent

router = APIRouter(prefix="/events", tags=["security events"])


@router.post(
    "",
    response_model=SecurityEventRead,
    status_code=status.HTTP_201_CREATED,
    responses={
        200: {"model": SecurityEventRead},
        409: {"description": "Event ID conflict"},
    },
    dependencies=[Depends(require_admin)],
)
def create_security_event(
    payload: SecurityEventCreate,
    response: Response,
    db: Session = Depends(get_db),
) -> SecurityEvent:
    """Admin ingestion until source-scoped collector credentials are available."""
    try:
        event, created = ingest_event(db, payload)
    except EventConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Event ID already exists for this source with different content",
        ) from exc
    if not created:
        response.status_code = status.HTTP_200_OK
    return event


@router.get(
    "", response_model=SecurityEventPage, dependencies=[Depends(get_current_user)]
)
def search_security_events(
    filters: Annotated[SecurityEventFilters, Query()],
    db: Session = Depends(get_db),
) -> SecurityEventPage:
    """Newest first; reuse the same filters when following next_cursor."""
    try:
        return list_events(db, filters)
    except InvalidCursorError as exc:
        raise HTTPException(status_code=422, detail="Invalid event cursor") from exc


@router.get(
    "/{event_id}",
    response_model=SecurityEventRead,
    dependencies=[Depends(get_current_user)],
)
def read_security_event(event_id: UUID, db: Session = Depends(get_db)) -> SecurityEvent:
    """Look up an event by its SIEM UUID, rather than its producer event_id."""
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Security event not found")
    return event

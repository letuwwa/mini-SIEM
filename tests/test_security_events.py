from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.v1.auth import register_user
from app.api.v1.schemas import UserRegister
from app.api.v1.schemas.security_event import SecurityEventCreate, SecurityEventFilters
from app.api.v1.services import EventConflictError, ingest_event, list_events
from app.db.models import SecurityEvent, UserRole

PAYLOAD = {
    "event_id": "event-1",
    "source": "demo-auth",
    "event_type": "authentication.failed",
    "occurred_at": "2026-10-22T12:00:00+03:00",
    "severity": "info",
    "actor_user_id": "alice",
    "actor_ip": "2001:db8::1",
    "metadata": {"reason": "invalid_credentials"},
}


@pytest.fixture
def admin_headers(db: Session) -> dict[str, str]:
    result = register_user(
        UserRegister(
            email="admin@example.com",
            username="admin",
            first_name="Admin",
            last_name="User",
            password="test-password-123",
        ),
        db,
    )
    result["user"].role = UserRole.ADMIN
    db.commit()
    return {"Authorization": f"Bearer {result['tokens'].access_token}"}


def test_ingestion_normalizes_and_deduplicates(db: Session) -> None:
    event, created = ingest_event(db, SecurityEventCreate.model_validate(PAYLOAD))
    assert created
    assert event.occurred_at.replace(tzinfo=UTC) == datetime(
        2026, 10, 22, 9, tzinfo=UTC
    )
    retried, created = ingest_event(
        db,
        SecurityEventCreate.model_validate(
            PAYLOAD
            | {
                "occurred_at": "2026-10-22T09:00:00Z",
                "actor_ip": "2001:0db8:0000:0000:0000:0000:0000:0001",
            }
        ),
    )
    assert not created
    assert retried.id == event.id
    with pytest.raises(EventConflictError):
        ingest_event(
            db, SecurityEventCreate.model_validate(PAYLOAD | {"severity": "high"})
        )
    assert db.scalar(select(func.count()).select_from(SecurityEvent)) == 1
    assert db.get(SecurityEvent, event.id).severity.value == "info"
    _, created = ingest_event(
        db, SecurityEventCreate.model_validate(PAYLOAD | {"source": "other-source"})
    )
    assert created


def test_http_event_lifecycle(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    response = client.post("/api/v1/events", json=PAYLOAD, headers=admin_headers)
    assert response.status_code == 201
    event = response.json()
    assert event["metadata"] == PAYLOAD["metadata"]
    assert event["occurred_at"] == "2026-10-22T09:00:00Z"
    assert event["ingested_at"].endswith("Z")
    assert "event_metadata" not in event
    response = client.post("/api/v1/events", json=PAYLOAD, headers=admin_headers)
    assert response.status_code == 200
    assert response.json() == event
    response = client.post(
        "/api/v1/events",
        json=PAYLOAD | {"metadata": {"reason": "changed"}},
        headers=admin_headers,
    )
    assert response.status_code == 409
    response = client.get(f"/api/v1/events/{event['id']}", headers=admin_headers)
    assert response.status_code == 200
    assert response.json() == event
    assert (
        client.get(f"/api/v1/events/{uuid4()}", headers=admin_headers).status_code
        == 404
    )
    assert (
        client.get("/api/v1/events/not-a-uuid", headers=admin_headers).status_code
        == 422
    )


def test_event_permissions(client: TestClient, admin_headers: dict[str, str]) -> None:
    for method, path in (
        ("POST", "/api/v1/events"),
        ("GET", "/api/v1/events"),
        ("GET", f"/api/v1/events/{uuid4()}"),
    ):
        assert client.request(method, path, json=PAYLOAD).status_code == 401
    registered = client.post(
        "/api/v1/auth/register",
        json={
            "email": "analyst@example.com",
            "username": "analyst",
            "first_name": "Analyst",
            "last_name": "User",
            "password": "test-password-123",
        },
    ).json()
    analyst = {"Authorization": f"Bearer {registered['tokens']['access_token']}"}
    assert (
        client.post("/api/v1/events", json=PAYLOAD, headers=analyst).status_code == 403
    )
    event = client.post("/api/v1/events", json=PAYLOAD, headers=admin_headers).json()
    assert client.get("/api/v1/events", headers=analyst).status_code == 200
    assert (
        client.get(f"/api/v1/events/{event['id']}", headers=analyst).status_code == 200
    )
    # No mutation endpoints: evidence cannot be edited or deleted through this API.
    assert (
        client.delete(
            f"/api/v1/events/{event['id']}", headers=admin_headers
        ).status_code
        == 405
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", " "),
        ("source", "x" * 256),
        ("event_type", ""),
        ("actor_user_id", " "),
        ("actor_ip", "invalid-ip"),
        ("occurred_at", "2026-10-22T09:00:00"),
        ("severity", "unknown"),
        ("metadata", []),
        ("metadata", {"large": "x" * 16_384}),
        ("unexpected", "value"),
    ],
)
def test_invalid_event_payloads(
    client: TestClient, admin_headers: dict[str, str], field: str, value: object
) -> None:
    response = client.post(
        "/api/v1/events", json=PAYLOAD | {field: value}, headers=admin_headers
    )
    assert response.status_code == 422


def test_search_filters_and_time_boundaries(
    client: TestClient, db: Session, admin_headers: dict[str, str]
) -> None:
    variations = [
        {},
        {"source": "other"},
        {"event_type": "authentication.succeeded"},
        {"severity": "high"},
        {"actor_user_id": "bob"},
        {"actor_ip": "192.0.2.1"},
        {"occurred_at": "2026-10-22T09:01:00Z"},
        {"occurred_at": "2026-10-22T08:59:00Z"},
    ]
    for index, variation in enumerate(variations):
        ingest_event(
            db,
            SecurityEventCreate.model_validate(
                PAYLOAD | variation | {"event_id": f"event-{index}"}
            ),
        )
    response = client.get(
        "/api/v1/events",
        params={
            "source": "demo-auth",
            "event_type": "authentication.failed",
            "severity": "info",
            "actor_user_id": "alice",
            "actor_ip": "2001:0db8::1",
            "occurred_from": "2026-10-22T12:00:00+03:00",
            "occurred_to": "2026-10-22T09:01:00Z",
        },
        headers=admin_headers,
    )
    assert response.status_code == 200
    assert [event["event_id"] for event in response.json()["items"]] == ["event-0"]


def test_cursor_pagination_with_equal_timestamps(db: Session) -> None:
    for index in range(7):
        ingest_event(
            db, SecurityEventCreate.model_validate(PAYLOAD | {"event_id": str(index)})
        )
    cursor = None
    ids = []
    while True:
        page = list_events(db, SecurityEventFilters(limit=2, cursor=cursor))
        ids.extend(event.id for event in page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    assert len(ids) == len(set(ids)) == 7
    assert ids == sorted(ids, reverse=True)
    assert list_events(db, SecurityEventFilters(source="missing")).items == []


def test_metadata_types_are_distinct_for_duplicate_detection(db: Session) -> None:
    ingest_event(
        db, SecurityEventCreate.model_validate(PAYLOAD | {"metadata": {"flag": True}})
    )
    with pytest.raises(EventConflictError):
        ingest_event(
            db, SecurityEventCreate.model_validate(PAYLOAD | {"metadata": {"flag": 1}})
        )


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 101},
        {"cursor": "!!!"},
        {"cursor": "e30="},
        {"occurred_from": "2026-10-22T09:00:00"},
        {
            "occurred_from": "2026-10-23T00:00:00Z",
            "occurred_to": "2026-10-22T00:00:00Z",
        },
        {"severity": "unknown"},
        {"actor_ip": "invalid"},
        {"unknown_filter": "value"},
    ],
)
def test_invalid_search_queries(
    client: TestClient, admin_headers: dict[str, str], params: dict
) -> None:
    assert (
        client.get("/api/v1/events", params=params, headers=admin_headers).status_code
        == 422
    )

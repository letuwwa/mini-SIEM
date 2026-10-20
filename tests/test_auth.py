from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.auth import logout_user, refresh_token, register_user
from app.api.v1.schemas import UserRegister
from app.api.v1.utils import authenticate_user
from app.core import settings
from app.core.security import decode_token, get_token_user
from app.db.models import TokenBlocklist, User, UserRole

REGISTER_PAYLOAD = {
    "email": "User@Example.com",
    "username": "exampleuser",
    "first_name": "Example",
    "last_name": "User",
    "password": "password123456",
}


def register(db: Session) -> dict:
    return register_user(UserRegister.model_validate(REGISTER_PAYLOAD), db)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("email", "not-an-email"),
        ("email", ""),
        ("username", "   "),
        ("username", "user@example.com"),
        ("username", "invalid username"),
        ("first_name", ""),
        ("last_name", "   "),
    ],
)
def test_registration_rejects_invalid_identity_fields(
    field: str,
    value: str,
) -> None:
    payload = REGISTER_PAYLOAD | {field: value}

    with pytest.raises(ValidationError):
        UserRegister.model_validate(payload)


def test_registration_normalizes_email_and_names(db: Session) -> None:
    payload = REGISTER_PAYLOAD | {
        "email": " User@EXAMPLE.com ",
        "username": " exampleuser ",
        "first_name": " Example ",
        "last_name": " User ",
    }

    user_in = UserRegister.model_validate(payload)
    response = register_user(user_in, db)

    user = response["user"]
    assert user.email == "user@example.com"
    assert user.username == "exampleuser"
    assert user.first_name == "Example"
    assert user.last_name == "User"


def test_login_email_is_case_insensitive(db: Session) -> None:
    register(db)

    user = authenticate_user(db, " USER@EXAMPLE.COM ", REGISTER_PAYLOAD["password"])

    assert user.email == "user@example.com"


def test_logout_revokes_access_and_refresh_tokens(db: Session) -> None:
    registered = register(db)
    user = registered["user"]
    tokens = registered["tokens"]

    logout = logout_user(tokens.access_token, db)

    assert logout == {"message": "Session revoked"}
    with pytest.raises(HTTPException) as access_error:
        get_token_user(db, decode_token(tokens.access_token), "access")
    assert access_error.value.status_code == 401
    with pytest.raises(HTTPException) as refresh_error:
        get_token_user(db, decode_token(tokens.refresh_token), "refresh")
    assert refresh_error.value.status_code == 401
    assert user.id is not None


def test_refresh_rotates_entire_token_pair(db: Session) -> None:
    old_tokens = register(db)["tokens"]

    new_tokens = refresh_token(old_tokens.refresh_token, db)

    assert new_tokens.access_token != old_tokens.access_token
    assert new_tokens.refresh_token != old_tokens.refresh_token
    with pytest.raises(HTTPException):
        get_token_user(db, decode_token(old_tokens.access_token), "access")
    with pytest.raises(HTTPException):
        refresh_token(old_tokens.refresh_token, db)
    assert (
        get_token_user(
            db,
            decode_token(new_tokens.access_token),
            "access",
        ).id
        is not None
    )


def test_revocation_removes_expired_blocklist_entries(
    db: Session,
) -> None:
    expired_id = "00000000-0000-0000-0000-000000000000"
    db.add(
        TokenBlocklist(
            jti=expired_id,
            token_type="session",
            user_id="00000000-0000-0000-0000-000000000000",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
    )
    db.commit()
    tokens = register(db)["tokens"]

    response = logout_user(tokens.refresh_token, db)

    assert response == {"message": "Session revoked"}
    assert (
        db.scalar(select(TokenBlocklist.id).where(TokenBlocklist.jti == expired_id))
        is None
    )


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("type", []),
        ("type", {}),
        ("sid", ""),
        ("sid", "s" * 37),
        ("jti", ""),
        ("jti", "j" * 37),
        ("exp", []),
        ("exp", float("inf")),
        ("session_exp", "tomorrow"),
        ("session_exp", True),
        ("session_exp", float("nan")),
        ("session_exp", float("inf")),
        ("session_exp", 10**100),
        ("session_exp", 1),
    ],
)
@pytest.mark.parametrize("endpoint", ["me", "logout", "refresh"])
def test_malformed_claims_return_401(
    client: TestClient, claim: str, value: object, endpoint: str
) -> None:
    tokens = client.post("/api/v1/auth/register", json=REGISTER_PAYLOAD).json()[
        "tokens"
    ]
    token = tokens["refresh_token" if endpoint == "refresh" else "access_token"]
    payload = decode_token(token) | {claim: value}
    malformed = jwt.encode(
        payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )

    response = client.request(
        "GET" if endpoint == "me" else "POST",
        f"/api/v1/auth/{endpoint}",
        headers={"Authorization": f"Bearer {malformed}"},
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_http_authentication_lifecycle(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/register", json=REGISTER_PAYLOAD | {"role": "admin"}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["user"]["role"] == "regular"
    assert "password" not in body["user"]
    assert "hashed_password" not in body["user"]
    tokens = body["tokens"]
    access = {"Authorization": f"Bearer {tokens['access_token']}"}
    refresh = {"Authorization": f"Bearer {tokens['refresh_token']}"}
    assert (
        client.get("/api/v1/auth/me", headers=access).json()["id"] == body["user"]["id"]
    )
    assert client.get("/api/v1/auth/admin-only", headers=access).status_code == 403
    assert client.get("/api/v1/auth/me", headers=refresh).status_code == 401
    assert client.post("/api/v1/auth/refresh", headers=access).status_code == 401
    assert (
        client.post("/api/v1/auth/register", json=REGISTER_PAYLOAD).status_code == 409
    )

    rotated = client.post("/api/v1/auth/refresh", headers=refresh)
    assert rotated.status_code == 200
    assert client.get("/api/v1/auth/me", headers=access).status_code == 401
    assert client.post("/api/v1/auth/refresh", headers=refresh).status_code == 401
    new_access = {"Authorization": f"Bearer {rotated.json()['access_token']}"}
    new_refresh = {"Authorization": f"Bearer {rotated.json()['refresh_token']}"}
    assert client.post("/api/v1/auth/logout", headers=new_refresh).status_code == 200
    assert client.get("/api/v1/auth/me", headers=new_access).status_code == 401
    assert client.post("/api/v1/auth/refresh", headers=new_refresh).status_code == 401


@pytest.mark.parametrize("endpoint", ["login", "token"])
def test_http_login_contract(client: TestClient, endpoint: str) -> None:
    client.post("/api/v1/auth/register", json=REGISTER_PAYLOAD)
    response = client.post(
        f"/api/v1/auth/{endpoint}",
        data={
            "username": " USER@EXAMPLE.COM ",
            "password": REGISTER_PAYLOAD["password"],
        },
    )
    assert response.status_code == 200
    tokens = response.json()["tokens"] if endpoint == "login" else response.json()
    assert tokens["token_type"] == "bearer"
    assert (
        client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        ).status_code
        == 200
    )
    invalid = client.post(
        f"/api/v1/auth/{endpoint}",
        data={"username": "exampleuser", "password": "incorrect-password"},
    )
    assert invalid.status_code == 401
    assert invalid.headers["www-authenticate"] == "Bearer"
    assert (
        client.post(
            f"/api/v1/auth/{endpoint}",
            data={"username": "exampleuser", "password": "x" * 129},
        ).status_code
        == 422
    )


def test_permissions_use_current_database_state(
    client: TestClient, db: Session
) -> None:
    body = client.post("/api/v1/auth/register", json=REGISTER_PAYLOAD).json()
    access = {"Authorization": f"Bearer {body['tokens']['access_token']}"}
    user = db.scalar(select(User).where(User.username == REGISTER_PAYLOAD["username"]))
    assert user is not None
    user.role = UserRole.ADMIN
    db.commit()
    assert client.get("/api/v1/auth/admin-only", headers=access).status_code == 200
    user.role = UserRole.REGULAR
    db.commit()
    assert client.get("/api/v1/auth/admin-only", headers=access).status_code == 403
    user.is_active = False
    db.commit()
    assert client.get("/api/v1/auth/me", headers=access).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/login",
            data={"username": "exampleuser", "password": REGISTER_PAYLOAD["password"]},
        ).status_code
        == 403
    )


def test_unknown_user_still_verifies_password(db: Session, monkeypatch) -> None:
    from app.api.v1.utils import auth
    from app.core.security import DUMMY_PASSWORD_HASH

    calls = []

    def verify(password: str, hashed: str) -> bool:
        calls.append((password, hashed))
        return True

    monkeypatch.setattr(auth, "verify_password", verify)
    with pytest.raises(HTTPException) as error:
        authenticate_user(db, "unknown", "password123456")
    assert error.value.status_code == 401
    assert calls == [("password123456", DUMMY_PASSWORD_HASH)]


@pytest.mark.parametrize("token", [None, "not-a-jwt"])
def test_missing_or_invalid_bearer_token(client: TestClient, token: str | None) -> None:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    response = client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_cors_only_allows_configured_origins(client: TestClient) -> None:
    for origin, expected in [
        (settings.allowed_origins[0], 200),
        ("https://untrusted.example", 400),
    ]:
        response = client.options(
            "/api/v1/auth/me",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
        assert response.status_code == expected
        if expected == 200:
            assert response.headers["access-control-allow-origin"] == origin
        else:
            assert "access-control-allow-origin" not in response.headers

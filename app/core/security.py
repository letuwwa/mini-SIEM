from datetime import UTC, datetime, timedelta
from math import isfinite
from typing import Any
from uuid import UUID, uuid4

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import settings
from app.db.deps import get_db
from app.db.models import TokenBlocklist, User, UserRole

password_hash = PasswordHash.recommended()
# Keep nonexistent-user logins on the same password-verification path.
DUMMY_PASSWORD_HASH = password_hash.hash("unused-dummy-password")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)


def create_access_token(
    user: User,
    session_id: str,
    session_expires_at: datetime,
) -> str:
    return _create_token(
        user=user,
        token_type="access",
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
        session_id=session_id,
        session_expires_at=session_expires_at,
    )


def create_refresh_token(
    user: User,
    session_id: str,
    session_expires_at: datetime,
) -> str:
    return _create_token(
        user=user,
        token_type="refresh",
        expires_delta=timedelta(days=settings.refresh_token_expire_days),
        session_id=session_id,
        session_expires_at=session_expires_at,
    )


def decode_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={
                "require": ["exp", "jti", "session_exp", "sid", "sub", "type"],
            },
        )
    except (jwt.InvalidTokenError, TypeError, ValueError, OverflowError) as exc:
        raise _credentials_exception() from exc

    # PyJWT checks registered claims, but our session claims need validation too.
    if payload.get("type") not in ("access", "refresh"):
        raise _credentials_exception()
    for claim in ("jti", "sid"):
        value = payload[claim]
        if not isinstance(value, str) or not 1 <= len(value) <= 36:
            raise _credentials_exception()

    for claim in ("exp", "session_exp"):
        value = payload[claim]
        if type(value) not in (int, float):
            raise _credentials_exception()
        try:
            if not isfinite(value):
                raise ValueError("Non-finite token timestamp")
            datetime.fromtimestamp(value, tz=UTC)
        except (ValueError, OverflowError, OSError) as exc:
            raise _credentials_exception() from exc

    # Otherwise an early session expiry lets cleanup remove a live revocation.
    if payload["exp"] > payload["session_exp"]:
        raise _credentials_exception()
    return payload


def is_token_revoked(db: Session, token_identifier: str) -> bool:
    token_id = db.scalar(
        select(TokenBlocklist.id).where(TokenBlocklist.jti == token_identifier)
    )
    return token_id is not None


def get_token_user(db: Session, payload: dict[str, Any], token_type: str) -> User:
    subject = payload.get("sub")
    jti = payload.get("jti")
    session_id = payload.get("sid")
    payload_token_type = payload.get("type")
    if (
        not isinstance(subject, str)
        or not isinstance(jti, str)
        or not isinstance(session_id, str)
        or payload_token_type != token_type
    ):
        raise _credentials_exception()

    if is_token_revoked(db, jti) or is_token_revoked(db, session_id):
        raise _credentials_exception()

    try:
        user_id = UUID(subject)
    except ValueError as exc:
        raise _credentials_exception() from exc

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _credentials_exception()

    return user


def _create_token(
    user: User,
    token_type: str,
    expires_delta: timedelta,
    session_id: str,
    session_expires_at: datetime,
) -> str:
    expires_at = min(
        datetime.now(UTC) + timedelta(seconds=int(expires_delta.total_seconds())),
        session_expires_at,
    )
    payload = {
        "sub": str(user.id),
        "role": user.role.value,
        "type": token_type,
        "jti": str(uuid4()),
        "sid": session_id,
        "session_exp": int(session_expires_at.timestamp()),
        "exp": expires_at,
    }
    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    payload = decode_token(token)
    return get_token_user(db, payload, token_type="access")


def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    return current_user


def _credentials_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

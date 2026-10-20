from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, status
from sqlalchemy import delete, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.v1.schemas import AuthResponse, TokenPair, UserRead, UserRegister
from app.api.v1.utils import authenticate_user, create_token_pair
from app.core.security import (
    decode_token,
    get_current_user,
    get_token_user,
    hash_password,
    oauth2_scheme,
    require_admin,
)
from app.db.deps import get_db
from app.db.models import TokenBlocklist, User, UserRole

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginForm:
    def __init__(
        self,
        username: Annotated[str, Form(min_length=1, max_length=255)],
        password: Annotated[str, Form(min_length=8, max_length=128)],
    ) -> None:
        self.username = username
        self.password = password


@router.post(
    "/register",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_user(
    user_in: UserRegister,
    db: Session = Depends(get_db),
) -> dict[str, User | TokenPair]:
    existing_user = db.scalar(
        select(User).where(
            or_(
                User.email == user_in.email,
                User.username == user_in.username,
            )
        )
    )
    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username already exists",
        )

    user = User(
        email=user_in.email,
        username=user_in.username,
        first_name=user_in.first_name,
        last_name=user_in.last_name,
        hashed_password=hash_password(user_in.password),
        role=UserRole.REGULAR,
    )

    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username already exists",
        ) from exc

    db.refresh(user)
    return {
        "user": user,
        "tokens": create_token_pair(user),
    }


@router.post("/login", response_model=AuthResponse)
def login_user(
    form_data: LoginForm = Depends(),
    db: Session = Depends(get_db),
) -> dict[str, User | TokenPair]:
    user = authenticate_user(
        db=db,
        username=form_data.username,
        password=form_data.password,
    )
    return {
        "user": user,
        "tokens": create_token_pair(user),
    }


@router.post("/token", response_model=TokenPair)
def token_user(
    form_data: LoginForm = Depends(),
    db: Session = Depends(get_db),
) -> TokenPair:
    user = authenticate_user(
        db=db,
        username=form_data.username,
        password=form_data.password,
    )
    return create_token_pair(user)


@router.post("/refresh", response_model=TokenPair)
def refresh_token(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> TokenPair:
    payload = decode_token(token)
    user = get_token_user(db, payload, token_type="refresh")
    revoke_session(db, payload, user)
    return create_token_pair(user)


@router.post("/logout")
def logout_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    payload = decode_token(token)
    token_type = payload.get("type")
    if token_type not in {"access", "refresh"}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_token_user(db, payload, token_type=token_type)
    revoke_session(db, payload, user)

    return {"message": "Session revoked"}


def revoke_session(db: Session, payload: dict, user: User) -> None:
    session_id = payload.get("sid")
    session_exp = payload.get("session_exp")
    if not isinstance(session_id, str) or not isinstance(session_exp, (int, float)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    now = datetime.now(UTC)
    expires_at = datetime.fromtimestamp(session_exp, tz=UTC)
    db.execute(delete(TokenBlocklist).where(TokenBlocklist.expires_at <= now))
    revoked_token = TokenBlocklist(
        jti=session_id,
        token_type="session",
        user_id=str(user.id),
        expires_at=expires_at,
    )

    db.add(revoked_token)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has already been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.get("/me", response_model=UserRead)
def read_current_user(
    current_user: User = Depends(get_current_user),
) -> User:
    return current_user


@router.get("/admin-only")
def read_admin_only(
    current_user: User = Depends(require_admin),
) -> dict[str, str]:
    return {
        "message": "Admin access granted",
        "user_id": str(current_user.id),
    }

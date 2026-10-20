"""Explicit PostgreSQL checks: TEST_POSTGRES_URL=... uv run pytest tests/postgres_checks.py.

Each test creates and removes its own schema; no application tables are touched.
"""

import os
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest
from alembic.config import Config
from fastapi import HTTPException
from sqlalchemy import Engine, create_engine, inspect, select, text
from sqlalchemy.orm import Session

from alembic import command
from app.api.v1 import auth
from app.api.v1.schemas import UserRegister
from app.core.security import decode_token, get_token_user
from app.db.models import TokenBlocklist


@pytest.fixture
def postgres_engine() -> Generator[Engine]:
    url = os.environ["TEST_POSTGRES_URL"]
    schema = f"audit_{uuid4().hex}"
    admin_engine = create_engine(url)
    engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        yield engine
    finally:
        engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()


def migrate(engine: Engine, direction: str, revision: str) -> None:
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        if direction == "upgrade":
            command.upgrade(config, revision)
        else:
            command.downgrade(config, revision)


def test_migration_round_trip_and_model_alignment(postgres_engine: Engine) -> None:
    migrate(postgres_engine, "upgrade", "head")
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    with postgres_engine.begin() as connection:
        config.attributes["connection"] = connection
        command.check(config)
    migrate(postgres_engine, "downgrade", "base")
    assert inspect(postgres_engine).get_enums() == []
    migrate(postgres_engine, "upgrade", "head")
    assert set(inspect(postgres_engine).get_table_names()) == {
        "alembic_version",
        "users",
        "token_blocklist",
    }


@pytest.mark.parametrize("operation", ["refresh", "register"])
def test_concurrent_authentication_writes(
    postgres_engine: Engine, monkeypatch, operation: str
) -> None:
    migrate(postgres_engine, "upgrade", "head")
    payload = UserRegister(
        email="race@example.com",
        username="raceuser",
        first_name="Race",
        last_name="User",
        password="password123456",
    )
    barrier = Barrier(2, timeout=10)
    if operation == "refresh":
        with Session(postgres_engine) as db:
            old_tokens = auth.register_user(payload, db)["tokens"]
        original_get_user = auth.get_token_user

        def synchronized_get_user(*args, **kwargs):
            user = original_get_user(*args, **kwargs)
            barrier.wait()
            return user

        monkeypatch.setattr(auth, "get_token_user", synchronized_get_user)
    else:
        original_hash = auth.hash_password

        def synchronized_hash(password: str) -> str:
            hashed = original_hash(password)
            barrier.wait()
            return hashed

        monkeypatch.setattr(auth, "hash_password", synchronized_hash)

    def request():
        with Session(postgres_engine) as db:
            try:
                if operation == "refresh":
                    return auth.refresh_token(old_tokens.refresh_token, db)
                return auth.register_user(payload, db)
            except HTTPException as exc:
                # Failed uniqueness writes must leave the session usable.
                assert db.scalar(select(1)) == 1
                return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: request(), range(2)))

    expected_status = 401 if operation == "refresh" else 409
    assert sum(result == expected_status for result in results) == 1
    if operation == "refresh":
        with Session(postgres_engine) as db:
            assert len(db.scalars(select(TokenBlocklist)).all()) == 1
            with pytest.raises(HTTPException) as error:
                get_token_user(db, decode_token(old_tokens.access_token), "access")
            assert error.value.status_code == 401
            winner = next(result for result in results if not isinstance(result, int))
            assert get_token_user(db, decode_token(winner.access_token), "access")

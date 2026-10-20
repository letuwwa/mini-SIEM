import pytest
from pydantic import ValidationError

from app.core.settings import Settings

BASE_SETTINGS = {
    "postgres_host": "db.example",
    "postgres_user": "user@tenant",
    "postgres_password": "p@ss/word:#",
    "postgres_db": "app_db",
    "jwt_secret_key": "a-secure-test-key-that-is-at-least-32-characters",
}


def test_database_url_preserves_special_characters() -> None:
    settings = Settings(_env_file=None, **BASE_SETTINGS)

    assert settings.database_url.username == "user@tenant"
    assert settings.database_url.password == "p@ss/word:#"
    assert settings.database_url.host == "db.example"
    assert settings.database_url.database == "app_db"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("jwt_secret_key", "too-short"),
        ("access_token_expire_minutes", 0),
        ("refresh_token_expire_days", -1),
        ("jwt_secret_key", " " * 32),
        ("jwt_algorithm", "none"),
        ("jwt_algorithm", "RS256"),
        ("jwt_algorithm", "unknown"),
        ("postgres_port", 0),
        ("postgres_port", 65536),
        ("allowed_origins", ["*"]),
    ],
)
def test_rejects_insecure_token_settings(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **(BASE_SETTINGS | {field: value}))


def test_rejects_access_tokens_that_outlive_refresh_session() -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            **BASE_SETTINGS,
            access_token_expire_minutes=1441,
            refresh_token_expire_days=1,
        )


def test_compose_backend_port_is_accepted_in_dotenv(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("BACKEND_PORT")
    env_file = tmp_path / ".env"
    env_file.write_text("BACKEND_PORT=8080\n")

    settings = Settings(_env_file=env_file, **BASE_SETTINGS)

    assert settings.backend_port == 8080


@pytest.mark.parametrize(
    ("algorithm", "length"), [("HS256", 32), ("HS384", 48), ("HS512", 64)]
)
def test_hmac_key_length_matches_algorithm(algorithm: str, length: int) -> None:
    values = BASE_SETTINGS | {
        "jwt_algorithm": algorithm,
        "jwt_secret_key": "a" * length,
    }
    assert Settings(_env_file=None, **values).jwt_algorithm == algorithm
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **(values | {"jwt_secret_key": "a" * (length - 1)}))


def test_settings_do_not_print_credentials() -> None:
    settings = Settings(_env_file=None, **BASE_SETTINGS)
    assert BASE_SETTINGS["jwt_secret_key"] not in repr(settings)
    assert BASE_SETTINGS["postgres_password"] not in repr(settings)
    with pytest.raises(ValidationError) as error:
        Settings(_env_file=None, **(BASE_SETTINGS | {"refresh_token_expire_days": 0}))
    assert BASE_SETTINGS["jwt_secret_key"] not in str(error.value)
    assert BASE_SETTINGS["postgres_password"] not in str(error.value)

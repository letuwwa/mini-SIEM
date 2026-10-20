from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL


class Settings(BaseSettings):
    app_name: str = "My API"
    environment: str = "development"
    # Compose consumes this value; accepting it also supports a shared .env.
    backend_port: int = Field(default=8000, ge=1, le=65535)

    allowed_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]

    postgres_host: str
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_user: str
    postgres_password: str = Field(repr=False)
    postgres_db: str

    jwt_secret_key: str = Field(min_length=32, repr=False)
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_expire_minutes: int = Field(default=30, gt=0)
    refresh_token_expire_days: int = Field(default=30, gt=0)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        hide_input_in_errors=True,
    )

    @field_validator("allowed_origins")
    @classmethod
    def reject_wildcard_origins(cls, origins: list[str]) -> list[str]:
        if "*" in origins:
            raise ValueError("Credentialed CORS requires explicit allowed origins")
        return origins

    @model_validator(mode="after")
    def validate_signing_key(self) -> Settings:
        minimum_bytes = {"HS256": 32, "HS384": 48, "HS512": 64}[self.jwt_algorithm]
        if (
            not self.jwt_secret_key.strip()
            or len(self.jwt_secret_key.encode()) < minimum_bytes
        ):
            raise ValueError(
                f"JWT signing key must contain at least {minimum_bytes} bytes and not be blank"
            )
        return self

    @model_validator(mode="after")
    def validate_token_lifetimes(self) -> Settings:
        refresh_minutes = self.refresh_token_expire_days * 24 * 60
        if self.access_token_expire_minutes > refresh_minutes:
            raise ValueError(
                "Access token lifetime cannot exceed refresh token lifetime"
            )
        return self

    @property
    def database_url(self) -> URL:
        return URL.create(
            drivername="postgresql+psycopg2",
            username=self.postgres_user,
            password=self.postgres_password,
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )


settings = Settings()

from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, StringConstraints, field_validator

from app.db.models import UserRole

Username = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=100,
        pattern=r"^[A-Za-z0-9_-]+$",
    ),
]
Name = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=30)
]
Email = Annotated[EmailStr, StringConstraints(max_length=255)]


class UserRegister(BaseModel):
    email: Email
    username: Username
    first_name: Name
    last_name: Name
    password: Annotated[str, StringConstraints(min_length=8, max_length=128)]

    @field_validator("email", mode="after")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).lower()


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    username: str
    first_name: str
    last_name: str
    role: UserRole
    is_active: bool

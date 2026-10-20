import enum

from sqlalchemy import CheckConstraint, Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base_model import BaseModel


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    REGULAR = "regular"


class User(BaseModel):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("username NOT LIKE '%@%'", name="ck_users_username_no_at"),
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )

    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    first_name: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )
    last_name: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role"),
        default=UserRole.REGULAR,
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(default=True)

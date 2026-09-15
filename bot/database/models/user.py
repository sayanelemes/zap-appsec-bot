from typing import TYPE_CHECKING
from sqlalchemy import BigInteger, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from bot.database.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from bot.database.models.dialog import DialogMessage


class User(Base, TimestampMixin):
    """
    Модель пользователя Telegram.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    telegram_id: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        index=True,
        nullable=False,
    )
    username: Mapped[str | None] = mapped_column(String(32), nullable=True)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False)

    # Связь с историей диалога пользователя
    messages: Mapped[list["DialogMessage"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="DialogMessage.id",
    )


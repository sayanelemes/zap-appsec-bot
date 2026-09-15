from typing import TYPE_CHECKING
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from bot.database.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from bot.database.models.user import User


class DialogMessage(Base, TimestampMixin):
    """
    Модель сообщения в диалоге с моделью Gemini.
    Хранит историю реплик (роли: 'user' и 'model') для поддержания контекста.
    """

    __tablename__ = "dialog_messages"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(10), nullable=False)  # 'user' или 'model'
    content: Mapped[str] = mapped_column(Text, nullable=False)

    user: Mapped["User"] = relationship(back_populates="messages")

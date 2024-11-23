from sqlalchemy import Identity, Integer
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase

from src.services.common import TimestampMixin


class Base(DeclarativeBase):
    pass


class BoilerplateModel(Base, TimestampMixin):
    __tablename__ = "boilerplate"

    id: Mapped[int] = mapped_column(Integer, Identity(always=True), primary_key=True)

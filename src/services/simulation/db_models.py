from datetime import datetime

from sqlalchemy import Column, Float, String, DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass

class VulnerabilitySql(Base):
    __tablename__ = "vulnerability"
    cve = Column(String, primary_key=True, index=True)
    title = Column(String)
    score = Column(Float)
    severity = Column(String)
    description = Column(String)
    url = Column(String)
    solution = Column(String)
    published_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        default=lambda: datetime.now(),
    )

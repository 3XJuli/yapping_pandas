from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, ConfigDict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class TimestampMixin(BaseModel):
    created_at: datetime
    updated_at: datetime


class Vulnerability(ORMModel):
    cve: str
    published_at: datetime
    title: Optional[str] = None
    score: Optional[float] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    solution: Optional[str] = None

class AffectedSoftware(ORMModel):
    elementId: str
    cve: str
    software: List[str]
    version: str
    update: Optional[str] = None
    edition: Optional[str] = None

class AffectedSystem(ORMModel):
    critical: bool
    provider: str
    software: List[AffectedSoftware]    #
    location: str   # location name
    network: str    # elementId to network node
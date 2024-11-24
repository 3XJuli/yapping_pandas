from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, ConfigDict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class TimestampMixin(BaseModel):
    created_at: datetime
    updated_at: datetime

@dataclass
class Country:
    name: str
    alpha_2: str
    alpha_3: str

class Person(ORMModel):
    firstname: str = ""
    lastname: str = ""
    email: str = ""

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
    product: str
    publisher: str
    version: str

class AffectedSystem(ORMModel):
    critical: bool
    provider: str
    software: List[AffectedSoftware]    #
    location: List[Country]
    network: str    # elementId to network node
    admin: Person

class CveReport(ORMModel):
    cve: Vulnerability
    affected_systems: List[AffectedSystem]
    total_systems: int
    total_affected_systems: int
    total_critical_systems: int

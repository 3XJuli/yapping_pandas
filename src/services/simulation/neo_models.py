from typing import Optional, List

from neomodel import (
    StructuredNode,
    StringProperty,
    IntegerProperty,
    FloatProperty,
    BooleanProperty,
    DateTimeProperty,
    ArrayProperty,
    RelationshipTo,
)
from pydantic import BaseModel


class SoftwareArtifact(StructuredNode):
    key = StringProperty()
    labelSet = ArrayProperty(base_property=StringProperty())


class SoftwareInstallation(StructuredNode):
    product = StringProperty()
    version = StringProperty()
    publisher = StringProperty()
    key = StringProperty()
    edition = StringProperty()

    related_artifact = RelationshipTo(SoftwareArtifact, "related_artifact")


class Country(StructuredNode):
    name = StringProperty()
    key = StringProperty()
    cc = IntegerProperty()


class System(StructuredNode):
    provider_name = StringProperty()
    sub_type = StringProperty()
    type = StringProperty()
    critical = IntegerProperty()
    key = StringProperty()
    identifier = IntegerProperty()

    related_software = RelationshipTo(SoftwareInstallation, "related_software")
    in_country = RelationshipTo(Country, "in_country")


class Incident(StructuredNode):
    friendly_name = StringProperty()
    security_incident = StringProperty()
    summary = StringProperty()
    confidence = StringProperty()
    impact = StringProperty()
    source_id = StringProperty()
    actor = StringProperty()
    timeline = StringProperty()
    action = StringProperty()
    discovery_mechanism = StringProperty()
    notes = StringProperty()
    status = StringProperty()
    key = StringProperty()
    action_cves = [StringProperty()]

    related_system = RelationshipTo(System, "related_subject")
    related_software_installation = RelationshipTo(SoftwareInstallation, "related_subject")

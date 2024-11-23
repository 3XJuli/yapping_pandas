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
    id = IntegerProperty()

    related_software = RelationshipTo(SoftwareInstallation, "related_software")
    in_country = RelationshipTo(Country, "in_country")

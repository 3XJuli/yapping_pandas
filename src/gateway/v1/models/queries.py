from pydantic import BaseModel, ConfigDict


class QueryBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class BoilerplateCreate(QueryBaseModel):
    pass


# would only contain patchable attributes
class BoilerplateUpdate(QueryBaseModel):
    pass

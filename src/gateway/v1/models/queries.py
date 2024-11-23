from pydantic import BaseModel, ConfigDict


class QueryBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

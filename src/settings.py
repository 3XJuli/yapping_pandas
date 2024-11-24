from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(from_attributes=True)
    postgres_url: str = Field(
        default="postgresql://postgres:postgres@localhost:5432/yapyap",)
    neo4j_url: str = Field(default="neo4j+ssc://hackatum-one.graphdatabase.ninja:443")
    neo4j_user: str = Field(default="attendee12")
    neo4j_password: str = Field(default="EXPL$76699")


APP_SETTINGS = AppSettings()


def set_db_url(db_url: str):
    global APP_SETTINGS
    APP_SETTINGS.postgres_url = db_url

def set_neo4j(url, user, password):
    global APP_SETTINGS
    APP_SETTINGS.neo4j_url = url
    APP_SETTINGS.neo4j_user = user
    APP_SETTINGS.neo4j_password = password

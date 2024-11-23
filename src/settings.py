from pydantic import Field
from pydantic_settings import BaseSettings


class AppSettings(BaseSettings):
    master_key: str = Field(default="test_master_key")
    backend_url: str = Field(
        default="postgresql://postgres@localhost:5432/boilerplate_db"
    )


APP_SETTINGS = AppSettings()


def set_db_url(db_url: str):
    global APP_SETTINGS
    APP_SETTINGS.backend_url = db_url

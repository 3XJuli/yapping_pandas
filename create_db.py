import alembic.config
import alembic.command
import sqlalchemy
from src.settings import APP_SETTINGS
from test.conftest import ALEMBIC_CONFIG_PATH
from sqlalchemy_utils import database_exists, create_database


def main():
    alembic_cfg = alembic.config.Config(ALEMBIC_CONFIG_PATH)
    engine = sqlalchemy.create_engine(APP_SETTINGS.postgres_url, echo=True)
    if database_exists(engine.url):
        raise ValueError("Database already exists")

    print("Creating database via alembic...")
    create_database(engine.url)
    alembic.command.upgrade(alembic_cfg, "head")

    print("Created Database.")


if __name__ == "__main__":
    main()

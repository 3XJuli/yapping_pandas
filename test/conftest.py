import pytest
from src import settings
import alembic.command
import alembic.config
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker, scoped_session
from src.services.boilerplate.db_models import Base as BoilerplateBase
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database, drop_database

TEST_DB_URI = "postgresql://postgres:postgres@localhost/unit_test_db"
ALEMBIC_CONFIG_PATH = "src/alembic/alembic.ini"

TEST_TARGET_METADATA = [
    BoilerplateBase.metadata,
]


@pytest.fixture(scope="session", autouse=True)
def set_db_url():
    """Ensure we never use the production database in tests."""
    settings.set_db_url(TEST_DB_URI)
    yield


@pytest.fixture(scope="class")
def make_db():
    alembic_cfg = alembic.config.Config(ALEMBIC_CONFIG_PATH)
    try:

        engine = create_engine(TEST_DB_URI)
        if database_exists(engine.url):
            drop_database(engine.url)

        create_database(engine.url)
        alembic.command.upgrade(alembic_cfg, "head")

        yield

    finally:
        drop_database(engine.url)


@pytest.fixture(scope="function")
def truncate_tables():

    yield

    engine = create_engine(TEST_DB_URI)

    Session = scoped_session(sessionmaker(bind=engine))

    with Session() as session:
        with session.begin():
            session.execute(text("SET CONSTRAINTS ALL DEFERRED;"))
            for metadata in TEST_TARGET_METADATA:
                for table in metadata.sorted_tables:
                    print(f"Truncating table {table.name}")
                    session.execute(text(f"TRUNCATE TABLE {table.name} CASCADE;"))
            session.execute(text("SET CONSTRAINTS ALL IMMEDIATE;"))

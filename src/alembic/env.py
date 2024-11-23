from logging.config import fileConfig
from sqlalchemy import create_engine
from alembic_utils.replaceable_entity import register_entities

from typing import TYPE_CHECKING

from alembic import context
from src.settings import APP_SETTINGS

import alembic_postgresql_enum

from src.services.boilerplate.db_models import Base as BoilerplateBase

from src.alembic.extensions import postgis, postgis_raster

if TYPE_CHECKING:
    # This side-effect library is used for autogeneration of migrations with Enum types and Postgres.
    # We use it here such that we don't accidentally remove it via a linter.
    alembic_postgresql_enum  # type: ignore

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config


# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata

target_metadata = [
    BoilerplateBase.metadata,
]

register_entities(
    [
        postgis,
        postgis_raster,
    ]
)


def include_name(name, type_, parent_names):
    if type_ == "table" or type_ == "view":
        return any(name in metadata.tables for metadata in target_metadata)
    else:
        return True


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    context.configure(
        url=APP_SETTINGS.backend_url,
        target_metadata=target_metadata,
        literal_binds=True,
        include_name=include_name,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = create_engine(APP_SETTINGS.backend_url)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_name=include_name,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

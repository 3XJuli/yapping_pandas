from alembic import command
import alembic.config
import pytest
from test.conftest import ALEMBIC_CONFIG_PATH


@pytest.mark.usefixtures("make_db")
class TestMigration:
    def test_migrations(self, make_db):
        alembic_cfg = alembic.config.Config(ALEMBIC_CONFIG_PATH)
        command.upgrade(alembic_cfg, "head")

        command.downgrade(alembic_cfg, "base")

        command.upgrade(alembic_cfg, "head")

from datetime import datetime
from geojson_pydantic import MultiPolygon, Point
from geojson_pydantic.types import Position2D
import pytest
from src.gateway.v1.models.filters import BoilerplateFilter
from src.gateway.v1.models.queries import (
    BoilerplateCreate,
    BoilerplateUpdate,
)

from src.services.exceptions import ForeignObjectNotFound
from src.services.boilerplate.boilerplate_service import BoilerplateService
from test.conftest import TEST_DB_URI

test_context = [
    (
        BoilerplateService,
        lambda index: BoilerplateCreate(),
        BoilerplateUpdate(),
        BoilerplateFilter(),
    ),
]


@pytest.mark.usefixtures("make_db", "truncate_tables")
@pytest.mark.parametrize(
    "Service,object_create,object_update,object_filter",
    test_context,
)
class TestService:
    def test_service(self, Service, object_create, object_update, object_filter):
        srv = Service(TEST_DB_URI)
        item = object_create(0)
        result_add = srv.add(item)
        assert result_add.id == 1
        assert result_add.created_at is not None
        assert result_add.updated_at is not None

        result_get = srv.get(result_add.id)
        assert result_add == result_get

        srv.delete(result_add.id)
        assert srv.get(result_add.id) is None

    def test_service_query(self, Service, object_create, object_update, object_filter):
        srv = Service(TEST_DB_URI)
        items = [srv.add(object_create(i)) for i in range(10)]

        items_get = (
            srv.query(object_filter, limit=100, skip=0)
            if object_filter is not None
            else srv.query(limit=100, skip=0)
        )
        assert len(items_get) == 10
        assert items_get == items

        items_get = (
            srv.query(object_filter, limit=5, skip=0)
            if object_filter is not None
            else srv.query(limit=5, skip=0)
        )
        assert len(items_get) == 5
        assert items_get == items[:5]

        items_get = (
            srv.query(object_filter, limit=5, skip=5)
            if object_filter is not None
            else srv.query(limit=5, skip=5)
        )
        assert len(items_get) == 5
        assert items_get == items[5:]

    def test_update(self, Service, object_create, object_update, object_filter):
        srv = Service(TEST_DB_URI)
        base = srv.add(object_create(0))
        updated_item_from_db = srv.update(base.id, object_update)

        assert base.created_at == updated_item_from_db.created_at
        assert base.updated_at < updated_item_from_db.updated_at

    def test_service_count(self, Service, object_create, object_update, object_filter):
        srv = Service(TEST_DB_URI)
        items = [srv.add(object_create(i)) for i in range(10)]

        if object_filter is not None:
            assert 10 == srv.query_count(object_filter)
        else:
            assert 10 == srv.query_count()

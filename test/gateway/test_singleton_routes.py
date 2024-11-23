import json
from unittest.mock import MagicMock
from geojson_pydantic import MultiPolygon, Point, Polygon
from geojson_pydantic.types import Position2D
from pydantic import BaseModel
import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from src.gateway.v1.models.queries import (
    BoilerplateCreate,
    BoilerplateUpdate,
)
from src.gateway.v1.models.responses import Boilerplate
from src.services.exceptions import ObjectAlreadyExists
from src.gateway.v1.routers import boilerplate

from src.services.exceptions import ObjectNotFound

from pytest_mock import MockerFixture
from src import settings
from test.fixtures import client  # noqa: F401

now = datetime.now()

test_context = [
    (
        "v1/boilerplate",
        boilerplate.boilerplate_service,
        BoilerplateCreate(),
        Boilerplate(
            id=1,
            created_at=now,
            updated_at=now,
        ),
    ),
]


AUTH_HEADER = {"X-Token": settings.APP_SETTINGS.master_key}
INVALID_AUTH_HEADER = {"X-Token": "BAD_TOKEN"}


@pytest.mark.parametrize("route,service,create_object,full_object", test_context)
class TestRead:
    def test_success(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        def mocked():
            m = MagicMock()
            m.query.return_value = [full_object]
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.get(f"/{route}/", headers=AUTH_HEADER)
        assert response.status_code == 200
        assert response.json() == [json.loads(full_object.model_dump_json())]

    def test_bad_token(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        response = client.get(f"/{route}/", headers=INVALID_AUTH_HEADER)
        assert response.status_code == 403

    def test_skip_param(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        local_instance = None

        def mocked():
            nonlocal local_instance
            m = MagicMock()
            m.query.return_value = [full_object]
            local_instance = m
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.get(f"/{route}/?skip=5", headers=AUTH_HEADER)
        assert response.status_code == 200
        assert response.json() == [json.loads(full_object.model_dump_json())]
        assert local_instance.query.call_args.kwargs["skip"] == 5

    def test_limit_param(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        local_instance = None

        def mocked():
            nonlocal local_instance
            m = MagicMock()
            m.query.return_value = [full_object]
            local_instance = m
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.get(f"/{route}/?limit=50", headers=AUTH_HEADER)
        assert response.status_code == 200
        local_instance.query.call_args.kwargs["limit"] == 50
        local_instance.query.call_args.kwargs["skip"] == 0

    def test_not_found(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        def mocked():
            m = MagicMock()
            m.get.side_effect = ObjectNotFound()
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.get(f"/{route}/1", headers=AUTH_HEADER)
        assert response.status_code == 404
        assert response.json() == {"detail": ObjectNotFound().detail}

    def test_invalid_skip_param(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        def mocked():
            m = MagicMock()
            m.query.return_value = None
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.get(f"/{route}/?skip=invalid", headers=AUTH_HEADER)
        assert response.status_code == 422
        assert response.json() == {
            "detail": [
                {
                    "loc": ["query", "skip"],
                    "msg": "Input should be a valid integer, unable to parse string as an integer",
                    "type": "int_parsing",
                    "input": "invalid",
                }
            ]
        }

    def test_limit_invalid(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        def mocked():
            m = MagicMock()
            m.query.return_value = None
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.get(f"/{route}/?limit=invalid", headers=AUTH_HEADER)
        assert response.status_code == 422
        assert response.json() == {
            "detail": [
                {
                    "loc": ["query", "limit"],
                    "msg": "Input should be a valid integer, unable to parse string as an integer",
                    "type": "int_parsing",
                    "input": "invalid",
                }
            ]
        }


@pytest.mark.parametrize("route,service", list(map(lambda x: x[:2], test_context)))
class TestCount:
    def test_success(
        self, client: TestClient, mocker: MockerFixture, route: str, service: type
    ):
        def mocked():
            m = MagicMock()
            m.query_count.return_value = 5
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.post(f"/{route}/count", headers=AUTH_HEADER)
        assert response.status_code == 200
        assert response.json() == 5

    def test_not_found(
        self, client: TestClient, mocker: MockerFixture, route: str, service: type
    ):
        def mocked():
            m = MagicMock()
            m.query_count.side_effect = ObjectNotFound()
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.post(f"/{route}/count", headers=AUTH_HEADER)
        assert response.status_code == 404
        assert response.json() == {"detail": ObjectNotFound().detail}

    def test_bad_token(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
    ):
        response = client.get(f"/{route}/count", headers=INVALID_AUTH_HEADER)
        assert response.status_code == 403


@pytest.mark.parametrize("route,service,create_object,full_object", test_context)
class TestCreate:
    def test_success(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        def mocked():
            m = MagicMock()
            m.add.return_value = full_object
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.post(
            f"/{route}/",
            json=json.loads(create_object.model_dump_json(exclude_none=True)),
            headers=AUTH_HEADER,
        )
        assert response.status_code == 200
        assert response.json() == json.loads(full_object.model_dump_json())

    def test_object_already_exists(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        def mocked():
            m = MagicMock()
            m.add.side_effect = ObjectAlreadyExists()
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.post(
            f"/{route}/",
            json=json.loads(create_object.model_dump_json(exclude_none=True)),
            headers=AUTH_HEADER,
        )
        assert response.status_code == 400
        assert response.json() == {"detail": ObjectAlreadyExists().detail}

    def test_bad_token(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        response = client.post(f"/{route}/", headers=INVALID_AUTH_HEADER)
        assert response.status_code == 403


@pytest.mark.parametrize("route,service,create_object,full_object", test_context)
class TestDelete:
    def test_success(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        def mocked():
            m = MagicMock()
            m.delete.return_value = None
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.delete(f"/{route}/1", headers=AUTH_HEADER)
        assert response.status_code == 204

    def test_bad_token(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        response = client.delete(f"/{route}/1", headers=INVALID_AUTH_HEADER)
        assert response.status_code == 403


@pytest.mark.parametrize("route,service,create_object,full_object", test_context)
class TestPatch:
    def test_success(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        def mocked():
            m = MagicMock()
            m.update.return_value = full_object
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.patch(
            f"/{route}/{full_object.id}",
            json=json.loads(create_object.model_dump_json(exclude_none=True)),
            headers=AUTH_HEADER,
        )
        assert response.status_code == 200

    def test_not_found(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        def mocked():
            m = MagicMock()
            m.update.side_effect = ObjectNotFound()
            return m

        client.app.dependency_overrides[service] = mocked

        response = client.patch(
            f"/{route}/{full_object.id}",
            json=json.loads(create_object.model_dump_json(exclude_none=True)),
            headers=AUTH_HEADER,
        )
        assert response.status_code == 404
        assert response.json() == {"detail": ObjectNotFound().detail}

    def test_bad_token(
        self,
        client: TestClient,
        mocker: MockerFixture,
        route: str,
        service: type,
        create_object: BaseModel,
        full_object: BaseModel,
    ):
        response = client.patch(
            f"/{route}/{full_object.id}",
            headers=INVALID_AUTH_HEADER,
            json=json.loads(create_object.model_dump_json(exclude_none=True)),
        )
        assert response.status_code == 403

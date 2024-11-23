from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import pytest
from src.gateway.app import app
from src.gateway.v1.routers import boilerplate


def make_service():
    return MagicMock()


@pytest.fixture
def client():
    client = TestClient(app)
    app.dependency_overrides[boilerplate.boilerplate_service] = make_service
    return client

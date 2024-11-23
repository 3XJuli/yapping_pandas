from fastapi.testclient import TestClient
from src.settings import APP_SETTINGS
from fastapi.testclient import TestClient

from test.fixtures import client


def test_header_missing(client: TestClient):
    response = client.get("/v1/boilerplate")
    assert response.status_code == 403


def test_header_bad_value(client: TestClient):
    response = client.get("/v1/boilerplate", headers={"X-Token": "bad"})
    assert response.status_code == 403


def test_require_header_good_value(client: TestClient):
    response = client.get(
        "/v1/boilerplate", headers={"X-Token": APP_SETTINGS.master_key}
    )
    assert response.status_code == 200


def test_header_master_key_good(client: TestClient):
    response = client.get(
        "/v1/boilerplate",
        headers={"Authorization": "MasterKey " + APP_SETTINGS.master_key},
    )
    assert response.status_code == 200


def test_header_master_key_bad(client: TestClient):
    response = client.get(
        "/v1/boilerplate", headers={"Authorization": "MasterKey " + "bad"}
    )
    assert response.status_code == 403


def test_header_master_key_both(client: TestClient):
    response = client.get(
        "/v1/boilerplate",
        headers={
            "Authorization": "MasterKey " + APP_SETTINGS.master_key,
            "X-Token": APP_SETTINGS.master_key,
        },
    )
    assert response.status_code == 200


def test_docs_dont_need_auth(client: TestClient):
    response = client.get("/docs")
    assert response.status_code == 200

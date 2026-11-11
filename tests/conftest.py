"""Synthetic NVD data and isolation from real HTTP requests/configuration."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

import nvd_client


@pytest.fixture(autouse=True)
def isolate_external_services(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(nvd_client, "load_dotenv", lambda: None)

    def block_http(*args, **kwargs):
        pytest.fail("Tests must mock HTTP requests instead of contacting NVD.")

    monkeypatch.setattr(requests.sessions.Session, "request", block_http)


@pytest.fixture
def payload():
    fixture = Path(__file__).parent / "fixtures" / "single_cve.json"
    return json.loads(fixture.read_text(encoding="utf-8"))


@pytest.fixture
def raw_cve(payload):
    return payload["vulnerabilities"][0]["cve"]


@pytest.fixture
def mock_get(monkeypatch, payload):
    response = Mock(status_code=200)
    response.json.return_value = payload
    get = Mock(return_value=response)
    monkeypatch.setattr(nvd_client.requests, "get", get)
    return get

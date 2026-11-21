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


@pytest.fixture(autouse=True)
def request_clock(monkeypatch):
    """Advance a fake clock instead of delaying tests for request pacing."""
    now = [0.0]

    def advance(seconds):
        now[0] += seconds

    delay = Mock(side_effect=advance)
    monkeypatch.setattr(nvd_client, "monotonic", lambda: now[0])
    monkeypatch.setattr(nvd_client, "sleep", delay)
    return now, delay


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


@pytest.fixture
def make_page(raw_cve):
    """Build a small response page; repeated numbers represent duplicate IDs."""
    def build(start, numbers, total):
        return {
            "startIndex": start,
            "resultsPerPage": len(numbers),
            "totalResults": total,
            "vulnerabilities": [
                {"cve": {**raw_cve, "id": f"CVE-2024-{number:04d}"}}
                for number in numbers
            ],
        }
    return build


@pytest.fixture
def mock_pages(mock_get):
    """Supply consecutive response payloads or transport exceptions."""
    def configure(*pages):
        responses = []
        for page in pages:
            if isinstance(page, Exception):
                responses.append(page)
            else:
                response = Mock(status_code=200)
                response.json.return_value = page
                responses.append(response)
        mock_get.side_effect = responses
        return mock_get
    return configure

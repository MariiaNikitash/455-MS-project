import pytest
import requests

from nvd_client import NVD_API_URL, NvdClient, NvdClientError


def test_single_lookup_yields_unwrapped_record(mock_get, raw_cve):
    records = list(NvdClient(api_key="test-key").iter_cves(cve_id=raw_cve["id"]))

    assert records == [raw_cve]
    mock_get.assert_called_once_with(
        NVD_API_URL,
        headers={"apiKey": "test-key"},
        params={"cveId": raw_cve["id"]},
        timeout=30,
    )
    mock_get.return_value.raise_for_status.assert_called_once()


@pytest.mark.parametrize("api_key", [None, ""])
def test_missing_key_omits_header(mock_get, raw_cve, api_key):
    list(NvdClient(api_key=api_key).iter_cves(cve_id=raw_cve["id"]))

    assert mock_get.call_args.kwargs["headers"] == {}


def test_reads_key_from_environment(monkeypatch, mock_get, raw_cve):
    monkeypatch.setenv("NVD_API_KEY", "environment-key")
    list(NvdClient().iter_cves(cve_id=raw_cve["id"]))

    assert mock_get.call_args.kwargs["headers"] == {"apiKey": "environment-key"}


def test_explicit_key_overrides_environment(monkeypatch, mock_get, raw_cve):
    monkeypatch.setenv("NVD_API_KEY", "environment-key")
    list(NvdClient(api_key="explicit-key").iter_cves(cve_id=raw_cve["id"]))

    assert mock_get.call_args.kwargs["headers"] == {"apiKey": "explicit-key"}


def test_no_match_yields_no_records(mock_get):
    mock_get.return_value.json.return_value = {"vulnerabilities": []}

    assert list(NvdClient().iter_cves(cve_id="CVE-2024-12345")) == []
    mock_get.assert_called_once()


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (requests.Timeout("private transport details"), "timed out"),
        (requests.ConnectionError("private transport details"), "complete the NVD"),
    ],
)
def test_request_errors_are_wrapped_without_retries(mock_get, error, message):
    mock_get.side_effect = error

    with pytest.raises(NvdClientError, match=message) as caught:
        list(NvdClient().iter_cves(cve_id="CVE-2024-12345"))

    assert "private transport details" not in str(caught.value)
    mock_get.assert_called_once()


def test_http_error_reports_status_without_response_details(mock_get):
    response = mock_get.return_value
    response.status_code = 401
    response.raise_for_status.side_effect = requests.HTTPError(
        "private details", response=response
    )

    with pytest.raises(NvdClientError, match="HTTP 401"):
        list(NvdClient().iter_cves(cve_id="CVE-2024-12345"))

    response.json.assert_not_called()
    mock_get.assert_called_once()


def test_http_error_without_response_is_still_a_client_error(mock_get):
    mock_get.side_effect = requests.HTTPError("private details")

    with pytest.raises(NvdClientError, match="NVD rejected the request"):
        list(NvdClient().iter_cves(cve_id="CVE-2024-12345"))

    mock_get.assert_called_once()


def test_invalid_json_is_a_client_error(mock_get):
    mock_get.return_value.json.side_effect = ValueError("invalid JSON")

    with pytest.raises(NvdClientError, match="invalid JSON"):
        list(NvdClient().iter_cves(cve_id="CVE-2024-12345"))


@pytest.mark.parametrize(
    "response_data",
    [
        None,
        [],
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": [{}]},
        {"vulnerabilities": [{"cve": []}]},
        {"vulnerabilities": [{"cve": {"id": "CVE-2024-9999"}}]},
        {"vulnerabilities": [{"cve": {}}, {"cve": {}}]},
    ],
)
def test_malformed_or_unexpected_response_fails(mock_get, response_data):
    mock_get.return_value.json.return_value = response_data

    with pytest.raises(NvdClientError):
        list(NvdClient().iter_cves(cve_id="CVE-2024-12345"))

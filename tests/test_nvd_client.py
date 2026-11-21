import pytest
import requests

from nvd_client import NVD_API_URL, REQUEST_INTERVAL, NvdClient, NvdClientError


DATE_QUERY = {"pub_start": "2024-01-01T00:00:00Z", "pub_end": "2024-01-03T00:00:00Z"}


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


def test_pagination_keeps_filters_and_advances_by_actual_records(
    make_page, mock_pages, request_clock,
):
    get = mock_pages(
        make_page(0, [1], 4),  # A short non-final page must not stop iteration.
        make_page(1, [2, 3], 4),
        make_page(3, [4], 4),
    )
    records = NvdClient(api_key="test-key", page_size=2).iter_cves(**DATE_QUERY)
    get.assert_not_called()  # The generator fetches pages only when consumed.
    assert next(records)["id"] == "CVE-2024-0001"
    assert get.call_count == 1
    assert [record["id"] for record in records] == [
        "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004",
    ]
    assert [call.kwargs["params"] for call in get.call_args_list] == [
        {"pubStartDate": DATE_QUERY["pub_start"], "pubEndDate": DATE_QUERY["pub_end"],
         "resultsPerPage": 2, "startIndex": offset}
        for offset in (0, 1, 3)
    ]
    assert all(call.kwargs["headers"] == {"apiKey": "test-key"}
               and call.kwargs["timeout"] == 30 for call in get.call_args_list)
    _, delay = request_clock
    assert [call.args for call in delay.call_args_list] == [
        (REQUEST_INTERVAL,), (REQUEST_INTERVAL,),
    ]  # No delay before the first request or after the final page.


def test_empty_date_query_makes_one_request(make_page, mock_pages, request_clock):
    get = mock_pages(make_page(0, [], 0))
    assert list(NvdClient().iter_cves(**DATE_QUERY)) == []
    get.assert_called_once()
    request_clock[1].assert_not_called()


@pytest.mark.parametrize(("field", "value"), [
    ("startIndex", True), ("resultsPerPage", "2"),
    ("totalResults", -1), ("totalResults", None),
])
def test_invalid_pagination_metadata_fails(make_page, mock_pages, field, value):
    page = make_page(0, [1], 1)
    page[field] = value
    get = mock_pages(page)
    with pytest.raises(NvdClientError, match="invalid pagination metadata"):
        list(NvdClient().iter_cves(**DATE_QUERY))
    get.assert_called_once()


@pytest.mark.parametrize("wrong_offset", [0, 2])
def test_second_page_offset_must_match_request(make_page, mock_pages, wrong_offset):
    get = mock_pages(make_page(0, [1], 2), make_page(wrong_offset, [2], 2))
    with pytest.raises(NvdClientError, match="offset"):
        list(NvdClient(page_size=1).iter_cves(**DATE_QUERY))
    assert get.call_count == 2


@pytest.mark.parametrize(("field", "value"), [
    ("resultsPerPage", 3), ("resultsPerPage", 0), ("totalResults", 0),
])
def test_inconsistent_page_counts_fail(make_page, mock_pages, field, value):
    page = make_page(0, [1], 1)
    page[field] = value
    mock_pages(page)
    with pytest.raises(NvdClientError, match="inconsistent pagination counts"):
        list(NvdClient(page_size=2).iter_cves(**DATE_QUERY))


def test_unexpected_empty_page_fails(make_page, mock_pages):
    get = mock_pages(make_page(0, [1], 2), make_page(1, [], 2))
    with pytest.raises(NvdClientError, match="empty page"):
        list(NvdClient(page_size=1).iter_cves(**DATE_QUERY))
    assert get.call_count == 2


def test_changed_total_fails_instead_of_claiming_complete_retrieval(make_page, mock_pages):
    mock_pages(make_page(0, [1], 3), make_page(1, [2], 2))
    with pytest.raises(NvdClientError, match="total changed"):
        list(NvdClient(page_size=1).iter_cves(**DATE_QUERY))


def test_later_page_timeout_propagates_without_retry(make_page, mock_pages):
    get = mock_pages(make_page(0, [1], 2), requests.Timeout())
    records = NvdClient(page_size=1).iter_cves(**DATE_QUERY)
    assert next(records)["id"] == "CVE-2024-0001"
    with pytest.raises(NvdClientError, match="timed out"):
        next(records)
    assert get.call_count == 2


def test_display_time_counts_toward_request_interval(make_page, mock_pages, request_clock):
    mock_pages(make_page(0, [1], 2), make_page(1, [2], 2))
    records = NvdClient(page_size=1).iter_cves(**DATE_QUERY)
    next(records)
    now, delay = request_clock
    now[0] += REQUEST_INTERVAL + 1
    list(records)
    delay.assert_not_called()


def test_pacing_applies_across_queries_on_the_same_client(mock_get, raw_cve, request_clock):
    client = NvdClient()
    list(client.iter_cves(cve_id=raw_cve["id"]))
    list(client.iter_cves(cve_id=raw_cve["id"]))
    assert mock_get.call_count == 2
    request_clock[1].assert_called_once_with(REQUEST_INTERVAL)


def test_combined_query_stays_a_single_request(mock_get, raw_cve, request_clock):
    assert list(NvdClient().iter_cves(cve_id=raw_cve["id"], **DATE_QUERY)) == [raw_cve]
    mock_get.assert_called_once()
    assert mock_get.call_args.kwargs["params"] == {
        "cveId": raw_cve["id"], "pubStartDate": DATE_QUERY["pub_start"],
        "pubEndDate": DATE_QUERY["pub_end"],
    }
    request_clock[1].assert_not_called()


@pytest.mark.parametrize("page_size", [0, 2001, True, 1.5])
def test_invalid_page_size_fails_before_request(mock_get, page_size):
    with pytest.raises(ValueError, match="Page size"):
        NvdClient(page_size=page_size)
    mock_get.assert_not_called()

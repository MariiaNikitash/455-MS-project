import importlib

import pytest
import requests

import main


def test_lookup_displays_complete_details_without_writing_files(
    mock_get, raw_cve, capsys, monkeypatch, tmp_path
):
    monkeypatch.chdir(tmp_path)

    assert main.main(["--cve-id", raw_cve["id"]]) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    for detail in (
        "CVE ID: CVE-2024-12345",
        "Description (en): Synthetic test vulnerability.",
        "Published: 2024-01-02T10:15:00.123000Z",
        "Last modified: 2024-02-03T10:00:00Z",
        "Status: Analyzed",
        "https://example.com/advisory",
        "Tags: Vendor Advisory, Patch",
        "CVSS 4.0: 9.3 (CRITICAL)",
        "CVSS 3.1: 9.8 (CRITICAL)",
        "CVSS 3.1: 8.1 (HIGH)",
        "CVSS 3.0: 0.0 (NONE)",
        "CVSS 2.0: 5.0 (MEDIUM)",
        "Source: nvd@nist.gov; Type: Primary",
        "Source: security@example.com; Type: Secondary",
        "Vector: AV:N/AC:L/Au:N/C:P/I:N/A:N",
        "Retrieved 1 CVE record.",
    ):
        assert detail in captured.out
    assert list(tmp_path.iterdir()) == []
    mock_get.assert_called_once()


def test_displays_unavailable_optional_fields(mock_get, raw_cve, capsys):
    for field in ("descriptions", "references", "metrics", "vulnStatus"):
        raw_cve.pop(field)

    assert main.main(["--cve-id", raw_cve["id"]]) == 0

    output = capsys.readouterr().out
    assert "Description (Not available): Not available" in output
    assert "Status: Not available" in output
    assert "References:\n  Not available" in output
    assert "CVSS assessments:\n  Not available" in output


@pytest.mark.parametrize("arguments", [[], ["--cve-id", "CVE-2024-123"]])
def test_invalid_input_fails_before_request(mock_get, arguments, capsys):
    with pytest.raises(SystemExit) as caught:
        main.main(arguments)

    assert caught.value.code == 2
    assert "error:" in capsys.readouterr().err
    mock_get.assert_not_called()


@pytest.mark.parametrize(
    "extra_arguments",
    [
        ["--published-from", "2024-01-01"],
        ["--output", "output.json"],
        ["--results-per-page", "2"],
    ],
)
def test_future_milestone_options_are_not_implemented(mock_get, extra_arguments):
    with pytest.raises(SystemExit) as caught:
        main.main(["--cve-id", "CVE-2024-12345", *extra_arguments])

    assert caught.value.code == 2
    mock_get.assert_not_called()


def test_help_does_not_request_data(mock_get, capsys):
    with pytest.raises(SystemExit) as caught:
        main.main(["--help"])

    assert caught.value.code == 0
    assert "--cve-id" in capsys.readouterr().out
    mock_get.assert_not_called()


def test_not_found_is_an_unsuccessful_lookup(mock_get, capsys):
    mock_get.return_value.json.return_value = {"vulnerabilities": []}

    assert main.main(["--cve-id", "CVE-2024-12345"]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "CVE not found: CVE-2024-12345" in captured.err


def test_request_failure_produces_readable_error(mock_get, capsys):
    mock_get.side_effect = requests.Timeout()

    assert main.main(["--cve-id", "CVE-2024-12345"]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Error: The NVD request timed out." in captured.err


def test_invalid_record_produces_readable_error(mock_get, raw_cve, capsys):
    raw_cve["published"] = "invalid"

    assert main.main(["--cve-id", raw_cve["id"]]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Error: published must be an ISO 8601 timestamp." in captured.err


def test_importing_main_does_not_request_data(mock_get):
    importlib.reload(main)

    mock_get.assert_not_called()

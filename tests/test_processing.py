from copy import deepcopy

import pytest

from processing import normalize_cve, validate_cve_id


def test_normalizes_required_record_fields(raw_cve):
    record = normalize_cve(raw_cve)

    assert {key: value for key, value in record.items() if key != "cvss_metrics"} == {
        "cve_id": "CVE-2024-12345",
        "description": "Synthetic test vulnerability.",
        "description_language": "en",
        "published_at": "2024-01-02T10:15:00.123000Z",
        "last_modified_at": "2024-02-03T10:00:00Z",
        "status": "Analyzed",
        "references": [
            {
                "url": "https://example.com/advisory",
                "source": "security@example.com",
                "tags": ["Vendor Advisory", "Patch"],
            }
        ],
    }


def test_preserves_all_cvss_versions_sources_and_zero(raw_cve):
    metrics = normalize_cve(raw_cve)["cvss_metrics"]

    assert [
        (m["version"], m["source"], m["type"], m["base_score"], m["severity"])
        for m in metrics
    ] == [
        ("4.0", "security@example.com", "Primary", 9.3, "CRITICAL"),
        ("3.1", "nvd@nist.gov", "Primary", 9.8, "CRITICAL"),
        ("3.1", "security@example.com", "Secondary", 8.1, "HIGH"),
        ("3.0", "security@example.com", "Primary", 0.0, "NONE"),
        ("2.0", "nvd@nist.gov", "Primary", 5.0, "MEDIUM"),
    ]
    assert metrics[0]["vector_string"] == (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    )
    assert metrics[-1]["vector_string"] == "AV:N/AC:L/Au:N/C:P/I:N/A:N"


def test_missing_optional_fields_are_explicit(raw_cve):
    for field in ("descriptions", "references", "metrics", "vulnStatus"):
        raw_cve.pop(field)

    record = normalize_cve(raw_cve)

    assert record["description"] is None
    assert record["description_language"] is None
    assert record["references"] == []
    assert record["cvss_metrics"] == []
    assert record["status"] is None


def test_non_english_fallback_and_rejected_status(raw_cve):
    raw_cve["descriptions"] = [{"lang": "es", "value": "Descripcion."}]
    raw_cve["vulnStatus"] = "Rejected"

    record = normalize_cve(raw_cve)

    assert record["description"] == "Descripcion."
    assert record["description_language"] == "es"
    assert record["status"] == "Rejected"


def test_missing_reference_metadata_and_cvss_fields(raw_cve):
    raw_cve["references"] = [{"url": "https://example.com/advisory"}]
    raw_cve["metrics"] = {"cvssMetricV31": [{"cvssData": {"version": "3.1"}}]}

    record = normalize_cve(raw_cve)

    assert record["references"] == [
        {"url": "https://example.com/advisory", "source": None, "tags": []}
    ]
    assert record["cvss_metrics"] == [
        {
            "version": "3.1",
            "source": None,
            "type": None,
            "base_score": None,
            "severity": None,
            "vector_string": None,
        }
    ]


def test_does_not_mutate_input(raw_cve):
    original = deepcopy(raw_cve)

    record = normalize_cve(raw_cve)
    record["references"][0]["tags"].append("Changed output")

    assert raw_cve == original


@pytest.mark.parametrize("field", ["published", "lastModified"])
@pytest.mark.parametrize("value", [None, "", "not-a-date", "2024-01-01", 123])
def test_invalid_required_timestamps_fail(raw_cve, field, value):
    raw_cve[field] = value

    with pytest.raises(ValueError, match=field):
        normalize_cve(raw_cve)


@pytest.mark.parametrize("value", [None, "", "CVE-2024-123", "CVE-24-12345", 123])
def test_invalid_required_ids_fail(raw_cve, value):
    raw_cve["id"] = value

    with pytest.raises(ValueError, match="CVE ID"):
        normalize_cve(raw_cve)


def test_accepts_long_cve_sequence_numbers():
    assert validate_cve_id("CVE-2024-1234567") == "CVE-2024-1234567"

"""Pure transformations from NVD CVE dictionaries to normalized records."""

import re
from datetime import datetime, timezone


def validate_cve_id(value: str) -> str:
    """Return a valid CVE ID or raise ValueError."""
    if not isinstance(value, str) or not re.fullmatch(
        r"CVE-[0-9]{4}-[0-9]{4,}", value
    ):
        raise ValueError("CVE ID must use the format CVE-YYYY-NNNN (4+ digits).")
    return value


def _utc_timestamp(value: str, field: str) -> str:
    """Convert an NVD timestamp to a UTC ISO 8601 string."""
    if not isinstance(value, str) or "T" not in value:
        raise ValueError(f"{field} must be an ISO 8601 timestamp.")
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO 8601 timestamp.") from exc
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _cvss_metrics(metrics: dict) -> list[dict]:
    """Keep all CVSS assessments, including the enclosing v2 severity field."""
    assessments = []
    for family in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(family) or []:
            data = metric.get("cvssData") or {}
            severity = data.get("baseSeverity")
            if severity is None:
                severity = metric.get("baseSeverity")
            assessments.append(
                {
                    "version": data.get("version"),
                    "source": metric.get("source"),
                    "type": metric.get("type"),
                    "base_score": data.get("baseScore"),
                    "severity": severity,
                    "vector_string": data.get("vectorString"),
                }
            )
    return assessments


def normalize_cve(cve: dict) -> dict:
    """Normalize the Section 4 record fields without changing the input."""
    cve_id = validate_cve_id(cve.get("id"))
    descriptions = cve.get("descriptions") or []
    description = next(
        (item for item in descriptions if item.get("lang") == "en"),
        descriptions[0] if descriptions else {},
    )
    references = [
        {
            "url": reference.get("url"),
            "source": reference.get("source"),
            "tags": list(reference.get("tags") or []),
        }
        for reference in cve.get("references") or []
    ]
    return {
        "cve_id": cve_id,
        "description": description.get("value"),
        "description_language": description.get("lang"),
        "published_at": _utc_timestamp(cve.get("published"), "published"),
        "last_modified_at": _utc_timestamp(cve.get("lastModified"), "lastModified"),
        "status": cve.get("vulnStatus"),
        "references": references,
        "cvss_metrics": _cvss_metrics(cve.get("metrics") or {}),
    }

"""Command-line lookup and readable display of one NVD CVE."""

import argparse
import sys

from nvd_client import NvdClient, NvdClientError
from processing import normalize_cve, validate_cve_id


def _cve_id_argument(value: str) -> str:
    try:
        return validate_cve_id(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _display(value) -> str:
    return "Not available" if value is None else str(value)


def display_cve(record: dict) -> None:
    """Display the normalized details, preserving every CVSS assessment."""
    print(f"CVE ID: {record['cve_id']}")
    print(
        f"Description ({_display(record['description_language'])}): "
        f"{_display(record['description'])}"
    )
    print(f"Published: {record['published_at']}")
    print(f"Last modified: {record['last_modified_at']}")
    print(f"Status: {_display(record['status'])}")

    print("References:")
    if not record["references"]:
        print("  Not available")
    for reference in record["references"]:
        print(f"  - {_display(reference['url'])}")
        if reference["source"] is not None:
            print(f"    Source: {reference['source']}")
        if reference["tags"]:
            print(f"    Tags: {', '.join(reference['tags'])}")

    print("CVSS assessments:")
    if not record["cvss_metrics"]:
        print("  Not available")
    for metric in record["cvss_metrics"]:
        print(
            f"  - CVSS {_display(metric['version'])}: "
            f"{_display(metric['base_score'])} ({_display(metric['severity'])})"
        )
        print(
            f"    Source: {_display(metric['source'])}; "
            f"Type: {_display(metric['type'])}"
        )
        print(f"    Vector: {_display(metric['vector_string'])}")


def main(argv: list[str] | None = None) -> int:
    """Retrieve, normalize, and display one CVE; return a process exit status."""
    parser = argparse.ArgumentParser(description="Retrieve one CVE from NVD.")
    parser.add_argument(
        "--cve-id",
        required=True,
        type=_cve_id_argument,
        help="CVE identifier, for example CVE-2021-44228",
    )
    args = parser.parse_args(argv)

    try:
        raw_cve = next(NvdClient().iter_cves(cve_id=args.cve_id), None)
        if raw_cve is None:
            print(f"Error: CVE not found: {args.cve_id}", file=sys.stderr)
            return 1
        record = normalize_cve(raw_cve)
    except (NvdClientError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    display_cve(record)
    print("\nRetrieved 1 CVE record.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Command-line lookup and readable display of one NVD CVE."""

import argparse
import sys

from nvd_client import NvdClient, NvdClientError
from processing import normalize_cve, validate_cve_id, validate_timestamp, validate_date_range


def _cve_id_argument(value: str) -> str:
    try:
        return validate_cve_id(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc

def _date_argument(value: str) -> str:
    try:
        return validate_timestamp(value, "Publication date")
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
        required=False,
        type=_cve_id_argument,
        help="CVE identifier, for example CVE-2021-44228",
    )
    parser.add_argument(
        "--pub-start",
        required=False,
        type=_date_argument,
        help="Specify start date, for example 2025-01-01T00:00:00Z"
    )
    parser.add_argument(
        "--pub-end",
        required=False,
        type=_date_argument,
        help="Specify end date, for example 2025-10-01T00:00:00Z"
    )
    args = parser.parse_args(argv)
    
    if args.cve_id is None and args.pub_start is None and args.pub_end is None: # Check if arguments provided, if none, error
        parser.error("Provide a CVE ID or publication date range.")

    if (args.pub_start is None) != (args.pub_end is None): # Check whether both arguments exist
        parser.error("Both publication start and end date are required.")

    if args.pub_start is not None: # Check publication date range
        try:
            validate_date_range(args.pub_start, args.pub_end)
        except ValueError as exc:
            parser.error(str(exc))

    # Fetch and display CVEs found
    count = 0 # Track count of CVEs found

    try:
        client = NvdClient()

        for raw_cve in client.iter_cves(cve_id=args.cve_id, pub_start=args.pub_start,pub_end=args.pub_end):
            record = normalize_cve(raw_cve)
            display_cve(record)
            print()
            count += 1

    except (NvdClientError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

   # display CVE count
    if count == 0:
        print("No matching CVEs found.")
    else:
        print(f"Retrieved {count} CVE records(s).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

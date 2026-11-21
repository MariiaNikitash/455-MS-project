"""Retrieve raw CVE records from the NVD API."""

import os
from collections.abc import Iterator
from time import monotonic, sleep

import requests
from dotenv import load_dotenv


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30
PAGE_SIZE = 2000
REQUEST_INTERVAL = 6.5


class NvdClientError(Exception):
    """An NVD request failed or returned an unexpected response."""


class NvdClient:
    """Retrieve matching CVEs with sequential, paced requests and no retries."""

    def __init__(self, api_key: str | None = None, *, page_size: int = PAGE_SIZE) -> None:
        if type(page_size) is not int or not 1 <= page_size <= PAGE_SIZE:
            raise ValueError(f"Page size must be an integer from 1 to {PAGE_SIZE}.")
        load_dotenv()
        self.api_key = api_key if api_key is not None else os.getenv("NVD_API_KEY")
        self.page_size = page_size
        self._last_request_at: float | None = None

    def _request_page(self, params: dict) -> dict:
        """Fetch one response, pacing attempts made through this client."""
        if self._last_request_at is not None:
            remaining = REQUEST_INTERVAL - (monotonic() - self._last_request_at)
            if remaining > 0:
                sleep(remaining)
        self._last_request_at = monotonic()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            response = requests.get(
                NVD_API_URL,
                headers=headers,
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            message = f"NVD returned HTTP {status}." if status is not None else (
                "NVD rejected the request."
            )
            raise NvdClientError(message) from exc
        except requests.Timeout as exc:
            raise NvdClientError("The NVD request timed out.") from exc
        except requests.RequestException as exc:
            raise NvdClientError("Could not complete the NVD request.") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise NvdClientError("NVD returned invalid JSON.") from exc

        if not isinstance(payload, dict) or not isinstance(
            payload.get("vulnerabilities"), list
        ):
            raise NvdClientError("NVD response is missing a CVE list.")
        return payload

    def iter_cves(
        self, *, cve_id: str | None = None,
        pub_start: str | None = None, pub_end: str | None = None,
    ) -> Iterator[dict]:
        """Yield raw CVEs, traversing every page for a publication-date query."""
        if (pub_start is None) != (pub_end is None):
            raise ValueError("Both publication start and end date are required.")
        if cve_id is None and pub_start is None:
            raise ValueError("Provide a CVE ID or publication date range.")

        params = {}
        if cve_id is not None:
            params["cveId"] = cve_id
        if pub_start is not None:
            params.update(pubStartDate=pub_start, pubEndDate=pub_end)

        offset = 0
        expected_total = None
        while True:
            page_params = dict(params)
            if cve_id is None:
                page_params.update(startIndex=offset, resultsPerPage=self.page_size)
            payload = self._request_page(page_params)
            entries = payload["vulnerabilities"]

            if cve_id is not None:
                if len(entries) > 1:
                    raise NvdClientError("NVD returned multiple records for a single CVE ID.")
            else:
                metadata = [payload.get(name) for name in (
                    "startIndex", "resultsPerPage", "totalResults",
                )]
                if any(type(value) is not int or value < 0 for value in metadata):
                    raise NvdClientError("NVD returned invalid pagination metadata.")
                start, returned_size, total = metadata
                if start != offset:
                    raise NvdClientError("NVD returned a different pagination offset than requested.")
                if (returned_size > self.page_size or len(entries) > returned_size
                        or offset + len(entries) > total):
                    raise NvdClientError("NVD returned inconsistent pagination counts.")
                if expected_total is not None and total != expected_total:
                    raise NvdClientError("NVD result total changed during retrieval; rerun the query.")
                expected_total = total
                if not entries and offset < total:
                    raise NvdClientError("NVD returned an empty page before retrieval was complete.")

            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("cve"), dict):
                    raise NvdClientError("NVD returned a malformed CVE record.")
                cve = entry["cve"]
                if cve_id is not None and cve.get("id") != cve_id:
                    raise NvdClientError("NVD returned a different CVE ID than requested.")
                yield cve

            if cve_id is not None:
                return
            offset += len(entries)
            if offset >= expected_total:
                return

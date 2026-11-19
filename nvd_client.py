"""Retrieve raw CVE records from the NVD API."""

import os
from collections.abc import Iterator

import requests
from dotenv import load_dotenv


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30


class NvdClientError(Exception):
    """An NVD request failed or returned an unexpected response."""


class NvdClient:
    """Single-ID client; each lookup makes one request without retries."""

    def __init__(self, api_key: str | None = None) -> None:
        load_dotenv()
        self.api_key = api_key if api_key is not None else os.getenv("NVD_API_KEY")

    def iter_cves(self, *, cve_id: str | None = None, pub_start: str | None = None, pub_end: str | None = None) -> Iterator[dict]:
        """Yield raw CVE dictionary matching a CVE ID or publication date range."""
        headers = {"apiKey": self.api_key} if self.api_key else {}

        params = {}

        if cve_id is not None: # if we parse in a CVE ID, load that into parameters
            params["cveId"] = cve_id

        if pub_start is not None and pub_end is not None: # if we parse in start and end date
            params["pubStartDate"] = pub_start
            params["pubEndDate"]= pub_end

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

        entries = payload["vulnerabilities"]
        if cve_id is not None and len(entries) > 1:
            raise NvdClientError("NVD returned multiple records for a single CVE ID.")

        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("cve"), dict):
                raise NvdClientError("NVD returned a malformed CVE record.")
            cve = entry["cve"]
            if cve_id is not None and cve.get("id") != cve_id:
                raise NvdClientError("NVD returned a different CVE ID than requested.")
            yield cve

# 455-MS-project

Local Python tool for retrieving CVE details from the [NVD API](https://services.nvd.nist.gov/rest/json/cves/2.0). Supports single-CVE lookup, publication-date queries with automatic pagination, combined ID/date filtering, and readable terminal output.

The project uses Python 3.14 and **uv**. uv manages the virtual environment and dependencies; manual environment activation is unnecessary.

## Getting Started

### 1. Install uv

If uv is not already installed, use the command for your operating system.

macOS / Linux:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 2. Install project dependencies

From the repository root, run:

```bash
uv sync --locked
```

This installs the versions in `uv.lock`, including the development dependencies used for tests. uv can download Python 3.14 automatically if needed.

### 3. Configure an API key (optional)

To use an NVD API key, create a local `.env` file based on `.env.example` and set:

```dotenv
NVD_API_KEY=your_nvd_api_key
```

You can also set `NVD_API_KEY` in your environment; that value takes precedence over `.env`. Keep your actual key out of Git. The `.env` file is ignored.

## Running the tool

Retrieve and display a CVE:

```bash
uv run main.py --cve-id CVE-2021-44228
```

Replace the ID to look up another CVE. The ID must use the format `CVE-YYYY-NNNN`, with at least four digits in the final component.

Retrieve all matching pages for a publication interval:

```bash
uv run main.py --pub-start "2025-01-01T00:00:00Z" \
  --pub-end "2025-01-01T01:00:00Z"
```

Both dates are required. Use ISO 8601 timestamps containing a time; `Z` means UTC. Offsets are converted to UTC, and timestamps without a timezone are interpreted as UTC. Reversed ranges and ranges longer than 120 days are rejected.

Bounds are passed to NVD without local boundary filtering. Live checks with `CVE-2021-44228` included its exact publication timestamp at the start boundary and excluded it at the end boundary.

Optionally combine an ID with dates to retrieve it only if its publication date matches the interval:

```bash
uv run main.py --cve-id CVE-2021-44228 \
  --pub-start "2021-12-01T00:00:00Z" --pub-end "2021-12-31T00:00:00Z"
```

View available arguments:

```bash
uv run main.py --help
```

The terminal displays the ID, description and language, publication and modification dates in UTC, status, references, and all available CVSS assessments with their versions and sources. Missing optional values display as `Not available`.

Dates-only queries retrieve pages automatically and display/count each CVE ID once. ID-containing queries make a single request. An empty dates-only query succeeds; an explicit ID with no match (including a combined query) or a request failure prints to stderr and returns a nonzero exit status.

The client requests up to 2,000 records per page and spaces request starts at least 6.5 seconds apart, with or without a key. Page size can be reduced in Python with `NvdClient(page_size=...)`; pagination requires no additional CLI flags. See the [NVD API reference](https://nvd.nist.gov/developers/vulnerabilities) and [developer guidance](https://nvd.nist.gov/developers/start-here) for upstream limits.

Requests have a 30-second timeout and are not retried automatically. Invalid page metadata, unexpected empty pages, and a changing result total stop retrieval with an error. Earlier CVEs may already be printed; a failed run does not print the successful retrieval summary. Rerun the query after a failure. NVD may update records during retrieval, so pagination is not a transactional snapshot.

This tool prints results to the console. JSON/CSV export and advanced retries are optional post-MVP work in [the design](docs/design.md).

## Running tests

```bash
uv run pytest -q
```

To see individual test cases:

```bash
uv run pytest -v
```

Tests use synthetic API responses and block real HTTP requests. They require no real API key and do not contact NVD.

## Adding New Packages

Use `uv add` to keep dependency declarations, the lockfile, and the environment in sync:

```bash
uv add <package_name>
```

Review and commit the resulting `pyproject.toml` and `uv.lock` changes together. After pulling dependency updates, run `uv sync --locked`.

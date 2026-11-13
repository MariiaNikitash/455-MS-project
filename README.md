# 455-MS-project

Local Python tool for retrieving CVE details from the [NVD API](https://services.nvd.nist.gov/rest/json/cves/2.0). The current milestone supports a single CVE lookup and readable terminal output.

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

View available arguments:

```bash
uv run main.py --help
```

The terminal displays the ID, description and language, publication and modification dates in UTC, status, references, and all available CVSS assessments with their versions and sources. Missing optional values display as `Not available`.

An unknown ID or request failure produces an error message and a nonzero exit status. This milestone prints results to the console; date-range queries, pagination, and file export are planned in [the design](docs/design.md).

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

# CVE Retrieval Tool — Design

## 1. Purpose, requirements, and scope

Build a local Python CLI that retrieves NVD CVEs and displays readable details. Support date-range collection with pagination and a single-CVE convenience mode. JSON is the primary, optional export format.

Required details: ID, description, published/modified dates, references, and available severity assessments. Submit an accessible repository, runnable code, README, authentic sample output, and a report of at most two pages.

CSV is an optional post-MVP milestone. Defer platform/product filters, long-range splitting, historical collection, databases, hosting, and analysis. Status: proposed behavior; the existing prototype and uv setup remain the starting point.

## 2. CLI and configuration

```bash
# Console details only; no output file required.
uv run main.py --cve-id CVE-2021-44228

# Console details plus optional JSON export.
uv run main.py --published-from 2024-01-01 --published-to 2024-02-01 \
  --output output/january.json
```

- Require exactly one mode: a CVE ID or both publication dates. `--output` is optional; without it, create no export file.
- Validate IDs, including sequence numbers longer than four digits. Dates use `YYYY-MM-DD`, midnight UTC, inclusive start/exclusive end; the example covers January. Reject invalid/reversed dates and ranges exceeding NVD's supported window before requesting data.
- Keep API configuration in the client: endpoint, optional key, timeout, page size, pacing, and retry settings. Read `NVD_API_KEY` from the environment or `.env`, with environment precedence. Omit absent keys and never log credentials.
- `--help` and input validation work offline. Console output uses labeled CVE blocks containing the required details, available CVSS versions/sources, explicit missing-value messages, and a final record count. Report a saved path only when export was requested. Diagnostics go to stderr; failures return nonzero.
- JSON is the default export when `--output` is supplied. CSV selection and flattening rules are defined only in the optional CSV milestone.

## 3. Architecture and Data Flow

Use a flat project; no `src/` package:

```text
main.py
nvd_client.py
processing.py
tests/
  fixtures/
  test_main.py
  test_nvd_client.py
  test_processing.py
docs/
pyproject.toml
uv.lock
.python-version
```

| Module | Responsibility |
| --- | --- |
| `nvd_client.py` | HTTP requests, API configuration, response validation, pagination, publication-boundary filtering, pacing, retries, and client errors. |
| `processing.py` | Pure transformation of raw NVD CVE dictionaries into normalized records; no network, console, or file operations. |
| `main.py` | CLI arguments, orchestration, deduplication, readable console output, JSON export, and optional post-MVP CSV export. |

Planned interfaces:

- `NvdClient.iter_cves(*, cve_id=None, published_from=None, published_to=None) -> Iterator[dict]`: accept validated IDs or UTC-aware date bounds. Yield individual raw CVE dictionaries without the outer `cve` wrapper; hide pagination. Retrieval/response failures raise `NvdClientError` during iteration.
- `normalize_cve(cve: dict) -> dict`: return the record defined below. Apply missing-value rules; malformed required IDs/dates raise `ValueError`.
- `main(argv=None) -> int`: accept an argument list, or process arguments when omitted. Coordinate retrieval, normalization, console display, and requested export; return zero on success and nonzero with diagnostics on expected failures.

Flow: CLI validation → client record iterator → normalization → deduplication/collection → console details → optional export. Imports make no requests; execution uses a main function and guard.

`tests/` mirrors the three modules. Fixtures describe raw responses and expected normalized records; fake iterators isolate CLI/output tests from networking.

## 4. Data contract and output

When JSON export is requested, save `query` (ID/dates, no credentials), `retrieved_at` (UTC), `record_count`, and `records`. Console and export use the same normalized records.

| Record field | Rule |
| --- | --- |
| `cve_id` | Required identifier and deduplication key. |
| `description`, `description_language` | Prefer English; otherwise retain the first available description and its language. Missing values are `null`. |
| `published_at`, `last_modified_at` | Separate UTC timestamps; interpret timezone-free NVD timestamps as UTC. |
| `status` | Preserve the upstream value, including rejected status; `null` if absent. |
| `references` | List of objects preserving URL, source, and tags when supplied. |
| `cvss_metrics` | List preserving every assessment's version, source, type, base score, severity, and vector; handle v2's different severity location. |

Use `[]` for missing collections and `null` for absent optional values. Preserve zero scores, all assessments, and unscored/rejected CVEs. Invalid required IDs/dates fail visibly. [NVD schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema).

For requested exports, create parent directories and refuse overwrites. After complete retrieval, write a temporary file and publish the final file only on success. Failures must not leave a complete-looking dataset. Empty date queries succeed with a zero-record console summary and, if requested, empty JSON records. Unknown explicit IDs fail clearly.

## 5. Retrieval and failure handling

Use `https://services.nvd.nist.gov/rest/json/cves/2.0` with `cveId`, or paired `pubStartDate`/`pubEndDate`. Verify API boundary behavior and locally enforce the requested half-open publication interval.

Retrieve batches using `resultsPerPage` and `startIndex`. Start at zero; validate the returned index, then advance by actual records received until reaching `totalResults`. Yield individual records internally. Do not stop merely on a short page. Unexpected empty pages, invalid JSON, mismatched offsets, and inconsistent pagination fail visibly.

Use sequential requests, a 30-second timeout, and pacing for every attempt. Retry connection failures, timeouts, 429, and transient 5xx errors with backoff/`Retry-After`, at most three attempts. Permanent request/access errors fail promptly; do not blindly retry 403.

Confirm/document page, date-window, and rate limits before coding: [API reference](https://nvd.nist.gov/developers/vulnerabilities), [developer guidance](https://nvd.nist.gov/developers/start-here). Exact settings remain a planning verification item. Basic compliant pacing applies before live repeated requests; milestone 6 completes reliability hardening.

## 6. Alternatives considered

| Decision | Alternatives and reason for choice |
| --- | --- |
| Source | NVD supplies the required CVE/enrichment fields. Official CVE records and GHSA remain alternatives for later validation/enrichment. |
| Interface | CLI versus web application: CLI meets local execution needs with little infrastructure. |
| Output/storage | Console details plus optional JSON versus mandatory files/CSV/database: readable results need no file, while JSON preserves nested data. CSV follows the MVP. |
| Organization | Three flat modules versus one script or a package: independently testable responsibilities without packaging overhead. |

## 7. Dependencies and environment

Preserve the existing uv setup, `pyproject.toml`, `uv.lock`, `.python-version`, and Python 3.14 configuration. Runtime dependencies remain `requests` and `python-dotenv`; pytest configuration/development dependency setup is planned for milestone 1. Use built-in argument/date/JSON/CSV/file modules. Ignore secrets, environments, caches, and generated output.

## 8. Testing

Add tests alongside each feature using small fixtures and mocked HTTP/clock functions. Automated tests run offline without real delays.

- **Processing:** missing fields, language fallback, multiple CVSS versions/sources, zero scores, references, rejected status, malformed required fields.
- **Client:** date boundaries, multiple/partial/empty pages, offset mismatches, malformed responses, pacing, bounded retries, permanent errors.
- **CLI/output:** invalid/conflicting inputs, offline help, console details without `--output`, deduplication, unknown IDs, JSON read-back, existing files, and failed retrieval/writes.
- **Live verification:** small single-ID and multi-page date queries; compare displayed counts/details with exports. Check keyed/keyless behavior separately and capture authentic output.

## 9. Implementation Plan

Each milestone ends with review and a focused commit containing its relevant tests. Milestones 1–6 build the MVP; milestone 8 completes submission verification. Milestone 7 is optional, may be skipped, and may follow milestone 8.

| Milestone | Scope | Completion check | Testing expectations |
| --- | --- | --- | --- |
| 1. Project Structure and Testing | Preserve uv/Python 3.14 and prototype behavior; organize flat modules and `tests/`; configure pytest. | Dependencies install and the test runner works. | Verify discovery/imports without live requests. |
| 2. Single CVE Retrieval | Implement one-ID lookup, basic field normalization, and readable console output. | One CVE is retrieved and displayed. | Mock retrieval; check mapping, console fields, and missing values. |
| 3. Date Range Queries | Add/validate publication dates and retrieve a supported interval. | A date query returns matching CVEs; full traversal follows in milestone 4. | Test invalid dates, UTC bounds, inclusive start/exclusive end. |
| 4. Pagination | Add `startIndex`/`resultsPerPage` and automatic multi-page retrieval. | All matching CVEs are retrieved automatically within the supported window. | Test multiple pages, partial/empty results, offsets, and duplicates. |
| 5. JSON Export | Add optional `--output` and save normalized CVEs/metadata. | Saved JSON can be read back correctly; console-only mode still works. | Check JSON fields/counts and that omitted output creates no file. |
| 6. Reliability | Complete pacing, bounded retries, errors, and safe output publishing. | Expected failures are handled and tested. | Simulate throttling/timeouts, retry exhaustion, permanent errors, existing files, and interrupted writes. |
| 7. Optional CSV Export | Define flattening of nested references/CVSS assessments, implement export, and add tests. | CSV contains valid records under the documented mapping. | Read CSV back; test quoting, missing values, and multiple nested items. |
| 8. Documentation and Verification | Live NVD checks, README, authentic samples, and report. | Another student reproduces results from a fresh checkout. | Reproduce documented commands, keyed/keyless checks, and sample results. |

Integrate a minimal query early and expand it incrementally. Console/export must meet the complete data contract before MVP acceptance. Keep `main` stable and update this design when interfaces change.

## 10. Acceptance criteria, assumptions, and limitations

- A fresh checkout can install locked dependencies and run both lookup modes using README instructions.
- Console details are readable without an output file. Requested JSON preserves normalized details and metadata; CSV is not required for MVP acceptance.
- Date mode retrieves all matching pages within its supported window. Missingness is explicit, counts are correct, and failures cannot appear successful.
- The accessible repository and report of at most two pages include the source, design, commands, authentic examples, and limitations.

Records remain in memory; oversized ranges are rejected and interrupted runs restart. Upstream changes prevent a transactional snapshot; preserve query/retrieval time in exports and document this limitation. CVE records alone do not establish AI authorship or causation.

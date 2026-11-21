# CVE Retrieval Tool — Design

## 1. Purpose, requirements, and scope

Build a local Python CLI that retrieves NVD CVEs and displays readable details. The MVP supports publication-date collection with pagination, single-CVE lookup, and combined ID/date filtering. File export is optional post-MVP work; JSON is the primary post-MVP export format.

Required details: ID, description, published/modified dates, references, and available severity assessments. Submit an accessible repository, runnable code, README, authentic sample output, and a report of at most two pages.

Defer JSON/CSV export, advanced retries/hardening, platform/product filters, long-range splitting, historical collection, databases, hosting, and analysis. Pagination is the final MVP coding milestone. Documentation and submission verification are required finishing work.

## 2. CLI and configuration

```bash
# Console details only; no output file required.
uv run main.py --cve-id CVE-2021-44228

# Publication-date query; console output only.
uv run python main.py --pub-start "2025-01-01T00:00:00Z" \
  --pub-end "2025-01-01T01:00:00Z"

# Combined filter: return this CVE only if published in the interval.
uv run python main.py --cve-id CVE-2021-44228 \
  --pub-start "2021-12-01T00:00:00Z" --pub-end "2021-12-31T00:00:00Z"
```

- Accept a CVE ID, both publication dates, or an ID plus both dates. Require at least one filter and always pair publication dates. Combined filters mean that the requested CVE must also match the interval; verify upstream behavior before considering this combination fully validated.
- Validate IDs, including sequence numbers longer than four digits. `--pub-start`/`--pub-end` accept ISO 8601 timestamps containing a time, normalize offsets to UTC, and interpret timezone-free timestamps as UTC. Reject invalid/reversed dates and ranges longer than 120 days before requesting data. Use verified upstream publication-boundary semantics and document endpoint inclusivity; do not assume an exclusive end.
- Keep API configuration in the client: endpoint, optional key, timeout, page size, and pacing; retry settings follow post-MVP. Read `NVD_API_KEY` from the environment or `.env`, with environment precedence. Omit absent keys and never log credentials.
- `--help` and input validation work offline. Console output uses labeled CVE blocks containing the required details, available CVSS versions/sources, explicit missing-value messages, and a final record count. Diagnostics go to stderr; failures return nonzero.
- File export is outside the MVP. Post-MVP, an optional `--output` defaults to JSON; CSV selection and flattening follow separately.

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
| `nvd_client.py` | HTTP requests, API configuration, response validation, pagination, basic pacing, and client errors. Advanced retries follow post-MVP. |
| `processing.py` | Pure transformation of raw NVD CVE dictionaries into normalized records; no network, console, or file operations. |
| `main.py` | CLI arguments, orchestration, ID deduplication, and readable console output/counts. JSON/CSV export follows post-MVP. |

Interfaces:

- `NvdClient.iter_cves(*, cve_id=None, pub_start=None, pub_end=None) -> Iterator[dict]`: accept a validated ID and/or paired normalized UTC timestamp strings. Retrieve all matching pages using `startIndex` and `resultsPerPage`, yielding individual raw CVE dictionaries without the outer `cve` wrapper. Hide pagination inside the iterator. Retrieval/response failures raise `NvdClientError` during iteration.
- `normalize_cve(cve: dict) -> dict`: return the record defined below. Apply missing-value rules; malformed required IDs/dates raise `ValueError`.
- `main(argv=None) -> int`: accept an argument list, or process arguments when omitted. Coordinate retrieval, normalization, and console display/counts; return zero on success and nonzero with diagnostics on expected failures.

Flow: CLI validation → client record iterator → normalization → ID deduplication → console details/count. Process records incrementally without a master collection. Imports make no requests; execution uses a main function and guard.

`tests/` mirrors the three modules. Fixtures describe raw responses and expected normalized records; fake iterators isolate CLI/output tests from networking.

## 4. Data contract and output

The MVP displays the following normalized records in the console. For optional post-MVP JSON export, save `query` (ID/dates, no credentials), `retrieved_at` (UTC), `record_count`, and `records`, using the same record contract.

| Record field | Rule |
| --- | --- |
| `cve_id` | Required identifier and deduplication key. |
| `description`, `description_language` | Prefer English; otherwise retain the first available description and its language. Missing values are `null`. |
| `published_at`, `last_modified_at` | Separate UTC timestamps; interpret timezone-free NVD timestamps as UTC. |
| `status` | Preserve the upstream value, including rejected status; `null` if absent. |
| `references` | List of objects preserving URL, source, and tags when supplied. |
| `cvss_metrics` | List preserving every assessment's version, source, type, base score, severity, and vector; handle v2's different severity location. |

Use `[]` for missing collections and `null` for absent optional values. Preserve zero scores, all assessments, and unscored/rejected CVEs. Invalid required IDs/dates fail visibly. [NVD schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema).

Empty dates-only queries return zero with a no-match summary. An explicit ID with no match returns nonzero and prints to stderr; combined queries explain that no CVE matched the ID and interval, rather than implying the ID does not exist.

Post-MVP export safety: create parent directories and refuse overwrites. After complete retrieval, write a temporary file and publish the final file only on success. Failures must not leave a complete-looking dataset; empty dates-only exports contain an empty records list.

## 5. Retrieval and failure handling

Use `https://services.nvd.nist.gov/rest/json/cves/2.0` with `cveId`, paired `pubStartDate`/`pubEndDate`, or both. Verify combined filtering and document upstream publication-boundary behavior; do not promise a half-open interval without enforcing it locally.

For date-only queries, retrieve batches using `resultsPerPage` and `startIndex`. Start at zero; require the returned index to match the requested offset, then advance by actual records received until reaching `totalResults`. Yield individual records internally. Do not stop merely on a short page. Unexpected empty pages, invalid JSON, mismatched offsets, and inconsistent pagination fail visibly. ID-containing queries return at most one matching record and need no additional pages.

Use a 30-second timeout, clear request/response errors, sequential requests, and basic compliant pacing. MVP request failures stop the run with a nonzero exit status; console output may already contain partial results, so do not print a successful completion summary after failure. Post-MVP: retry connection failures, timeouts, 429, and transient 5xx errors with backoff/`Retry-After`, at most three attempts. Permanent request/access errors fail promptly; do not blindly retry 403.

Confirm/document page, date-window, and rate limits before implementing pagination: [API reference](https://nvd.nist.gov/developers/vulnerabilities), [developer guidance](https://nvd.nist.gov/developers/start-here). Cap ranges at 120 days; verify this and page/pacing settings against upstream guidance. Basic compliant pacing applies before live repeated requests; advanced reliability hardening is post-MVP.

## 6. Alternatives considered

| Decision | Alternatives and reason for choice |
| --- | --- |
| Source | NVD supplies the required CVE/enrichment fields. Official CVE records and GHSA remain alternatives for later validation/enrichment. |
| Interface | CLI versus web application: CLI meets local execution needs with little infrastructure. |
| Query filters | Allow ID and dates separately or together versus exclusive modes: combined filtering is flexible and shares the retrieval flow, but adds validation cases and requires careful no-match wording. |
| Output/storage | Console-only MVP versus mandatory files/CSV/database: readable results meet the local retrieval requirement. Optional post-MVP JSON preserves nested data; CSV follows separately. |
| Organization | Three flat modules versus one script or a package: independently testable responsibilities without packaging overhead. |

## 7. Dependencies and environment

Preserve the existing uv setup, `pyproject.toml`, `uv.lock`, `.python-version`, and Python 3.14 configuration. Runtime dependencies remain `requests` and `python-dotenv`, with pytest for testing. Use built-in argument/date modules and, for later exports, JSON/CSV/file modules. Ignore secrets, environments, caches, and generated output.

## 8. Testing

Cover single-CVE retrieval, processing, console output, errors, and pagination with focused automated tests using mocked HTTP/clock functions. Automated tests run offline without real delays. Manual checks cover date validation and combined filtering for the MVP; broader automated date-query coverage is post-MVP. Keep existing tests passing.

- **Processing:** missing fields, language fallback, multiple CVSS versions/sources, zero scores, references, rejected status, malformed required fields.
- **Client:** test multiple/partial/empty pages, offset mismatches, malformed responses, pacing, and duplicate handling. Verify date boundaries and combined filters, including intervals containing and excluding a known CVE's publication date.
- **CLI/output:** invalid/missing inputs, offline help, console details, deduplication/counts, and ID-only/combined no-match failures. Manually check valid, missing, invalid, reversed, and oversized date ranges.
- **Live verification:** small single-ID, combined, and multi-page date queries; check counts/details, keyed/keyless behavior, and capture authentic output.
- **Post-MVP:** broader automated date-query coverage, bounded retries, JSON/CSV read-back, existing files, and failed retrieval/writes during export.

## 9. Implementation Plan

Implement the MVP in the following order, ending with pagination. Each stage ends with review and a focused commit; existing tests must pass. Use manual date-query checks and focused automated pagination coverage. Documentation and submission verification follow as required finishing work.

| Milestone | Scope | Completion check | Testing expectations |
| --- | --- | --- | --- |
| 1. Project Structure and Testing | Preserve uv/Python 3.14 and prototype behavior; organize flat modules and `tests/`; configure pytest. | Dependencies install and the test runner works. | Verify discovery/imports without live requests. |
| 2. Single CVE Retrieval | Implement one-ID lookup, the complete Section 4 record contract, and readable console output. | One CVE is retrieved and displayed. | Mock retrieval; check mapping, all CVSS assessments, console fields, and missing values. |
| 3. Date Range Queries | Add/validate timestamps and support date-only or combined ID/date queries. | Queries return matching CVEs; full date traversal follows in milestone 4. | Manual input, UTC, boundary, and combined-filter checks; broader automated date coverage is post-MVP. |
| 4. Pagination | Add `startIndex`/`resultsPerPage`, automatic multi-page retrieval, basic pacing, and ID deduplication. | All matching CVEs are retrieved and counted once within the supported window; failures stop clearly. | Test multiple pages, partial/empty results, offsets, duplicates, and pacing; perform a live multi-page check. |

Before submission, finish README/design updates, authentic samples, the report, and fresh-checkout verification. Reproduce documented commands and verify keyed/keyless behavior; another student must be able to run the tool.

Optional post-MVP milestones:

- **JSON Export:** add optional `--output`, normalized records/metadata, safe publishing, and read-back/failure tests. Console-only operation remains supported.
- **Reliability:** add bounded retries/backoff and broader error/response hardening, with throttling, timeout, and retry-exhaustion tests.
- **CSV Export:** define nested-field flattening, implement export, and test quoting, missing values, and multiple nested items.

Console details must meet the complete Section 4 record contract before MVP acceptance. Keep `main` stable and update this design when interfaces change.

## 10. Acceptance criteria, assumptions, and limitations

- A fresh checkout can install locked dependencies and run ID-only, dates-only, and combined queries using README instructions.
- Console details preserve the full normalized record contract and are readable without an output file. JSON/CSV export is not required for MVP acceptance.
- Date mode retrieves all matching pages within its supported window. Missingness is explicit, counts are correct, and failures cannot appear successful.
- The accessible repository and report of at most two pages include the source, design, commands, authentic examples, and limitations.

Records are processed incrementally; each response page is held in memory, with a seen-ID set for deduplication. Oversized ranges are rejected and interrupted runs restart. Upstream changes prevent a transactional snapshot; document this limitation and preserve query/retrieval time in future exports. CVE records alone do not establish AI authorship or causation.

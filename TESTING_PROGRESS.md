# Testing Progress

## Status: In Progress — 2026-05-12

All source bug fixes are complete. 63 unit tests passing across 5 suites. Scanner
integration tests against real AWS accounts remain pending.

## What's been tested

- **Unit tests** — 63 tests across 5 suites
  - `tests/analysis/severities.test.js` — 7 tests (SEVERITY_ORDER, enrichment, threshold filter)
  - `tests/analysis/rules.test.js` — 39 tests (IAM, S3, EC2 rules, access-denied handling, ICMP/null ports)
  - `tests/utils/reporter.test.js` — 6 tests (output, summary, JSON file export, error handling)
  - `tests/cli/parseArgs.test.js` — 7 tests (flag parsing, edge cases, empty values)
  - `tests/cli/exitCodes.test.js` — 3 tests (unknown services, empty services, invalid format)
- **Smoke test** — CLI loads, parseArgs correct, invalid services/format exit 1

## Bug fixes applied (2026-05-12)

| Bug | Severity | Fix |
|---|---|---|
| BUG-1 | HIGH | Per-scanner try/catch so one failure does not abort others |
| BUG-2 | HIGH | S3 cross-region bucket support via GetBucketLocation + per-region clients |
| BUG-3 | MEDIUM | JSON output schema now includes `totalFindings` and `summary` |
| BUG-4 | MEDIUM | `--services=` empty string no longer falls back to default |
| BUG-5 | MEDIUM | `--format` validated against `table` \| `json`; invalid values exit 1 |
| BUG-6 | LOW | Null port values produce safe wording instead of `null-null` |
| BUG-7 | LOW | ICMP/ICMPv6 rules show protocol name instead of misleading port range |
| BUG-8 | LOW | Test counts and coverage updated to match reality |
| BUG-9 | LOW | Added 11 new unit tests covering edge cases and access-denied handling |
| BUG-10 | LOW | S3 access-denied errors tracked per-bucket; false-positive rules suppressed; S3-000 INFO emitted |
| BUG-11 | INFO | README documents `scan:json` behaviour |

## What still needs testing

- [ ] Live IAM scan against a real AWS account (verify pagination, URL-decoded policies)
- [ ] Live S3 scan (verify ACL/policy/encryption/BPA fetches, cross-region routing)
- [ ] Live EC2 scan (verify security group pagination, IPv6 range detection)
- [ ] Full pipeline end-to-end (`npm run scan`) with real findings
- [ ] `--format=json` output to file (schema consistency)
- [ ] `--min-severity=HIGH` filter in practice
- [ ] CI exit code 1 triggered by a real CRITICAL finding
- [ ] `npm run scan:json` (JSON export to `./reports/latest.json`)
- [ ] Scanner unit tests with mocked AWS SDK clients

## How to resume

```bash
cd "/Users/main/Security Apps/cloud-security"
AWS_PROFILE=<your-profile> AWS_REGION=<your-region> npm run scan
```

Ensure the scanning identity has the minimum IAM policy documented in README.md.
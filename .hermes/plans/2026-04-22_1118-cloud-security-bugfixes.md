# Cloud Security Scanner — Bug Fix Plan

> **Status:** COMPLETE — All 5 original bugs plus 6 additional bugs identified and fixed.

## Original Bugs (from plan creation 2026-04-22)

- [x] **Bug 1 — HIGH:** `Statement` field can be single object or array → Fixed with `normalizeStatements()` helper
- [x] **Bug 2 — HIGH:** Array Principal with `"*"` not detected → Fixed with `isPublicPrincipal()` helper
- [x] **Bug 3 — MEDIUM:** `scan:json` npm script used `--format=table` → Fixed to `--format=json`
- [x] **Bug 4 — LOW:** `--output` ignored when `--format=json` → Fixed with file-writing in JSON path
- [x] **Bug 5 — LOW:** `--services` with all-unknown exits 0 → Fixed with empty-services guard + exit 1

## Additional Bugs Found During 2026-05-12 Review

- [x] **BUG-1 — HIGH:** Single service failure aborted entire multi-service scan → Per-scanner try/catch
- [x] **BUG-2 — HIGH:** S3 cross-region buckets produced false positives/negatives → `GetBucketLocation` + per-region clients
- [x] **BUG-3 — MEDIUM:** JSON output missing `totalFindings` and `summary` → Schema unified with reporter
- [x] **BUG-4 — MEDIUM:** `--services=` empty string fell back to default → Nullish coalescing
- [x] **BUG-5 — MEDIUM:** No `--format` validation → Added validation against `table`/`json`
- [x] **BUG-6 — LOW:** Null ports produced `Port range null-null` → Safe fallback wording
- [x] **BUG-7 — LOW:** ICMP rules showed misleading port range → ICMP/ICMPv6-specific detail text
- [x] **BUG-10 — LOW:** S3 AccessDenied produced silent false positives → Per-bucket access tracking + S3-000
- [x] **BUG-8 — LOW:** TESTING_PROGRESS.md stale (43 tests vs actual 63) → Updated
- [x] **BUG-11 — INFO:** `scan:json` naming documented → README updated

All 63 tests pass.
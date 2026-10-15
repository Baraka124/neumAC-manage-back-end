# Mi Espacio · Phase 43A — fail closed on source-query errors

Status: **Backend proposal, not deployed.** Date: 15 October 2026.

The authenticated `GET /api/me/context` endpoint reads staff, on-call, rotations, absences, research lines, clinical trials, innovation projects, and structured publication authorship. Before this phase, query responses were converted using `(result.data || [])` without checking per-query `error`: a failed query could be misrepresented as zero verified personal records. This is incorrect, particularly for medical research history and responsibilities.

## Scope and contract

- No new table, migration, route, credential, clinical source or cross-account read.
- Assert the `medical_staff` identity lookup and **all nine** personal context collection reads succeeded before serializing any personal activity.
- A successful empty list remains valid. Failed and malformed responses yield one safe, consistent HTTP **503**, with `error: MI_ESPACIO_SOURCE_UNAVAILABLE` and a plain Spanish retry message. The response does not reveal database source names, identifiers, raw SQL details or clinical record content. Operational logs contain only source names and bounded error codes.
- An unexpected exception yields a generic 500 without returning raw `e.message` to the client.
- Existing frontend activity error handling already stops showing the research/agenda overview and offers retry on rejected requests; no separate frontend change is made while Phase 42 PR #158 is open.
- Unit and static integration tests verify success/error/null-source separation, sanitized messaging, source coverage and preservation of scoped research relation checks. New narrow GitHub workflow runs the checks on relevant backend changes.

## Explicitly unresolved (Phase 43B clinical governance)

- The current resolver filters completed, terminated and withdrawn clinical trials, excludes innovation projects whose `current_stage=completed`, and limits each of these lists to the 20 most recently updated rows. This is not a complete historical portfolio; fixing errors here does **not** make the returned research history exhaustive.
- Co-investigator is not a verified Co-IP role. Do not infer Co-IP or clinical trial type from study titles or table membership.
- Project `development_stage` and `current_stage` may reflect different concepts; mapping and lifecycle should be agreed upon with the record owners before changing presentation or ordering.
- Decide authorized historical visibility, lifecycle flags, pagination/limits and source-unavailable states in Phase 43B before including closed/withdrawn records.

## Review / acceptance

No real patient or personnel data is needed in test fixtures. Before a deployment, run GitHub CI and verify an authorized account's server errors distinguish “temporarily unavailable” from “no recorded studies.” This is a **backend PR** requiring separate review/deployment coordination; do not merge or deploy by default. Phase 42 frontend PR #158 stays untouched.

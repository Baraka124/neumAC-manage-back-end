# Phase 43B · Historical scientific participation (opt-in backend proposal)

This PR adds GET /api/me/research-history, authenticated and linked-staff scoped. The existing /api/me/context remains unchanged and displays the currently filtered operational overview. The history endpoint is read-only and not called by the frontend until a separate UI review.

### Scope
- Studies with explicitly completed recorded statuses, projects with current_stage=completed; no inference from development_stage.
- Withdrawn/terminated, archived, cancelled and unknown historical statuses are not included pending research-governance approval. "Historial completado" does not mean exhaustive lifetime history.
- Exact user-linked principal/co-/subinvestigator or lead/co-investigator relationships only; never elevate Co-IP from co-investigator.
- Bounded page size (1–20), page (1–100), stable update/id order, one extra row to derive has_more; no total count claim.
- Safe 400/403/503 responses, no SQL details or hospital records in errors. No migration, write route, or staff-wide read.
- A separate review is required for historical visibility policy, consent/authorization, terminated research, lifecycle rules, and a future frontend history disclosure.
- No production or patient data changed; this PR is not approved for merge/deployment solely because CI passes.

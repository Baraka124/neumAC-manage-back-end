# neumDesk V46.14 — Phase 5.1 Operational Decision Intelligence

## Purpose

Phase 5.1 adds a deterministic, explainable decision layer above the Phase 5.0 Temporal Integrity foundation. The reference implementation is **Resident Rotations**, but the contract is intentionally UI-free and storage-free so Leave and On-call can adopt it next.

The core rule is:

> **A hard block must be justified by a named invariant. Everything else is context, advice, or a governed exception.**

This prevents neumDesk from turning every unusual operational situation into a frustrating generic error.

## Decision scale

The shared `decision51.js` engine emits five levels:

- `pass` — no material finding.
- `context` — relevant operational information; no action required.
- `advisory` — a minor deviation worth seeing; no exception approval required.
- `warning` — a material issue; continuation requires a governed exception when the finding is marked overridable.
- `block` — a named invariant would be violated; normal override is not allowed.

The engine returns a typed `decision51.rotation.v1` review containing the proposed assignment, overall decision, findings, evidence, policy reason, possible resolutions, commit/override state and review timestamp.

## Rotation reference rules

### Named hard invariants

Examples currently treated as non-overridable blocks:

- invalid/missing resident reference;
- inactive or ineligible resident;
- invalid/inactive unit;
- missing/inactive/ineligible formal supervisor;
- invalid date window;
- genuine concurrent primary resident rotation (`ONE_PRIMARY_ROTATION_AT_A_TIME`).

A concurrent-rotation finding includes the conflicting unit, dates and exact overlap days rather than returning only “dates conflict.”

### Reviewable operational findings

Examples deliberately **not** hard-blocked:

- non-standard/mid-month monthly rotation block;
- configured unit capacity exceeded for part of the proposed period;
- material resident leave inside the rotation;
- material supervisor leave inside the rotation.

These are warnings with explicit reasons and possible resolutions. When the finding is overridable, committing requires both `rotation_exceptions` write permission and an explicit reason.

### Context rather than conflict

Examples shown without blocking normal workflow:

- the assignment reaches, but does not exceed, configured unit capacity;
- one or two leave days within the block;
- resident primary or backup on-call duties during the period;
- several overlapping resident-supervision assignments where no hard supervision-capacity policy exists.

This is intentional: the system distinguishes **something worth knowing** from **something that makes the assignment invalid**.

## Temporal capacity

Capacity review is period-aware rather than a single present-day number. For each day in the proposed rotation, the engine computes existing qualifying rotations and projected occupancy after the proposed assignment.

A capacity warning therefore carries the affected date window and projected peak, for example:

`Configured capacity 3 · projected 4 · 11–15 Oct`

The unit selector may still display present occupancy, but it is explicitly labelled as current state. Future assignment judgment comes from the decision review.

## Governed exceptions

There is no generic “Ignore error” pathway.

An overridable warning can be continued only when:

1. the review has no hard block;
2. the actor has write access to the explicit `rotation_exceptions` permission module (admins/system admins remain covered by the existing role bypass); and
3. an exception reason of at least 8 characters is provided.

The frontend sends a structured `decision_override` object. The backend does not trust the client review: it performs a fresh authoritative review immediately before the write.

## Decision audit

Phase 5.1 adds the additive `operational_decision_events` table. It can retain:

- domain/action;
- subject and proposed state;
- complete deterministic findings;
- review contract/version;
- whether an override was required/used;
- override reason and actor/time;
- committed record reference;
- event state (`reviewed`, `blocked`, `exception_required`, `committed`, `cancelled`, `superseded`);
- creation/commit timestamps.

This creates a future institutional-learning surface without making the decision engine probabilistic. Grounded can later answer questions about recorded decision events rather than inventing reasons after the fact.

## One contract, multiple interfaces

The ordinary Rotation UI and Grounded both consume the same `Decision51.reviewRotation(...)` contract.

The standard UI renders an inline **Assignment review** with findings and exception controls. Grounded's rotation proposal carries the same findings and applies the same exception requirements.

The backend imports the same pure engine and re-runs the review against authoritative records before creation/update. This is the key convergence:

`UI proposal → shared decision contract → backend revalidation → audited commit`

## Separation from UI

`decision51.js` contains no CSS, Vue assumptions, API calls or storage code. `decision51.css` is only a renderer for the current neumDesk UI. A future interface can consume exactly the same findings without changing the underlying decision rules.

## What Phase 5.1 does not claim

- It does not yet migrate Leave or On-call writes onto the generic Decision51 contract.
- It does not infer clinical policy that has not been configured.
- Configured unit capacity is currently an overridable operational warning, not an absolute legal/clinical hard cap. If a true absolute capacity invariant is required, it should be represented explicitly as a separate policy rather than inferred.
- It does not let an LLM decide whether an operation is safe. The reference engine remains deterministic.
- The new database migration and backend still require deployment/live authenticated validation.

## Next convergence

Phase 5.2 should apply the same contract to **Leave and On-call**:

- Leave: duty/coverage collisions, meaningful rotation impact, supervisor/clinical-unit dependencies, governed exceptions.
- On-call: leave conflict, eligibility/rest/coverage constraints, replacement context, governed exceptions where departmental policy permits.

Those domains should reuse the same severity, evidence, exception and audit model rather than creating new one-off warning systems.

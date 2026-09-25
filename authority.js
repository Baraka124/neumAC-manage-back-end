// neumDesk V46.14 · Phase 5.3D · Authority Resolver + Projection-Aware Policy · 2026-09-24
// Stable production filename: authority.js. Update this file in place.
//
// Pure policy engine: no database, HTTP, Vue or Supabase dependencies.
// Runtime identity/override loading remains in index.js. This module answers:
// actor + permission + relationship scopes + explicit overrides ->
// ALLOW | ALLOW_LIMITED | DENY.

'use strict';

const DECISIONS = Object.freeze({
  ALLOW: 'ALLOW',
  ALLOW_LIMITED: 'ALLOW_LIMITED',
  DENY: 'DENY'
});

const SCOPES = Object.freeze(['none', 'own', 'supervisees', 'unit', 'department', 'all']);
const VISIBILITIES = Object.freeze(['none', 'summary', 'operational', 'full']);

const ROLE_ALIASES = Object.freeze({
  system_admin: 'system_admin',
  department_head: 'department_head',
  coordinator: 'coordinator',
  clinician: 'clinician',
  resident: 'resident',
  // Transitional legacy values. Keep until production identities are normalized.
  resident_manager: 'coordinator',
  attending_physician: 'clinician',
  viewing_doctor: 'clinician',
  medical_resident: 'resident'
});

const PERMISSION_CATALOG = Object.freeze({
  // Identity / account administration
  'identity.users.view': { domain: 'identity', label: 'View user identities' },
  'identity.users.invite': { domain: 'identity', label: 'Invite users' },
  'identity.users.manage': { domain: 'identity', label: 'Manage user identity bindings and roles' },
  'identity.users.lifecycle': { domain: 'identity', label: 'Suspend, lock, reactivate or archive users' },
  'identity.users.security': { domain: 'identity', label: 'Manage account security actions' },
  'identity.overrides.manage': { domain: 'identity', label: 'Manage explicit authority overrides' },

  'staff.create': { domain: 'staff', label: 'Create staff records' },
  'staff.archive': { domain: 'staff', label: 'Archive staff records' },
  'leave.cancel': { domain: 'leave', label: 'Cancel leave records' },
  'leave.purge': { domain: 'leave', label: 'Permanently remove leave records' },
  // People / professional identity
  'staff.directory.view': { domain: 'staff', label: 'View departmental professional directory' },
  'staff.profile.view': { domain: 'staff', label: 'View professional profile' },
  'staff.profile.edit': { domain: 'staff', label: 'Edit professional profile' },

  // Clinical operations
  'rotation.view': { domain: 'rotations', label: 'View rotations' },
  'rotation.create': { domain: 'rotations', label: 'Create rotations' },
  'rotation.edit': { domain: 'rotations', label: 'Edit rotations' },
  'rotation.terminate': { domain: 'rotations', label: 'Terminate rotations' },
  'rotation.approve_exception': { domain: 'rotations', label: 'Approve rotation exceptions' },

  'leave.view': { domain: 'leave', label: 'View leave / absence information' },
  'leave.create': { domain: 'leave', label: 'Create leave / absence records' },
  'leave.edit': { domain: 'leave', label: 'Edit leave / absence records' },
  'leave.return_to_duty': { domain: 'leave', label: 'Record return to duty' },
  'leave.approve_exception': { domain: 'leave', label: 'Approve leave exceptions' },

  'oncall.view': { domain: 'oncall', label: 'View on-call schedule' },
  'oncall.assign': { domain: 'oncall', label: 'Create on-call assignments' },
  'oncall.edit': { domain: 'oncall', label: 'Edit on-call assignments' },
  'oncall.cancel': { domain: 'oncall', label: 'Cancel on-call assignments' },
  'oncall.approve_exception': { domain: 'oncall', label: 'Approve on-call exceptions' },

  // Grounded
  'grounded.ask': { domain: 'grounded', label: 'Ask Grounded questions' },
  'grounded.propose': { domain: 'grounded', label: 'Ask Grounded to propose changes' },
  'grounded.commit': { domain: 'grounded', label: 'Confirm Grounded writes' },

  // Governance / external source integrity
  'governance.view': { domain: 'governance', label: 'View operational governance' },
  'governance.review': { domain: 'governance', label: 'Review governance decisions' },
  'sync.oncall.preview': { domain: 'sync', label: 'Preview on-call external-source sync' },
  'sync.oncall.commit': { domain: 'sync', label: 'Commit on-call external-source sync' },
  'sync.rotations.preview': { domain: 'sync', label: 'Preview rotations external-source sync' },
  'sync.rotations.commit': { domain: 'sync', label: 'Commit rotations external-source sync' },

  // Research / system
  'research.view': { domain: 'research', label: 'View research portfolio' },
  'research.edit': { domain: 'research', label: 'Edit research portfolio' },
  'publications.view': { domain: 'publications', label: 'View publications' },
  'publications.edit': { domain: 'publications', label: 'Edit publications' },
  'system.settings.view': { domain: 'system', label: 'View system settings' },
  'system.settings.edit': { domain: 'system', label: 'Edit system settings' }
});

const rule = (scope, visibility = 'full', reason = '') => Object.freeze({ scope, visibility, reason });

const ROLE_POLICIES = Object.freeze({
  system_admin: Object.freeze({
    '*': Object.freeze([rule('all', 'full', 'System administrators have full platform authority.')])
  }),

  department_head: Object.freeze({
    'staff.create': Object.freeze([rule('department', 'full')]),
    'staff.archive': Object.freeze([rule('department', 'full')]),
    'leave.cancel': Object.freeze([rule('department', 'full')]),
    'identity.users.view': Object.freeze([rule('all', 'full', 'Department heads may review account identities but do not administer them by default.')]),

    'staff.directory.view': Object.freeze([rule('department', 'full')]),
    'staff.profile.view': Object.freeze([rule('own', 'full'), rule('department', 'full')]),
    'staff.profile.edit': Object.freeze([rule('department', 'full')]),

    'rotation.view': Object.freeze([rule('department', 'full')]),
    'rotation.create': Object.freeze([rule('department', 'full')]),
    'rotation.edit': Object.freeze([rule('department', 'full')]),
    'rotation.terminate': Object.freeze([rule('department', 'full')]),
    'rotation.approve_exception': Object.freeze([rule('department', 'full')]),

    'leave.view': Object.freeze([rule('department', 'full')]),
    'leave.create': Object.freeze([rule('department', 'full')]),
    'leave.edit': Object.freeze([rule('department', 'full')]),
    'leave.return_to_duty': Object.freeze([rule('department', 'full')]),
    'leave.approve_exception': Object.freeze([rule('department', 'full')]),

    'oncall.view': Object.freeze([rule('department', 'full')]),
    'oncall.assign': Object.freeze([rule('department', 'full')]),
    'oncall.edit': Object.freeze([rule('department', 'full')]),
    'oncall.cancel': Object.freeze([rule('department', 'full')]),
    'oncall.approve_exception': Object.freeze([rule('department', 'full')]),

    'grounded.ask': Object.freeze([rule('department', 'full')]),
    'grounded.propose': Object.freeze([rule('department', 'full')]),
    'grounded.commit': Object.freeze([rule('department', 'full')]),
    'governance.view': Object.freeze([rule('department', 'full')]),
    'governance.review': Object.freeze([rule('department', 'full')]),

    'research.view': Object.freeze([rule('department', 'full')]),
    'research.edit': Object.freeze([rule('department', 'full')]),
    'publications.view': Object.freeze([rule('department', 'full')]),
    'publications.edit': Object.freeze([rule('department', 'full')]),
    'system.settings.view': Object.freeze([rule('all', 'full')])
  }),

  coordinator: Object.freeze({
    'staff.create': Object.freeze([rule('department', 'full')]),
    'staff.archive': Object.freeze([rule('department', 'full')]),
    'leave.cancel': Object.freeze([rule('department', 'full')]),
    'staff.directory.view': Object.freeze([rule('department', 'summary')]),
    'staff.profile.view': Object.freeze([rule('own', 'full'), rule('department', 'operational')]),
    'staff.profile.edit': Object.freeze([rule('department', 'full')]),

    'rotation.view': Object.freeze([rule('department', 'full')]),
    'rotation.create': Object.freeze([rule('department', 'full')]),
    'rotation.edit': Object.freeze([rule('department', 'full')]),
    'rotation.terminate': Object.freeze([rule('department', 'full')]),

    'leave.view': Object.freeze([rule('department', 'full')]),
    'leave.create': Object.freeze([rule('department', 'full')]),
    'leave.edit': Object.freeze([rule('department', 'full')]),
    'leave.return_to_duty': Object.freeze([rule('department', 'full')]),

    'oncall.view': Object.freeze([rule('department', 'full')]),
    'oncall.assign': Object.freeze([rule('department', 'full')]),
    'oncall.edit': Object.freeze([rule('department', 'full')]),
    'oncall.cancel': Object.freeze([rule('department', 'full')]),

    'grounded.ask': Object.freeze([rule('department', 'full')]),
    'grounded.propose': Object.freeze([rule('department', 'full')]),
    'grounded.commit': Object.freeze([rule('department', 'full')]),
    'governance.view': Object.freeze([rule('department', 'full')]),

    'research.view': Object.freeze([rule('department', 'full')]),
    'research.edit': Object.freeze([rule('department', 'full')]),
    'publications.view': Object.freeze([rule('department', 'full')]),
    'publications.edit': Object.freeze([rule('department', 'full')]),
    'system.settings.view': Object.freeze([rule('all', 'full')])
  }),

  clinician: Object.freeze({
    'leave.cancel': Object.freeze([rule('own', 'full')]),
    'staff.directory.view': Object.freeze([rule('department', 'summary')]),
    'staff.profile.view': Object.freeze([rule('own', 'full'), rule('department', 'summary')]),
    'staff.profile.edit': Object.freeze([rule('own', 'full')]),

    'rotation.view': Object.freeze([rule('department', 'operational')]),
    'leave.view': Object.freeze([rule('own', 'full'), rule('department', 'operational')]),
    'leave.create': Object.freeze([rule('own', 'full')]),
    'leave.edit': Object.freeze([rule('own', 'full')]),
    'oncall.view': Object.freeze([rule('department', 'operational')]),

    'grounded.ask': Object.freeze([rule('department', 'operational')]),
    'grounded.propose': Object.freeze([rule('own', 'full')]),
    'research.view': Object.freeze([rule('department', 'summary')]),
    'publications.view': Object.freeze([rule('department', 'full')]),
    'publications.edit': Object.freeze([rule('own', 'full')])
  }),

  resident: Object.freeze({
    'leave.cancel': Object.freeze([rule('own', 'full')]),
    'staff.directory.view': Object.freeze([rule('department', 'summary')]),
    'staff.profile.view': Object.freeze([rule('own', 'full'), rule('department', 'summary')]),
    'staff.profile.edit': Object.freeze([rule('own', 'full')]),

    'rotation.view': Object.freeze([rule('own', 'full')]),
    'leave.view': Object.freeze([rule('own', 'full')]),
    'leave.create': Object.freeze([rule('own', 'full')]),
    'oncall.view': Object.freeze([rule('department', 'operational')]),

    'grounded.ask': Object.freeze([rule('department', 'operational')]),
    'publications.view': Object.freeze([rule('department', 'full')])
  })
});

const SCOPE_SPECIFICITY = Object.freeze({ none: 0, all: 10, department: 20, unit: 30, supervisees: 35, own: 40 });
const VISIBILITY_STRENGTH = Object.freeze({ none: 0, summary: 10, operational: 20, full: 30 });

function normalizeRole(roleName) {
  return ROLE_ALIASES[String(roleName || '').trim()] || null;
}

function normalizeScopes(context = {}) {
  const incoming = Array.isArray(context.scopes)
    ? context.scopes
    : (context.scope ? [context.scope] : []);
  const valid = [...new Set(incoming.filter(scope => SCOPES.includes(scope) && scope !== 'none'))];
  return valid.length ? valid : ['none'];
}

function scopeMatches(ruleScope, requestScopes) {
  if (ruleScope === 'all') return true;
  return requestScopes.includes(ruleScope);
}

function pickBestRule(rules, requestScopes) {
  const matches = (rules || []).filter(r => scopeMatches(r.scope, requestScopes));
  if (!matches.length) return null;
  return matches.sort((a, b) => {
    const scopeDelta = (SCOPE_SPECIFICITY[b.scope] || 0) - (SCOPE_SPECIFICITY[a.scope] || 0);
    if (scopeDelta) return scopeDelta;
    return (VISIBILITY_STRENGTH[b.visibility] || 0) - (VISIBILITY_STRENGTH[a.visibility] || 0);
  })[0];
}

function normalizeOverride(raw) {
  if (!raw || !raw.permission_key) return null;
  const effect = raw.effect === 'deny' ? 'deny' : (raw.effect === 'allow' ? 'allow' : null);
  const scope = SCOPES.includes(raw.scope) ? raw.scope : null;
  const visibility = VISIBILITIES.includes(raw.visibility) ? raw.visibility : 'full';
  if (!effect || !scope) return null;
  return { ...raw, effect, scope, visibility };
}

function isOverrideActive(override, nowMs) {
  if (!override.expires_at) return true;
  const expires = Date.parse(override.expires_at);
  return Number.isFinite(expires) && expires > nowMs;
}

function decisionForVisibility(visibility) {
  return visibility === 'full' ? DECISIONS.ALLOW : DECISIONS.ALLOW_LIMITED;
}

function resolveAuthority({ actor, permission, context = {}, overrides = [], now = new Date() }) {
  const canonicalRole = normalizeRole(actor?.user_role || actor?.role);
  const requestScopes = normalizeScopes(context);
  const nowMs = now instanceof Date ? now.getTime() : Date.parse(now);

  const base = {
    permission,
    canonical_role: canonicalRole,
    actor_user_id: actor?.id || null,
    actor_staff_id: actor?.medical_staff_id || null,
    scopes: requestScopes,
    visibility: 'none'
  };

  if (!actor?.id) {
    return { ...base, decision: DECISIONS.DENY, source: 'identity', reason: 'No authenticated actor identity was supplied.' };
  }
  if (!canonicalRole) {
    return { ...base, decision: DECISIONS.DENY, source: 'role', reason: `Unknown or unsupported role: ${actor?.user_role || actor?.role || 'none'}.` };
  }
  if (!PERMISSION_CATALOG[permission]) {
    return { ...base, decision: DECISIONS.DENY, source: 'catalog', reason: `Unknown permission key: ${permission}.` };
  }

  const activeOverrides = (overrides || [])
    .map(normalizeOverride)
    .filter(Boolean)
    .filter(o => o.permission_key === permission)
    .filter(o => isOverrideActive(o, nowMs))
    .filter(o => scopeMatches(o.scope, requestScopes));

  // Explicit denial always wins over role defaults and explicit grants.
  const denyOverride = pickBestRule(activeOverrides.filter(o => o.effect === 'deny'), requestScopes);
  if (denyOverride) {
    return {
      ...base,
      decision: DECISIONS.DENY,
      source: 'user_override_deny',
      matched_scope: denyOverride.scope,
      override_id: denyOverride.id || null,
      reason: denyOverride.reason || 'An explicit user denial overrides role defaults.'
    };
  }

  const allowOverride = pickBestRule(activeOverrides.filter(o => o.effect === 'allow'), requestScopes);
  if (allowOverride) {
    return {
      ...base,
      decision: decisionForVisibility(allowOverride.visibility),
      source: 'user_override_allow',
      matched_scope: allowOverride.scope,
      visibility: allowOverride.visibility,
      override_id: allowOverride.id || null,
      reason: allowOverride.reason || 'An explicit user grant extends the role default.'
    };
  }

  const policy = ROLE_POLICIES[canonicalRole] || {};
  const rules = policy[permission] || policy['*'] || [];
  const matched = pickBestRule(rules, requestScopes);
  if (!matched) {
    return {
      ...base,
      decision: DECISIONS.DENY,
      source: 'role_default',
      reason: `${canonicalRole} does not grant ${permission} for the requested scope.`
    };
  }

  return {
    ...base,
    decision: decisionForVisibility(matched.visibility),
    source: 'role_default',
    matched_scope: matched.scope,
    visibility: matched.visibility,
    reason: matched.reason || `${canonicalRole} grants ${permission} at ${matched.scope} scope.`
  };
}

function rolePolicy(roleName) {
  const canonicalRole = normalizeRole(roleName);
  return canonicalRole ? (ROLE_POLICIES[canonicalRole] || {}) : {};
}

function catalogEntries() {
  return Object.entries(PERMISSION_CATALOG).map(([key, meta]) => ({ key, ...meta }));
}

module.exports = Object.freeze({
  DECISIONS,
  SCOPES,
  VISIBILITIES,
  ROLE_ALIASES,
  ROLE_POLICIES,
  PERMISSION_CATALOG,
  normalizeRole,
  normalizeScopes,
  resolveAuthority,
  rolePolicy,
  catalogEntries
});

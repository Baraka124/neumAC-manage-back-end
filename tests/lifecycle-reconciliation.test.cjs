'use strict';
// Contract: rotation/leave lifecycle views must not let finished or drifted records
// masquerade as live, and must expose a reconciliation surface for records whose date
// has passed but whose status was never closed. Structural assertions over index.js
// (no live DB in CI), matching the existing backend test style.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');

function sliceHandler(route, method = 'get') {
  const needle = `app.${method}('${route}'`;
  const start = src.indexOf(needle);
  assert.ok(start !== -1, `handler ${method.toUpperCase()} ${route} not found`);
  const end = src.indexOf('app.', start + needle.length);
  return src.slice(start, end === -1 ? src.length : end);
}

test('rotations operational list excludes completed by default, with explicit history escape', () => {
  const h = sliceHandler('/api/rotations');
  // default view drops finished history
  assert.match(h, /not\('rotation_status', 'in', '\(terminated_early,cancelled,completed\)'\)/);
  // opt-in to see completed too
  assert.match(h, /include_completed === 'true'/);
  // an explicit status query still returns that status (history remains reachable)
  assert.match(h, /if \(rotation_status\) query = query\.eq\('rotation_status', rotation_status\)/);
});

test('rotations needs-review surfaces live-status rotations whose planned end has passed', () => {
  const h = sliceHandler('/api/rotations/needs-review');
  assert.match(h, /\.in\('rotation_status', \['scheduled','active','extended'\]\)/);
  assert.match(h, /\.lt\('end_date', today\)/);
  assert.match(h, /review_reason: 'ended_not_closed'/);
  // read-only: no write/update on this path
  assert.doesNotMatch(h, /\.update\(|\.insert\(|\.delete\(/);
});

test('absence current view ignores records that already have a recorded return', () => {
  const h = sliceHandler('/api/absence-records/current');
  assert.match(h, /\.eq\('current_status', 'currently_absent'\)\.is\('actual_return_date', null\)/);
});

test('absence needs-review covers overdue returns and never-activated planned leaves', () => {
  const h = sliceHandler('/api/absence-records/needs-review');
  assert.match(h, /current_status\.eq\.currently_absent,actual_return_date\.is\.null,end_date\.lt\./);
  assert.match(h, /current_status\.eq\.planned_leave,start_date\.lt\./);
  assert.match(h, /overdue_return/);
  assert.match(h, /planned_not_started/);
  assert.doesNotMatch(h, /\.update\(|\.insert\(|\.delete\(/);
});

test('needs-review sub-route is registered before the /:id route so Express does not treat it as an id', () => {
  const needsReview = src.indexOf("app.get('/api/absence-records/needs-review'");
  const byId = src.indexOf("app.get('/api/absence-records/:id'");
  assert.ok(needsReview !== -1 && byId !== -1, 'both routes must exist');
  assert.ok(needsReview < byId, 'needs-review must be declared before /:id');
});

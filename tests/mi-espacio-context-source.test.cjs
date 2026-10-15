'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { unavailableSources, sendUnavailable } = require('../mi-espacio-source-integrity');
const source = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const ownList = data => ({ data, error: null });

test('valid empty source lists are genuinely empty; linked staff may be null', () => {
  assert.deepEqual(unavailableSources([
    { name: 'clinical_trials', result: ownList([]), shape: 'list' },
    { name: 'innovation_projects', result: ownList([{ id: 'authorized-project' }]), shape: 'list' },
    { name: 'medical_staff', result: { data: null, error: null }, shape: 'single' }
  ]), []);
});

test('an upstream error cannot be represented as an empty research list', () => {
  const err = { code: '42P01', message: 'sensitive database query text' };
  assert.deepEqual(unavailableSources([
    { name: 'clinical_trials', result: { data: null, error: err }, shape: 'list' },
    { name: 'innovation_projects', result: ownList([]), shape: 'list' }
  ]), [{ source: 'clinical_trials', code: '42P01' }]);
});

test('failed medical staff lookup, malformed payload and null list all fail closed', () => {
  assert.deepEqual(unavailableSources([
    { name: 'medical_staff', result: { data: null, error: { code: 'XX000' } }, shape: 'single' },
    { name: 'publication_authors', result: { data: null, error: null }, shape: 'list' },
    { name: 'guardias', result: { data: {}, error: null }, shape: 'list' },
    { name: 'projects', result: null, shape: 'list' }
  ]).map(x => x.source), ['medical_staff', 'publication_authors', 'guardias', 'projects']);
});

test('503 message never leaks query text, identifiers or raw database errors', () => {
  let status, payload, logged;
  const old = console.error;
  console.error = (...args) => { logged = args; };
  try {
    const res = { status(value) { status = value; return this; }, json(value) { payload = value; return this; } };
    sendUnavailable(res, unavailableSources([{
      name: 'innovation_projects',
      result: { data: null, error: { code: 'PGRST301', message: 'private clinical record: patient X' } },
      shape: 'list'
    }]));
  } finally { console.error = old; }
  assert.equal(status, 503);
  assert.equal(payload.error, 'MI_ESPACIO_SOURCE_UNAVAILABLE');
  assert.match(payload.message, /No se puede consultar toda tu actividad/);
  assert.doesNotMatch(JSON.stringify(payload) + JSON.stringify(logged), /patient X|private clinical record|PGRST301.*message/);
  assert.deepEqual(logged[1], [{ source: 'innovation_projects', code: 'PGRST301' }]);
});

test('the personal-context route validates every source before generating response', () => {
  const route = source.slice(source.indexOf("app.get('/api/me/context'"), source.indexOf("app.post('/api/auth/register'"));
  assert.ok(route.length > 3000);
  assert.match(route, /unavailableSources\(\[\s*\{ name: 'oncall_schedule'/);
  for (const src of ['resident_rotations', 'supervised_rotations', 'staff_absence_records', 'coordinated_research_lines', 'research_line_members', 'clinical_trials', 'innovation_projects', 'publication_authors']) {
    assert.ok(route.includes("name: '" + src + "'"), src + ' must be checked');
  }
  assert.ok(route.indexOf('if (unavailable.length)') < route.indexOf('const studies ='), 'no partial success before validation');
  assert.match(route, /unavailableStaff.length/);
  assert.doesNotMatch(route, /json\(\{ error: 'Failed to build personal context', message: e.message \}\)/);
});

test('Phase 43A does not silently broaden historical/withdrawn research or infer scientific role', () => {
  const route = source.slice(source.indexOf("app.get('/api/me/context'"), source.indexOf("app.post('/api/auth/register'"));
  assert.ok(route.includes(".not('status', 'in',"), 'closed clinical trial filtering remains governed');
  assert.ok(route.includes(".neq('current_stage', 'completed')"), 'completed project coverage requires separate governance');
  assert.ok(route.includes("inArr(t.co_investigators, sid) ? 'co-investigator' : 'sub-investigator'"));
  assert.ok(route.includes("p.lead_investigator_id === sid ? 'lead' : 'co-investigator'"));
});

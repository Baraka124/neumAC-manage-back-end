'use strict';
// Contract: the self-reported indexed-publication count + h-index + research links
// captured in Mi espacio must reach the public website, shaped to the site's
// governance-aware research_footprint contract, gated on is_public, and dated.
// These are structural assertions over index.js (no live DB in CI), matching the
// existing backend test style.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');

// Isolate the /api/team/website handler so assertions can't be satisfied by an
// unrelated endpoint that happens to contain the same tokens.
function sliceHandler(route) {
  const start = src.indexOf(`app.get('${route}'`);
  assert.ok(start !== -1, `handler ${route} not found`);
  const end = src.indexOf('app.get(', start + 1);
  return src.slice(start, end === -1 ? src.length : end);
}
const teamWebsite = sliceHandler('/api/team/website');

test('team/website selects the self-reported metric columns', () => {
  assert.match(teamWebsite, /indexed_publications_count, h_index, metrics_updated_at/);
});

test('team/website emits research profile links at top level', () => {
  assert.match(teamWebsite, /orcid_id:\s*m\.orcid_id/);
  assert.match(teamWebsite, /scholar_url:\s*m\.scholar_url/);
  assert.match(teamWebsite, /researchgate_url:\s*m\.researchgate_url/);
});

test('team/website emits a research_footprint built by the shared helper', () => {
  assert.match(teamWebsite, /research_footprint:\s*publicResearchFootprint\(m\)/);
});

test('footprint helper gates on is_public and on at least one non-zero metric', () => {
  const start = src.indexOf('function publicResearchFootprint');
  assert.ok(start !== -1, 'publicResearchFootprint helper not found');
  const fn = src.slice(start, start + 900);
  // public-only
  assert.match(fn, /m\.is_public !== true\)\s*return null/);
  // non-zero metric required (both null -> no footprint)
  assert.match(fn, /> 0 \? m\.indexed_publications_count : null/);
  assert.match(fn, /> 0 \? m\.h_index : null/);
  assert.match(fn, /if \(pubs == null && h == null\) return null/);
  // governance contract + honest provenance labelling
  assert.match(fn, /visibility:\s*'approved_public'/);
  assert.match(fn, /person_approval:\s*'approved'/);
  assert.match(fn, /source:\s*'Autoinformado'/);
  assert.match(fn, /verified_at:\s*verified/);
});

test('self-service PUT stamps metrics_updated_at only when a metric actually changes', () => {
  const start = src.indexOf("app.put('/api/medical-staff/:id'");
  assert.ok(start !== -1, 'medical-staff PUT not found');
  const handler = src.slice(start, start + 4000);
  assert.match(handler, /const touchesMetrics =/);
  assert.match(handler, /const changed =/);
  assert.match(handler, /if \(changed\) validated\.value\.metrics_updated_at = new Date\(\)\.toISOString\(\)/);
  // and the stamped column is returned so the editor can show it
  assert.match(handler, /metrics_updated_at'\)\.single\(\)/);
});

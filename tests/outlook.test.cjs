'use strict';
// Outlook: facts from the plan + trends against set targets; nothing invented.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { buildOutlook, mondayOf } = require('../outlook.js');
const idx = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const T = '2026-10-17';   // Saturday → week 1 = Mon 12 Oct
const base = { today: T, weeks: 4, units: [], rotations: [], oncall: [], oncallHistory: [], absences: [], stocks: [], meetings: [] };
const days = (from, n) => Array.from({ length: n }, (_, i) => { const d = new Date(from + 'T12:00:00Z'); d.setUTCDate(d.getUTCDate() + i); return d.toISOString().slice(0, 10); });

test('weeks are Monday–Sunday from this week', () => {
  const o = buildOutlook(base);
  assert.equal(mondayOf(T), '2026-10-12'); assert.equal(o.weeks[0].start, '2026-10-12'); assert.equal(o.weeks[0].end, '2026-10-18'); assert.equal(o.weeks.length, 4);
});

test('guardias: unplanned soon = alert; planned-until noted; gaps and missing backup only where backup is normally used', () => {
  assert.ok(buildOutlook(base).weeks[0].signals.some(s => s.kind === 'oncall' && s.level === 'alert'));
  assert.match(buildOutlook(base).notes[0], /No guardias are planned/);
  const planned = days(T, 10).filter(d => d !== '2026-10-20').map(d => ({ duty_date: d, primary_physician_id: 'a', backup_physician_id: d === '2026-10-21' ? null : 'b' }));
  const hist = days('2026-08-01', 20).map(d => ({ duty_date: d, primary_physician_id: 'a', backup_physician_id: 'b' }));
  const o = buildOutlook({ ...base, oncall: planned, oncallHistory: hist });
  const w2 = o.weeks[1].signals.map(s => s.text);
  assert.ok(w2.includes('1 day without a guardia assigned'));
  assert.ok(w2.includes('1 guardia without backup'));
  assert.match(o.notes.join(' '), /planned until 2026-10-26/);
  const noBackupHabit = buildOutlook({ ...base, oncall: planned, oncallHistory: hist.map(h => ({ ...h, backup_physician_id: null })) });
  assert.ok(!noBackupHabit.weeks[1].signals.some(s => /backup/.test(s.text)));   // not flagged where backup is not the norm
});

test('a unit with nobody from its team on a working day is an alert; absence reasons are never used', () => {
  const o = buildOutlook({ ...base, units: [{ id: 'u1', unit_name: 'PFR', roster: ['a', 'b'] }],
    absences: [{ staff_member_id: 'a', start_date: '2026-10-19', end_date: '2026-10-23', name: 'Dra. A', absence_reason: 'x' }, { staff_member_id: 'b', start_date: '2026-10-21', end_date: '2026-10-22', name: 'Dr. B' }] });
  const w2 = o.weeks[1].signals;
  assert.ok(w2.some(s => s.level === 'alert' && s.text === 'PFR: nobody from the team on 2 working days'));
  assert.ok(w2.some(s => s.kind === 'absence' && /Dra\. A, Dr\. B/.test(s.text)));
  assert.ok(!JSON.stringify(o).includes('absence_reason'));
});

test('residents over the unit capacity; starts and finishes', () => {
  const r = (id, s, e) => ({ resident_id: id, training_unit_id: 'u1', start_date: s, end_date: e, rotation_status: 'active', resident_name: id });
  const o = buildOutlook({ ...base, units: [{ id: 'u1', unit_name: 'Sueño', maximum_residents: 1, roster: [] }],
    rotations: [r('Laura', '2026-09-01', '2026-10-31'), r('Iria', '2026-10-26', '2026-12-31'), r('Pablo', '2026-10-01', '2026-10-01')] });
  assert.ok(o.weeks[2].signals.some(s => s.kind === 'capacity' && s.text === 'Sueño: 2 residents for 1 place'));
  assert.ok(o.weeks[2].signals.some(s => s.text === 'Sueño: Iria starts'));
  assert.ok(o.weeks[2].signals.some(s => s.text === 'Sueño: Laura finishes'));
});

test('pending trend: flagged only when, at the current pace, it would pass a target the department set', () => {
  const pts = [{ date: '2026-09-19', value: 30 }, { date: '2026-10-03', value: 34 }, { date: '2026-10-17', value: 38 }];   // +2 / week
  const withTarget = buildOutlook({ ...base, stocks: [{ unit_id: 'u1', unit_name: 'PFR', label: 'Lista de espera', points: pts, target: { value: 40, direction: 'max' } }] });
  assert.equal(withTarget.trends[0].per_week, 2); assert.equal(withTarget.trends[0].crosses, '2026-10-24');
  assert.ok(withTarget.weeks[1].signals.some(s => s.kind === 'trend' && /would pass the target \(≤ 40\) around 2026-10-24/.test(s.text)));
  const noTarget = buildOutlook({ ...base, stocks: [{ unit_id: 'u1', unit_name: 'PFR', label: 'Lista de espera', points: pts, target: null }] });
  assert.equal(noTarget.trends[0].crosses, null);
  assert.ok(!noTarget.weeks.some(w => w.signals.some(s => s.kind === 'trend')));      // no target → no flag
  assert.equal(buildOutlook({ ...base, stocks: [{ label: 'x', points: pts.slice(0, 2), target: { value: 1 } }] }).trends.length, 0);   // too few points
});

test('route: read-only, Units read', () => {
  assert.match(idx, /app\.get\('\/api\/ops\/outlook', authenticateToken, Portfolio\.read\('training_units'\), apiLimiter,/);
});

'use strict';
/* Import cross-checks (Phase C). Pure: no DB, no clock — the route loads data and passes `today`.
   Looks at the WHOLE selected import (plus what neumDesk already holds) and returns per-row
   findings and an impact summary. Findings here never block: they are "review" (needs a human
   look) or "info". Hard blocks stay in the per-row dry-run (decision engine).

   input (oncall):    { kind:'oncall', today, proposed:[{key,duty_date,primary_physician_id,resident_physician_id,shift_type}],
                        existing:{ oncall:[...], rotations:[{resident_id,start_date,end_date,actual_end_date,rotation_status,unit:{unit_code,unit_name}}] },
                        staff:[{id,full_name}] }
   input (rotations): { kind:'rotations', today, proposed:[{key,resident_id,training_unit_id,start_date,end_date}],
                        existing:{ rotations:[...] }, staff:[...], units:[{id,unit_name,unit_code}] } */

const DAY = 86400000;
const toDate = s => new Date(String(s).slice(0, 10) + 'T12:00:00Z');
const iso = d => d.toISOString().slice(0, 10);
const addDays = (s, n) => iso(new Date(toDate(s).getTime() + n * DAY));
const addMonths = (s, n) => { const d = toDate(s); d.setUTCMonth(d.getUTCMonth() + n); return iso(d); };
const month = s => String(s).slice(0, 7);
const live = r => r && !r.deleted_at && !['cancelled'].includes(r.rotation_status);
const effEnd = r => String(r.actual_end_date || r.end_date).slice(0, 10);
const overlaps = (a1, a2, b1, b2) => a1 <= b2 && b1 <= a2;
// Human dates for messages: "3 nov" (year added when it is not the current year), "nov 2026".
const human = (d, today) => { const x = toDate(d); const o = { day: 'numeric', month: 'short', timeZone: 'UTC' }; if (String(d).slice(0, 4) !== String(today).slice(0, 4)) o.year = 'numeric'; return x.toLocaleDateString('es-ES', o); };
const humanMonth = m => toDate(m + '-01').toLocaleDateString('es-ES', { month: 'short', year: 'numeric', timeZone: 'UTC' });
const isExternal = u => !!u && (/^ROT-EXT$/i.test(u.unit_code || '') || /extern/i.test(u.unit_name || ''));

function nameOf(staff) { const m = new Map((staff || []).map(s => [String(s.id), s.full_name])); return id => m.get(String(id)) || 'Unknown'; }
function push(map, key, f) { (map[key] = map[key] || []).push(f); }

function reviewOncall(input) {
  const today = input.today, proposed = input.proposed || [], ex = input.existing || {}, name = nameOf(input.staff);
  const rows = {}, summary = { kind: 'oncall', shifts: proposed.length, people: 0, consecutive: 0, overload: [], externalRotation: 0, withoutMir: 0, uncoveredDays: [], past: 0, far: 0 };
  if (!proposed.length) return { rows, summary };
  const byDate = new Map();                                             // final picture: proposed wins over existing on its date
  for (const s of ex.oncall || []) if (!s.deleted_at) byDate.set(String(s.duty_date).slice(0, 10), { ...s, _existing: true });
  for (const s of proposed) byDate.set(s.duty_date, s);
  const people = new Set();
  const dutyOf = new Map();                                             // person -> Set(dates)
  for (const [d, s] of byDate) for (const id of [s.primary_physician_id, s.resident_physician_id].filter(Boolean)) {
    people.add(String(id)); if (!dutyOf.has(String(id))) dutyOf.set(String(id), new Set()); dutyOf.get(String(id)).add(d);
  }
  const horizon = addMonths(today, 12);
  for (const s of proposed) {
    if (s.duty_date < today) summary.past++;
    if (s.duty_date > horizon) summary.far++;
    for (const [id, role] of [[s.primary_physician_id, 'staff'], [s.resident_physician_id, 'MIR']].filter(([id]) => id)) {
      const dates = dutyOf.get(String(id));
      for (const n of [addDays(s.duty_date, -1), addDays(s.duty_date, 1)]) if (dates.has(n)) {
        push(rows, s.key, { severity: 'review', code: 'IMPORT_CONSECUTIVE_DUTY', message: `${name(id)} (${role}) also has a guardia on ${human(n, today)} — no rest day between guardias.` });
        summary.consecutive++; break;
      }
    }
    if (!s.resident_physician_id) { push(rows, s.key, { severity: 'info', code: 'IMPORT_NO_MIR', message: 'No MIR assigned to this guardia.' }); summary.withoutMir++; }
    else {
      const rot = (ex.rotations || []).find(r => live(r) && String(r.resident_id) === String(s.resident_physician_id) && overlaps(String(r.start_date).slice(0, 10), effEnd(r), s.duty_date, s.duty_date) && isExternal(r.unit));
      if (rot) { push(rows, s.key, { severity: 'review', code: 'IMPORT_MIR_ON_EXTERNAL_ROTATION', message: `${name(s.resident_physician_id)} is on ${rot.unit?.unit_name || 'an external rotation'} (${human(String(rot.start_date).slice(0, 10), today)} → ${human(effEnd(rot), today)}).` }); summary.externalRotation++; }
    }
  }
  // Workload: guardias per person per month in the final picture, compared with the month's average.
  const months = [...new Set(proposed.map(s => month(s.duty_date)))];
  for (const m of months) {
    const count = new Map();
    for (const [d, s] of byDate) if (month(d) === m) for (const id of [s.primary_physician_id, s.resident_physician_id].filter(Boolean)) count.set(String(id), (count.get(String(id)) || 0) + 1);
    const vals = [...count.values()]; if (vals.length < 3) continue;
    const avg = vals.reduce((a, b) => a + b, 0) / vals.length, limit = Math.max(avg + 2, avg * 1.5);
    for (const [id, n] of count) if (n > limit) {
      summary.overload.push({ person: name(id), month: m, count: n, average: Math.round(avg * 10) / 10 });
      for (const s of proposed) if (month(s.duty_date) === m && [s.primary_physician_id, s.resident_physician_id].map(String).includes(id))
        push(rows, s.key, { severity: 'review', code: 'IMPORT_WORKLOAD', message: `${name(id)} would have ${n} guardias in ${humanMonth(m)} (team average ${Math.round(avg * 10) / 10}).` });
    }
  }
  // Coverage: days inside the file's period (from today on) with no guardia at all.
  const dates = proposed.map(s => s.duty_date).sort();
  for (let d = dates[0] < today ? today : dates[0]; d <= dates[dates.length - 1]; d = addDays(d, 1)) if (!byDate.has(d)) summary.uncoveredDays.push(d);
  summary.people = people.size;
  return { rows, summary };
}

function reviewRotations(input) {
  const today = input.today, proposed = input.proposed || [], ex = input.existing || {}, name = nameOf(input.staff);
  const unitName = id => (input.units || []).find(u => String(u.id) === String(id))?.unit_name || 'unit';
  const rows = {}, summary = { kind: 'rotations', rotations: proposed.length, residents: 0, inFileOverlaps: 0, gaps: [], past: 0, far: 0 };
  const horizon = addMonths(today, 12);
  const byRes = new Map();
  for (const p of proposed) { if (!byRes.has(String(p.resident_id))) byRes.set(String(p.resident_id), []); byRes.get(String(p.resident_id)).push(p);
    if (p.end_date < today) summary.past++; if (p.start_date > horizon) summary.far++; }
  // Two rows of the SAME file overlapping each other (the per-row dry run only compares with the DB).
  for (const [, list] of byRes) {
    const sorted = list.slice().sort((a, b) => a.start_date < b.start_date ? -1 : 1);
    for (let i = 0; i < sorted.length; i++) for (let j = i + 1; j < sorted.length && sorted[j].start_date <= sorted[i].end_date; j++) {
      const a = sorted[i], b = sorted[j];
      push(rows, a.key, { severity: 'review', code: 'IMPORT_IN_FILE_OVERLAP', message: `Overlaps another row of this file: ${unitName(b.training_unit_id)} ${human(b.start_date, today)} → ${human(b.end_date, today)}.` });
      push(rows, b.key, { severity: 'review', code: 'IMPORT_IN_FILE_OVERLAP', message: `Overlaps another row of this file: ${unitName(a.training_unit_id)} ${human(a.start_date, today)} → ${human(a.end_date, today)}.` });
      summary.inFileOverlaps++;
    }
  }
  // Gaps: months in the next 12 with no rotation at all, after this import (existing + proposed).
  const winStart = today.slice(0, 8) + '01', winEnd = addMonths(winStart, 12);
  for (const [rid, list] of byRes) {
    const spans = [...list.map(p => [p.start_date, p.end_date]),
      ...(ex.rotations || []).filter(r => live(r) && String(r.resident_id) === rid).map(r => [String(r.start_date).slice(0, 10), effEnd(r)])];
    const empty = [];
    for (let m = winStart; m < winEnd; m = addMonths(m, 1)) {
      const mEnd = addDays(addMonths(m, 1), -1);
      if (!spans.some(([s, e]) => overlaps(s, e, m, mEnd))) empty.push(month(m));
    }
    if (empty.length) summary.gaps.push({ resident: name(rid), months: empty });
  }
  summary.residents = byRes.size;
  return { rows, summary };
}

function reviewImport(input) {
  if (!input || !/^\d{4}-\d{2}-\d{2}$/.test(input.today || '')) throw new Error('today (YYYY-MM-DD) is required');
  if (input.kind === 'oncall') return reviewOncall(input);
  if (input.kind === 'rotations') return reviewRotations(input);
  throw new Error('Unknown import kind');
}

module.exports = { reviewImport, isExternal };

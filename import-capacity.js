'use strict';
/* Unit capacity advice for imports. Pure: callers pass rotations, units and dates.
   A rotation occupies its unit on every day from its effective start to its effective end
   (actual_* dates win), unless it is cancelled. This matches how the decision engine counts
   residents in a unit.

   advise({unit, rotations, start, end, horizonEnd, units, unitRotations})
     unit          : {id, unit_name, maximum_residents}
     rotations     : rotations of THIS unit overlapping [start, horizonEnd] (+ pending rows of the same file)
     start, end    : the proposed window (YYYY-MM-DD)
     horizonEnd    : how far to look for the next opening after `end` (default end + 365 days)
     units         : other candidate units [{id, unit_name, maximum_residents, unit_status}]
     unitRotations : rotations of those units overlapping [start, end]
   → { capacity, full:[{start,end,peak}], next_start, next_opening, open_units:[{id,unit_name,free,capacity}] }
     next_start   : earliest day in (start, end] from which the file's END date still fits (null if none)
     next_opening : when no next_start: first day after `end` with a free place (null if none in the horizon)
     open_units   : units with a free place on every day of [start, end], most free first (max 5) */

const DAY = 86400000;
const iso = d => String(d || '').slice(0, 10);
const addDays = (d, n) => new Date(new Date(iso(d) + 'T12:00:00Z').getTime() + n * DAY).toISOString().slice(0, 10);
const effStart = r => iso(r.actual_start_date || r.start_date);
const effEnd = r => iso(r.actual_end_date || r.end_date);
const occupies = r => r && !r.deleted_at && String(r.rotation_status || '').toLowerCase() !== 'cancelled';

function occupancy(rotations, unitId, from, to) {
  const rel = (rotations || []).filter(r => occupies(r) && String(r.training_unit_id) === String(unitId) && effStart(r) <= to && effEnd(r) >= from);
  const out = new Map();
  for (let d = from; d <= to; d = addDays(d, 1)) out.set(d, rel.filter(r => effStart(r) <= d && effEnd(r) >= d).length);
  return out;
}

function merge(days) {
  const out = [];
  for (const x of days) {
    const last = out[out.length - 1];
    if (last && addDays(last.end, 1) === x.day) { last.end = x.day; last.peak = Math.max(last.peak, x.n); }
    else out.push({ start: x.day, end: x.day, peak: x.n });
  }
  return out;
}

function advise({ unit, rotations, start, end, horizonEnd, units, unitRotations }) {
  const capacity = Number(unit && unit.maximum_residents) || null;
  const res = { capacity, full: [], next_start: null, next_opening: null, open_units: [] };
  if (!capacity || !start || !end || end < start) return res;
  const horizon = horizonEnd || addDays(end, 365);
  const occ = occupancy(rotations, unit.id, start, horizon);
  const fullDays = [];
  for (let d = start; d <= end; d = addDays(d, 1)) if (occ.get(d) >= capacity) fullDays.push({ day: d, n: occ.get(d) });
  res.full = merge(fullDays);
  if (!fullDays.length) return res;
  const lastFull = fullDays[fullDays.length - 1].day;
  if (lastFull < end) res.next_start = addDays(lastFull, 1);
  // Only when no start inside the window fits: the first free day after it.
  if (!res.next_start) for (let d = addDays(end, 1); d <= horizon; d = addDays(d, 1)) if (occ.get(d) < capacity) { res.next_opening = d; break; }
  for (const u of units || []) {
    if (String(u.id) === String(unit.id)) continue;
    if (u.unit_status && u.unit_status !== 'active') continue;
    const cap = Number(u.maximum_residents) || 0; if (!cap) continue;
    const o = occupancy(unitRotations, u.id, start, end);
    const peak = Math.max(0, ...o.values());
    if (peak < cap) res.open_units.push({ id: u.id, unit_name: u.unit_name, free: cap - peak, capacity: cap });
  }
  res.open_units.sort((a, b) => b.free - a.free || String(a.unit_name).localeCompare(String(b.unit_name), 'es'));
  res.open_units = res.open_units.slice(0, 5);
  return res;
}

module.exports = { advise, occupancy, addDays };

'use strict';
/* Outlook — the next weeks, from records that already exist (no new data entry, no invented thresholds).
   Every signal is a fact about the plan (guardias, absences, rotations, unit capacity) or a trend at the current
   pace compared with a target the department set. Weeks are Monday–Sunday. */

const iso = d => (d ? String(d).slice(0, 10) : null);
const addDays = (d, n) => { const x = new Date(iso(d) + 'T12:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
const mondayOf = d => { const x = new Date(iso(d) + 'T12:00:00Z'); x.setUTCDate(x.getUTCDate() - ((x.getUTCDay() + 6) % 7)); return x.toISOString().slice(0, 10); };
const daysOf = (start, end) => { const out = []; for (let d = start; d <= end; d = addDays(d, 1)) out.push(d); return out; };
const overlaps = (s, e, a, b) => s <= b && e >= a;
const effStart = r => iso(r.actual_start_date || r.start_date), effEnd = r => iso(r.actual_end_date || r.end_date);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

/* data: {
     today, weeks (default 8),
     units: [{ id, unit_name, maximum_residents, roster: [staff ids] }],
     rotations: [{ resident_id, training_unit_id, start_date, end_date, actual_*, rotation_status, resident_name }],
     oncall: [{ duty_date, primary_physician_id, backup_physician_id, resident_physician_id }],
     oncallHistory: [same, past ~90 days]  (to know whether backup is normally used),
     absences: [{ staff_member_id, start_date, end_date, current_status, name }],
     staffNames: { id: name },
     stocks: [{ unit_id, unit_name, label, points: [{date, value}], target: {value, direction} | null }],
     meetings: [{ title, starts_at }] } */
function buildOutlook(data) {
  const today = iso(data.today), nWeeks = Math.min(Math.max(data.weeks || 8, 1), 12);
  const first = mondayOf(today), weeks = [];
  for (let i = 0; i < nWeeks; i++) { const s = addDays(first, 7 * i); weeks.push({ start: s, end: addDays(s, 6), signals: [] }); }
  const horizonEnd = weeks[weeks.length - 1].end;
  const live = (data.rotations || []).filter(r => !r.deleted_at && String(r.rotation_status || '').toLowerCase() !== 'cancelled');
  const absences = (data.absences || []).filter(a => !a.deleted_at && !['cancelled', 'rejected', 'returned'].includes(String(a.current_status || '').toLowerCase()));
  const notes = [];

  // Guardias: is the plan written? Then: days without a guardia, guardias without backup (only if backup is normally used).
  const oncall = data.oncall || [];
  const planned = oncall.map(o => iso(o.duty_date)).filter(Boolean).sort();
  const plannedUntil = planned.length ? planned[planned.length - 1] : null;
  const hist = data.oncallHistory || [];
  const backupNormal = hist.length >= 10 && hist.filter(o => o.backup_physician_id).length / hist.length >= 0.5;
  if (!plannedUntil || plannedUntil < today) notes.push('No guardias are planned from today.');
  else if (plannedUntil < horizonEnd) notes.push(`Guardias are planned until ${plannedUntil}.`);
  const byDate = oncall.reduce((m, o) => { (m[iso(o.duty_date)] = m[iso(o.duty_date)] || []).push(o); return m; }, {});

  for (const w of weeks) {
    const from = w.start < today ? today : w.start;
    const push = (level, kind, text, unit = null) => w.signals.push({ level, kind, text, unit });

    if (plannedUntil && plannedUntil >= from) {
      const days = daysOf(from, w.end <= plannedUntil ? w.end : plannedUntil);
      const empty = days.filter(d => !(byDate[d] || []).some(o => o.primary_physician_id));
      if (empty.length) push('alert', 'oncall', `${plural(empty.length, 'day', 'days')} without a guardia assigned`);
      if (backupNormal) { const nob = days.filter(d => (byDate[d] || []).some(o => o.primary_physician_id) && !(byDate[d] || []).some(o => o.backup_physician_id)); if (nob.length) push('watch', 'oncall', `${plural(nob.length, 'guardia', 'guardias')} without backup`); }
    }
    if (plannedUntil && plannedUntil >= w.start && plannedUntil < w.end && plannedUntil >= today) push('watch', 'oncall', `Guardias planned only until ${plannedUntil}`);
    if ((!plannedUntil || plannedUntil < w.start) && w.start <= addDays(today, 21)) push('alert', 'oncall', 'Guardias not planned yet');

    // Absences: who is out; a unit left with nobody from its team on some working day.
    const out = absences.filter(a => overlaps(iso(a.start_date), iso(a.end_date), from, w.end));
    if (out.length) {
      const names = [...new Set(out.map(a => a.name || (data.staffNames || {})[String(a.staff_member_id)] || '—'))];
      push('info', 'absence', `${plural(names.length, 'person', 'people')} absent: ${names.slice(0, 4).join(', ')}${names.length > 4 ? '…' : ''}`);
    }
    for (const u of data.units || []) {
      const team = (u.roster || []).map(String); if (!team.length) continue;
      const working = daysOf(from, w.end).filter(d => { const k = new Date(d + 'T12:00:00Z').getUTCDay(); return k !== 0 && k !== 6; });
      const bare = working.filter(d => team.every(sid => out.some(a => String(a.staff_member_id) === sid && iso(a.start_date) <= d && iso(a.end_date) >= d)));
      if (bare.length) push('alert', 'coverage', `${u.unit_name}: nobody from the team on ${plural(bare.length, 'working day', 'working days')}`, u.id);
    }

    // Residents: over the unit's configured capacity; rotation changes (who starts / leaves).
    for (const u of data.units || []) {
      const here = live.filter(r => String(r.training_unit_id) === String(u.id) && overlaps(effStart(r), effEnd(r), from, w.end));
      const cap = Number(u.maximum_residents) || 0;
      if (cap) { const peak = Math.max(0, ...daysOf(from, w.end).map(d => here.filter(r => effStart(r) <= d && effEnd(r) >= d).length)); if (peak > cap) push('alert', 'capacity', `${u.unit_name}: ${peak} residents for ${plural(cap, 'place', 'places')}`, u.id); }
      const starts = here.filter(r => effStart(r) >= from && effStart(r) <= w.end), ends = here.filter(r => effEnd(r) >= from && effEnd(r) <= w.end);
      if (starts.length) push('info', 'rotation', `${u.unit_name}: ${starts.map(r => r.resident_name || 'resident').join(', ')} ${starts.length === 1 ? 'starts' : 'start'}`, u.id);
      if (ends.length) push('info', 'rotation', `${u.unit_name}: ${ends.map(r => r.resident_name || 'resident').join(', ')} ${ends.length === 1 ? 'finishes' : 'finish'}`, u.id);
    }

    // Sessions and seminars that week.
    const mt = (data.meetings || []).filter(m => iso(m.starts_at) >= from && iso(m.starts_at) <= w.end);
    if (mt.length) push('info', 'agenda', `${plural(mt.length, 'session', 'sessions')}: ${mt.slice(0, 3).map(m => m.title).join(', ')}${mt.length > 3 ? '…' : ''}`);
  }

  // Pending work: trend at the current pace; flagged only against a target the department set.
  const trends = [];
  for (const s of data.stocks || []) {
    const pts = (s.points || []).filter(p => p.value !== null && p.value !== undefined).sort((a, b) => iso(a.date).localeCompare(iso(b.date)));
    if (pts.length < 3) continue;
    const t0 = Date.parse(pts[0].date + 'T12:00:00Z'), xs = pts.map(p => (Date.parse(iso(p.date) + 'T12:00:00Z') - t0) / (7 * 86400000)), ys = pts.map(p => Number(p.value));
    const mx = xs.reduce((a, b) => a + b, 0) / xs.length, my = ys.reduce((a, b) => a + b, 0) / ys.length;
    const den = xs.reduce((a, x) => a + (x - mx) ** 2, 0); if (!den) continue;
    const slope = xs.reduce((a, x, i) => a + (x - mx) * (ys[i] - my), 0) / den;            // per week
    const last = pts[pts.length - 1], lastX = xs[xs.length - 1];
    const tr = { unit_id: s.unit_id, unit: s.unit_name, label: s.label, latest: Number(last.value), latest_date: iso(last.date), per_week: Math.round(slope * 10) / 10, crosses: null };
    if (s.target && s.target.value !== null && s.target.value !== undefined && slope) {
      const tv = Number(s.target.value), dir = s.target.direction || 'max';
      const bad = dir === 'max' ? slope > 0 && Number(last.value) <= tv : slope < 0 && Number(last.value) >= tv;
      if (bad) {
        const weeksTo = (tv - Number(last.value)) / slope, when = addDays(iso(last.date), Math.ceil(weeksTo * 7));
        if (when <= horizonEnd) {
          tr.crosses = when;
          const w = weeks.find(x => when >= x.start && when <= x.end) || weeks[0];
          w.signals.push({ level: 'watch', kind: 'trend', unit: s.unit_id, text: `${s.unit_name} · ${s.label}: at the current pace it would pass the target (${dir === 'max' ? '≤' : '≥'} ${tv}) around ${when}` });
        }
      } else if (dir === 'max' ? Number(last.value) > tv : Number(last.value) < tv) tr.off_target_now = true;
    }
    trends.push(tr);
  }

  const order = { alert: 0, watch: 1, info: 2 };
  for (const w of weeks) { w.signals.sort((a, b) => order[a.level] - order[b.level]); w.level = w.signals.some(s => s.level === 'alert') ? 'alert' : w.signals.some(s => s.level === 'watch') ? 'watch' : 'ok'; }
  return { today, weeks, trends, notes, planned_oncall_until: plannedUntil,
    summary: { alerts: weeks.reduce((n, w) => n + w.signals.filter(s => s.level === 'alert').length, 0), watch: weeks.reduce((n, w) => n + w.signals.filter(s => s.level === 'watch').length, 0) } };
}

module.exports = { buildOutlook, mondayOf, addDays };

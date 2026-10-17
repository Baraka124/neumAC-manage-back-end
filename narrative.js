'use strict';
/* Report narrative — plain words from a report snapshot (unit or department). Only what the numbers say:
   what rose, what fell, what to watch, what was not recorded. No interpretation of causes. */
const pct = v => (v > 0 ? '+' : '') + v + ' %';
const BIG = 10;   // a change of 10 % or more is worth a sentence; smaller ones are "stable"

function narrateUnit(c) {
  const rose = [], fell = [], watch = [], notes = [];
  for (const a of c.activity || []) {
    if (!a.recorded) { notes.push(`${a.label}: not recorded in this period`); continue; }
    if (a.change_pct !== null && a.change_pct !== undefined && a.previous > 0) {
      if (a.change_pct >= BIG) rose.push(`${a.label}: ${a.total} (${pct(a.change_pct)} vs ${a.previous})`);
      else if (a.change_pct <= -BIG) fell.push(`${a.label}: ${a.total} (${pct(a.change_pct)} vs ${a.previous})`);
    }
    if (a.breakdown && a.breakdown.length && a.total) { const top = a.breakdown[0]; if (top.count / a.total >= 0.4) notes.push(`${a.label}: ${top.label} was ${Math.round(100 * top.count / a.total)} %`); }
  }
  for (const p of c.pending || []) {
    if (!p.latest) continue;
    if (p.previous_value !== null && p.previous_value !== undefined && p.previous_value > 0) {
      const ch = Math.round(((p.latest.value - p.previous_value) / p.previous_value) * 1000) / 10;
      if (ch >= BIG) watch.push(`${p.label} grew to ${p.latest.value} (${pct(ch)})`);
      else if (ch <= -BIG) fell.push(`${p.label} down to ${p.latest.value} (${pct(ch)})`);
    }
    if (p.latest.oldest_days !== null && p.latest.oldest_days !== undefined && p.latest.oldest_days > 60) watch.push(`${p.label}: oldest waiting ${p.latest.oldest_days} days`);
  }
  const inc = c.incidents || {};
  if (inc.open_at_end) watch.push(`${inc.open_at_end} incident${inc.open_at_end === 1 ? '' : 's'} still open at the end`);
  const notMet = (c.indicators || []).filter(i => i.met === false), met = (c.indicators || []).filter(i => i.met === true);
  for (const i of notMet) watch.push(`Objective not met: ${i.name} (${i.value} vs ${i.direction === 'min' ? '≥' : '≤'} ${i.target})`);
  const headline = notMet.length ? `${notMet.length} objective${notMet.length === 1 ? '' : 's'} not met` : met.length ? 'All objectives with data met' : rose.length || fell.length ? 'Activity changed' : 'A stable period';
  return { headline, rose, fell, watch, notes };
}

function narrateDepartment(c) {
  const rose = [], fell = [], watch = [], notes = [];
  const ic = c.interconsults || {};
  if (ic.received_previous > 0) { const ch = Math.round(((ic.received - ic.received_previous) / ic.received_previous) * 1000) / 10; if (ch >= BIG) rose.push(`Interconsultas received: ${ic.received} (${pct(ch)})`); else if (ch <= -BIG) fell.push(`Interconsultas received: ${ic.received} (${pct(ch)})`); }
  if (ic.within_target_pct !== null && ic.within_target_pct !== undefined) (ic.within_target_pct < 80 ? watch : notes).push(`${ic.within_target_pct} % of interconsultas answered within target (median ${ic.median_hours} h)`);
  const calls = c.calls || {};
  if (calls.previous_total > 0) { const ch = Math.round(((calls.total - calls.previous_total) / calls.previous_total) * 1000) / 10; if (ch >= BIG) rose.push(`Calls from other services: ${calls.total} (${pct(ch)}, ${calls.minutes} min)`); else if (ch <= -BIG) fell.push(`Calls from other services: ${calls.total} (${pct(ch)})`); }
  else if (calls.total) notes.push(`${calls.total} calls from other services (${calls.minutes} min)`);
  for (const u of c.units || []) {
    if (u.indicators_not_met) watch.push(`${u.name}: ${u.indicators_not_met} objective${u.indicators_not_met === 1 ? '' : 's'} not met`);
    if (u.incidents_open) watch.push(`${u.name}: ${u.incidents_open} incident${u.incidents_open === 1 ? '' : 's'} open`);
    if (u.activity_measures && !u.activity_recorded) notes.push(`${u.name}: no activity recorded`);
  }
  const notMet = (c.indicators || []).filter(i => i.met === false);
  for (const i of notMet) watch.push(`Department objective not met: ${i.name}`);
  const headline = watch.length ? `${watch.length} thing${watch.length === 1 ? '' : 's'} to watch` : 'A stable period';
  return { headline, rose, fell, watch, notes };
}
const narrate = content => (content && content.kind === 'department' ? narrateDepartment(content) : narrateUnit(content || {}));
function narrativeText(n) {
  const L = [n.headline + '.'];
  if (n.rose.length) L.push('Rose: ' + n.rose.join('; ') + '.');
  if (n.fell.length) L.push('Fell: ' + n.fell.join('; ') + '.');
  if (n.watch.length) L.push('To watch: ' + n.watch.join('; ') + '.');
  if (n.notes.length) L.push('Notes: ' + n.notes.join('; ') + '.');
  return L.join(' ');
}
module.exports = { narrate, narrateUnit, narrateDepartment, narrativeText };

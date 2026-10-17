'use strict';
/* Imports (IM-1) — hospital activity counts into Ops measures. Pure: no database, no clock (today is passed in).
   A hospital system sends rows  key · date · value [· category]. A mapping turns (system, key) into a unit measure
   (and, for a measure with a breakdown, one category of it). Counts only: a file with a column that looks like a patient
   identifier is rejected whole. Manual values are never overwritten. */

const crypto = require('crypto');
const iso = d => (d ? String(d).slice(0, 10) : null);
const isIso = s => /^\d{4}-\d{2}-\d{2}$/.test(s || '') && !isNaN(Date.parse(s + 'T12:00:00Z')) && new Date(s + 'T12:00:00Z').toISOString().slice(0, 10) === s;

const MAX_ROWS = 5000, MAX_BYTES = 1024 * 1024;
const HEADERS = {
  key: ['key', 'clave', 'codigo', 'código', 'code', 'indicador', 'external_key'],
  date: ['date', 'fecha', 'dia', 'día', 'measured_on'],
  value: ['value', 'valor', 'n', 'count', 'numero', 'número', 'total', 'cantidad'],
  category: ['category', 'categoria', 'categoría', 'breakdown', 'grupo']
};
// Columns that would carry patient data. Matched on the normalised header, whole word.
const PATIENT_COLUMNS = ['nhc', 'historia', 'historia_clinica', 'nombre', 'name', 'apellido', 'apellidos', 'surname', 'paciente', 'patient',
  'dni', 'nie', 'nif', 'pasaporte', 'passport', 'sip', 'cip', 'tis', 'nuss', 'nass', 'naf', 'telefono', 'phone', 'email', 'direccion', 'address',
  'fecha_nacimiento', 'nacimiento', 'birth', 'dob', 'edad_exacta', 'episodio', 'episode', 'cama_paciente'];
const SYSTEM_RE = /^[a-z0-9_]{2,30}$/;
const KEY_RE = /^[A-Za-z0-9._:/-]{1,80}$/;

const norm = h => String(h || '').trim().toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

// CSV with , or ; (Spanish Excel), quotes, CRLF. Returns array of string arrays.
function splitCsv(text) {
  const src = String(text || '').replace(/^﻿/, '');
  const first = src.split(/\r?\n/, 1)[0] || '';
  const delim = (first.match(/;/g) || []).length > (first.match(/,/g) || []).length ? ';' : (first.includes('\t') && !first.includes(',') ? '\t' : ',');
  const rows = []; let row = [], cell = '', q = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (q) { if (c === '"') { if (src[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c; continue; }
    if (c === '"') q = true;
    else if (c === delim) { row.push(cell); cell = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && src[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; }
    else cell += c;
  }
  if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
  return { rows: rows.filter(r => r.some(x => String(x).trim() !== '')), delim };
}

// dd/mm/yyyy, d-m-yyyy or yyyy-mm-dd → ISO, else null.
function parseDate(s) {
  const t = String(s || '').trim();
  if (isIso(t.slice(0, 10)) && (t.length === 10 || /^\d{4}-\d{2}-\d{2}[ T]/.test(t))) return t.slice(0, 10);
  const m = t.match(/^(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})$/);
  if (m) { const d = `${m[3]}-${m[2].padStart(2, '0')}-${m[1].padStart(2, '0')}`; return isIso(d) ? d : null; }
  return null;
}

// text → { rows: [{ line, key, date, value, category }], errors, columns } or { error } for a file that cannot be used.
function parseFile(text) {
  if (!text || !String(text).trim()) return { error: 'The file is empty.' };
  if (Buffer.byteLength(String(text)) > MAX_BYTES) return { error: 'The file is larger than 1 MB. Split it by month.' };
  const { rows } = splitCsv(text);
  if (rows.length < 2) return { error: 'The file needs a header row and at least one data row.' };
  const head = rows[0].map(norm);
  const patient = head.filter(h => PATIENT_COLUMNS.includes(h) || PATIENT_COLUMNS.some(p => h.startsWith(p + '_') || h.endsWith('_' + p)));
  if (patient.length) return { error: `This file has a column that may contain patient data (${patient.join(', ')}). Only counts may be imported: remove that column and try again.`, patient_columns: patient };
  const col = {};
  for (const [k, names] of Object.entries(HEADERS)) { const i = head.findIndex(h => names.map(norm).includes(h)); if (i >= 0) col[k] = i; }
  const missing = ['key', 'date', 'value'].filter(k => col[k] === undefined);
  if (missing.length) return { error: `Missing column(s): ${missing.join(', ')}. Expected headers: key (clave/código), date (fecha), value (valor), and optionally category (categoría).` };
  const extra = head.filter((h, i) => !Object.values(col).includes(i) && h);
  if (rows.length - 1 > MAX_ROWS) return { error: `More than ${MAX_ROWS} rows. Split the file.` };
  const out = [];
  for (let r = 1; r < rows.length; r++) {
    const cell = k => (col[k] === undefined ? '' : String(rows[r][col[k]] ?? '').trim());
    out.push({ line: r + 1, key: cell('key'), date: cell('date'), value: cell('value'), category: cell('category') || null });
  }
  return { rows: out, errors: [], columns: { used: Object.keys(col), ignored: extra } };
}

// Feed JSON rows → same shape as parseFile rows.
function fromFeed(rows) {
  if (!Array.isArray(rows) || !rows.length) return { error: 'rows must be a non-empty array.' };
  if (rows.length > MAX_ROWS) return { error: `More than ${MAX_ROWS} rows.` };
  const bad = new Set(); for (const r of rows) for (const k of Object.keys(r || {})) { const h = norm(k); if (PATIENT_COLUMNS.includes(h)) bad.add(h); }
  if (bad.size) return { error: `Rows have fields that may contain patient data (${[...bad].join(', ')}). Only counts may be sent.`, patient_columns: [...bad] };
  return { rows: rows.map((r, i) => ({ line: i + 1, key: String(r?.key ?? '').trim(), date: String(r?.date ?? '').trim(), value: String(r?.value ?? '').trim(), category: r?.category ? String(r.category).trim() : null })), errors: [] };
}

function validateMapping(body, { partial = false } = {}) {
  const v = {};
  if (!partial || body.system !== undefined) { const s = String(body.system || '').trim().toLowerCase(); if (!SYSTEM_RE.test(s)) return { error: 'System: 2–30 lowercase letters, digits or _ (e.g. his, cex_agenda).' }; v.system = s; }
  if (!partial || body.external_key !== undefined) { const k = String(body.external_key || '').trim(); if (!KEY_RE.test(k)) return { error: 'Hospital key: 1–80 characters (letters, digits, . _ : / -).' }; v.external_key = k; }
  if (!partial || body.unit_id !== undefined) { if (!body.unit_id) return { error: 'Choose the unit.' }; v.unit_id = String(body.unit_id); }
  if (!partial || body.type_id !== undefined) { if (!body.type_id) return { error: 'Choose the measure.' }; v.type_id = String(body.type_id); }
  if (body.category_code !== undefined) { const c = body.category_code ? String(body.category_code).trim() : null; if (c && !/^[a-z0-9_]{1,40}$/.test(c)) return { error: 'Invalid category.' }; v.category_code = c; }
  if (body.active !== undefined) v.active = !!body.active;
  if (body.note !== undefined) v.note = body.note ? String(body.note).slice(0, 200) : null;
  return { value: v };
}

const sortObj = o => (o ? Object.fromEntries(Object.entries(o).filter(([, n]) => Number(n) > 0).sort(([a], [b]) => a.localeCompare(b))) : null);
const sameBreakdown = (a, b) => JSON.stringify(sortObj(a) || {}) === JSON.stringify(sortObj(b) || {});

/* Plan an import.
   rows: from parseFile/fromFeed · system · today
   mappings: [{ system, external_key, unit_id, type_id, category_code, active }]
   types: { id: { id, unit_id, label, kind, active, breakdown (catalogue name or null) } }
   categories: { catalogueName: [codes] }
   existing: [{ id, type_id, measured_on, value, breakdown, source }] for the touched types and dates
   → { errors, writes: [{ unit_id, type_id, measured_on, value, breakdown }], plan, checksum } */
function planImport({ rows, system, today, mappings, types, categories = {}, existing = [] }) {
  const errors = [], byKey = {};
  for (const m of mappings || []) if (m.active !== false && m.system === system) byKey[m.external_key] = m;
  const groups = new Map();   // type|date → { type, date, value, breakdown, lines }
  const unknownKeys = new Set();
  for (const r of rows) {
    const m = byKey[r.key];
    if (!r.key) { errors.push({ line: r.line, error: 'Empty key.' }); continue; }
    if (!m) { unknownKeys.add(r.key); errors.push({ line: r.line, error: `No mapping for key “${r.key}”.` }); continue; }
    const t = types[String(m.type_id)];
    if (!t || t.active === false) { errors.push({ line: r.line, error: `The measure mapped to “${r.key}” is switched off.` }); continue; }
    const date = parseDate(r.date);
    if (!date) { errors.push({ line: r.line, error: `Invalid date “${r.date}” (use YYYY-MM-DD or DD/MM/YYYY).` }); continue; }
    if (date > today) { errors.push({ line: r.line, error: 'Future dates cannot be imported.' }); continue; }
    const n = Number(String(r.value).replace(/\s/g, ''));
    if (!Number.isInteger(n) || n < 0 || n > 100000) { errors.push({ line: r.line, error: `Value “${r.value}” must be a whole number from 0.` }); continue; }
    const cat = m.category_code || r.category || null;
    if (t.breakdown) {
      const allowed = categories[t.breakdown] || [];
      if (!cat) { errors.push({ line: r.line, error: `“${t.label}” is counted by category: map the key to a category or add a category column.` }); continue; }
      if (allowed.length && !allowed.includes(cat)) { errors.push({ line: r.line, error: `Unknown category “${cat}” for “${t.label}”.` }); continue; }
    }
    const gk = `${t.id}|${date}`;
    const g = groups.get(gk) || { unit_id: String(t.unit_id), type_id: String(t.id), measured_on: date, value: 0, breakdown: t.breakdown ? {} : null, lines: [], kind: t.kind, label: t.label };
    if (t.breakdown) g.breakdown[cat] = (g.breakdown[cat] || 0) + n;
    if (!t.breakdown && g.lines.length && t.kind === 'stock') { errors.push({ line: r.line, error: `Two snapshots for “${t.label}” on ${date}.` }); continue; }
    g.value += n; g.lines.push(r.line); groups.set(gk, g);
  }
  const exist = new Map((existing || []).map(e => [`${e.type_id}|${iso(e.measured_on)}`, e]));
  const plan = { insert: 0, update: 0, unchanged: 0, manual_kept: [] }, writes = [];
  for (const [k, g] of groups) {
    const e = exist.get(k);
    if (e && (e.source || 'manual') === 'manual') { plan.manual_kept.push({ label: g.label, date: g.measured_on, manual: e.value, file: g.value }); continue; }
    if (e && Number(e.value) === g.value && sameBreakdown(e.breakdown, g.breakdown)) { plan.unchanged++; continue; }
    plan[e ? 'update' : 'insert']++;
    writes.push({ unit_id: g.unit_id, type_id: g.type_id, measured_on: g.measured_on, value: g.value, breakdown: g.breakdown ? sortObj(g.breakdown) : null });
  }
  writes.sort((a, b) => (a.type_id + a.measured_on).localeCompare(b.type_id + b.measured_on));
  const dates = [...groups.values()].map(g => g.measured_on).sort();
  // Same content → same checksum whatever the row order or file format (idempotent re-sends).
  const checksum = sha256(system + '\n' + [...groups.values()].map(g => `${g.type_id}|${g.measured_on}|${g.value}|${JSON.stringify(sortObj(g.breakdown))}`).sort().join('\n'));
  return { errors, unknown_keys: [...unknownKeys], writes, plan, checksum, rows: rows.length, groups: groups.size,
    range: dates.length ? { from: dates[0], to: dates[dates.length - 1] } : null };
}

// Constant-time token check for the feed.
function tokenOk(given, expected) {
  if (!expected || !given) return false;
  const a = Buffer.from(sha256(String(given))), b = Buffer.from(sha256(String(expected)));
  return crypto.timingSafeEqual(a, b);
}

module.exports = { MAX_ROWS, MAX_BYTES, PATIENT_COLUMNS, splitCsv, parseDate, parseFile, fromFeed, validateMapping, planImport, tokenOk, sameBreakdown, norm };

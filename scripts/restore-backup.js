#!/usr/bin/env node
'use strict';
/* Restore an Ops + Comms backup made by neumDesk (Configuración → Estado del sistema → Back up now, or the nightly job).

   node scripts/restore-backup.js <file.json.gz>                     dry run: what is in the file vs the database now
   node scripts/restore-backup.js <file.json.gz> --apply             upsert every row by id (adds missing, puts back changed)
   node scripts/restore-backup.js <file.json.gz> --apply --tables ops_measurements,ops_reports

   Needs SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in the environment (the same values as Railway).
   Never deletes: rows created after the backup stay. Practise it on a Supabase branch first (see PILOT.md §4). */

const fs = require('fs');
const zlib = require('zlib');
const { createClient } = require('@supabase/supabase-js');
const { BACKUP_TABLES } = require('../health.js');

async function main() {
  const args = process.argv.slice(2);
  const file = args.find(a => !a.startsWith('--'));
  const apply = args.includes('--apply');
  const only = (args[args.indexOf('--tables') + 1] && args.includes('--tables')) ? args[args.indexOf('--tables') + 1].split(',') : null;
  if (!file) { console.error('Usage: node scripts/restore-backup.js <file.json.gz> [--apply] [--tables a,b]'); process.exit(2); }
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) { console.error('Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.'); process.exit(2); }

  const raw = fs.readFileSync(file);
  const dump = JSON.parse((file.endsWith('.gz') ? zlib.gunzipSync(raw) : raw).toString('utf8'));
  if (dump?.meta?.kind !== 'neumdesk-ops-comms') { console.error('Not a neumDesk Ops + Comms backup.'); process.exit(2); }
  console.log(`Backup from ${dump.meta.created_at} (release ${dump.meta.release || '—'}, ${dump.meta.trigger})`);
  console.log(apply ? 'MODE: APPLY (upsert by id, never deletes)\n' : 'MODE: dry run (nothing is written; add --apply)\n');

  const db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
  const order = BACKUP_TABLES.filter(t => dump.tables[t] && (!only || only.includes(t)));
  let problems = 0;
  for (const t of order) {
    const rows = dump.tables[t];
    const { count, error } = await db.from(t).select('*', { head: true, count: 'exact' });
    if (error) { console.log(`${t.padEnd(26)} ✗ ${error.message}`); problems++; continue; }
    let line = `${t.padEnd(26)} backup ${String(rows.length).padStart(6)} · now ${String(count).padStart(6)}`;
    if (apply && rows.length) {
      let done = 0;
      for (let i = 0; i < rows.length; i += 500) {
        const { error: e } = await db.from(t).upsert(rows.slice(i, i + 500), { onConflict: 'id' });
        if (e) { line += ` · ✗ at row ${i}: ${e.message}`; problems++; break; }
        done += Math.min(500, rows.length - i);
      }
      line += ` · restored ${done}`;
    }
    console.log(line);
  }
  console.log(problems ? `\n${problems} table(s) with problems.` : '\nDone.');
  process.exit(problems ? 1 : 0);
}
main().catch(e => { console.error(e.message); process.exit(1); });

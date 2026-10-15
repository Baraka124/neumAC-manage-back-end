'use strict';

// Phase 43B: read-only, on-demand research history for the authenticated
// staff member. Never substitute a department-wide portfolio for a personal
// record. Completed and interrupted studies are distinct clinical lifecycles.
const DONE_STUDY_STATES = Object.freeze([
  'Completado', 'Finalizado',
  'completed', 'finished', 'finalized'
]);
const PAGE_MAX = 20;
const PAGE_NUMBER_MAX = 100;

function parseRequest(query) {
  const kind = String(query?.kind || 'studies');
  if (!['studies', 'projects'].includes(kind)) return { error: 'invalid kind' };
  const pageText = String(query?.page ?? '1');
  const limitText = String(query?.limit ?? '10');
  if (!/^[1-9]\d*$/.test(pageText) || !/^[1-9]\d*$/.test(limitText)) return { error: 'invalid pagination' };
  const page = Number(pageText), limit = Number(limitText);
  if (!Number.isSafeInteger(page) || !Number.isSafeInteger(limit) ||
    page > PAGE_NUMBER_MAX || limit > PAGE_MAX) return { error: 'pagination outside bounds' };
  return { kind, page, limit };
}

const includesPerson = (list, sid) => Array.isArray(list) && list.includes(sid);

function normalizeItems(kind, rows, sid) {
  return rows.flatMap(row => {
    if (!row || typeof row !== 'object' || !row.id || !row.title) return [];
    if (kind === 'studies') {
      const pi = row.principal_investigator_id === sid;
      const coinv = includesPerson(row.co_investigators, sid);
      const subinv = includesPerson(row.sub_investigators, sid);
      if (!pi && !coinv && !subinv || !DONE_STUDY_STATES.includes(row.status)) return [];
      return [{
        id: row.id, kind: 'study', title: row.title,
        protocol_id: row.protocol_id || null,
        status: row.status, lifecycle: 'completed',
        role: pi ? 'PI' : coinv ? 'co-investigator' : 'sub-investigator'
      }];
    }
    const lead = row.lead_investigator_id === sid;
    const coinv = includesPerson(row.co_investigators, sid);
    if (!lead && !coinv || row.current_stage !== 'completed') return [];
    return [{
      id: row.id, kind: 'project', title: row.title,
      category: row.category || null,
      stage: row.current_stage, lifecycle: 'completed',
      role: lead ? 'lead' : 'co-investigator'
    }];
  });
}

function queryHistory(supabase, sid, opts) {
  const { kind, page, limit } = opts;
  // Application JWT is the only source of staff identity. The client may not
  // choose a staff/department or provide arbitrary PostgREST filter fields.
  if (typeof sid !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(sid)) {
    throw new Error('Invalid linked professional identifier');
  }
  const offset = (page - 1) * limit;
  let query;
  if (kind === 'studies') {
    query = supabase.from('clinical_trials')
      .select('id, title, protocol_id, status, principal_investigator_id, co_investigators, sub_investigators')
      .in('status', DONE_STUDY_STATES)
      .or(`principal_investigator_id.eq.${sid},co_investigators.cs.{${sid}},sub_investigators.cs.{${sid}}`);
  } else {
    query = supabase.from('innovation_projects')
      .select('id, title, current_stage, category, lead_investigator_id, co_investigators')
      .eq('current_stage', 'completed')
      .or(`lead_investigator_id.eq.${sid},co_investigators.cs.{${sid}}`);
  }
  // Fetch one extra to derive has_more without an expensive total count.
  // Stable tie-break by record id; never trust UI ordering as provenance.
  return query.order('updated_at', { ascending: false })
    .order('id', { ascending: true })
    .range(offset, offset + limit);
}

async function getHistoryPage(supabase, sid, opts) {
  const result = await queryHistory(supabase, sid, opts);
  if (!result || result.error || !Array.isArray(result.data)) {
    const error = new Error('Source temporarily unavailable');
    error.code = 'MI_ESPACIO_SOURCE_UNAVAILABLE';
    throw error;
  }
  const has_more = result.data.length > opts.limit;
  const items = normalizeItems(opts.kind, result.data.slice(0, opts.limit), sid);
  // The query is already identity-scoped; if malformed/unexpected rows appear,
  // fail closed instead of returning an incomplete "empty history" assertion.
  if (items.length !== Math.min(opts.limit, result.data.length)) {
    const error = new Error('History source did not match the personal contract');
    error.code = 'MI_ESPACIO_SOURCE_UNAVAILABLE';
    throw error;
  }
  return {
    kind: opts.kind, scope: 'own', coverage: 'completed_only',
    items, pagination: {
      page: opts.page, limit: opts.limit, has_more,
      next_page: has_more ? opts.page + 1 : null
    }
  };
}

module.exports = {
  DONE_STUDY_STATES, PAGE_MAX, parseRequest, normalizeItems,
  queryHistory, getHistoryPage
};

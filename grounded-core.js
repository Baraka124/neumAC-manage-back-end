(function(root, factory){
  const api = factory()
  if (typeof module === 'object' && module.exports) module.exports = api
  if (root) root.neumGroundedCore = api
})(typeof window !== 'undefined' ? window : globalThis, function(){
  'use strict'

  const VERSION = '46.11'
  const ACCESS = Object.freeze({ READ:'read', PROPOSE:'propose', WRITE:'write' })
  const TRACE_KEY = 'neumdesk:grounded:traces:v4611'
  const TRACE_LIMIT = 80
  const SESSION_MEMORY_KEY = 'neumdesk:grounded:session:v4611'

  const nowIso = () => new Date().toISOString()
  const makeId = (prefix='gr') => `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2,9)}`
  const elapsedMs = (a,b) => Math.max(0, Math.round((b||Date.now())-(a||Date.now())))

  const storage = () => {
    try { return typeof sessionStorage !== 'undefined' ? sessionStorage : null } catch { return null }
  }

  // Observability intentionally stores operational metadata only. It never records
  // hidden chain-of-thought, raw model reasoning, passwords, tokens or full records.
  const sanitize = (value, depth=0) => {
    if (depth > 4) return '[trimmed]'
    if (value === null || value === undefined) return value
    if (typeof value === 'string') return value.length > 240 ? value.slice(0,237)+'…' : value
    if (typeof value === 'number' || typeof value === 'boolean') return value
    if (Array.isArray(value)) return value.slice(0,16).map(v=>sanitize(v,depth+1))
    if (typeof value === 'object') {
      const out = {}
      for (const [k,v] of Object.entries(value)) {
        if (/password|token|secret|authorization|cookie/i.test(k)) continue
        out[k] = sanitize(v,depth+1)
      }
      return out
    }
    return String(value)
  }

  const readTraces = () => {
    try { return JSON.parse(storage()?.getItem(TRACE_KEY) || '[]') || [] } catch { return [] }
  }
  const writeTraces = (rows) => {
    try { storage()?.setItem(TRACE_KEY, JSON.stringify((rows||[]).slice(0,TRACE_LIMIT))) } catch {}
  }
  const getTrace = (traceId) => readTraces().find(t=>t.id===traceId) || null
  const mutateTrace = (traceId, fn) => {
    const rows = readTraces(); const i = rows.findIndex(t=>t.id===traceId)
    if (i < 0) return null
    fn(rows[i]); rows[i].updatedAt = nowIso(); writeTraces(rows); return rows[i]
  }

  const startTrace = (meta={}) => {
    const startedMs = Date.now()
    const trace = {
      id: makeId('gr'), version: VERSION, startedAt: nowIso(), startedMs,
      status: 'running', query: sanitize(meta.query || ''), intent: meta.intent || null,
      view: meta.view || null, context: sanitize(meta.context || null), userRole: meta.userRole || null,
      events: [], tools: [], outcome: null, durationMs: null
    }
    const rows = readTraces(); rows.unshift(trace); writeTraces(rows)
    return trace.id
  }

  const addTraceEvent = (traceId, type, data={}) => mutateTrace(traceId, t => {
    t.events.push({ at:nowIso(), type, data:sanitize(data) })
    if (t.events.length > 40) t.events = t.events.slice(-40)
  })

  const finishTrace = (traceId, outcome={}) => mutateTrace(traceId, t => {
    const ended = Date.now()
    t.status = outcome.status || 'ok'
    t.durationMs = elapsedMs(t.startedMs, ended)
    t.outcome = sanitize({
      intent: outcome.intent || t.intent || null,
      confidence: outcome.confidence || null,
      sources: outcome.sources || [],
      emptyState: !!outcome.emptyState,
      error: outcome.error || null,
      actionClass: outcome.actionClass || 'read'
    })
    delete t.startedMs
  })

  const recentTraces = (limit=30) => readTraces().slice(0,Math.max(1,Math.min(TRACE_LIMIT,limit)))
  const clearTraces = () => { try { storage()?.removeItem(TRACE_KEY) } catch {} }

  // Context engineering contract: the model/tool layer receives compact task context,
  // not the entire application state. Additional module adapters can extend `module`.
  const buildContextEnvelope = (input={}) => ({
    schema: 'grounded.context.v1',
    capturedAt: nowIso(),
    view: input.view || null,
    lens: input.lens || null,
    subject: sanitize(input.subject || null),
    timeScope: sanitize(input.timeScope || null),
    user: sanitize(input.user || null),
    permissions: sanitize(input.permissions || []),
    sourceHealth: sanitize(input.sourceHealth || []),
    module: sanitize(input.module || null)
  })

  // Memory policy: only short-lived task/session context is stored here. Hospital facts,
  // patient facts and authoritative operational records remain in source systems.
  const readSessionMemory = () => {
    try { return JSON.parse(storage()?.getItem(SESSION_MEMORY_KEY) || '{}') || {} } catch { return {} }
  }
  const setSessionMemory = (key, value) => {
    const mem = readSessionMemory(); mem[key] = sanitize(value); mem.updatedAt = nowIso()
    try { storage()?.setItem(SESSION_MEMORY_KEY, JSON.stringify(mem)) } catch {}
    return mem[key]
  }
  const getSessionMemory = (key) => readSessionMemory()[key]
  const clearSessionMemory = () => { try { storage()?.removeItem(SESSION_MEMORY_KEY) } catch {} }

  const createToolRegistry = ({ permissionCheck }={}) => {
    const defs = new Map()
    const register = (def) => {
      if (!def || !def.name || typeof def.run !== 'function') throw new Error('Grounded tool needs name + run()')
      defs.set(def.name, Object.freeze({
        description:'', access:ACCESS.READ, module:null, inputSchema:null, ...def
      }))
      return defs.get(def.name)
    }
    const list = () => Array.from(defs.values()).map(({run,...d})=>d)
    const get = (name) => defs.get(name) || null
    const invoke = (name, input={}, opts={}) => {
      const def = defs.get(name)
      if (!def) { const e=new Error(`Unknown Grounded tool: ${name}`); e.code='GROUND_TOOL_NOT_FOUND'; throw e }
      const requested = def.access || ACCESS.READ
      const permissionAction = requested === ACCESS.WRITE ? 'write' : 'read'
      if (def.module && typeof permissionCheck === 'function' && !permissionCheck(def.module, permissionAction)) {
        const e = new Error(`Permission denied for ${name}`); e.code='GROUND_PERMISSION_DENIED'
        if (opts.traceId) addTraceEvent(opts.traceId,'tool_blocked',{tool:name,module:def.module,access:requested})
        throw e
      }
      if (requested === ACCESS.WRITE && opts.confirmed !== true) {
        const e = new Error(`Human confirmation required for ${name}`); e.code='GROUND_CONFIRMATION_REQUIRED'
        if (opts.traceId) addTraceEvent(opts.traceId,'tool_blocked',{tool:name,reason:'confirmation_required'})
        throw e
      }
      const started = Date.now()
      if (opts.traceId) addTraceEvent(opts.traceId,'tool_start',{tool:name,access:requested,module:def.module,input:sanitize(input)})
      try {
        const result = def.run(input, opts)
        if (result && typeof result.then === 'function') {
          return result.then(out=>{
            if(opts.traceId) addTraceEvent(opts.traceId,'tool_end',{tool:name,durationMs:elapsedMs(started),status:'ok',result:sanitize(out)})
            return out
          }).catch(err=>{
            if(opts.traceId) addTraceEvent(opts.traceId,'tool_end',{tool:name,durationMs:elapsedMs(started),status:'error',error:err?.message||String(err)})
            throw err
          })
        }
        if(opts.traceId) addTraceEvent(opts.traceId,'tool_end',{tool:name,durationMs:elapsedMs(started),status:'ok',result:sanitize(result)})
        return result
      } catch (err) {
        if(opts.traceId) addTraceEvent(opts.traceId,'tool_end',{tool:name,durationMs:elapsedMs(started),status:'error',error:err?.message||String(err)})
        throw err
      }
    }
    return { register, list, get, invoke }
  }

  // Bounded orchestration primitive. Current Grounded is deterministic; this provides
  // the execution contract for future planners without introducing autonomous looping.
  const runBoundedPlan = async ({ steps=[], maxSteps=6, context={}, traceId=null }={}) => {
    const results=[]; const cap=Math.max(1,Math.min(12,maxSteps))
    for (let i=0;i<Math.min(steps.length,cap);i++) {
      const step=steps[i]
      if (traceId) addTraceEvent(traceId,'plan_step_start',{index:i,label:step.label||step.name||`step ${i+1}`})
      const out = await step.run({ context, results })
      results.push(out)
      if (traceId) addTraceEvent(traceId,'plan_step_end',{index:i,stop:!!out?.stop,status:out?.status||'ok'})
      if (out?.stop) break
    }
    return results
  }

  const actionPolicy = Object.freeze({
    canAutoExecute(access){ return access === ACCESS.READ },
    requiresConfirmation(access){ return access === ACCESS.WRITE },
    mayPropose(access){ return access === ACCESS.READ || access === ACCESS.PROPOSE || access === ACCESS.WRITE }
  })

  const evaluateTrace = (trace) => {
    const issues=[]
    if (!trace) return { ok:false, issues:['trace_missing'] }
    const events=trace.events||[]
    const failed=events.filter(e=>e.type==='tool_end' && e.data?.status==='error')
    if(failed.length) issues.push('tool_failure')
    if(trace.status==='error') issues.push('run_error')
    const writeStart=events.find(e=>e.type==='tool_start' && e.data?.access===ACCESS.WRITE)
    const confirmed=events.find(e=>e.type==='human_confirmation')
    if(writeStart && !confirmed) issues.push('write_without_confirmation_trace')
    return { ok:issues.length===0, issues }
  }

  return {
    VERSION, ACCESS, startTrace, addTraceEvent, finishTrace, recentTraces, clearTraces, getTrace,
    buildContextEnvelope, createToolRegistry, runBoundedPlan, actionPolicy, evaluateTrace,
    sessionMemory:{ set:setSessionMemory, get:getSessionMemory, read:readSessionMemory, clear:clearSessionMemory }
  }
})

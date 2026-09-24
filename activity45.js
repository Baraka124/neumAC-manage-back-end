/* neumDesk V46.14. Deterministic Portfolio Intelligence projection + formal document renderer. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Activity45 = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const escape = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const same = (a,b) => a != null && b != null && String(a) !== '' && String(a) === String(b);
  const list = v => {
    if (Array.isArray(v)) return v;
    if (!v) return [];
    if (typeof v !== 'string') return [];
    try { const a=JSON.parse(v); if(Array.isArray(a)) return a; } catch (_) {}
    return v.split(/[,;]/).map(x=>x.trim()).filter(Boolean);
  };
  const date = v => {
    const s=String(v || '').slice(0,10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return '';
    const d=new Date(s+'T00:00:00Z');
    return Number.isFinite(+d) && d.toISOString().slice(0,10)===s ? s : '';
  };
  const addDay = (s,n=1) => { const d=new Date(s+'T00:00:00Z'); d.setUTCDate(d.getUTCDate()+n); return d.toISOString().slice(0,10); };
  const overlaps = (a,b,start,end) => !!(a&&b&&start&&end&&a<=end&&b>=start);
  const pretty = s => date(s) ? new Date(date(s)+'T00:00:00Z').toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric',timeZone:'UTC'}) : 'Not recorded';
  const nice = s => String(s || 'Not recorded').replace(/_/g,' ');
  const specs = [
    {key:'staff',label:'Staff directory',module:'medical_staff',path:'/api/medical-staff?limit=500&employment_status=all'},
    {key:'oncall',label:'On-call duties',module:'oncall_schedule',path:'/api/oncall'},
    {key:'rotations',label:'Rotations',module:'resident_rotations',path:'/api/rotations?limit=500'},
    {key:'units',label:'Clinical units',module:'training_units',path:'/api/training-units'},
    {key:'studies',label:'Research studies',module:'clinical_trials',path:'/api/clinical-trials?limit=500'},
    {key:'projects',label:'Innovation projects',module:'innovation_projects',path:'/api/innovation-projects?limit=500'},
    {key:'lines',label:'Research programmes',module:'research_lines',path:'/api/research-lines'}
  ];
  async function fetchRows(request,path,signal) {
    const rows=[]; const seen=new Set();
    for(let page=1;page<=100;page++) {
      const response=await request(path+(page>1?(path.includes('?')?'&':'?')+'page='+page:''),{skipCache:true,signal});
      const batch=Array.isArray(response)?response:response?.data;
      if(!Array.isArray(batch)||response?.success===false) throw Error('Invalid source response');
      for(const r of batch) {
        if(!r || typeof r!=='object' || Array.isArray(r) || r.id == null) throw Error('Invalid record');
        if(seen.has(String(r.id))) throw Error('Repeated record in source pages');
        seen.add(String(r.id)); rows.push(r);
      }
      if(!response?.pagination) {
        if(rows.length>=1000) throw Error('Unpaginated source may have reached its record cap');
        return rows;
      }
      const total=Number(response.pagination.total);
      if(!Number.isFinite(total)||total<0) throw Error('Invalid pagination');
      if(rows.length>=total) return rows;
      if(!batch.length) throw Error('Incomplete source');
    }
    throw Error('Source verification limit reached');
  }
  async function load(request,allowed,signal,scope={}) {
    const results=await Promise.all(specs.map(async s=>{
      if(scope.directoryOnly && s.key!=='staff') return [s.key,{state:'not included',rows:[],label:s.label}];
      if(scope.selected && s.key!=='staff' && !scope.selected[s.key] && !(s.key==='units'&&scope.selected.rotations)) return [s.key,{state:'not included',rows:[],label:s.label}];
      if(!allowed(s.module,'read')) return [s.key,{state:'restricted',rows:[],label:s.label}];
      const path=s.key==='oncall'&&scope.personId ? s.path+'?physician_id='+encodeURIComponent(scope.personId)+'&start_date='+encodeURIComponent(scope.start)+'&end_date='+encodeURIComponent(scope.end) : s.path;
      try {
        let sourceRows, notes=[];
        if(s.key==='rotations') {
          // The normal rotations endpoint deliberately omits soft-terminated records.
          // Personal Activity needs them for truthful historical relationships, so retrieve
          // both populations and merge by id. A terminated record is never treated as a
          // completed calendar span unless an explicit actual termination date exists.
          const current=await fetchRows(request,path,signal);
          const terminated=await fetchRows(request,'/api/rotations?limit=500&rotation_status=terminated_early',signal);
          const merged=new Map(); [...current,...terminated].forEach(r=>merged.set(String(r.id),r));
          sourceRows=[...merged.values()];
          notes.push(`${terminated.length} soft-terminated rotation record${terminated.length===1?'':'s'} retrieved separately`);
        } else sourceRows=await fetchRows(request,path,signal);
        return [s.key,{state:'ready',rows:sourceRows.filter(r=>!r.deleted_at),label:s.label,checkedAt:new Date().toISOString(),notes}];
      }
      catch (err) { return [s.key,{state:'unavailable',rows:[],label:s.label,error:err?.message||'Source unavailable'}]; }
    }));
    return Object.fromEntries(results);
  }
  async function snapshot(request,allowed,personId,start,end,selected={oncall:true,rotations:true,studies:true,projects:true,lines:true},signal=null) {
    const sources=await load(request,allowed,signal,{personId,start,end,selected});
    if(sources.staff?.state!=='ready') throw Error('The staff directory could not be retrieved with your current access.');
    const person=(sources.staff.rows||[]).find(p=>same(p.id,personId));
    if(!person) throw Error('This person is not available in the accessible staff directory.');
    return build(person,start,end,sources,selected);
  }
  function build(person,start,end,sources,selected={oncall:true,rotations:true,studies:true,projects:true,lines:true}) {
    start=date(start); end=date(end);
    if(!person?.id) throw Error('Select a staff member.');
    if(!start||!end||end<start) throw Error('Choose a valid start and end date.');
    if((new Date(end)-new Date(start))/86400000>365) throw Error('Choose a period of up to 366 days.');
    const rows=k=>sources[k]?.state==='ready' ? sources[k].rows : [];
    const model={person:{id:String(person.id),name:person.full_name||'Unnamed staff member',role:nice(person.staff_type)},start,end,generatedAt:new Date().toISOString(),events:[],studies:[],projects:[],lines:[],supervision:[],residentAssignments:[],issues:[],sources:[],selected:{...selected}};
    const includeKeys=['staff',...Object.keys(selected).filter(k=>selected[k]),...(selected.rotations?['units']:[])];
    model.sources=specs.filter(s=>includeKeys.includes(s.key)).map(s=>({key:s.key,label:s.label,state:sources[s.key]?.state||'unavailable',checkedAt:sources[s.key]?.checkedAt||null,notes:sources[s.key]?.notes||[],error:sources[s.key]?.error||null}));
    const unitName=id=>rows('units').find(u=>same(u.id,id))?.unit_name || 'Clinical unit not available';
    const lineName=id=>rows('lines').find(l=>same(l.id,id))?.name || rows('lines').find(l=>same(l.id,id))?.research_line_name || '';
    const staffName=id=>rows('staff').find(x=>same(x.id,id))?.full_name || 'Staff member not available';
    function event(r,kind,title,role,s,e,detail) {
      const from=date(s),to=date(e)||from;
      if(!from||to<from) { model.issues.push(`${title}: missing or invalid dates; not placed on the calendar.`); return; }
      if(from>end||to<start) return;
      model.events.push({kind,title,role,start:from,end:to,detail:detail||'',ref:String(r.id),source:kind==='oncall'?'On-call duties':kind==='rotation'?'Rotations':kind==='study'?'Research studies':'Innovation projects',sourceKey:kind==='oncall'?'oncall':kind==='rotation'?'rotations':kind==='study'?'studies':'projects',evidenceKind:(kind==='study'||kind==='project')?'shared':'person'});
    }
    if(selected.oncall) rows('oncall').filter(r=>!['cancelled','canceled'].includes(String(r.status||'').toLowerCase())).forEach(r=>{
      const roles=[]; if(same(r.primary_physician_id,person.id)) roles.push('Primary'); if(same(r.backup_physician_id,person.id)) roles.push('Backup');
      if(roles.length) event(r,'oncall','On-call duty',roles.join(' · '),r.duty_date,r.duty_date,[nice(r.shift_type),r.start_time&&r.end_time?`${r.start_time}–${r.end_time} (recorded local time)`:'Duty time not recorded'].join(' · '));
    });
    if(selected.rotations) rows('rotations').filter(r=>!['cancelled','canceled'].includes(String(r.rotation_status||'').toLowerCase())).forEach(r=>{
      const roles=[]; if(same(r.resident_id,person.id)) roles.push('Resident'); if(same(r.supervising_attending_id,person.id)) roles.push('Supervisor');
      if(!roles.length) return;
      const rawStart=r.start_date||r.rotation_start_date, rawPlannedEnd=r.end_date||r.rotation_end_date;
      const s=date(rawStart), plannedEnd=date(rawPlannedEnd);
      const explicitTermination=date(r.actual_end_date||r.termination_date||r.terminated_date);
      const unit=unitName(r.training_unit_id), status=nice(r.rotation_status);
      const terminated=String(r.rotation_status||'').toLowerCase()==='terminated_early';
      if(terminated) {
        const changed=date(r.updated_at);
        const timing=explicitTermination
          ? `Terminated early on ${pretty(explicitTermination)}; planned end ${pretty(plannedEnd)}`
          : `Marked terminated early${changed?` in the system on ${pretty(changed)}`:''}; an explicit actual termination date is not stored`;
        model.issues.push(`${unit}: ${timing}. The planned rotation span is not shown as completed activity.`);
        const actualSpanKnown=!!(s&&explicitTermination);
        const inSelectedPeriod=actualSpanKnown&&overlaps(s,explicitTermination,start,end);
        if(inSelectedPeriod&&same(r.resident_id,person.id)) model.residentAssignments.push({title:unit,role:'Resident',supervisor:staffName(r.supervising_attending_id),start:s,end:explicitTermination,status,ref:String(r.id),timing,terminatedEarly:true,evidenceKind:'person'});
        if(inSelectedPeriod&&same(r.supervising_attending_id,person.id)) model.supervision.push({title:unit,role:'Formal resident supervisor',resident:staffName(r.resident_id),start:s,end:explicitTermination,status,ref:String(r.id),timing,terminatedEarly:true,evidenceKind:'person'});
        if(actualSpanKnown) event(r,'rotation',unit,roles.join(' · '),s,explicitTermination,`${status} · explicit actual end recorded`);
        return;
      }
      if(!plannedEnd) { model.issues.push(`${unit}: rotation end date missing; not placed on the calendar.`); return; }
      event(r,'rotation',unit,roles.join(' · '),s,plannedEnd,status);
      const timing=s&&plannedEnd?`${pretty(s)} — ${pretty(plannedEnd)}`:'Dates not established';
      const inSelectedPeriod=overlaps(s,plannedEnd,start,end);
      if(inSelectedPeriod&&same(r.resident_id,person.id)) model.residentAssignments.push({title:unit,role:'Resident',supervisor:staffName(r.supervising_attending_id),start:s,end:plannedEnd,status,ref:String(r.id),timing,evidenceKind:'person'});
      if(inSelectedPeriod&&same(r.supervising_attending_id,person.id)) model.supervision.push({title:unit,role:'Formal resident supervisor',resident:staffName(r.resident_id),start:s,end:plannedEnd,status,ref:String(r.id),timing,evidenceKind:'person'});
    });
    function portfolio(key,leadField,leadRole) {
      if(!selected[key]) return;
      rows(key).forEach(r=>{
        const roles=[];
        if(same(r[leadField],person.id)) roles.push(leadRole);
        if(list(r.co_investigators).some(x=>same(x,person.id))||same(r.co_investigator_id,person.id)) roles.push('Co-investigator');
        if(key==='studies'&&(list(r.sub_investigators).some(x=>same(x,person.id))||same(r.sub_investigator_id,person.id))) roles.push('Sub-investigator');
        if(key==='studies'&&same(r.data_manager_id,person.id)) roles.push('Data manager');
        if(r.team_roles && Object.prototype.hasOwnProperty.call(r.team_roles,String(person.id))) roles.push(String(r.team_roles[person.id]||'Team member'));
        if(!roles.length) return;
        const s=date(r.start_date),e=date(r.actual_end_date||r.end_date||r.estimated_end_date);
        const invalid=(r.start_date&&!s)||((r.actual_end_date||r.end_date||r.estimated_end_date)&&!e)||(s&&e&&e<s);
        if(!invalid&&((s&&s>end)||(e&&e<start))) return;
        const missing=invalid||!s||!e;
        const item={title:r.title||'Untitled record',role:[...new Set(roles)].join(' · '),status:nice(r.status||r.current_stage||r.development_stage),line:lineName(r.research_line_id),start:s,end:e,ref:String(r.id),evidenceKind:'relationship',timing:missing?'Period relevance unverified — project/study dates are incomplete or invalid':'Project/study record dates overlap this period; personal participation dates are not separately recorded'};
        model[key].push(item);
        if(missing) model.issues.push(`${item.title}: period relevance is unverified; shown in the portfolio only where dates cannot establish overlap.`);
        list(r.milestones).filter(m=>m&&typeof m==='object').forEach(m=>{
          if(!m.date||!date(m.date)) { model.issues.push(`${item.title}: an undated milestone is not on the calendar.`); return; }
          event(r,key==='studies'?'study':'project',m.label||'Milestone','Shared milestone',m.date,m.date,`${item.title} · ${m.done?'Marked complete':'Not marked complete'} · Personal ownership not established`);
        });
      });
    }
    portfolio('studies','principal_investigator_id','Principal investigator');
    portfolio('projects','lead_investigator_id','Project lead');
    if(selected.lines) model.lines=rows('lines').filter(r=>same(r.coordinator_id,person.id)).map(r=>({title:r.name||r.research_line_name||'Research programme',role:'Coordinator',status:r.active===false?'Inactive':'Recorded assignment',timing:'Current recorded relationship; historical period membership is not established',ref:String(r.id),evidenceKind:'relationship'}));
    model.events.sort((a,b)=>a.start.localeCompare(b.start)||a.kind.localeCompare(b.kind)||a.title.localeCompare(b.title));
    const rotationRefs=new Set([...(model.residentAssignments||[]),...(model.supervision||[])].map(x=>x.ref));
    const matches={staff:1,oncall:model.events.filter(x=>x.kind==='oncall').length,rotations:rotationRefs.size,units:new Set([...(model.residentAssignments||[]),...(model.supervision||[])].map(x=>x.title)).size,studies:model.studies.length,projects:model.projects.length,lines:model.lines.length};
    model.sources=model.sources.map(source=>({...source,matchCount:source.state==='ready'?(matches[source.key]||0):null}));
    model.issues=[...new Set(model.issues)];
    model.summary=summarize(model);
    return model;
  }
  function narrative(m) {
    const events=Array.isArray(m?.events)?m.events:[];
    const selected=m?.selected||{};
    const sources=Object.fromEntries((m?.sources||[]).map(x=>[x.key,x]));
    const parts=[];
    const oncall=events.filter(x=>x.kind==='oncall').length;
    const rotations=events.filter(x=>x.kind==='rotation');
    // Use the same selected-period relationship collections that power the metrics,
    // Portfolio and formal document. Narrative must never independently recount rotations.
    const resident=(m?.residentAssignments||[]).length;
    const supervised=(m?.supervision||[]).length;
    if(selected.oncall && sources.oncall?.state==='ready') parts.push(oncall?`${oncall} on-call dut${oncall===1?'y was':'ies were'} recorded in the selected period.`:'No on-call duty is recorded in the successfully retrieved schedule for the selected period.');
    if(selected.rotations && sources.rotations?.state==='ready') {
      if(rotations.length) {
        const bits=[]; if(resident) bits.push(`${resident} resident assignment${resident===1?'':'s'}`); if(supervised) bits.push(`${supervised} supervised rotation${supervised===1?'':'s'}`);
        const subject=bits.join(' and '); parts.push(`${subject} ${resident+supervised===1?'overlaps':'overlap'} the selected period.`);
      } else parts.push('No resident or supervision rotation overlaps the selected period in the retrieved rotation records.');
    }
    const rel=[];
    if(selected.studies && sources.studies?.state==='ready') rel.push(`${m.studies.length} linked stud${m.studies.length===1?'y':'ies'}`);
    if(selected.projects && sources.projects?.state==='ready') rel.push(`${m.projects.length} innovation project${m.projects.length===1?'':'s'}`);
    if(selected.lines && sources.lines?.state==='ready') rel.push(`${m.lines.length} programme coordination role${m.lines.length===1?'':'s'}`);
    if(rel.length) {
      const allZero=(m?.studies?.length||0)+(m?.projects?.length||0)+(m?.lines?.length||0)===0;
      parts.push(allZero ? 'No research, innovation or programme coordination relationship is established by the successfully retrieved records.' : `The portfolio view establishes ${rel.join(', ')} from explicit recorded relationships.`);
    }
    const degraded=(m?.sources||[]).filter(x=>x.state!=='ready');
    if(degraded.length) parts.push(`${degraded.length} included source${degraded.length===1?' was':'s were'} not fully available, so this snapshot must be read as partial.`);
    return parts.join(' ');
  }
  function timelineGroups(m) {
    const events=Array.isArray(m?.events)?m.events:[];
    const groups=[]; const by=new Map();
    for(const item of events) {
      const key=String(item.start||'').slice(0,7)||'undated';
      if(!by.has(key)) { const g={key,label:key==='undated'?'Undated':new Date(key+'-01T00:00:00Z').toLocaleDateString('en-GB',{month:'long',year:'numeric',timeZone:'UTC'}),events:[]}; by.set(key,g); groups.push(g); }
      by.get(key).events.push(item);
    }
    return groups;
  }
  function summarize(m) {
    const events=Array.isArray(m?.events)?m.events:[];
    const sources=Array.isArray(m?.sources)?m.sources:[];
    const sourceBy=Object.fromEntries(sources.map(x=>[x.key,x]));
    const ready=sources.filter(x=>x.state==='ready').length;
    const degraded=sources.filter(x=>x.state!=='ready');
    const rotations=events.filter(x=>x.kind==='rotation');
    const stateFor=(key,selected=true)=>!selected?'not_included':sourceBy[key]?.state==='ready'?'known':'unknown';
    const metric=(key,value,selected=true)=>({state:stateFor(key,selected),value:stateFor(key,selected)==='known'?value:null,source:key});
    const milestoneSelected=!!(m?.selected?.studies||m?.selected?.projects);
    const milestoneStates=[m?.selected?.studies?sourceBy.studies?.state:null,m?.selected?.projects?sourceBy.projects?.state:null].filter(Boolean);
    const milestoneKnown=milestoneStates.length&&milestoneStates.every(x=>x==='ready');
    const milestonePartial=milestoneStates.some(x=>x==='ready')&&milestoneStates.some(x=>x!=='ready');
    const portfolioMetricSources=[['studies',m?.selected?.studies],['projects',m?.selected?.projects],['lines',m?.selected?.lines]].filter(([,sel])=>sel);
    const portfolioStates=portfolioMetricSources.map(([k])=>sourceBy[k]?.state);
    const portfolioKnown=portfolioStates.length&&portfolioStates.every(x=>x==='ready');
    const portfolioPartial=portfolioStates.some(x=>x==='ready')&&portfolioStates.some(x=>x!=='ready');
    const summary={
      oncall:events.filter(x=>x.kind==='oncall').length,
      rotations:rotations.length,
      residentRotations:(m?.residentAssignments||[]).filter(x=>!x.terminatedEarly).length,
      supervisedRotations:(m?.supervision||[]).filter(x=>!x.terminatedEarly).length,
      supervision:Array.isArray(m?.supervision)?m.supervision.length:0,
      residentAssignments:Array.isArray(m?.residentAssignments)?m.residentAssignments.length:0,
      studies:Array.isArray(m?.studies)?m.studies.length:0,
      projects:Array.isArray(m?.projects)?m.projects.length:0,
      programmes:Array.isArray(m?.lines)?m.lines.length:0,
      milestones:events.filter(x=>x.kind==='study'||x.kind==='project').length,
      datedActivity:events.filter(x=>x.kind==='oncall'||x.kind==='rotation'||x.kind==='study'||x.kind==='project').length,
      professionalPortfolioRelationships:(m?.studies?.length||0)+(m?.projects?.length||0)+(m?.lines?.length||0),
      trainingRelationships:(m?.supervision?.length||0)+(m?.residentAssignments?.length||0),
      sourceReady:ready,sourceTotal:sources.length,retrievalCoverage:sources.length?Math.round((ready/sources.length)*100):0,
      sourceCoverage:sources.length?Math.round((ready/sources.length)*100):0,
      degradedSources:degraded.length,issues:Array.isArray(m?.issues)?m.issues.length:0,status:degraded.length?'partial':'complete'
    };
    summary.metrics={
      oncall:metric('oncall',summary.oncall,m?.selected?.oncall),
      residentActivity:metric('rotations',summary.residentRotations,m?.selected?.rotations),
      supervisionActivity:metric('rotations',summary.supervisedRotations,m?.selected?.rotations),
      residentAssignments:metric('rotations',summary.residentAssignments,m?.selected?.rotations),
      supervision:metric('rotations',summary.supervision,m?.selected?.rotations),
      studies:metric('studies',summary.studies,m?.selected?.studies),
      projects:metric('projects',summary.projects,m?.selected?.projects),
      programmes:metric('lines',summary.programmes,m?.selected?.lines),
      milestones:{state:!milestoneSelected?'not_included':milestoneKnown?'known':milestonePartial?'partial':'unknown',value:milestoneKnown||milestonePartial?summary.milestones:null,sources:milestoneStates},
      portfolioRelationships:{state:portfolioKnown?'known':portfolioPartial?'partial':portfolioStates.length?'unknown':'not_included',value:portfolioKnown||portfolioPartial?summary.professionalPortfolioRelationships:null},
      trainingRelationships:metric('rotations',summary.trainingRelationships,m?.selected?.rotations)
    };
    summary.narrative=narrative(m);
    return summary;
  }
  function render(m,demo=false) {
    const e=escape;
    const stat=(key,count,label)=>!m.selected[key]?'':`<div class="stat"><b>${m.sources.find(s=>s.key===key)?.state==='ready'?count:'—'}</b><span>${e(label)}</span></div>`;
    const table=(headers,body)=>`<div class="table-wrap"><table><thead><tr>${headers.map(h=>`<th scope="col">${e(h)}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table></div>`;
    const sourceState=k=>m.sources.find(s=>s.key===k)?.state;
    const empty=k=>sourceState(k)==='ready'?'No matching linked records in this snapshot.':`Source ${sourceState(k)||'not included'}; this section cannot establish whether activities exist.`;
    let months=''; let cursor=m.start.slice(0,7)+'-01';
    while(cursor<=m.end) {
      const d=new Date(cursor+'T00:00:00Z'); const month=d.getUTCMonth();
      const offset=(d.getUTCDay()+6)%7; let cells=Array(offset).fill('<td class="outside"></td>');
      while(d.getUTCMonth()===month) {
        const day=d.toISOString().slice(0,10),inside=day>=m.start&&day<=m.end;
        const events=inside?m.events.filter(x=>x.start<=day&&x.end>=day):[];
        cells.push(`<td class="${inside?'':'outside'}"><b class="day">${d.getUTCDate()}</b>${events.map(x=>`<span class="event ${x.kind}">${e(x.kind==='rotation'?x.role+' · '+x.title:x.kind==='oncall'?x.role+' on-call':x.title)}${x.role==='Shared milestone'?'<small>Shared milestone</small>':''}</span>`).join('')}</td>`);
        d.setUTCDate(d.getUTCDate()+1);
      }
      while(cells.length%7) cells.push('<td class="outside"></td>');
      const weeks=[];for(let i=0;i<cells.length;i+=7)weeks.push('<tr>'+cells.slice(i,i+7).join('')+'</tr>');
      months+=`<section class="month"><h3>${new Date(cursor+'T00:00:00Z').toLocaleDateString('en-GB',{month:'long',year:'numeric',timeZone:'UTC'})}</h3><table class="calendar"><thead><tr>${['Mon','Tue','Wed','Thu','Fri','Sat','Sun'].map(x=>`<th scope="col">${x}</th>`).join('')}</tr></thead><tbody>${weeks.join('')}</tbody></table></section>`;
      cursor=d.toISOString().slice(0,10);
    }
    const portfolio=(key,title,no)=>!m.selected[key]?'':`<section><div class="section-title"><span>${no}</span><h2>${title}</h2></div><p class="muted">Linked roles and recorded status. Incomplete dates remain visible and are labelled.</p>${m[key].length?m[key].map(x=>`<article class="portfolio"><div><span class="tag">${e(x.status)}</span><h3>${e(x.title)}</h3><p>${e(x.role)}${x.line?' · '+e(x.line):''}</p></div><div class="record-meta"><p>${pretty(x.start)} — ${pretty(x.end)}</p><p>${e(x.timing)}</p><small>Record ${e(x.ref)}</small></div></article>`).join(''):`<p class="empty">${e(empty(key))}</p>`}</section>`;
    const unavailable=m.sources.filter(s=>s.state!=='ready');
    const relationship=(items,title,no,kind)=>`<section><div class="section-title"><span>${no}</span><h2>${e(title)}</h2></div><p class="muted">Explicit ${e(kind)} relationships for the selected person. Soft-terminated records remain visible and are labelled.</p>${items.length?items.map(x=>`<article class="portfolio"><div><span class="tag">${e(x.status)}</span><h3>${e(kind==='resident assignment'?x.title:x.resident||x.title)}</h3><p>${e(x.role)}${x.supervisor?' · Supervisor: '+e(x.supervisor):''}${x.resident?' · '+e(x.title):''}</p></div><div class="record-meta"><p>${e(x.timing||((x.start?pretty(x.start):'Dates not established')+(x.end?' — '+pretty(x.end):'')))}</p><small>Rotations · Record ${e(x.ref)}</small></div></article>`).join(''):`<p class="empty">${e(empty('rotations'))}</p>`}</section>`;
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'"><title>${e(m.person.name)} · Activity brief</title><style>
    :root{color-scheme:light;--ink:#183d38;--muted:#586b66;--line:#d9e1dc}*{box-sizing:border-box}body{margin:0;background:#edece7;color:var(--ink);font:14px/1.55 Arial,sans-serif}.paper{max-width:1120px;margin:28px auto;padding:52px 56px;background:#fffefa}header{border-top:5px solid var(--ink);padding-top:24px}.brand{display:flex;justify-content:space-between;font-size:12px;letter-spacing:2px;text-transform:uppercase}.eyebrow{margin:38px 0 8px;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--muted)}h1{font:48px/1.1 Georgia,serif;letter-spacing:-1.3px;margin:0 0 12px;overflow-wrap:anywhere}h2{font:28px/1.2 Georgia,serif;margin:0}h3{font-size:16px;margin:0 0 12px}p{margin:6px 0 12px}.intro{font-size:17px}.summary-copy{font-size:15px;line-height:1.7;max-width:900px}.period{display:flex;justify-content:space-between;gap:20px;border-block:1px solid var(--line);padding:18px 0;margin:25px 0}.period span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px}.stats{display:flex;flex-wrap:wrap;gap:22px;margin:25px 0}.stat b{display:block;font:30px Georgia,serif}.stat span{font-size:12px;color:var(--muted)}section{margin-top:34px}.section-title{display:flex;align-items:baseline;gap:14px;margin-bottom:12px}.section-title>span{font:12px Arial;color:var(--muted)}.muted,small{color:var(--muted)}.notice{border-left:3px solid #b58132;background:#f9f2e6;padding:14px 18px;margin:20px 0}.notice p:last-child{margin-bottom:0}.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:11px;margin:12px 0}.legend span{padding:3px 7px;border-radius:3px}.oncall{background:#e6efec;border-left:2px solid #316b5b}.rotation{background:#edf0f5;border-left:2px solid #687c9c}.study{background:#f4ecdf;border-left:2px solid #b58132}.project{background:#efe9f0;border-left:2px solid #907394}table{border-collapse:collapse;width:100%;text-align:left}th{font-size:11px;letter-spacing:.3px;color:var(--muted);background:#f3f5f1}td,th{padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}td{font-size:12px}thead{display:table-header-group}.calendar{table-layout:fixed}.calendar td{height:82px;padding:6px;border:1px solid var(--line)}.calendar th{padding:6px;text-align:center}.calendar .outside{background:#f5f5f1;color:#9baba4}.day{font-size:11px;font-weight:normal}.event{display:block;font-size:9px;line-height:1.3;padding:3px;margin-top:4px;overflow-wrap:anywhere}.event small{display:block;font-size:8px}.month{margin-top:24px}.portfolio{display:grid;grid-template-columns:1.2fr 1fr;gap:22px;padding:20px 0;border-bottom:1px solid var(--line);break-inside:avoid}.portfolio h3{font:21px/1.3 Georgia,serif;margin:8px 0}.record-meta{font-size:12px}.tag{font-size:10px;letter-spacing:.5px;text-transform:uppercase;color:var(--muted)}.empty{padding:20px;border:1px dashed var(--line);color:var(--muted)}footer{margin-top:40px;border-top:1px solid var(--line);padding-top:16px;font-size:11px;color:var(--muted)}li{margin-bottom:8px}.print-hint{font-size:12px;text-align:center;padding:14px;color:var(--muted)}.reference{font-size:10px;color:var(--muted)}
    @media(max-width:650px){.paper{margin:0;padding:24px 16px}h1{font-size:36px}.period,.portfolio{display:block}.period>div+div{margin-top:12px}.calendar td{padding:3px}.event{font-size:8px}.table-wrap{overflow-x:auto}.table-wrap table{min-width:540px}}
    @page{size:A4 portrait;margin:14mm}@media print{body{background:white;font-size:11px}.paper{margin:0;padding:0;max-width:none}h1{font-size:36px}h2{font-size:24px}.print-hint{display:none}.calendar td{height:62px}.month{break-inside:avoid}tr{break-inside:avoid}h2,h3,.section-title{break-after:avoid}section{margin-top:25px}.event{font-size:8px}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}.table-wrap{overflow:visible}.table-wrap table{min-width:0}}
    </style></head><body><div class="print-hint">Use your browser’s Print → Save as PDF to share a PDF copy. This document also opens offline.</div><main class="paper"><header><div class="brand"><b>neumAC</b><span>neumDesk / Personal activity</span></div>${demo?'<div class="notice"><b>Illustrative example — fictional records, not a live staff report.</b></div>':''}<p class="eyebrow">Calendar & professional portfolio</p><h1>${e(m.person.name)}</h1><p class="intro">${e(m.person.role)}</p><div class="period"><div><span>Reporting period</span>${pretty(m.start)} — ${pretty(m.end)}</div><div><span>Snapshot generated (UTC)</span>${e(m.generatedAt.replace('T',' ').slice(0,16))}</div></div></header>
    <p class="summary-copy">${e((m.summary||summarize(m)).narrative||'A consolidated view of recorded duties, training and explicitly linked professional activity for the selected period.')}</p><div class="stats">${stat('oncall',m.events.filter(x=>x.kind==='oncall').length,'Recorded duties')}${stat('rotations',m.events.filter(x=>x.kind==='rotation').length,'Dated rotation spans')}${stat('studies',m.studies.length,'Linked studies')}${stat('projects',m.projects.length,'Innovation projects')}</div>
    ${unavailable.length?`<div class="notice"><b>Partial view</b><p>${unavailable.map(s=>e(s.label)+': '+e(s.state)).join(' · ')}. Missing sources are not evidence of no activity.</p></div>`:''}
    <section><div class="section-title"><span>01</span><h2>Calendar</h2></div><p class="muted">Blank dates mean no dated activities appear in the included records; they do not establish availability. Rotation spans indicate an assignment, not daily attendance. Milestones belong to a linked study or project.</p><div class="legend"><span class="oncall">On-call</span><span class="rotation">Rotation</span><span class="study">Study milestone</span><span class="project">Innovation milestone</span></div>${months}</section>
    <section><div class="section-title"><span>02</span><h2>Activity agenda</h2></div>${m.events.length?table(['Date / period','Activity','Recorded role','Detail / source'],m.events.map(x=>`<tr><td>${pretty(x.start)}${x.end!==x.start?' – '+pretty(x.end):''}</td><td><b>${e(x.title)}</b></td><td>${e(x.role)}</td><td>${e(x.detail)}<br><span class="reference">${e(x.source)} · Record ${e(x.ref)}</span></td></tr>`).join('')):'<p class="empty">No dated activity is visible in the successfully retrieved sources. Unavailable or restricted sources remain unknown; review retrieval evidence below.</p>'}</section>
    ${m.selected.rotations?relationship(m.residentAssignments||[],'Resident assignments','03','resident assignment'):''}${m.selected.rotations?relationship(m.supervision||[],'Formal resident supervision','04','supervision'):''}${portfolio('studies','Research involvement','05')}${portfolio('projects','Innovation involvement','06')}
    ${m.selected.lines?`<section><div class="section-title"><span>07</span><h2>Programme coordination</h2></div><p class="muted">Current recorded coordinator assignments; historical period membership is not established.</p>${m.lines.length?m.lines.map(x=>`<article class="portfolio"><div><h3>${e(x.title)}</h3><p>${e(x.role)}</p></div><div>${e(x.status)}<br><small>Record ${e(x.ref)}</small></div></article>`).join(''):`<p class="empty">${e(empty('lines'))}</p>`}</section>`:''}
    <section><div class="section-title"><span>08</span><h2>Scope & retrieval evidence</h2></div><p>Explicit staff identifiers establish involvement. This is a record snapshot, not a complete account of workload or a confirmation of availability. Leave reasons, contact details and free-text staff notes are excluded.</p>${table(['Source','Retrieval state','Relevant records','Checked (UTC)'],m.sources.map(s=>`<tr><td>${e(s.label)}</td><td>${s.state==='ready'?'Retrieved':e(s.state)}</td><td>${s.state==='ready'?e(s.matchCount):'—'}</td><td>${s.checkedAt?e(s.checkedAt.replace('T',' ').slice(0,16)):'—'}</td></tr>`).join(''))}${m.issues.length?'<div class="notice"><b>Information to review</b><ul>'+m.issues.map(x=>'<li>'+e(x)+'</li>').join('')+'</ul></div>':''}</section><footer>neumAC · neumDesk · Personal activity brief<br>Prepared for deliberate review. Check the selected sections before sharing. Changes made after this snapshot are not reflected here.</footer></main></body></html>`;
  }
  return {escape,date,addDay,pretty,same,list,specs,fetchRows,load,snapshot,build,narrative,timelineGroups,summarize,render};
});

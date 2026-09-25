'use strict';
// Phase 5.3H: resource ownership, field projection and scoped reads/writes.
const map=(read,edit)=>({read,create:edit,update:edit,delete:edit});
const MODULES=Object.freeze({training_units:map('units.view','units.edit'),clinical_units:map('units.view','units.edit'),research_lines:map('research.view','research.edit'),clinical_trials:map('research.view','research.edit'),innovation_projects:map('research.view','research.edit'),news_posts:map('publications.view','publications.edit'),partners:map('research.catalog.view','research.catalog.edit'),partner_needs:map('research.catalog.view','research.catalog.edit')});
const SPECS={
 training_units:{table:'training_units',department:true},
 clinical_units:{table:'clinical_units',department:true},
 research_lines:{table:'research_lines',owner:'coordinator_id'},
 clinical_trials:{table:'clinical_trials',owner:'principal_investigator_id'},
 innovation_projects:{table:'innovation_projects',owner:'lead_investigator_id'},
 news_posts:{table:'news_posts',owner:'author_id'},
 partners:{table:'partners',global:true},partner_needs:{table:'partner_needs',global:true}
};
const SAFE={
 training_units:['id','unit_name','unit_code','department_id','department_name','unit_status','unit_type','maximum_residents','supervisor_id','default_supervisor_id','specialty','unit_description','location_building','location_floor'],
 clinical_units:['id','name','code','department_id','status','unit_type','description','supervisor_id'],
 research_lines:['id','line_number','name','research_line_name','short_name','description','capabilities','sort_order','active','coordinator_id','coordinator_name'],
 clinical_trials:['id','title','protocol_id','phase','status','description','research_line_id','principal_investigator_id','start_date','end_date','target_end_date','scope_type','target_diseases','tags','study_type','display_order'],
 innovation_projects:['id','title','category','current_stage','development_stage','status','description','research_line_id','lead_investigator_id','start_date','end_date','target_end_date','project_nature','target_diseases','tags','display_order'],
 news_posts:['id','title','post_type','status','author_id','research_line_id','published_at','created_at','journal_name','doi','keywords'],
 partners:['id','name','type','website','logo_url'],partner_needs:['id','need_name','category']
};
const pick=(row,keys)=>Object.fromEntries(keys.filter(k=>row[k]!==undefined).map(k=>[k,row[k]]));
const fail=(message='Access restricted',status=403)=>Object.assign(new Error(message),{status});
function createPortfolio({db,resolve,loadStaff,collection}) {
 async function record(resource,id){const spec=SPECS[resource];const r=await db.from(spec.table).select('*').eq('id',id).maybeSingle();if(r.error)throw r.error;if(!r.data)throw fail('Record not found',404);return r.data;}
 async function context(req,resource,row){
  const spec=SPECS[resource];if(spec.global)return {scopes:['all']};
  req.portfolioStaff ||= new Map();
  const ownerId=spec.owner&&row[spec.owner];
  if(ownerId&&!req.portfolioStaff.has(ownerId))req.portfolioStaff.set(ownerId,loadStaff(ownerId));
  const owner=ownerId?await req.portfolioStaff.get(ownerId):null;
  const department=spec.department?row.department_id:owner?.department_id;
  return {scopes:[...(owner?.id&&owner.id===req.user.medical_staff_id?['own']:[]),...(department&&department===req.user.department_id?['department']:[])]};
 }
 async function decision(req,resource,row,action='read'){return resolve(req,MODULES[resource][action],await context(req,resource,row));}
 async function project(req,resource,row){
  const d=await decision(req,resource,row);if(d.decision==='DENY')return null;
  const result=d.decision==='ALLOW'?{...row}:pick(row,SAFE[resource]);
  // Even full parent access does not authorize joined personal contact fields.
  for(const key of ['pi','dm','lead','author','coordinator','supervisor','medical_staff'])if(result[key])result[key]=pick(result[key],['id','full_name','staff_type']);
  result._access={visibility:d.visibility,can_edit:(await decision(req,resource,row,'update')).decision==='ALLOW'};
  return result;
 }
 async function filter(req,resource,rows){const out=[];for(const row of rows||[]){const r=await project(req,resource,row);if(r)out.push(r);}return out;}
 async function query(req,resource,q){
  const spec=SPECS[resource],plan=await collection(req,MODULES[resource].read);
  if(plan.authority?.decision==='DENY')throw fail();
  if(spec.global||plan.scope==='all')return {query:q};
  if(spec.department){if(plan.scope!=='department'||!req.user.department_id)throw fail();return {query:q.eq('department_id',req.user.department_id)};}
  if(plan.scope==='own'&&req.user.medical_staff_id)return {query:q.eq(spec.owner,req.user.medical_staff_id)};
  if(plan.scope==='department'&&req.user.department_id){const r=await db.from('medical_staff').select('id').eq('department_id',req.user.department_id).is('deleted_at',null);if(r.error)throw r.error;return {query:q.in(spec.owner,(r.data||[]).map(s=>s.id))};}
  throw fail();
 }
 function read(resource,{child=false}={}){return async(req,res,next)=>{
  try {
   const id=req.params?.unitId||req.params?.projectId||req.params?.id;
   if(id){const parent=await record(resource,id);const d=await decision(req,resource,parent);if(d.decision==='DENY'||(child&&!SPECS[resource].department&&d.decision!=='ALLOW'))throw fail();}
   else if((await collection(req,MODULES[resource].read)).authority?.decision==='DENY')throw fail();
   res.setHeader('Cache-Control','no-store');
   if(child&&req.path?.endsWith('/execution-clearance'))return next();
   const json=res.json.bind(res);
   res.json=payload=>{
    if(res.statusCode>=400)return json(payload);
    Promise.resolve().then(async()=>{
     if(child&&req.path?.endsWith('/partners')){const rows=[];for(const r of payload.data||[]){const partner=r.partner?await project(req,'partners',r.partner):null;if(partner)rows.push({...pick(r,['id','project_id','partner_id','role']),partner});}return json({...payload,data:rows});}
     if(child){const rows=[];for(const r of payload.data||[]){const staff=await loadStaff(r.staff?.id);if(!staff)continue;const d=await resolve(req,'staff.directory.view',{scopes:[...(staff.id===req.user.medical_staff_id?['own']:[]),...(staff.department_id===req.user.department_id?['department']:[])]});if(d.decision!=='DENY')rows.push({...pick(r,['id','role','assigned_from','assigned_until']),staff:pick(r.staff,['id','full_name','staff_type','employment_status'])});}return json({...payload,data:rows});}
     if(Array.isArray(payload))return json(await filter(req,resource,payload));
     if(payload?.data!==undefined){const data=Array.isArray(payload.data)?await filter(req,resource,payload.data):payload.data?await project(req,resource,payload.data):null;
      if(id&&!data)return res.status(403),json({error:'Access restricted'});
      const clean={...payload,data};
      // Do not expose counts that include individually denied rows.
      if(clean.pagination)clean.pagination={page:clean.pagination.page,limit:clean.pagination.limit,returned:data?.length||0,has_more:Array.isArray(payload.data)&&payload.data.length>=Number(clean.pagination.limit||50)};
      return json(clean);
     }
     const data=await project(req,resource,payload);if(!data)return res.status(403),json({error:'Access restricted'});return json(data);
    }).catch(()=>{if(!res.headersSent){res.status(500);json({error:'Could not project authorized records'});}});return res;
   };
   next();
  }catch(e){res.status(e.status||500).json({error:e.status?e.message:'Access check failed',code:'AUTHORITY_DENIED'});}
 };}
 async function authorize(req,resource){
  const spec=SPECS[resource],id=req.params?.unitId||req.params?.projectId||req.params?.id;
  const existing=id?await record(resource,id):null;
  const isChild=/\/(staff|partners|execution-clearance)(\/|$)/.test(req.path||'');
  const proposed={...(existing||{}),...(isChild?{}:req.body||{}),...(req.path?.endsWith('/coordinator')?{coordinator_id:req.body?.coordinator_id||null}:{})};
  for(const row of [existing,proposed].filter(Boolean))if((await decision(req,resource,row,'update')).decision!=='ALLOW')throw fail();
  // Ownership of the affected person must also be within the unit manager's scope.
  if(spec.department&&isChild){
   let staffId=req.body?.staff_id||req.params?.staffId;
   if(req.params?.assignmentId){const r=await db.from('clinical_unit_assignments').select('staff_id,clinical_unit_id').eq('id',req.params.assignmentId).maybeSingle();if(r.error)throw r.error;if(!r.data||r.data.clinical_unit_id!==id)throw fail('Assignment not found',404);staffId=r.data.staff_id;}
   if(staffId){const s=await loadStaff(staffId);if(!s)throw fail('Staff not found',404);if((await resolve(req,'units.edit',{scopes:s.department_id===req.user.department_id?['department']:[]})).decision!=='ALLOW')throw fail();}
  }
  return true;
 }
 function write(resource){return async(req,res,next)=>{try{await authorize(req,resource);next();}catch(e){res.status(e.status||500).json({error:e.status?e.message:'Access check failed',code:'AUTHORITY_DENIED'});}};}
 // Global aggregates have no record projection: require full all-scope authority.
 function all(permission){return async(req,res,next)=>{try{if((await resolve(req,permission,{scopes:['all']})).decision!=='ALLOW')throw fail();for(const scope of ['department','own','unit','supervisees'])if((await resolve(req,permission,{scopes:[scope]})).source==='user_override_deny')throw fail();next();}catch(e){res.status(e.status||500).json({error:e.status?e.message:'Access check failed',code:'AUTHORITY_DENIED'});}};}
 return {read,write,authorize,project,filter,query,all,decision,context};
}
module.exports={MODULES,SPECS,SAFE,createPortfolio};

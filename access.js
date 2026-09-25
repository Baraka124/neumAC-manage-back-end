'use strict';
// Canonical access integration. Stable runtime filename.
const MODULES = Object.freeze({
  medical_staff: {read:'staff.directory.view',create:'staff.create',update:'staff.profile.edit',delete:'staff.archive'},
  staff_absence: {read:'leave.view',create:'leave.create',update:'leave.edit',delete:'leave.cancel'},
  resident_rotations: {read:'rotation.view',create:'rotation.create',update:'rotation.edit',delete:'rotation.terminate'},
  oncall_schedule: {read:'oncall.view',create:'oncall.assign',update:'oncall.edit',delete:'oncall.cancel'},
  user_management: {read:'identity.users.view',create:'identity.users.invite',update:'identity.users.manage',delete:'identity.users.lifecycle'},
  rotation_exceptions:{read:'rotation.approve_exception',write:'rotation.approve_exception'},
  leave_exceptions:{read:'leave.approve_exception',write:'leave.approve_exception'},
  oncall_exceptions:{read:'oncall.approve_exception',write:'oncall.approve_exception'}
});
const TARGETS = {
  medical_staff: {table:'medical_staff', fields:['id'], select:'id,department_id'},
  staff_absence: {table:'staff_absence_records',fields:['staff_member_id'], select:'id,staff_member_id'},
  resident_rotations: {table:'resident_rotations',fields:['resident_id'], select:'id,resident_id,supervising_attending_id,training_unit_id'},
  oncall_schedule: {table:'oncall_schedule',fields:['primary_physician_id','backup_physician_id'],select:'id,primary_physician_id,backup_physician_id'}
};
function createAccess({db, Authority, resolve, loadStaff, loadPermissions}) {
  const full = d => d?.decision === Authority.DECISIONS.ALLOW;
  async function capabilities(req) {
    const scopes=['all'];
    if(req.user.department_id) scopes.push('department');
    if(req.user.medical_staff_id) scopes.push('own');
    const decisions={};
    for(const {key} of Authority.catalogEntries()) {
      decisions[key]={};
      for(const scope of scopes) decisions[key][scope]=req.user.account_status && req.user.account_status!=='active' ? {decision:'DENY',visibility:'none',source:'identity',reason:'Account is not active.'} : await resolve(req,key,{scopes:[scope]});
    }
    const permissions=await loadPermissions(req.user.id);
    const legacy={};
    const broad=['system_admin','department_head'].includes(Authority.normalizeRole(req.user.user_role));
    for(const module of ['training_units','communications','research_lines','clinical_trials','innovation_projects','analytics','news_posts','system_settings','departments','staff_types','academic_degrees','audit_logs','attachments','users']) {
      const p=permissions.get(module);
      legacy[module]={read:broad||p?.can_read===true,write:broad||p?.can_write===true};
    }
    return {legacy,contract:'neumdesk.capabilities.v1',actor:{id:req.user.id,staff_id:req.user.medical_staff_id||null,department_id:req.user.department_id||null},decisions,modules:MODULES};
  }
  async function targets(req,resource,action) {
    const spec=req.path?.startsWith('/api/emergency-callouts') ? {table:'emergency_callouts',fields:['staff_id'],select:'id,staff_id'} : TARGETS[resource], body=req.body||{}, records=[];
    const id=req.params?.staffId || req.params?.id || (req.path?.endsWith('/review') ? body.exclude_id : null);
    if(id) {
      const r=await db.from(spec.table).select(spec.select).eq('id',id).maybeSingle();
      if(r.error) throw r.error;
      if(!r.data) throw Object.assign(new Error('Record not found'),{status:404});
      records.push(r.data);
      if(action!=='delete') records.push({...r.data,...body,...(resource==='medical_staff'?{department_id:body.department_id||null}:{}),id});
    } else records.push(body);
    const contexts=[];
    for(const record of records) {
      if(resource==='medical_staff') {
        const staff=id?await loadStaff(id):{department_id:record.department_id};
        if(!staff) throw Object.assign(new Error('Staff not found'),{status:404});
        contexts.push(staff);
        if(Object.hasOwn(record,'department_id')) contexts.push({...staff,department_id:record.department_id});
      } else {
        for(const field of spec.fields) {
          if(!record[field]) continue;
          const staff=await loadStaff(record[field]);
          if(!staff) throw Object.assign(new Error('Staff not found'),{status:404});
          contexts.push(staff);
        }

      }
    }
    if(!contexts.length) contexts.push({}); // Only an explicit all-scope grant can pass without a target.
    return contexts;
  }
  const context=(req,s)=>({scopes:[...(s.id&&s.id===req.user.medical_staff_id?['own']:[]),...(s.department_id&&s.department_id===req.user.department_id?['department']:[])]});
  async function authorize(req, resource, action, permissionOverride) {
    let key=permissionOverride || MODULES[resource]?.[action];
    if(!key) throw Object.assign(new Error('Unsupported action'),{status:403});
    const records=await targets(req,resource,action);
    for(const record of records) {
      const d=await resolve(req,key,context(req,record));
      if(!full(d)) throw Object.assign(new Error(d.reason||'Access restricted'),{status:403,decision:d});
    }
    req.accessTargets=records; req.accessResource=resource;
    return true;
  }
  function middleware(resource,action) {
    return async(req,res,next)=>{
      try {
        if(req.path==='/api/oncall/batch') {
          if(!Array.isArray(req.body?.shifts)||!req.body.shifts.length||req.body.shifts.length>200) return res.status(400).json({error:'Provide 1 to 200 shifts.'});
          const allTargets=[];
          for(const shift of req.body.shifts) {
            const child={...req,params:{},path:'/api/oncall',body:shift};
            await authorize(child,resource,'create');
            if(req.body.force_override===true) await authorize(child,resource,'update');
            allTargets.push(...child.accessTargets);
          }
          req.accessTargets=allTargets;return next();
        }
        const actual=req.path?.endsWith('/review') && req.body?.exclude_id?'update':action;
        const key=resource==='staff_absence'&&req.path.endsWith('/return')?'leave.return_to_duty':resource==='staff_absence'&&req.path.endsWith('/purge')?'leave.purge':null;
        await authorize(req,resource,actual,key);
        next();
      } catch(e){res.status(e.status||500).json({error:e.status?e.message:'Access check failed',code:'AUTHORITY_DENIED',reason:e.status?e.message:undefined});}
    };
  }
  async function exception(req,key) {
    if(!req.accessTargets?.length) return false;
    for(const target of req.accessTargets) if(!full(await resolve(req,key,context(req,target)))) return false;
    return true;
  }
  return {capabilities,authorize,middleware,exception};
}
module.exports={MODULES,createAccess};

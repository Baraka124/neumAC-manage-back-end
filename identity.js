'use strict';
// Development credentials never act as a master password and fail closed in production.
const developmentEnabled = (env=process.env) => env.NODE_ENV === 'development' && env.IDENTITY_DEV_PASSWORDS_ENABLED === 'true';
function developmentPasswordStatus(isSystemAdmin,env=process.env) {
 if(!isSystemAdmin)return {status:'system_admin_required'};
 const development=env.NODE_ENV==='development',flag=env.IDENTITY_DEV_PASSWORDS_ENABLED==='true';
 return {status:development&&flag?'enabled':!development?'development_required':'flag_required',checks:{development_mode:development,password_flag:flag}};
}
const credentialBlock = (user,enabled) => user.password_reset_required ? 'Choose an individual password using your reset email before signing in.' : user.development_credentials && !enabled ? 'Development credentials are disabled. Ask an administrator for an individual password reset.' : null;
const emailKey = value => String(value||'').trim().toLowerCase();
function registerIdentityWorkspace({app,supabase,authenticateToken,requireAuthority,apiLimiter,bcrypt,jwt,JWT_SECRET,APP_URL,sendAccountEmail,tokenDigest,recordIdentityEvent,Authority,resolveRequestAuthority}) {
 const protect=key=>[authenticateToken,requireAuthority(key,{scopes:['all']}),apiLimiter];
 const fail=(res,e)=>res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'This staff profile or email already has an account. Refresh and manage the existing account.':'Identity action failed. Refresh and try again.'});
 app.get('/api/identity/staff',...protect('identity.users.view'),async(req,res)=>{
  try {
   // Fetch every page: onboarding must not silently hide staff beyond Supabase's row cap.
   const rows=[];let start=0;
   while(true){const {data,error}=await supabase.from('medical_staff').select('id,full_name,professional_email,department_id,employment_status,staff_type').is('deleted_at',null).order('id').range(start,start+499);if(error)throw error;rows.push(...(data||[]));if(!data||data.length<500)break;start+=500;}
   res.setHeader('Cache-Control','no-store');res.json({data:rows});
  }catch(e){fail(res,e)}
 });
 app.post('/api/identity/development-accounts',...protect('identity.users.invite'),async(req,res)=>{
  try{
   if(!developmentEnabled())return res.status(403).json({error:'Development account provisioning is disabled.'});
   if(Authority.normalizeRole(req.user.user_role)!=='system_admin')return res.status(403).json({error:'Only a system administrator can provision development accounts.'});
   const {medical_staff_id,user_role,password}=req.body||{};
   if(!/^[0-9a-f-]{36}$/i.test(medical_staff_id||'')||!['clinician','resident'].includes(user_role)||typeof password!=='string'||password.length<8||Buffer.byteLength(password)>72)return res.status(400).json({error:'Select staff and a clinician or resident role. Use a temporary password of at least 8 characters, at most 72 bytes.'});
   const {data:staff,error:staffError}=await supabase.from('medical_staff').select('id,full_name,professional_email,department_id,employment_status,deleted_at').eq('id',medical_staff_id).maybeSingle();if(staffError)throw staffError;
   if(!staff||staff.deleted_at||staff.employment_status!=='active')return res.status(409).json({error:'Choose an active staff profile.'});
   const email=emailKey(staff.professional_email);
   if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({error:'Add a valid professional email to the staff profile first.'});
   const {data:owners,error:ownerError}=await supabase.from('app_users').select('id,email,medical_staff_id');if(ownerError)throw ownerError;
   if((owners||[]).some(u=>u.medical_staff_id===staff.id||emailKey(u.email)===email))return res.status(409).json({error:'An account already uses this staff profile or email.'});
   const now=new Date().toISOString();
   const {data:user,error}=await supabase.from('app_users').insert({email,full_name:staff.full_name,medical_staff_id:staff.id,department_id:staff.department_id,user_role,admin_level:0,account_status:'active',password_hash:await bcrypt.hash(password,12),development_credentials:true,password_reset_required:false,activated_at:now,auth_version:1,created_at:now,updated_at:now}).select('id,email,full_name,user_role,account_status').single();if(error)throw error;
   await recordIdentityEvent(req.user.id,user.id,'development_account_created',null,{role:user_role});
   res.status(201).json({success:true,user});
  }catch(e){fail(res,e)}
 });
 // The simple editor changes only ordinary module actions, never administrative powers.
 app.put('/api/identity/users/:id/access-pills',...protect('identity.overrides.manage'),async(req,res)=>{
  try{
   if(req.params.id===req.user.id)return res.status(403).json({error:'Another administrator must change your own access.'});
   const {scope,changes,restore}=req.body||{};
   const simpleDomains=['staff','rotations','leave','oncall','units','research','publications','grounded'];
   if(!['own','department','all'].includes(scope)||!Array.isArray(changes)||!changes.length||changes.length>50||new Set(changes.map(c=>c?.key)).size!==changes.length||!(restore===undefined||typeof restore==='boolean'))return res.status(400).json({error:'Invalid access selection.'});
   const {data:target,error:targetError}=await supabase.from('app_users').select('id').eq('id',req.params.id).maybeSingle();if(targetError)throw targetError;if(!target)return res.status(404).json({error:'Account not found.'});
   const rows=[];
   for(const change of changes){
    const meta=Authority.PERMISSION_CATALOG[change?.key];
    if(!meta||!simpleDomains.includes(meta.domain)||!['allow','deny'].includes(change.effect))return res.status(400).json({error:'This action requires the advanced editor.'});
    // Restoring defaults may remove a denial: apply the same grantor ceiling.
    if(change.effect==='allow'||restore){const grant=await resolveRequestAuthority(req,change.key,{scopes:[scope]});if(grant.decision!=='ALLOW'||grant.visibility!=='full')return res.status(403).json({error:'You cannot grant or restore access beyond your own authority.'});}
    rows.push({user_id:target.id,permission_key:change.key,effect:change.effect,scope,visibility:'full',reason:'Administrator updated module access using permission pills.',granted_by:req.user.id,expires_at:null,updated_at:new Date().toISOString()});
   }
   // One database statement: either all selected actions change or none do.
   const result=restore?await supabase.from('authority_overrides').delete().eq('user_id',target.id).eq('scope',scope).in('permission_key',rows.map(r=>r.permission_key)):await supabase.from('authority_overrides').upsert(rows,{onConflict:'user_id,permission_key,scope'});
   if(result.error)throw result.error;
   await recordIdentityEvent(req.user.id,target.id,restore?'module_defaults_restored':'module_access_updated',null,{scope,changes:rows.map(r=>({key:r.permission_key,effect:restore?'role_default':r.effect}))});
   res.json({success:true});
  }catch(e){fail(res,e)}
 });
 app.post('/api/identity/users/:id/development-password',...protect('identity.users.security'),async(req,res)=>{
  try{
   if(!developmentEnabled()||Authority.normalizeRole(req.user.user_role)!=='system_admin')return res.status(403).json({error:'Development credential management is disabled.'});
   const password=req.body?.password;
   if(typeof password!=='string'||password.length<8||Buffer.byteLength(password)>72)return res.status(400).json({error:'Use at least 8 characters and at most 72 bytes.'});
   const {data:user,error}=await supabase.from('app_users').select('id,user_role,account_status,auth_version,development_credentials').eq('id',req.params.id).maybeSingle();if(error)throw error;
   if(!user||user.id===req.user.id||!user.development_credentials||!['clinician','resident'].includes(user.user_role)||user.account_status!=='active')return res.status(409).json({error:'Select an active non-admin development account.'});
   const {data:changed,error:updateError}=await supabase.from('app_users').update({password_hash:await bcrypt.hash(password,12),auth_version:Number(user.auth_version)+1,password_reset_required:false,reset_token:null,reset_token_expires_at:null,updated_at:new Date().toISOString()}).eq('id',user.id).eq('auth_version',user.auth_version).eq('development_credentials',true).eq('account_status','active').eq('user_role',user.user_role).select('id').maybeSingle();if(updateError)throw updateError;if(!changed)return res.status(409).json({error:'Account changed. Refresh and try again.'});
   await recordIdentityEvent(req.user.id,user.id,'development_password_replaced',null,{});res.json({success:true});
  }catch(e){fail(res,e)}
 });
 app.post('/api/identity/users/:id/security',...protect('identity.users.security'),async(req,res)=>{
  try{
   const {action,reason}=req.body||{};
   if(!['revoke_sessions','require_password_reset'].includes(action)||typeof reason!=='string'||reason.trim().length<5||reason.length>1000)return res.status(400).json({error:'Choose a security action and enter a reason of at least five characters.'});
   if(req.params.id===req.user.id)return res.status(409).json({error:'Use your own password settings; another administrator must restrict your account.'});
   const {data:user,error}=await supabase.from('app_users').select('id,email,user_role,account_status,auth_version').eq('id',req.params.id).maybeSingle();if(error)throw error;
   if(!user||user.account_status!=='active')return res.status(409).json({error:'Choose an active account.'});
   if(Authority.normalizeRole(user.user_role)==='system_admin'&&Authority.normalizeRole(req.user.user_role)!=='system_admin')return res.status(403).json({error:'Only a system administrator can manage another administrator.'});
   const patch={auth_version:Number(user.auth_version||1)+1,updated_at:new Date().toISOString()};let rawToken;
   if(action==='require_password_reset'){
    rawToken=jwt.sign({purpose:'password_reset',userId:user.id,email:user.email,jti:require('crypto').randomUUID()},JWT_SECRET,{expiresIn:'1h'});
    Object.assign(patch,{password_reset_required:true,reset_token:tokenDigest(rawToken),reset_token_expires_at:new Date(Date.now()+3600000).toISOString()});
   }
   const {data:updated,error:updateError}=await supabase.from('app_users').update(patch).eq('id',user.id).eq('account_status','active').eq('auth_version',user.auth_version).select('id').maybeSingle();if(updateError)throw updateError;if(!updated)return res.status(409).json({error:'Account changed. Refresh before retrying.'});
   let delivery=null;
   if(rawToken){try{delivery=await sendAccountEmail(user.email,'Choose your individual Neumact password',`<p>Your administrator requires a new individual password. Existing sessions have ended.</p><p><a href="${APP_URL}?reset_token=${encodeURIComponent(rawToken)}">Choose password</a></p><p>This link expires in one hour.</p>`)}catch{delivery={delivered:false,mode:'delivery_failed'}}}
   await recordIdentityEvent(req.user.id,user.id,action,reason.trim(),{delivery:delivery?.mode||null});
   res.json({success:true,delivery});
  }catch(e){fail(res,e)}
 });
}
module.exports={developmentPasswordStatus,developmentEnabled,credentialBlock,emailKey,registerIdentityWorkspace};

'use strict';
const crypto=require('crypto');
const rateLimit=require('express-rate-limit');
const TEMP_MS=24*60*60*1000;
const passwordValid=p=>typeof p==='string'&&p.length>=15&&Buffer.byteLength(p,'utf8')<=72;
function setupChallenge(user,jwt,secret){
 if(!user.password_reset_required||!user.temporary_password_expires_at)return null;
 if(Date.parse(user.temporary_password_expires_at)<=Date.now())return {expired:true};
 return {password_setup_required:true,setup_token:jwt.sign({id:user.id,auth_version:Number(user.auth_version||1),purpose:'credential_setup'},secret,{expiresIn:'10m'})};
}
function register({app,db,authenticateToken,requireAuthority,bcrypt,jwt,secret,recordIdentityEvent,Authority}){
 const limit=rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:true,legacyHeaders:false,message:{error:'Too many credential attempts. Wait 15 minutes before trying again.'}});
 const noStore=(req,res,next)=>{res.setHeader('Cache-Control','no-store');next()};
 const protect=[authenticateToken,requireAuthority('identity.users.security',{scopes:['all']}),limit,noStore];
 async function confirmAdmin(req,res){
  if(Authority.normalizeRole(req.user.user_role)!=='system_admin'||req.testSession){res.status(403).json({error:'A system administrator must issue temporary credentials.'});return false}
  if(typeof req.body?.admin_password!=='string'||Buffer.byteLength(req.body.admin_password)>72){res.status(400).json({error:'Confirm your own administrator password.'});return false}
  const {data,error}=await db.from('app_users').select('password_hash,auth_version,account_status').eq('id',req.user.id).maybeSingle();
  if(error||!data||data.account_status!=='active'||Number(data.auth_version||1)!==req.user.auth_version||!await bcrypt.compare(req.body.admin_password,data.password_hash||'')){res.status(403).json({error:'Administrator password confirmation failed.'});return false}
  if(typeof req.body.reason!=='string'||req.body.reason.trim().length<5||req.body.reason.length>1000){res.status(400).json({error:'Enter a reason of 5–1000 characters.'});return false}
  return true;
 }
 const createSecret=()=>crypto.randomBytes(18).toString('base64url');
 app.post('/api/identity/users/:id/temporary-password',...protect,async(req,res)=>{
  try{
   if(!await confirmAdmin(req,res))return;
   const {data:u,error}=await db.from('app_users').select('id,email,account_status,user_role,auth_version,password_hash').eq('id',req.params.id).maybeSingle();if(error)throw error;
   if(!u||u.id===req.user.id||u.account_status!=='active'||Authority.normalizeRole(u.user_role)==='system_admin')return res.status(409).json({error:'Choose an active non-administrator account. Reactivate disabled accounts separately.'});
   const password=createSecret(),expires=new Date(Date.now()+TEMP_MS).toISOString();
   const {data:changed,error:updateError}=await db.from('app_users').update({password_hash:await bcrypt.hash(password,12),development_credentials:false,password_reset_required:true,temporary_password_expires_at:expires,reset_token:null,reset_token_expires_at:null,auth_version:Number(u.auth_version||1)+1,updated_at:new Date().toISOString()}).eq('id',u.id).eq('auth_version',u.auth_version).eq('password_hash',u.password_hash).eq('account_status','active').eq('user_role',u.user_role).select('id').maybeSingle();if(updateError)throw updateError;
   if(!changed)return res.status(409).json({error:'Account changed. Refresh and try again.'});
   await recordIdentityEvent(req.user.id,u.id,'temporary_password_issued',req.body.reason.trim(),{expires_at:expires});
   return res.json({success:true,credentials:{email:u.email,password,expires_at:expires},message:'Shown once. Personal password required before workspace access.'});
  }catch{res.status(500).json({error:'Could not issue credentials. Check the release migration and refresh the account before retrying.'})}
 });
 app.post('/api/identity/production-accounts',...protect,requireAuthority('identity.users.invite',{scopes:['all']}),async(req,res)=>{
  try{
   if(!await confirmAdmin(req,res))return;
   const {medical_staff_id,user_role}=req.body;
   if(!/^[0-9a-f-]{36}$/i.test(medical_staff_id||'')||!['clinician','resident','coordinator','department_head'].includes(user_role))return res.status(400).json({error:'Choose a staff profile and a non-administrator role.'});
   const {data:staff,error}=await db.from('medical_staff').select('id,full_name,professional_email,department_id,employment_status,deleted_at').eq('id',medical_staff_id).maybeSingle();if(error)throw error;
   const email=String(staff?.professional_email||'').trim().toLowerCase();
   if(!staff||staff.deleted_at||staff.employment_status!=='active'||! /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(409).json({error:'Choose active staff with a valid professional email.'});
   const [byStaff,byEmail]=await Promise.all([db.from('app_users').select('id').eq('medical_staff_id',staff.id),db.from('app_users').select('id').ilike('email',email)]);if(byStaff.error||byEmail.error)throw byStaff.error||byEmail.error;
   if(byStaff.data?.length||byEmail.data?.length)return res.status(409).json({error:'An account already uses that profile or email.'});
   const password=createSecret(),now=new Date().toISOString(),expires=new Date(Date.now()+TEMP_MS).toISOString();
   const {data:u,error:insertError}=await db.from('app_users').insert({email,full_name:staff.full_name,medical_staff_id:staff.id,department_id:staff.department_id,user_role,admin_level:0,account_status:'active',password_hash:await bcrypt.hash(password,12),development_credentials:false,password_reset_required:true,temporary_password_expires_at:expires,auth_version:1,activated_at:now,created_at:now,updated_at:now}).select('id,email,full_name,user_role,account_status').single();if(insertError)throw insertError;
   await recordIdentityEvent(req.user.id,u.id,'production_account_created',req.body.reason.trim(),{role:user_role,expires_at:expires});
   res.status(201).json({success:true,user:u,credentials:{email,password,expires_at:expires}});
  }catch(e){res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'An account already uses that profile or email.':'Account creation failed. Check the migration, then refresh before retrying.'})}
 });
 app.post('/api/auth/complete-password-setup',limit,noStore,async(req,res)=>{
  try{
   if(!passwordValid(req.body?.new_password)||typeof req.body?.setup_token!=='string')return res.status(400).json({error:'Use 15 or more characters, up to 72 UTF-8 bytes.'});
   let token;try{token=jwt.verify(req.body.setup_token,secret)}catch{return res.status(401).json({error:'Setup expired. Sign in again with your temporary password.'})}
   if(token.purpose!=='credential_setup'||!token.id)return res.status(401).json({error:'Invalid setup token.'});
   const {data:u,error}=await db.from('app_users').select('id,user_role,account_status,auth_version,password_hash,password_reset_required,temporary_password_expires_at').eq('id',token.id).maybeSingle();if(error)throw error;
   if(u&&Authority.normalizeRole(u.user_role)==='system_admin')return res.status(403).json({error:'Administrator password protected'});
   if(!u||u.account_status!=='active'||!u.password_reset_required||!u.temporary_password_expires_at||Date.parse(u.temporary_password_expires_at)<=Date.now()||Number(u.auth_version||1)!==token.auth_version)return res.status(401).json({error:'This setup is no longer valid. Request new credentials from your administrator.'});
   if(await bcrypt.compare(req.body.new_password,u.password_hash))return res.status(400).json({error:'Choose a personal password different from your temporary password.'});
   const {data:changed,error:updateError}=await db.from('app_users').update({password_hash:await bcrypt.hash(req.body.new_password,12),password_reset_required:false,development_credentials:false,temporary_password_expires_at:null,reset_token:null,reset_token_expires_at:null,auth_version:Number(u.auth_version||1)+1,updated_at:new Date().toISOString()}).eq('id',u.id).eq('auth_version',u.auth_version).eq('password_hash',u.password_hash).eq('password_reset_required',true).eq('user_role',u.user_role).eq('account_status','active').gt('temporary_password_expires_at',new Date().toISOString()).select('id').maybeSingle();if(updateError)throw updateError;
   if(!changed)return res.status(409).json({error:'Password setup was already completed or changed. Sign in again.'});
   await recordIdentityEvent(u.id,u.id,'personal_password_set',null,{});
   res.json({success:true,message:'Personal password saved. Sign in to continue.'});
  }catch{res.status(500).json({error:'Password setup failed. Try again shortly.'})}
 });
}
module.exports={register,setupChallenge,passwordValid};

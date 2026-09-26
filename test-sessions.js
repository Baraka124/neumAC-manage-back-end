'use strict';
const enabled=(env=process.env)=>env.NODE_ENV==='development'&&env.IDENTITY_DEV_TEST_SESSIONS_ENABLED==='true';
async function validate({decoded,identity,supabase,Authority}){
 if(decoded.purpose!=='development_test')return null;
 if(!enabled()||!decoded.test_actor_id||decoded.test_actor_id===identity.id||Authority.normalizeRole(identity.user_role)==='system_admin')throw Error('Development test session unavailable');
 const {data:actor,error}=await supabase.from('app_users').select('id,full_name,user_role,account_status,auth_version,password_reset_required').eq('id',decoded.test_actor_id).maybeSingle();
 if(error||!actor||actor.account_status!=='active'||actor.password_reset_required||Authority.normalizeRole(actor.user_role)!=='system_admin'||Number(actor.auth_version||1)!==decoded.test_actor_version)throw Error('Administrator session is no longer valid');
 return {actor_id:actor.id,actor_name:actor.full_name,expires_at:new Date(decoded.exp*1000).toISOString()};
}
function register({app,authenticateToken,apiLimiter,supabase,Authority,jwt,JWT_SECRET,credentialBlock,developmentEnabled}){
 app.post('/api/identity/users/:id/test-session',authenticateToken,apiLimiter,async(req,res)=>{
  if(!enabled()||req.testSession||Authority.normalizeRole(req.user.user_role)!=='system_admin')return res.status(403).json({error:'User testing is available only to a system administrator in development.'});
  try{
   const {data:user,error}=await supabase.from('app_users').select('id,email,full_name,user_role,account_status,auth_version,medical_staff_id,department_id,development_credentials,password_reset_required').eq('id',req.params.id).maybeSingle();
   if(error)throw error;
   if(!user||user.id===req.user.id||user.account_status!=='active'||Authority.normalizeRole(user.user_role)==='system_admin'||credentialBlock(user,developmentEnabled()))return res.status(409).json({error:'Choose an active non-system-administrator account with completed password setup.'});
   const token=jwt.sign({id:user.id,role:user.user_role,email:user.email,full_name:user.full_name,medical_staff_id:user.medical_staff_id||null,auth_version:Number(user.auth_version||1),purpose:'development_test',test_actor_id:req.user.id,test_actor_version:Number(req.user.auth_version||1)},JWT_SECRET,{expiresIn:'15m'});
   res.setHeader('Cache-Control','no-store');res.json({token,user,expires_in:900});
  }catch(e){res.status(500).json({error:'Test session could not be created.'})}
 });
}
module.exports={enabled,validate,register};

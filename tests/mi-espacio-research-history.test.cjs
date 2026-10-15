'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const h=require('../mi-espacio-research-history');
const route=fs.readFileSync(require('node:path').join(__dirname,'..','index.js'),'utf8');
const sid='ac423e00-0000-4000-8000-000000000001';
test('bounded validated pagination and no freeform identity input',()=>{
 assert.deepEqual(h.parseRequest({kind:'studies',page:'2',limit:'20'}),{kind:'studies',page:2,limit:20});
 for(const x of [{page:'0'},{page:'101'},{page:'abc'},{limit:'21'},{kind:'other'},{limit:'1.5'}])assert.ok(h.parseRequest(x).error);
});
test('only completed personal studies and projects are emitted; never infer Co-IP',()=>{
 const rows=[{id:'1',title:'Study',status:'Completado',principal_investigator_id:sid,co_investigators:[],sub_investigators:[]},{id:'2',title:'Other person',status:'completed',principal_investigator_id:'someone-else'}];
 assert.deepEqual(h.normalizeItems('studies',rows,sid).map(x=>x.role),['PI']);
 assert.deepEqual(h.normalizeItems('projects',[{id:'3',title:'Project',current_stage:'completed',lead_investigator_id:sid}],sid)[0].stage,'completed');
 assert.deepEqual(h.normalizeItems('studies',[{...rows[0],status:'withdrawn'}],sid),[]);
});
test('query is own-staff scoped, bounded, stable, and uses authoritative project stage',async()=>{
 const chain=[];
 const q=new Proxy({}, {get:(_t,k)=> (...args)=>{chain.push([k,...args]);return q;}});
 const db={from:(name)=>{chain.push(['from',name]);return q;}};
 h.queryHistory(db,sid,{kind:'projects',page:2,limit:10});
 assert.ok(chain.some(x=>x[0]==='eq'&&x[1]==='current_stage'&&x[2]==='completed'));
 assert.ok(chain.some(x=>x[0]==='or'&&x[1].includes(sid)));
 assert.deepEqual(chain.find(x=>x[0]==='range').slice(1),[10,20]);
 assert.ok(chain.some(x=>x[0]==='order'&&x[1]==='id'));
});
test('page metadata differentiates actual last page from more results',async()=>{
 let db={from(){return {select(){return this},in(){return this},or(){return this},order(){return this},range(){return Promise.resolve({data:Array.from({length:11},(_,i)=>({id:String(i+1),title:'Study '+i,status:'completed',principal_investigator_id:sid})),error:null})}}}};
 const result=await h.getHistoryPage(db,sid,{kind:'studies',page:1,limit:10});
 assert.equal(result.items.length,10);assert.equal(result.pagination.has_more,true);assert.equal(result.pagination.next_page,2);
});
test('source failure and unexpected identities fail closed',async()=>{
 const db={from(){return {select(){return this},in(){return this},or(){return this},order(){return this},range(){return Promise.resolve({data:null,error:{code:'42P01'}})}}}};
 await assert.rejects(h.getHistoryPage(db,sid,{kind:'studies',page:1,limit:10}),{code:'MI_ESPACIO_SOURCE_UNAVAILABLE'});
 assert.throws(()=>h.queryHistory(db,'invalid,query',{kind:'studies',page:1,limit:10}),/Invalid linked/);
});
test('route requires auth and restricts response to own staff',()=>{
 assert.match(route,/app.get\('\/api\/me\/research-history', authenticateToken, apiLimiter/);
 assert.match(route,/req.user.medical_staff_id/);
 assert.doesNotMatch(route.slice(route.indexOf("app.get('/api/me/research-history'"),route.indexOf("app.post('/api/auth/register'")),/req.query.staff_id|req.params.staff_id/);
});

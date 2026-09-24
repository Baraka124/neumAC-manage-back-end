(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.Entry46=api;})(typeof globalThis!=='undefined'?globalThis:this,function(){
  'use strict';
  const clean=(s,n)=>typeof s==='string'?s.trim().slice(0,n):'';
  function safeImage(value){const s=clean(value,180);return /^(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_-]+\.(?:svg|png|jpe?g|webp|avif)$/i.test(s)?s:'';}
  function stamp(v){if(v===null||v===undefined||v==='')return null;if(typeof v!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/.test(v))return NaN;const d=new Date(v.slice(0,10)+'T00:00:00Z');if(!Number.isFinite(+d)||d.toISOString().slice(0,10)!==v.slice(0,10))return NaN;return Date.parse(v);}
  function safeLink(value){try{const u=new URL(clean(value,1000));return u.protocol==='https:'&&!u.username&&!u.password?u.href:'';}catch(_){return '';}}
  const fallback={id:'welcome',category:'At neumAC',title:'A place for shared knowledge.',summary:'Pneumology · Área Sanitaria de A Coruña y Cee',detail:'',navTitle:'Welcome to neumAC',image:'',imageAlt:'',imageCredit:'neumAC',accent:'sage'};
  function active(items,now=Date.now()){
    if(!Array.isArray(items))return [{...fallback}];
    const seen=new Set(),valid=[];
    for(const x of items){
      if(!x||x.enabled!==true||x.audience!=='public')continue;
      const id=clean(x.id,60),title=clean(x.title,110),start=stamp(x.startsAt),end=stamp(x.expiresAt);
      if(!id||seen.has(id)||!title||Number.isNaN(start)||Number.isNaN(end)||(start!==null&&end!==null&&end<=start)||(start!==null&&now<start)||(end!==null&&now>=end))continue;
      seen.add(id);valid.push({id,title,category:clean(x.category,45)||'At neumAC',summary:clean(x.summary,240),detail:clean(x.detail,650),navTitle:clean(x.navTitle,70)||title,image:safeImage(x.image),imageAlt:clean(x.imageAlt,200),imageCredit:clean(x.imageCredit,100),accent:['sage','sand','blue'].includes(x.accent)?x.accent:'sage',linkUrl:safeLink(x.linkUrl),linkLabel:clean(x.linkLabel,40)||'Read more'});
    }
    return valid.slice(0,3).length?valid.slice(0,3):[{...fallback}];
  }
  return {active,safeImage,safeLink};
});

/* neumDesk V46.14 · Phase 5.1.2 · Production frontend · 2026-09-24 */
/* Public login editorial content. Never copy internal announcements here automatically.
   Only enabled entries explicitly marked audience:'public' can appear before sign-in.
   Optional startsAt/expiresAt must be ISO timestamps with Z or an explicit offset.
   Artwork is a local decorative SVG; replace with a cleared local photograph if desired. */
(function(root){
  const stories=[
    {id:'research',enabled:true,audience:'public',category:'Research & knowledge',title:'Every study begins with a clinical question.',summary:'Explore the questions, collaborations and research programmes that connect our work in respiratory medicine.',detail:'A question from clinical practice can become a shared research objective. Bringing different perspectives together helps define what to investigate, how to study it and what the findings could mean for care.',navTitle:'Clinical questions. Shared knowledge.',image:'entry-art-research.svg',imageAlt:'',imageCredit:'Abstract editorial illustration',accent:'sage'},
    {id:'innovation',enabled:true,audience:'public',category:'Clinical innovation',title:'A better way can start with an everyday observation.',summary:'Clinical experience creates opportunities to explore, develop and evaluate new approaches.',detail:'Innovation begins with understanding a need. Clinical, research and technical perspectives help turn an observation into a question that can be explored, tested and refined.',navTitle:'From observation to possibility.',image:'entry-art-innovation.svg',imageAlt:'',imageCredit:'Abstract editorial illustration',accent:'sand'},
    {id:'community',enabled:true,audience:'public',category:'People & collaboration',title:'Progress is a shared endeavour.',summary:'Care, research and learning bring different perspectives into the same conversation.',detail:'Sharing questions, experience and knowledge creates opportunities to learn together. Every discipline contributes a different perspective on the work we share.',navTitle:'People make the connection.',image:'entry-art-community.svg',imageAlt:'',imageCredit:'Abstract editorial illustration',accent:'blue'}
  ];
  if(typeof module==='object'&&module.exports) module.exports=stories;
  else root.NEUMDESK_ENTRY_HIGHLIGHTS=stories;
})(typeof globalThis!=='undefined'?globalThis:this);

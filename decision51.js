/* neumDesk V46.14 · Phase 5.2 · Operational Decision Intelligence · 2026-09-24 */
/* neumDesk V46.14 · Shared Decision Intelligence Engine
 * Phase 5.2 domains: Rotations + Leave + On-call. Browser: window.Decision51. Node: module.exports.
 * UI-free and storage-free by design.
 */
(function(root,factory){
  const api=factory();
  if(typeof module==='object'&&module.exports) module.exports=api;
  if(root) root.Decision51=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(){
  'use strict';

  const VERSION='decision51.rotation.v1';
  const LEAVE_VERSION='decision51.leave.v1';
  const ONCALL_VERSION='decision51.oncall.v1';
  const LEVELS=['pass','context','advisory','warning','block'];
  const rank=s=>Math.max(0,LEVELS.indexOf(s));
  const maxSeverity=(findings=[])=>findings.reduce((m,f)=>rank(f.severity)>rank(m)?f.severity:m,'pass');
  const iso=v=>{
    if(!v) return null;
    if(typeof v==='string'){
      const m=v.match(/^(\d{4})-(\d{2})-(\d{2})/); if(m) return `${m[1]}-${m[2]}-${m[3]}`;
    }
    const d=v instanceof Date?new Date(v):new Date(v);
    if(Number.isNaN(d.getTime())) return null;
    return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  };
  const date=v=>{const s=iso(v);return s?new Date(`${s}T12:00:00`):null};
  const addDays=(v,n)=>{const d=date(v);if(!d)return null;d.setDate(d.getDate()+n);return iso(d)};
  const daysInclusive=(a,b)=>{const x=date(a),y=date(b);if(!x||!y||y<x)return 0;return Math.round((y-x)/86400000)+1};
  const overlap=(a1,a2,b1,b2)=>{const s=[iso(a1),iso(b1)].sort().pop(),e=[iso(a2),iso(b2)].sort()[0];return s&&e&&s<=e?{start:s,end:e,days:daysInclusive(s,e)}:null};
  const monthEnd=v=>{const d=date(v);if(!d)return null;return iso(new Date(d.getFullYear(),d.getMonth()+1,0,12))};
  const monthStart=v=>{const d=date(v);if(!d)return null;return iso(new Date(d.getFullYear(),d.getMonth(),1,12))};
  const dayOfMonth=v=>date(v)?.getDate()||null;
  const sameMonth=(a,b)=>{const x=date(a),y=date(b);return !!(x&&y&&x.getFullYear()===y.getFullYear()&&x.getMonth()===y.getMonth())};
  const clean=(arr)=>Array.isArray(arr)?arr.filter(Boolean):[];
  const activeStatus=s=>['active','scheduled','extended'].includes(String(s||'').toLowerCase());
  const activeAbsence=a=>!['cancelled','returned_to_duty'].includes(String(a?.current_status||'').toLowerCase());
  const effectiveAbsStart=a=>iso(a?.actual_start_date||a?.start_date);
  const effectiveAbsEnd=a=>iso(a?.actual_return_date||a?.end_date);
  const effectiveRotEnd=r=>iso(r?.actual_end_date||r?.end_date);
  const effectiveRotStart=r=>iso(r?.actual_start_date||r?.start_date);
  const finding=(code,severity,title,summary,extra={})=>({code,severity,title,summary,...extra});

  function mergePeriods(periods){
    const sorted=clean(periods).filter(p=>p.start&&p.end).sort((a,b)=>a.start.localeCompare(b.start));
    const out=[];
    for(const p of sorted){
      const prev=out[out.length-1];
      if(prev&&p.start<=addDays(prev.end,1)){
        if(p.end>prev.end) prev.end=p.end;
        prev.peak=Math.max(prev.peak||0,p.peak||0);
      }else out.push({...p});
    }
    return out;
  }

  function capacityProjection(proposal,unit,rotations,excludeId){
    const start=iso(proposal.start),end=iso(proposal.end),cap=Number(unit?.maximum_residents||0)||null;
    if(!start||!end||!cap) return {capacity:cap,peakBefore:0,peakAfter:0,periodsOver:[],periodsAt:[],overlapping:[]};
    const relevant=clean(rotations).filter(r=>String(r.id)!==String(excludeId||'')&&String(r.training_unit_id)===String(proposal.unitId)&&activeStatus(r.rotation_status)&&overlap(start,end,effectiveRotStart(r),effectiveRotEnd(r)));
    let peakBefore=0,peakAfter=0; const over=[],at=[];
    for(let d=start;d<=end;d=addDays(d,1)){
      const before=relevant.filter(r=>{const s=effectiveRotStart(r),e=effectiveRotEnd(r);return s&&e&&s<=d&&e>=d}).length;
      const after=before+1; peakBefore=Math.max(peakBefore,before);peakAfter=Math.max(peakAfter,after);
      if(after>cap) over.push({start:d,end:d,peak:after});
      else if(after===cap) at.push({start:d,end:d,peak:after});
    }
    return {capacity:cap,peakBefore,peakAfter,periodsOver:mergePeriods(over),periodsAt:mergePeriods(at),overlapping:relevant};
  }

  function rotationBlockFinding(proposal){
    const start=iso(proposal.start),end=iso(proposal.end); if(!start||!end) return null;
    if((proposal.category||'clinical_rotation')!=='clinical_rotation') return null;
    const duration=daysInclusive(start,end),sDay=dayOfMonth(start),endOfMonth=monthEnd(end),canonical=sameMonth(start,end)&&start===monthStart(start)&&end===monthEnd(end);
    if(canonical) return null;
    const reasons=[]; let severity='advisory';
    if(sDay>=8){severity='warning';reasons.push(`starts on day ${sDay} of the month`)}
    else if(sDay>1) reasons.push(`starts ${sDay-1} day${sDay-1===1?'':'s'} after the month begins`);
    if(duration<21){severity='warning';reasons.push(`covers only ${duration} days`)}
    else if(duration>40){severity='warning';reasons.push(`covers ${duration} days`)}
    if(!reasons.length&&end!==endOfMonth) reasons.push('does not follow a calendar-month boundary');
    const alignedStart=monthStart(start),alignedEnd=monthEnd(start);
    return finding('ROTATION_NON_STANDARD_BLOCK',severity,severity==='warning'?'Non-standard rotation block':'Rotation dates differ from the usual monthly block',`The proposed clinical rotation ${reasons.join(' and ')}.`,{
      evidence:{start,end,durationDays:duration,usualBlock:{start:alignedStart,end:alignedEnd}},
      policy:{overridable:severity==='warning',invariant:null,reason:'Clinical rotations are normally organised as monthly blocks; deviations require review rather than automatic rejection.'},
      resolutions:[{kind:'adjust_dates',label:'Align to the calendar month',start:alignedStart,end:alignedEnd},{kind:'continue',label:'Keep these dates'}]
    });
  }

  function reviewRotation(input={}){
    const proposal=input.proposal||{};
    const start=iso(proposal.start||proposal.start_date),end=iso(proposal.end||proposal.end_date),residentId=proposal.residentId||proposal.resident_id,unitId=proposal.unitId||proposal.training_unit_id,supervisorId=proposal.supervisorId||proposal.supervising_attending_id,excludeId=proposal.excludeId||proposal.id||null,category=proposal.category||proposal.rotation_category||'clinical_rotation';
    const normalized={residentId,unitId,supervisorId,start,end,excludeId,category};
    const resident=input.resident||null,unit=input.unit||null,supervisor=input.supervisor||null,rotations=clean(input.rotations),absences=clean(input.absences),oncall=clean(input.oncall);
    const findings=[];

    if(!resident) findings.push(finding('RESIDENT_NOT_FOUND','block','Resident record unavailable','The selected resident could not be verified.',{policy:{overridable:false,invariant:'VALID_RESIDENT_REFERENCE'}}));
    else {
      if((resident.employment_status||'active')!=='active') findings.push(finding('RESIDENT_INACTIVE','block','Resident is not active',`${resident.full_name||'The selected resident'} is not recorded as active.`,{policy:{overridable:false,invariant:'ACTIVE_RESIDENT_REQUIRED'}}));
      if(!/resident|medical_resident|fellow|mir/i.test(String(resident.staff_type||''))) findings.push(finding('RESIDENT_NOT_ELIGIBLE','block','Selected person is not a resident',`${resident.full_name||'The selected person'} is not recorded with a resident/fellow staff type.`,{policy:{overridable:false,invariant:'RESIDENT_ROLE_REQUIRED'}}));
    }
    if(!unit) findings.push(finding('UNIT_NOT_FOUND','block','Clinical unit unavailable','The selected clinical unit could not be verified.',{policy:{overridable:false,invariant:'VALID_UNIT_REFERENCE'}}));
    else if((unit.unit_status||'active')==='inactive') findings.push(finding('UNIT_INACTIVE','block','Clinical unit is inactive',`${unit.unit_name||'The selected unit'} is marked inactive.`,{policy:{overridable:false,invariant:'ACTIVE_UNIT_REQUIRED'}}));
    if(!supervisor) findings.push(finding('SUPERVISOR_NOT_FOUND','block','Supervisor unavailable','A formal resident supervisor could not be verified.',{policy:{overridable:false,invariant:'FORMAL_SUPERVISOR_REQUIRED'}}));
    else if((supervisor.employment_status||'active')!=='active') findings.push(finding('SUPERVISOR_INACTIVE','block','Supervisor is not active',`${supervisor.full_name||'The supervisor'} is not recorded as active.`,{policy:{overridable:false,invariant:'ACTIVE_SUPERVISOR_REQUIRED'}}));
    else {
      const supervisorRoleEligible=/attending|physician|fellow/i.test(String(supervisor.staff_type||'')) || supervisor.can_supervise_residents===true;
      if(!supervisorRoleEligible || /resident|medical_resident|mir/i.test(String(supervisor.staff_type||''))) findings.push(finding('SUPERVISOR_NOT_ELIGIBLE','block','Supervisor is not eligible',`${supervisor.full_name||'The selected person'} is not eligible for formal resident supervision.`,{policy:{overridable:false,invariant:'ELIGIBLE_SUPERVISOR_REQUIRED'}}));
    }

    if(!start||!end||end<start) findings.push(finding('INVALID_DATE_WINDOW','block','Invalid rotation dates','The rotation needs a valid start and end date, with the end on or after the start.',{evidence:{start,end},policy:{overridable:false,invariant:'VALID_TEMPORAL_WINDOW'}}));
    if(findings.some(f=>f.code==='INVALID_DATE_WINDOW')) return finalize(normalized,findings,input);

    const duration=daysInclusive(start,end);
    const overlaps=rotations.filter(r=>String(r.id)!==String(excludeId||'')&&String(r.resident_id)===String(residentId)&&activeStatus(r.rotation_status)).map(r=>({record:r,window:overlap(start,end,effectiveRotStart(r),effectiveRotEnd(r))})).filter(x=>x.window);
    for(const x of overlaps){
      const r=x.record,w=x.window,unitName=r.training_unit?.unit_name||r.unit_name||r.training_unit_name||'another clinical unit';
      findings.push(finding('ROTATION_CONCURRENT_PRIMARY','block','Concurrent resident rotation',`${resident?.full_name||'This resident'} already has a ${String(r.rotation_status||'scheduled').replace('_',' ')} rotation in ${unitName} overlapping ${w.days} day${w.days===1?'':'s'}.`,{
        evidence:{conflictId:r.id,unitId:r.training_unit_id,unitName,status:r.rotation_status,start:effectiveRotStart(r),end:effectiveRotEnd(r),overlapStart:w.start,overlapEnd:w.end,overlapDays:w.days},
        policy:{overridable:false,invariant:'ONE_PRIMARY_ROTATION_AT_A_TIME',reason:'A resident cannot hold two blocking rotation assignments over the same dates.'},
        resolutions:[{kind:'open_record',label:'Review existing rotation',recordId:r.id},{kind:'adjust_dates',label:'Start after existing rotation',start:addDays(effectiveRotEnd(r),1),end:addDays(effectiveRotEnd(r),duration)}]
      }));
    }

    const blockPattern=rotationBlockFinding({...normalized,start,end,category}); if(blockPattern) findings.push(blockPattern);

    if(unit){
      const cp=capacityProjection(normalized,unit,rotations,excludeId);
      if(cp.capacity&&cp.periodsOver.length){
        const p=cp.periodsOver[0],extra=cp.periodsOver.length>1?` and ${cp.periodsOver.length-1} other period${cp.periodsOver.length-1===1?'':'s'}`:'';
        findings.push(finding('UNIT_CAPACITY_EXCEEDED','warning','Configured unit capacity would be exceeded',`${unit.unit_name} would reach ${cp.peakAfter}/${cp.capacity} residents from ${p.start} to ${p.end}${extra}.`,{
          evidence:{capacity:cp.capacity,peakProjected:cp.peakAfter,periods:cp.periodsOver,overlappingRotationIds:cp.overlapping.map(r=>r.id)},
          policy:{overridable:true,invariant:null,reason:'Configured capacity is an operational planning limit. An authorised exception may be recorded when a safe local arrangement exists.'},
          resolutions:[{kind:'review_capacity',label:'Review projected occupancy'},{kind:'choose_unit',label:'Choose another unit'},{kind:'continue_exception',label:'Continue with exception'}]
        }));
      } else if(cp.capacity&&cp.periodsAt.length){
        const p=cp.periodsAt[0]; findings.push(finding('UNIT_REACHES_CAPACITY','context','Unit reaches configured capacity',`${unit.unit_name} is projected to reach ${cp.peakAfter}/${cp.capacity} residents during ${p.start} to ${p.end}.`,{evidence:{capacity:cp.capacity,peakProjected:cp.peakAfter,periods:cp.periodsAt},policy:{overridable:false,invariant:null}}));
      }
    }

    const residentLeaves=absences.filter(a=>String(a.staff_member_id)===String(residentId)&&activeAbsence(a)).map(a=>({record:a,window:overlap(start,end,effectiveAbsStart(a),effectiveAbsEnd(a))})).filter(x=>x.window);
    if(residentLeaves.length){
      const days=[...new Set(residentLeaves.flatMap(x=>{const out=[];for(let d=x.window.start;d<=x.window.end;d=addDays(d,1))out.push(d);return out}))].length;
      const ratio=duration?days/duration:0,severity=days<=2?'context':(days<=5&&ratio<0.2?'advisory':'warning');
      findings.push(finding('RESIDENT_LEAVE_OVERLAP',severity,severity==='warning'?'Resident leave materially overlaps the rotation':'Recorded leave occurs during the rotation',`${resident?.full_name||'The resident'} has ${days} recorded leave day${days===1?'':'s'} within the proposed ${duration}-day rotation.`,{
        evidence:{overlapDays:days,rotationDays:duration,share:Number((ratio*100).toFixed(1)),records:residentLeaves.map(x=>({id:x.record.id,start:x.window.start,end:x.window.end,reason:x.record.absence_reason||null}))},
        policy:{overridable:severity==='warning',invariant:null,reason:'Leave can legitimately occur during a rotation; material overlap requires explicit review rather than an automatic block.'},
        resolutions:[{kind:'open_leave',label:'Review leave record'},{kind:'adjust_dates',label:'Adjust rotation dates'},{kind:'continue_exception',label:'Continue with exception'}]
      }));
    }

    const supervisorLeaves=absences.filter(a=>String(a.staff_member_id)===String(supervisorId)&&activeAbsence(a)).map(a=>({record:a,window:overlap(start,end,effectiveAbsStart(a),effectiveAbsEnd(a))})).filter(x=>x.window);
    if(supervisorLeaves.length){
      const days=[...new Set(supervisorLeaves.flatMap(x=>{const out=[];for(let d=x.window.start;d<=x.window.end;d=addDays(d,1))out.push(d);return out}))].length;
      const ratio=duration?days/duration:0,severity=days<=2?'context':(days<=5&&ratio<0.2?'advisory':'warning');
      findings.push(finding('SUPERVISOR_LEAVE_OVERLAP',severity,severity==='warning'?'Supervisor availability needs review':'Supervisor has recorded leave during the rotation',`${supervisor?.full_name||'The formal supervisor'} is recorded away for ${days} day${days===1?'':'s'} during the proposed rotation.`,{
        evidence:{overlapDays:days,rotationDays:duration,share:Number((ratio*100).toFixed(1)),records:supervisorLeaves.map(x=>({id:x.record.id,start:x.window.start,end:x.window.end,reason:x.record.absence_reason||null}))},
        policy:{overridable:severity==='warning',invariant:null,reason:'Short supervisor absences can be managed operationally; material absence needs an explicit supervision plan.'},
        resolutions:[{kind:'choose_supervisor',label:'Choose another supervisor'},{kind:'open_leave',label:'Review supervisor leave'},{kind:'continue_exception',label:'Continue with exception'}]
      }));
    }

    const duties=oncall.filter(o=>(String(o.primary_physician_id)===String(residentId)||String(o.backup_physician_id)===String(residentId))&&iso(o.duty_date)>=start&&iso(o.duty_date)<=end);
    if(duties.length) findings.push(finding('RESIDENT_ONCALL_CONTEXT','context','On-call duties occur during this rotation',`${resident?.full_name||'The resident'} has ${duties.length} recorded on-call dut${duties.length===1?'y':'ies'} during the proposed period.`,{evidence:{count:duties.length,dates:duties.map(x=>iso(x.duty_date)).filter(Boolean)},policy:{overridable:false,invariant:null,reason:'On-call duty is normally compatible with a clinical rotation and is shown as context, not a conflict.'}}));

    const supervised=rotations.filter(r=>String(r.id)!==String(excludeId||'')&&String(r.supervising_attending_id)===String(supervisorId)&&activeStatus(r.rotation_status)&&overlap(start,end,effectiveRotStart(r),effectiveRotEnd(r)));
    if(supervised.length>=3) findings.push(finding('SUPERVISOR_LOAD_CONTEXT','advisory','Supervisor already has several overlapping resident assignments',`${supervisor?.full_name||'The supervisor'} is already recorded as formal supervisor for ${supervised.length} overlapping rotations.`,{evidence:{overlappingAssignments:supervised.map(r=>({id:r.id,residentId:r.resident_id,start:effectiveRotStart(r),end:effectiveRotEnd(r)}))},policy:{overridable:false,invariant:null,reason:'No hard supervision-capacity rule is configured; this is workload context only.'}}));

    return finalize(normalized,findings,input);
  }


  function reviewLeave(input={}){
    const proposal=input.proposal||{};
    const staffId=proposal.staffId||proposal.staff_member_id;
    const coveringStaffId=proposal.coveringStaffId||proposal.covering_staff_id||null;
    const start=iso(proposal.start||proposal.start_date),end=iso(proposal.end||proposal.end_date);
    const excludeId=proposal.excludeId||proposal.id||null;
    const absenceType=proposal.absenceType||proposal.absence_type||'planned';
    const reason=proposal.reason||proposal.absence_reason||'other';
    const coverageArranged=proposal.coverageArranged??proposal.coverage_arranged??!!coveringStaffId;
    const normalized={staffId,coveringStaffId,start,end,excludeId,absenceType,reason,coverageArranged};
    const staff=input.staff||null,coveringStaff=input.coveringStaff||null,absences=clean(input.absences),rotations=clean(input.rotations),oncall=clean(input.oncall);
    const findings=[];

    if(!staff) findings.push(finding('LEAVE_STAFF_NOT_FOUND','block','Staff record unavailable','The selected staff member could not be verified.',{policy:{overridable:false,invariant:'VALID_STAFF_REFERENCE'}}));
    else if((staff.employment_status||'active')!=='active') findings.push(finding('LEAVE_STAFF_INACTIVE','block','Staff member is not active',`${staff.full_name||'The selected staff member'} is not recorded as active.`,{policy:{overridable:false,invariant:'ACTIVE_STAFF_REQUIRED'}}));
    if(!start||!end||end<start) findings.push(finding('LEAVE_INVALID_DATE_WINDOW','block','Invalid leave dates','Leave needs a valid start and end date, with the end on or after the start.',{evidence:{start,end},policy:{overridable:false,invariant:'VALID_TEMPORAL_WINDOW'}}));
    if(coveringStaffId&&String(coveringStaffId)===String(staffId)) findings.push(finding('LEAVE_SELF_COVERAGE','block','Covering clinician cannot be the person on leave','A leave record cannot name the absent staff member as their own cover.',{policy:{overridable:false,invariant:'DISTINCT_COVERING_STAFF'}}));
    if(coveringStaffId&&!coveringStaff) findings.push(finding('LEAVE_COVERING_STAFF_NOT_FOUND','block','Covering staff record unavailable','The named covering staff member could not be verified.',{policy:{overridable:false,invariant:'VALID_COVERING_STAFF_REFERENCE'}}));
    else if(coveringStaff&&(coveringStaff.employment_status||'active')!=='active') findings.push(finding('LEAVE_COVERING_STAFF_INACTIVE','block','Covering clinician is not active',`${coveringStaff.full_name||'The covering clinician'} is not recorded as active.`,{policy:{overridable:false,invariant:'ACTIVE_COVERING_STAFF_REQUIRED'}}));
    if(findings.some(f=>f.code==='LEAVE_INVALID_DATE_WINDOW')) return finalizeLeave(normalized,findings,input);

    const duration=daysInclusive(start,end);
    const duplicate=absences.map(a=>({record:a,window:overlap(start,end,effectiveAbsStart(a),effectiveAbsEnd(a))}))
      .filter(x=>String(x.record.id)!==String(excludeId||'')&&String(x.record.staff_member_id)===String(staffId)&&String(x.record.current_status||'').toLowerCase()!=='cancelled'&&x.window);
    if(duplicate.length){
      const x=duplicate[0];
      findings.push(finding('LEAVE_OVERLAPPING_RECORD','block','Another leave record overlaps this period',`${staff?.full_name||'This staff member'} already has recorded leave overlapping ${x.window.days} day${x.window.days===1?'':'s'}.`,{
        evidence:{recordId:x.record.id,start:effectiveAbsStart(x.record),end:effectiveAbsEnd(x.record),overlapStart:x.window.start,overlapEnd:x.window.end,overlapDays:x.window.days,status:x.record.current_status,reason:x.record.absence_reason||null},
        policy:{overridable:false,invariant:'ONE_EFFECTIVE_ABSENCE_RECORD_PER_PERSON',reason:'Overlapping leave records for the same person create ambiguous availability and coverage state.'},
        resolutions:[{kind:'open_leave',label:'Review existing leave',recordId:x.record.id},{kind:'adjust_dates',label:'Adjust requested dates'}]
      }));
    }

    const staffDuties=oncall.filter(o=>(String(o.primary_physician_id)===String(staffId)||String(o.backup_physician_id)===String(staffId))&&iso(o.duty_date)>=start&&iso(o.duty_date)<=end);
    if(staffDuties.length){
      const prim=staffDuties.filter(o=>String(o.primary_physician_id)===String(staffId));
      const backup=staffDuties.length-prim.length;
      findings.push(finding('LEAVE_ONCALL_OVERLAP','warning','On-call duties need coverage resolution',`${staff?.full_name||'This staff member'} has ${staffDuties.length} recorded on-call dut${staffDuties.length===1?'y':'ies'} during this leave (${prim.length} primary${backup?`, ${backup} backup`:''}).`,{
        evidence:{count:staffDuties.length,primaryCount:prim.length,backupCount:backup,dates:staffDuties.map(o=>iso(o.duty_date)).filter(Boolean),records:staffDuties.map(o=>({id:o.id,date:iso(o.duty_date),role:String(o.primary_physician_id)===String(staffId)?'primary':'backup',coverageAreaId:o.coverage_area_id||null}))},
        policy:{overridable:true,invariant:null,reason:'Leave can be legitimate while duty records still exist, but the unresolved on-call coverage must be acknowledged and managed.'},
        resolutions:[{kind:'review_oncall',label:'Review overlapping duties'},{kind:'find_replacement',label:'Find replacement cover'},{kind:'continue_exception',label:'Record leave with exception'}]
      }));
    }

    const staffRotations=rotations.map(r=>({record:r,window:overlap(start,end,effectiveRotStart(r),effectiveRotEnd(r))}))
      .filter(x=>activeStatus(x.record.rotation_status)&&x.window&&(String(x.record.resident_id)===String(staffId)||String(x.record.supervising_attending_id)===String(staffId)));
    if(staffRotations.length){
      const days=[...new Set(staffRotations.flatMap(x=>{const out=[];for(let d=x.window.start;d<=x.window.end;d=addDays(d,1))out.push(d);return out}))].length;
      const asResident=staffRotations.filter(x=>String(x.record.resident_id)===String(staffId)).length;
      const asSupervisor=staffRotations.length-asResident;
      const ratio=duration?days/duration:0;
      const severity=days<=2?'context':(days<=5&&ratio<0.25?'advisory':'warning');
      findings.push(finding('LEAVE_ROTATION_CONTEXT',severity,severity==='warning'?'Rotation responsibilities need review':'Rotation activity overlaps this leave',`${staff?.full_name||'This staff member'} has ${staffRotations.length} overlapping rotation responsibilit${staffRotations.length===1?'y':'ies'} (${asResident} as resident, ${asSupervisor} as supervisor) across ${days} leave day${days===1?'':'s'}.`,{
        evidence:{overlapDays:days,leaveDays:duration,share:Number((ratio*100).toFixed(1)),residentAssignments:asResident,supervisionAssignments:asSupervisor,records:staffRotations.map(x=>({id:x.record.id,start:x.window.start,end:x.window.end,residentId:x.record.resident_id,supervisorId:x.record.supervising_attending_id,unitId:x.record.training_unit_id}))},
        policy:{overridable:severity==='warning',invariant:null,reason:'Rotation responsibilities may coexist with short leave, but material overlap needs an explicit continuity/supervision plan.'},
        resolutions:[{kind:'review_rotations',label:'Review rotation responsibilities'},{kind:'continue_exception',label:'Record leave with exception'}]
      }));
    }

    if(coveringStaffId&&coveringStaff){
      const coverLeave=absences.map(a=>({record:a,window:overlap(start,end,effectiveAbsStart(a),effectiveAbsEnd(a))}))
        .filter(x=>String(x.record.staff_member_id)===String(coveringStaffId)&&String(x.record.current_status||'').toLowerCase()!=='cancelled'&&x.window);
      if(coverLeave.length){
        findings.push(finding('LEAVE_COVERING_STAFF_UNAVAILABLE','warning','Named cover has overlapping leave',`${coveringStaff.full_name||'The covering clinician'} is also recorded away during part of this leave period.`,{
          evidence:{records:coverLeave.map(x=>({id:x.record.id,start:x.window.start,end:x.window.end,overlapDays:x.window.days}))},
          policy:{overridable:true,invariant:null,reason:'A named covering clinician should normally be available for the period they are covering; an authorised exception may document a partial or alternative arrangement.'},
          resolutions:[{kind:'choose_cover',label:'Choose another covering clinician'},{kind:'continue_exception',label:'Keep cover with exception'}]
        }));
      }
      const coverDuties=oncall.filter(o=>(String(o.primary_physician_id)===String(coveringStaffId)||String(o.backup_physician_id)===String(coveringStaffId))&&iso(o.duty_date)>=start&&iso(o.duty_date)<=end);
      if(coverDuties.length) findings.push(finding('LEAVE_COVERING_STAFF_ONCALL','context','Covering clinician also has on-call duties',`${coveringStaff.full_name||'The covering clinician'} has ${coverDuties.length} recorded on-call dut${coverDuties.length===1?'y':'ies'} during the coverage period.`,{evidence:{count:coverDuties.length,dates:coverDuties.map(o=>iso(o.duty_date)).filter(Boolean)},policy:{overridable:false,invariant:null,reason:'On-call duty does not automatically make a clinician unavailable for daytime/unit coverage; it is shown as context.'}}));
    }

    if(!coverageArranged&&!coveringStaffId) findings.push(finding('LEAVE_COVERAGE_NOT_RECORDED','advisory','No covering clinician is recorded','This leave can be recorded, but no named covering clinician is attached to the record.',{policy:{overridable:false,invariant:null,reason:'Coverage requirements vary by role and service; absence of named cover is surfaced for review rather than treated as a universal block.'},resolutions:[{kind:'choose_cover',label:'Add covering clinician'},{kind:'continue',label:'Record without named cover'}]}));
    const today=iso(new Date());
    if(end&&end<today) findings.push(finding('LEAVE_RETROSPECTIVE_RECORD','context','Retrospective leave record',`This leave period ended before today (${end}).`,{policy:{overridable:false,invariant:null,reason:'Historical recording is permitted and is shown as context.'}}));
    return finalizeLeave(normalized,findings,input);
  }

  function reviewOnCall(input={}){
    const proposal=input.proposal||{};
    const staffId=proposal.staffId||proposal.primaryId||proposal.primary_physician_id;
    const backupId=proposal.backupId||proposal.backup_physician_id||null;
    const dutyDate=iso(proposal.date||proposal.duty_date);
    const coverageAreaId=proposal.coverageAreaId||proposal.coverage_area_id||null;
    const shiftType=proposal.shiftType||proposal.shift_type||'primary_call';
    const excludeId=proposal.excludeId||proposal.id||null;
    const normalized={staffId,backupId,date:dutyDate,coverageAreaId,shiftType,startTime:proposal.startTime||proposal.start_time||null,endTime:proposal.endTime||proposal.end_time||null,excludeId};
    const staff=input.staff||input.primary||null,backup=input.backup||null,coverageArea=input.coverageArea||null,absences=clean(input.absences),oncall=clean(input.oncall);
    const findings=[];
    const eligiblePerson=(p)=>!!(p&&(p.employment_status||'active')==='active'&&(/attending|physician|fellow|resident|medical_resident|mir/i.test(String(p.staff_type||''))||p.oncall_eligible===true));

    if(!staff) findings.push(finding('ONCALL_STAFF_NOT_FOUND','block','Primary clinician unavailable','The selected primary clinician could not be verified.',{policy:{overridable:false,invariant:'VALID_PRIMARY_CLINICIAN'}}));
    else if((staff.employment_status||'active')!=='active') findings.push(finding('ONCALL_STAFF_INACTIVE','block','Primary clinician is not active',`${staff.full_name||'The selected clinician'} is not recorded as active.`,{policy:{overridable:false,invariant:'ACTIVE_PRIMARY_CLINICIAN'}}));
    else if(!eligiblePerson(staff)) findings.push(finding('ONCALL_STAFF_NOT_ELIGIBLE','block','Primary clinician is not on-call eligible',`${staff.full_name||'The selected clinician'} is not recorded in an on-call eligible clinical role.`,{policy:{overridable:false,invariant:'ONCALL_ELIGIBLE_PRIMARY'}}));
    if(!dutyDate) findings.push(finding('ONCALL_INVALID_DATE','block','Invalid duty date','On-call scheduling requires one valid duty date.',{policy:{overridable:false,invariant:'VALID_DUTY_DATE'}}));
    if(backupId&&String(backupId)===String(staffId)) findings.push(finding('ONCALL_BACKUP_SAME_AS_PRIMARY','block','Primary and backup must be different people','The same clinician cannot be recorded as both primary and backup for one duty.',{policy:{overridable:false,invariant:'DISTINCT_PRIMARY_AND_BACKUP'}}));
    if(backupId&&!backup) findings.push(finding('ONCALL_BACKUP_NOT_FOUND','block','Backup clinician unavailable','The selected backup clinician could not be verified.',{policy:{overridable:false,invariant:'VALID_BACKUP_CLINICIAN'}}));
    else if(backupId&&!eligiblePerson(backup)) findings.push(finding('ONCALL_BACKUP_NOT_ELIGIBLE','block','Backup clinician is not eligible',`${backup?.full_name||'The selected backup'} is not an active on-call eligible clinician.`,{policy:{overridable:false,invariant:'ONCALL_ELIGIBLE_BACKUP'}}));
    if(!dutyDate) return finalizeOnCall(normalized,findings,input);

    const today=iso(new Date());
    if(dutyDate<today) findings.push(finding('ONCALL_RETROSPECTIVE_ASSIGNMENT','warning','Duty date is in the past',`This on-call duty is being entered retrospectively for ${dutyDate}.`,{policy:{overridable:true,invariant:null,reason:'Historical data entry may be legitimate, but it should be explicitly acknowledged.'},resolutions:[{kind:'adjust_date',label:'Choose a future/current date'},{kind:'continue_exception',label:'Record retrospectively'}]}));

    const activeLeave=absences.filter(a=>String(a.staff_member_id)===String(staffId)&&String(a.current_status||'').toLowerCase()!=='cancelled'&&effectiveAbsStart(a)<=dutyDate&&effectiveAbsEnd(a)>=dutyDate);
    if(activeLeave.length) findings.push(finding('ONCALL_PRIMARY_ON_LEAVE','warning','Primary clinician has recorded leave',`${staff?.full_name||'The primary clinician'} is recorded away on ${dutyDate}.`,{
      evidence:{records:activeLeave.map(a=>({id:a.id,start:effectiveAbsStart(a),end:effectiveAbsEnd(a),reason:a.absence_reason||null,status:a.current_status||null}))},
      policy:{overridable:true,invariant:null,reason:'The leave record may require correction or an exceptional local arrangement, but scheduling against recorded leave must be explicitly justified.'},
      resolutions:[{kind:'review_leave',label:'Review leave record'},{kind:'choose_primary',label:'Choose another clinician'},{kind:'continue_exception',label:'Schedule with exception'}]
    }));

    if(backupId){
      const backupLeave=absences.filter(a=>String(a.staff_member_id)===String(backupId)&&String(a.current_status||'').toLowerCase()!=='cancelled'&&effectiveAbsStart(a)<=dutyDate&&effectiveAbsEnd(a)>=dutyDate);
      if(backupLeave.length) findings.push(finding('ONCALL_BACKUP_ON_LEAVE','warning','Backup clinician has recorded leave',`${backup?.full_name||'The backup clinician'} is recorded away on ${dutyDate}.`,{evidence:{records:backupLeave.map(a=>({id:a.id,start:effectiveAbsStart(a),end:effectiveAbsEnd(a),reason:a.absence_reason||null}))},policy:{overridable:true,invariant:null,reason:'A backup recorded as away may not provide reliable resilience unless an authorised alternative arrangement exists.'},resolutions:[{kind:'choose_backup',label:'Choose another backup'},{kind:'continue_exception',label:'Keep backup with exception'}]}));
    }

    const sameDate=oncall.filter(o=>String(o.id)!==String(excludeId||'')&&iso(o.duty_date)===dutyDate);
    const samePerson=sameDate.filter(o=>String(o.primary_physician_id)===String(staffId));
    const exactDuplicate=samePerson.filter(o=>String(o.shift_type||'primary_call')===String(shiftType)&&String(o.coverage_area_id||'')===String(coverageAreaId||''));
    if(exactDuplicate.length) findings.push(finding('ONCALL_DUPLICATE_ASSIGNMENT','block','This clinician already has the same duty assignment',`${staff?.full_name||'The clinician'} already has an equivalent ${shiftType.replaceAll('_',' ')} record on ${dutyDate}.`,{evidence:{records:exactDuplicate.map(o=>({id:o.id,coverageAreaId:o.coverage_area_id||null,shiftType:o.shift_type||null}))},policy:{overridable:false,invariant:'NO_DUPLICATE_ONCALL_RECORD',reason:'Duplicate operational records create ambiguous duty ownership.'}}));
    else if(samePerson.length) findings.push(finding('ONCALL_MULTI_AREA_DUTY','warning','Clinician already has another duty that day',`${staff?.full_name||'The clinician'} already has ${samePerson.length} other on-call assignment${samePerson.length===1?'':'s'} on ${dutyDate}.`,{evidence:{records:samePerson.map(o=>({id:o.id,coverageAreaId:o.coverage_area_id||null,shiftType:o.shift_type||null}))},policy:{overridable:true,invariant:null,reason:'One clinician may occasionally cover multiple roles/areas, but the additional duty must be intentional and documented.'},resolutions:[{kind:'review_oncall',label:'Review existing duty'},{kind:'choose_primary',label:'Choose another clinician'},{kind:'continue_exception',label:'Keep multiple duties'}]}));

    if(shiftType==='primary_call'){
      const occupied=sameDate.filter(o=>String(o.shift_type||'primary_call')==='primary_call'&&String(o.primary_physician_id)!==String(staffId)).filter(o=>coverageAreaId?String(o.coverage_area_id||'')===String(coverageAreaId):!o.coverage_area_id);
      if(occupied.length) findings.push(finding('ONCALL_PRIMARY_SLOT_OCCUPIED','block','Primary on-call slot already has a clinician',coverageAreaId?`Another primary clinician is already recorded for this coverage area on ${dutyDate}.`:`Another area-less primary call is already recorded on ${dutyDate}.`,{evidence:{records:occupied.map(o=>({id:o.id,primaryId:o.primary_physician_id,coverageAreaId:o.coverage_area_id||null}))},policy:{overridable:false,invariant:'ONE_PRIMARY_PER_COVERAGE_SLOT',reason:'The same primary coverage slot cannot have two authoritative primary owners.'},resolutions:[{kind:'review_oncall',label:'Review existing primary duty'},{kind:'choose_area',label:'Choose another coverage area'}]}));
    }

    if(backupId){
      const backupPrimary=sameDate.filter(o=>String(o.primary_physician_id)===String(backupId));
      if(backupPrimary.length) findings.push(finding('ONCALL_BACKUP_ALREADY_PRIMARY','advisory','Backup is primary on-call elsewhere that day',`${backup?.full_name||'The backup clinician'} is already recorded as primary on-call on ${dutyDate}.`,{evidence:{records:backupPrimary.map(o=>({id:o.id,coverageAreaId:o.coverage_area_id||null}))},policy:{overridable:false,invariant:null,reason:'This may be acceptable locally, but it reduces the independence of the backup arrangement.'}}));
    } else if(shiftType==='primary_call'){
      const severity=coverageArea?.requires_coverage===true?'warning':'advisory';
      findings.push(finding('ONCALL_NO_BACKUP_RECORDED',severity,severity==='warning'?'Coverage area has no backup recorded':'No backup clinician is recorded',coverageArea?.requires_coverage===true?`${coverageArea.name||'This coverage area'} is configured as requiring coverage, but no backup clinician is assigned.`:'The primary duty has no named backup clinician.',{policy:{overridable:severity==='warning',invariant:null,reason:severity==='warning'?'This area is configured as requiring coverage resilience; proceeding without backup needs an authorised reason.':'Backup is optional unless local coverage policy requires it.'},resolutions:[{kind:'choose_backup',label:'Assign backup'},{kind:severity==='warning'?'continue_exception':'continue',label:severity==='warning'?'Continue with exception':'Continue without backup'}]}));
    }
    return finalizeOnCall(normalized,findings,input);
  }

  function finalizeLeave(proposal,findings,input={}){
    const sorted=[...findings].sort((a,b)=>rank(b.severity)-rank(a.severity)||a.code.localeCompare(b.code));
    const decision=maxSeverity(sorted),warnings=sorted.filter(f=>f.severity==='warning'),blocks=sorted.filter(f=>f.severity==='block');
    return {contract:LEAVE_VERSION,domain:'staff_absence',action:input.action||'record',proposal,decision,canCommit:blocks.length===0,requiresOverride:warnings.some(f=>f.policy?.overridable===true),counts:Object.fromEntries(LEVELS.map(s=>[s,sorted.filter(f=>f.severity===s).length])),findings:sorted,reviewedAt:new Date().toISOString(),sourceState:input.sourceState||null};
  }

  function finalizeOnCall(proposal,findings,input={}){
    const sorted=[...findings].sort((a,b)=>rank(b.severity)-rank(a.severity)||a.code.localeCompare(b.code));
    const decision=maxSeverity(sorted),warnings=sorted.filter(f=>f.severity==='warning'),blocks=sorted.filter(f=>f.severity==='block');
    return {contract:ONCALL_VERSION,domain:'oncall_schedule',action:input.action||'assign',proposal,decision,canCommit:blocks.length===0,requiresOverride:warnings.some(f=>f.policy?.overridable===true),counts:Object.fromEntries(LEVELS.map(s=>[s,sorted.filter(f=>f.severity===s).length])),findings:sorted,reviewedAt:new Date().toISOString(),sourceState:input.sourceState||null};
  }

  function finalize(proposal,findings,input={}){
    const sorted=[...findings].sort((a,b)=>rank(b.severity)-rank(a.severity)||a.code.localeCompare(b.code));
    const decision=maxSeverity(sorted),warnings=sorted.filter(f=>f.severity==='warning'),blocks=sorted.filter(f=>f.severity==='block');
    return {
      contract:VERSION,
      domain:'resident_rotations', action:input.action||'assign', proposal,
      decision, canCommit:blocks.length===0, requiresOverride:warnings.some(f=>f.policy?.overridable===true),
      counts:Object.fromEntries(LEVELS.map(s=>[s,sorted.filter(f=>f.severity===s).length])),
      findings:sorted,
      reviewedAt:new Date().toISOString(),
      sourceState:input.sourceState||null
    };
  }

  return {VERSION,LEAVE_VERSION,ONCALL_VERSION,LEVELS,reviewRotation,reviewLeave,reviewOnCall,maxSeverity,daysInclusive,overlap,capacityProjection};
});

/* neumDesk Phase 5.0 — Temporal Integrity interpreter.
 * Deterministic, dependency-free temporal semantics shared by Grounded actions.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.NeumTemporal = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const DAY = 86400000;
  const norm = s => String(s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/\s+/g, ' ').trim();
  const pad = n => String(n).padStart(2, '0');
  const localIso = d => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
  const parseIso = s => {
    const m = String(s || '').match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (!m) return null;
    const d = new Date(Number(m[1]), Number(m[2])-1, Number(m[3]));
    return d.getFullYear()===Number(m[1]) && d.getMonth()===Number(m[2])-1 && d.getDate()===Number(m[3]) ? d : null;
  };
  const addDays = (iso, n) => { const d=parseIso(iso); if(!d) return null; d.setDate(d.getDate()+n); return localIso(d); };
  const daysBetween = (a,b) => { const da=parseIso(a), db=parseIso(b); return da&&db ? Math.round((db-da)/DAY) : null; };
  const monthEndIso = (year, month0) => localIso(new Date(year, month0+1, 0));

  const MONTHS = {
    jan:0,january:0,enero:0,ene:0,
    feb:1,february:1,febrero:1,
    mar:2,march:2,marzo:2,
    apr:3,april:3,abril:3,abr:3,
    may:4,mayo:4,
    jun:5,june:5,junio:5,
    jul:6,july:6,julio:6,
    aug:7,august:7,agosto:7,ago:7,
    sep:8,sept:8,september:8,septiembre:8,setiembre:8,
    oct:9,october:9,octubre:9,
    nov:10,november:10,noviembre:10,
    dec:11,december:11,diciembre:11,dic:11
  };
  const MONTH_WORD = '(?:jan(?:uary)?|enero|ene|feb(?:ruary)?|febrero|mar(?:ch|zo)?|apr(?:il)?|abril|abr|may|mayo|jun(?:e|io)?|jul(?:y|io)?|aug(?:ust)?|agosto|ago|sep(?:t(?:ember|iembre)?)?|setiembre|oct(?:ober|ubre)?|nov(?:ember|iembre)?|dec(?:ember)?|diciembre|dic)';
  const WEEKDAYS = {
    sun:0,sunday:0,domingo:0,
    mon:1,monday:1,lunes:1,
    tue:2,tues:2,tuesday:2,martes:2,
    wed:3,wednesday:3,miercoles:3,
    thu:4,thur:4,thurs:4,thursday:4,jueves:4,
    fri:5,friday:5,viernes:5,
    sat:6,saturday:6,sabado:6
  };

  function asNow(value) {
    if (value instanceof Date && Number.isFinite(+value)) return new Date(value);
    if (typeof value === 'string') {
      const d = new Date(value);
      if (Number.isFinite(+d)) return d;
    }
    return new Date();
  }

  function resolveMonthToken(token) {
    const t=norm(token);
    if (Object.prototype.hasOwnProperty.call(MONTHS,t)) return MONTHS[t];
    return null;
  }

  function chooseYear(now, month0, day, explicitYear, futureBias=false) {
    if (explicitYear) return Number(explicitYear);
    let year=now.getFullYear();
    const candidate=new Date(year,month0,day);
    const today=new Date(now.getFullYear(),now.getMonth(),now.getDate());
    if (futureBias && candidate < today) year += 1;
    else if (candidate < today && (today-candidate) > 180*DAY) year += 1;
    return year;
  }

  function point(iso, granularity='day', source='explicit', meta={}) {
    return { point: iso, start: iso, end: iso, granularity, source, ...meta };
  }

  function monthSpan(year, month0, source='month') {
    return { point: `${year}-${pad(month0+1)}-01`, start:`${year}-${pad(month0+1)}-01`, end:monthEndIso(year,month0), granularity:'month', source };
  }

  function weekdayAfter(anchorIso, weekday) {
    const anchor=parseIso(anchorIso);
    if(!anchor || weekday===undefined || weekday===null) return null;
    let delta=(weekday-anchor.getDay()+7)%7;
    if(delta===0) delta=7;
    const d=new Date(anchor); d.setDate(d.getDate()+delta);
    return localIso(d);
  }

  function currentWeekSpan(now, offsetWeeks=0) {
    const base=new Date(now.getFullYear(),now.getMonth(),now.getDate());
    const monday=new Date(base);
    const day=base.getDay()||7;
    monday.setDate(base.getDate()-(day-1)+(offsetWeeks*7));
    const sunday=new Date(monday); sunday.setDate(monday.getDate()+6);
    return { point:localIso(monday), start:localIso(monday), end:localIso(sunday), granularity:'week', source:offsetWeeks?'next-week':'this-week' };
  }

  const NUMBER_WORDS={one:1,two:2,three:3,four:4,five:5,six:6,seven:7,eight:8,nine:9,ten:10,eleven:11,twelve:12,uno:1,una:1,dos:2,tres:3,cuatro:4,cinco:5,seis:6,siete:7,ocho:8,nueve:9,diez:10,once:11,doce:12};
  function numberValue(token){ if(/^\d+$/.test(String(token||''))) return Number(token); return NUMBER_WORDS[norm(token)]||null; }

  function parseAtom(text, now, opts={}) {
    const q=norm(text);
    if(!q) return null;

    // Relative anchors.
    if(/\b(today|hoy)\b/.test(q)) return point(localIso(now),'day','relative',{label:'today'});
    if(/\b(tomorrow|manana)\b/.test(q)) { const d=new Date(now); d.setDate(d.getDate()+1); return point(localIso(d),'day','relative',{label:'tomorrow'}); }
    if(/\b(yesterday|ayer)\b/.test(q)) { const d=new Date(now); d.setDate(d.getDate()-1); return point(localIso(d),'day','relative',{label:'yesterday'}); }

    // ISO date.
    let m=q.match(/\b(\d{4})-(\d{2})-(\d{2})\b/);
    if(m && parseIso(m[0])) return point(m[0],'day','iso');

    // European numeric dd/mm[/yyyy] or dd-mm-yyyy. Four-digit-first handled above.
    m=q.match(/\b(\d{1,2})[\/-](\d{1,2})(?:[\/-](\d{4}))?\b/);
    if(m) {
      const day=Number(m[1]), month0=Number(m[2])-1;
      if(month0>=0&&month0<=11&&day>=1&&day<=31){
        const year=chooseYear(now,month0,day,m[3],false);
        const d=new Date(year,month0,day);
        if(d.getMonth()===month0&&d.getDate()===day) return point(localIso(d),'day','numeric');
      }
    }

    // Day month [year], including Spanish "de".
    m=q.match(new RegExp(`\\b(\\d{1,2})\\s*(?:de\\s+)?(${MONTH_WORD})(?:\\s*(?:de\\s+)?(\\d{4}))?\\b`,'i'));
    if(m){
      const day=Number(m[1]), month0=resolveMonthToken(m[2]);
      if(month0!==null&&day>=1&&day<=31){
        const year=chooseYear(now,month0,day,m[3],false);
        const d=new Date(year,month0,day);
        if(d.getMonth()===month0&&d.getDate()===day) return point(localIso(d),'day','named-date');
      }
    }

    // Month day [year].
    m=q.match(new RegExp(`\\b(${MONTH_WORD})\\s+(\\d{1,2})(?:,?\\s*(\\d{4}))?\\b`,'i'));
    if(m){
      const month0=resolveMonthToken(m[1]), day=Number(m[2]);
      if(month0!==null&&day>=1&&day<=31){
        const year=chooseYear(now,month0,day,m[3],false);
        const d=new Date(year,month0,day);
        if(d.getMonth()===month0&&d.getDate()===day) return point(localIso(d),'day','named-date');
      }
    }

    // This/next month.
    if(/\b(this month|este mes)\b/.test(q)) return monthSpan(now.getFullYear(),now.getMonth(),'relative-month');
    if(/\b(next month|proximo mes|mes siguiente)\b/.test(q)) { const d=new Date(now.getFullYear(),now.getMonth()+1,1); return monthSpan(d.getFullYear(),d.getMonth(),'relative-month'); }
    if(/\b(this week|esta semana)\b/.test(q)) return currentWeekSpan(now,0);
    if(/\b(next week|proxima semana|semana siguiente)\b/.test(q)) return currentWeekSpan(now,1);

    // Weekday. "this Monday" stays within the current Mon-Sun window. Bare weekday means upcoming weekday.
    const wdMatch=q.match(/\b(?:(next|this|proximo|este)\s+)?(sunday|sun|domingo|monday|mon|lunes|tuesday|tues|tue|martes|wednesday|wed|miercoles|thursday|thurs|thur|thu|jueves|friday|fri|viernes|saturday|sat|sabado)\b/);
    if(wdMatch){
      const qualifier=wdMatch[1]||''; const wd=WEEKDAYS[wdMatch[2]];
      const base=new Date(now.getFullYear(),now.getMonth(),now.getDate());
      if(qualifier==='this'||qualifier==='este'){
        const current=(base.getDay()+6)%7; const target=(wd+6)%7;
        const d=new Date(base); d.setDate(base.getDate()+(target-current));
        return point(localIso(d),'day','weekday',{label:'this-week'});
      }
      let delta=(wd-base.getDay()+7)%7;
      if(delta===0) delta=7;
      if(qualifier==='next'||qualifier==='proximo') {
        // neumDesk convention: "next Friday" means the coming Friday, not Friday + 7 days.
      }
      const d=new Date(base); d.setDate(base.getDate()+delta);
      return point(localIso(d),'day','weekday',{label:qualifier||'upcoming'});
    }

    // Bare named month [year]. Keep the full month span; the domain policy decides whether that is actionable.
    m=q.match(new RegExp(`\\b(${MONTH_WORD})(?:\\s+(\\d{4}))?\\b`,'i'));
    if(m){
      const month0=resolveMonthToken(m[1]);
      if(month0!==null){
        let year=m[2]?Number(m[2]):now.getFullYear();
        if(!m[2] && /\bnext\b/.test(q) && month0<=now.getMonth()) year++;
        else if(!m[2]) {
          const d=new Date(year,month0,1), today=new Date(now.getFullYear(),now.getMonth(),now.getDate());
          if(d<today && (today-d)>180*DAY) year++;
        }
        return monthSpan(year,month0,'month');
      }
    }
    return null;
  }

  function formatInterpretation(start,end,target,granularity) {
    if(target==='end'&&end&&!start) return `end ${end}`;
    if(target==='start'&&start&&!end) return `start ${start}`;
    if(start&&end&&start!==end) return `${start} → ${end}`;
    if(start||end) return start||end;
    return 'date not established';
  }

  function interpret(input, options={}) {
    const raw=String(input||''); const q=norm(raw); const now=asNow(options.now);
    const domain=options.domain||'generic';
    const forcedTarget=options.target||null;
    let target=forcedTarget;
    let start=null,end=null,granularity='day',source='none',explicitRange=false,confidence='high';
    let needsClarification=false, clarificationReason=null;

    // Determine update intent before generic extraction. "end/until" or "start/from" with one date must not mutate both ends.
    if(!target){
      if(/\b(end|ending|ends|finish|finishes|return date|returning|until|till|through|thru|hasta)\b/.test(q)) target='end';
      else if(/\b(start|starting|starts|begin|begins|from|desde)\b/.test(q)) target='start';
      else target='range';
    }

    const takeSpan=(a,b,rangeSource='range')=>{
      if(!a||!b) return false;
      start=a.granularity==='month'?a.start:a.point;
      end=b.granularity==='month'?b.end:b.point;
      granularity=(a.granularity==='month'||b.granularity==='month')?'mixed':(a.granularity||'day');
      source=rangeSource; explicitRange=true; target='range'; return true;
    };

    // Explicit labelled boundaries, e.g. "start 1 Oct end 31 Oct".
    let m=q.match(/\b(?:start|starting|begin|begins|desde)\s+(.+?)\s+(?:end|ending|finish|until|hasta)\s+(.+)$/);
    if(m) takeSpan(parseAtom(m[1],now),parseAtom(m[2],now),'labelled-range');

    // Shared-month shorthand, e.g. "1 to 31 October" / "between 1 and 31 October".
    if(!start&&!end){
      m=q.match(new RegExp(`\\b(?:from\\s+|between\\s+)?(\\d{1,2})\\s*(?:to|until|through|thru|and|hasta|[-–—])\\s*(\\d{1,2})\\s*(?:de\\s+)?(${MONTH_WORD})(?:\\s*(?:de\\s+)?(\\d{4}))?\\b`,'i'));
      if(m){
        const mo=resolveMonthToken(m[3]), d1=Number(m[1]), d2=Number(m[2]);
        if(mo!==null){
          const yr=chooseYear(now,mo,d1,m[4],false);
          const a=new Date(yr,mo,d1), b=new Date(yr,mo,d2);
          if(a.getMonth()===mo&&b.getMonth()===mo&&d2>=d1) takeSpan(point(localIso(a),'day','shared-month'),point(localIso(b),'day','shared-month'),'shared-month-range');
        }
      }
    }

    // Explicit from/between ranges. Parse each side independently so "tomorrow until 30 Sept" keeps both anchors.
    if(!start&&!end) m=q.match(/\b(?:from|desde)\s+(.+?)\s+(?:until|till|through|thru|to|hasta)\s+(.+)$/);
    if(m) takeSpan(parseAtom(m[1],now),parseAtom(m[2],now),'from-to');
    if(!start&&!end){
      m=q.match(/\b(?:between|entre)\s+(.+?)\s+(?:and|y)\s+(.+)$/);
      if(m) takeSpan(parseAtom(m[1],now),parseAtom(m[2],now),'between');
    }
    if(!start&&!end){
      // Range without "from", e.g. "tomorrow until 30 Sept". Try connectors only when both sides contain temporal atoms.
      const connectors=[/\buntil\b/,/\btill\b/,/\bthrough\b/,/\bthru\b/,/\bhasta\b/,/\bto\b/];
      for(const rx of connectors){
        const hit=rx.exec(q); if(!hit) continue;
        const left=q.slice(0,hit.index), right=q.slice(hit.index+hit[0].length);
        const a=parseAtom(left,now), b=parseAtom(right,now);
        if(a&&b){
          takeSpan(a,b,'connector-range');
          // A weekday on the right is relational in a range. If its ordinary
          // "upcoming" resolution lands before the left boundary, advance it
          // to the next matching weekday instead of manufacturing a backwards range.
          if(start&&end&&end<start&&b.source==='weekday'){
            const wm=norm(right).match(/\b(sunday|sun|domingo|monday|mon|lunes|tuesday|tues|tue|martes|wednesday|wed|miercoles|thursday|thurs|thur|thu|jueves|friday|fri|viernes|saturday|sat|sabado)\b/);
            if(wm){ const adjusted=weekdayAfter(start,WEEKDAYS[wm[1]]); if(adjusted) end=adjusted; }
          }
          break;
        }
      }
    }

    // Relative window, e.g. "next 3 days" / "next two weeks".
    if(!start&&!end){
      m=q.match(/\bnext\s+(\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)\s+(day|days|week|weeks)\b/);
      if(m){
        const n=Math.max(1,numberValue(m[1])||1), unit=m[2];
        start=localIso(now); end=addDays(start,/week/.test(unit)?n*7-1:n-1);
        explicitRange=true; target='range'; granularity='duration'; source='relative-duration';
      }
    }

    // Duration, e.g. "from tomorrow for 3 days" or "tomorrow for 2 weeks".
    if(!start&&!end){
      m=q.match(/\bfor\s+(\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|uno|una|dos|tres|cuatro|cinco|seis|siete|ocho|nueve|diez|once|doce)\s+(day|days|week|weeks|month|months|dia|dias|semana|semanas|mes|meses)\b/);
      if(m){
        const before=q.slice(0,m.index), a=parseAtom(before,now)||parseAtom(q,now);
        if(a){
          start=a.granularity==='month'?a.start:a.point;
          const n=Math.max(1,numberValue(m[1])||1); const unit=m[2];
          if(/week|semana/.test(unit)) end=addDays(start,n*7-1);
          else if(/month|mes/.test(unit)) { const d=parseIso(start); const e=new Date(d.getFullYear(),d.getMonth()+n,d.getDate()); e.setDate(e.getDate()-1); end=localIso(e); }
          else end=addDays(start,n-1);
          explicitRange=true; target='range'; granularity='duration'; source='duration';
        }
      }
    }

    // If still unresolved, parse the best single atom / month span.
    if(!start&&!end){
      const a=parseAtom(q,now,{domain});
      if(a){
        granularity=a.granularity||'day'; source=a.source||'single';
        if(a.start&&a.end&&a.start!==a.end&&(a.granularity==='month'||a.granularity==='week')){
          if(target==='end' && (forcedTarget==='end' || /\b(end|ending|ends|finish|finishes|until|hasta)\b/.test(q))) { end=a.end; source=a.source||a.granularity; }
          else if(target==='start' && (forcedTarget==='start' || /\b(start|starting|starts|begin|begins|desde)\b/.test(q))) { start=a.start; source=a.source||a.granularity; }
          else if(domain==='rotation'||domain==='generic') { start=a.start; end=a.end; target='range'; explicitRange=true; }
          else if(domain==='leave') { start=a.start; end=a.end; target='range'; explicitRange=true; if(a.granularity==='month'){needsClarification=true;clarificationReason='leave_month_requires_confirmation';confidence='medium';} }
          else if(domain==='oncall') { start=a.start; end=a.end; target='range'; explicitRange=true; needsClarification=true; clarificationReason=a.granularity==='month'?'oncall_month_requires_single_date':'oncall_range_requires_batch'; confidence='low'; }
          else { start=a.start; end=a.end; target='range'; explicitRange=true; }
        } else if(target==='end') { end=a.point; }
        else if(target==='start') { start=a.point; }
        else { start=a.point; end=a.point; }
      }
    }

    // If target is end/start but a range was explicitly supplied, the range wins. For a single target keep only that endpoint.
    if(!explicitRange && forcedTarget==='end' && start && !end){ end=start; start=null; target='end'; }
    if(!explicitRange && forcedTarget==='start' && end && !start){ start=end; end=null; target='start'; }

    // Domain policies.
    if(domain==='rotation' && !options.allowPartial){
      if(start&&end&&start===end&&granularity!=='month') { needsClarification=true; clarificationReason='rotation_end_required'; confidence='medium'; end=null; target='start'; }
      else if(start&&!end&&target!=='end') { needsClarification=true; clarificationReason='rotation_end_required'; confidence='medium'; }
      else if(!start&&end&&target==='end') { /* explicit end-only interpretation retained for follow-up/extend flows */ }
    }
    if(domain==='oncall' && start&&end&&start!==end){ needsClarification=true; clarificationReason='oncall_range_requires_batch'; confidence='low'; }
    else if(domain==='oncall' && (!start || !end)){ needsClarification=true; clarificationReason='oncall_requires_single_date'; confidence='low'; }

    if(start&&end&&end<start){ needsClarification=true; clarificationReason='end_before_start'; confidence='low'; }

    return {
      start,end,target,granularity,explicitRange,source,confidence,
      needsClarification,clarificationReason,
      interpretation:formatInterpretation(start,end,target,granularity),
      raw
    };
  }

  return { interpret, parseAtom, addDays, daysBetween };
});

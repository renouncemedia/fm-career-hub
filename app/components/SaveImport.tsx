"use client";
import { useMemo, useRef, useState } from "react";
import { parseSave, type FM24Save, type FM24Player } from "../lib/fm24-save-parser";

type Props = { db:any; career:any; session:any; onDone:()=>Promise<void> };
type Preview = { save:FM24Save; fileName:string; existing:number; fresh:number; ambiguous:number; unmatched:number; squad:number; otherClubs:number; noClub:number };
const normalise=(s:string)=>s.normalize("NFD").replace(/[\u0300-\u036f]/g,"").toLowerCase().replace(/[^a-z0-9]/g,"");
const uniqueByName=(players:FM24Player[])=>{const m=new Map<string,number>();for(const p of players){const k=normalise(p.fullName||p.name);m.set(k,(m.get(k)||0)+1);}return m;};
const clubKey=(value:string|null|undefined)=>{
 const key=normalise(value||"");
 const aliases:Record<string,string>={"sportingcp":"sporting","sportingclubedeportugal":"sporting","sportingclubedeportugalfutebol":"sporting"};
 return aliases[key]||key;
};
const sameClub=(playerClub:string|null|undefined,careerClub:string|null|undefined)=>{
 const player=clubKey(playerClub),career=clubKey(careerClub);
 return !!player&&!!career&&player===career;
};

export default function SaveImport({db,career,session,onDone}:Props){
 const input=useRef<HTMLInputElement>(null);
 const [preview,setPreview]=useState<Preview|null>(null);
 const [progress,setProgress]=useState(0);
 const [message,setMessage]=useState("");
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState("");
 const [done,setDone]=useState("");
 const [fields,setFields]=useState<string[]>(["name","birthDate","nationality","positions","ca","pa","age","club"]);
 const importFields=[["name","Nome"],["birthDate","Data de nascimento"],["nationality","Nacionalidade"],["positions","Posição"],["ca","CA"],["pa","PA / CA potencial"],["age","Idade"],["club","Clube"]];
 const counts=useMemo(()=>preview?{total:preview.save.players.length,existing:preview.existing,fresh:preview.fresh,ambiguous:preview.ambiguous,unmatched:preview.unmatched,squad:preview.squad,otherClubs:preview.otherClubs,noClub:preview.noClub}:null,[preview]);
 async function inspect(file?:File){
  if(!file)return;
  setBusy(true);setError("");setDone("");setPreview(null);setProgress(0);
  try{
   if(!file.name.toLowerCase().endsWith(".fm"))throw new Error("Seleciona um ficheiro de save com extensão .fm.");
   const bytes=new Uint8Array(await file.arrayBuffer());
   const save=await parseSave(bytes,(p,m)=>{setProgress(Math.round(p));setMessage(m);});
   const {data:people,error:peopleError}=await db.from("players").select("id,full_name,external_ids").eq("owner_id",session.user.id);
   if(peopleError)throw peopleError;
   const {data:links,error:linkError}=await db.from("career_players").select("id,player_id").eq("career_id",career.id);
   if(linkError)throw linkError;
   const linkByPlayer=new Map((links||[]).map((x:any)=>[x.player_id,x.id]));
   const byFmId=new Map<number,any>(),byName=new Map<string,any[]>();
   for(const p of people||[]){
    const fmId=Number(p.external_ids?.fm24?.id);
    if(Number.isFinite(fmId)&&p.external_ids?.fm24?.id!==undefined)byFmId.set(fmId,p);
    const k=normalise(p.full_name||"");if(k){const a=byName.get(k)||[];a.push(p);byName.set(k,a);}
   }
   const countsByName=uniqueByName(save.players);let existing=0,fresh=0,ambiguous=0,unmatched=0,squad=0,otherClubs=0,noClub=0;
   const targetClub=String(career.club_name||"");
   for(const p of save.players){
    if(!p.club){noClub++;continue;}
    if(!sameClub(p.club,targetClub)){otherClubs++;continue;}
    squad++;
    const match=byFmId.get(p.id)||((byName.get(normalise(p.fullName||p.name))||[]).length===1?(byName.get(normalise(p.fullName||p.name))||[])[0]:null);
    if(match){if(linkByPlayer.has(match.id))existing++;else fresh++;}
    else if((byName.get(normalise(p.fullName||p.name))||[]).length>1||(countsByName.get(normalise(p.fullName||p.name))||0)>1)ambiguous++;
    else fresh++;
   }
   unmatched=0;
   setPreview({save,fileName:file.name,existing,fresh,ambiguous,unmatched,squad,otherClubs,noClub});
   setMessage("Análise concluída. Confirma antes de importar.");
  }catch(e:any){setError(e.message||"Não foi possível analisar o save.");}
  setBusy(false);
 }
 async function apply(){
  if(!preview)return;
  setBusy(true);setError("");setDone("");setProgress(0);
  let created=0,updated=0,skipped=0;
  try{
   const {data:people,error:peopleError}=await db.from("players").select("id,full_name,external_ids").eq("owner_id",session.user.id);
   if(peopleError)throw peopleError;
   const {data:links,error:linkError}=await db.from("career_players").select("id,player_id").eq("career_id",career.id);
   if(linkError)throw linkError;
   const byFmId=new Map<number,any>(),byName=new Map<string,any[]>();
   for(const p of people||[]){
    const id=Number(p.external_ids?.fm24?.id);if(Number.isFinite(id)&&p.external_ids?.fm24?.id!==undefined)byFmId.set(id,p);
    const k=normalise(p.full_name||"");if(k){const a=byName.get(k)||[];a.push(p);byName.set(k,a);}
   }
   const linkByPlayer=new Map((links||[]).map((x:any)=>[x.player_id,x.id]));
   const seen=new Set<string>();
   const squadPlayers=preview.save.players.filter(p=>sameClub(p.club,String(career.club_name||"")));
   if(!squadPlayers.length){const detected=[...new Set(preview.save.players.map(p=>p.club).filter(Boolean))].slice(0,20).join(", ");throw new Error("Não encontrei correspondência para o clube da carreira ("+(career.club_name||"não definido")+"). Clubes detetados no save: "+(detected||"nenhum identificado")+". Nenhum jogador foi importado.");}
   for(let i=0;i<squadPlayers.length;i++){
    const p=squadPlayers[i],key=normalise(p.fullName||p.name);
    if(seen.has(String(p.id))){skipped++;continue;}seen.add(String(p.id));
    const candidates=byName.get(key)||[];
    let existing=byFmId.get(p.id)|| (candidates.length===1?candidates[0]:null);
    if(candidates.length>1&&!byFmId.has(p.id)){skipped++;continue;}
    const externalIds={...(existing?.external_ids||{}),fm24:{id:p.id,uid:p.uid,formatVersion:preview.save.formatVersion}};
    let playerId:string;
    if(existing){
     playerId=existing.id;
     const playerPatch:any={external_ids:externalIds,updated_at:new Date().toISOString()};
     if(fields.includes("name"))playerPatch.full_name=p.fullName||p.name;
     if(fields.includes("birthDate"))playerPatch.date_of_birth=p.birthDate;
     if(fields.includes("nationality"))playerPatch.nationality=(await import("../lib/fm24-save-parser")).NATIONS[String(p.nationId)]||null;
     if(fields.includes("positions"))playerPatch.positions=p.positions;
     const u=await db.from("players").update(playerPatch).eq("id",playerId);
     if(u.error)throw u.error;
     const linkId=linkByPlayer.get(playerId);
     if(linkId){
      const careerPatch:any={updated_at:new Date().toISOString()};
      if(fields.includes("ca"))careerPatch.ca=p.ca;
      if(fields.includes("pa"))careerPatch.pa=p.pa;
      if(fields.includes("age"))careerPatch.age=p.age;
      if(fields.includes("club"))careerPatch.club_name=p.club||null;
      if(fields.includes("positions"))careerPatch.position=p.positions.join(", ");
      const l=await db.from("career_players").update(careerPatch).eq("id",linkId);
      if(l.error)throw l.error;
     }else{
      const l=await db.from("career_players").insert({owner_id:session.user.id,career_id:career.id,player_id:playerId,squad_status:"Plantel principal",club_name:fields.includes("club")?p.club||null:career.club_name,position:fields.includes("positions")?p.positions.join(", "):null,ca:fields.includes("ca")?p.ca:null,pa:fields.includes("pa")?p.pa:null,age:fields.includes("age")?p.age:null});
      if(l.error)throw l.error;
     }
     updated++;
    }else{
     const ins=await db.from("players").insert({owner_id:session.user.id,full_name:p.fullName||p.name,date_of_birth:p.birthDate,nationality:(await import("../lib/fm24-save-parser")).NATIONS[String(p.nationId)]||null,positions:p.positions,external_ids:externalIds}).select("id").single();
     if(ins.error)throw ins.error;playerId=ins.data.id;
     const l=await db.from("career_players").insert({owner_id:session.user.id,career_id:career.id,player_id:playerId,squad_status:"Plantel principal",club_name:p.club||null,position:p.positions.join(", "),ca:p.ca,pa:p.pa,age:p.age});
     if(l.error)throw l.error;created++;
    }
    const snap=await db.from("player_attribute_snapshots").insert({owner_id:session.user.id,career_id:career.id,player_id:playerId,ca:p.ca,pa:p.pa,attributes:{...p.attributes,positionRatings:p.positionRatings,rawAttributes:p.rawAttributes,gameDate:preview.save.gameDate,formatVersion:preview.save.formatVersion},source:"Save FM24"});
    if(snap.error)throw snap.error;
    if(i%10===0){setProgress(Math.round((i+1)/squadPlayers.length*100));setMessage("A guardar jogadores e snapshots...");}
   }
   const log=await db.from("import_jobs").insert({owner_id:session.user.id,career_id:career.id,source_format:"fm24-save",file_name:preview.fileName,status:"completed",records_total:preview.save.players.length,records_created:created,records_updated:updated,records_skipped:skipped,report:{gameDate:preview.save.gameDate,formatVersion:preview.save.formatVersion,saveName:preview.save.name,warnings:preview.save.warnings},completed_at:new Date().toISOString()});
   if(log.error)throw log.error;
   setDone("Importação concluída: "+created+" novos, "+updated+" atualizados, "+skipped+" ignorados.");
   setPreview(null);await onDone();
  }catch(e:any){setError(e.message||"Erro ao guardar os dados importados.");}
  setBusy(false);
 }
 return <section className="panel" style={{marginBottom:20}}>
  <div className="panel-heading"><div><p className="eyebrow">IMPORTAÇÃO AVANÇADA</p><h2>Save Football Manager 2024</h2></div><span className="status-tag">FM24 · 24.3</span></div>
  <p className="intro">Lê o ficheiro .fm e importa para o plantel apenas os jogadores cujo clube coincide com o clube da carreira. Os restantes clubes são ignorados. O parser só valida saves no formato <b>24.3.0+0</b>.</p>
  <input ref={input} type="file" accept=".fm" hidden onChange={e=>void inspect(e.target.files?.[0])}/>
  <div className="panel-actions"><button className="outline-btn" disabled={busy} onClick={()=>input.current?.click()}>{busy?"A analisar...":"Selecionar save .fm"}</button>{preview&&<button className="primary-btn" disabled={busy||fields.length===0} onClick={()=>void apply()}>Importar jogadores</button>}</div>
  {preview&&<div className="import-field-picker"><h3>Escolhe o que atualizar nos jogadores existentes</h3><p className="module-description">Os campos desmarcados ficam exatamente como estão. Os jogadores novos recebem os dados disponíveis no ficheiro.</p><div className="form-grid">{importFields.map(([key,label])=><label key={key}><input type="checkbox" checked={fields.includes(key)} onChange={e=>setFields(old=>e.target.checked?[...old,key]:old.filter(x=>x!==key))}/> {label}</label>)}</div></div>}
  {busy&&<div style={{marginTop:14}}><div className="filters"><b>{progress}%</b><span>{message}</span></div><div style={{height:7,background:"var(--line)",borderRadius:8,overflow:"hidden"}}><div style={{height:"100%",width:progress+"%",background:"var(--accent)",transition:"width .2s"}}/></div></div>}
  {counts&&<><div className="stat-grid" style={{marginTop:16}}><article><span>JOGADORES NO SAVE</span><strong>{counts.total}</strong></article><article><span>DO TEU CLUBE</span><strong>{counts.squad}</strong></article><article><span>OUTROS CLUBES (IGNORADOS)</span><strong>{counts.otherClubs}</strong></article><article><span>SEM CLUBE (IGNORADOS)</span><strong>{counts.noClub}</strong></article></div><div className="stat-grid" style={{marginTop:10}}><article><span>JÁ NA CARREIRA</span><strong>{counts.existing}</strong></article><article><span>REGISTOS NOVOS</span><strong>{counts.fresh}</strong></article><article><span>NOMES AMBÍGUOS</span><strong>{counts.ambiguous}</strong></article><article><span>A IMPORTAR</span><strong>{counts.squad}</strong></article></div></>}
  {preview&&preview.save.warnings.length>0&&<p className="alert">{preview.save.warnings.join(" ")}</p>}
  {error&&<p className="alert error">{error}</p>}{done&&<p className="alert success">{done}</p>}
 </section>;
}

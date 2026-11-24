"use client";
import { useMemo, useRef, useState } from "react";
import { parseSave, type FM24Save, type FM24Player } from "../lib/fm24-save-parser";

type Props = { db:any; career:any; session:any; onDone:()=>Promise<void> };
type Preview = { save:FM24Save; fileName:string; existing:number; fresh:number; ambiguous:number; unmatched:number; squad:number; loanedOut:number; otherClubs:number; noClub:number };
const normalise=(s:string)=>s.normalize("NFD").replace(/[\u0300-\u036f]/g,"").toLowerCase().replace(/[^a-z0-9]/g,"");
const uniqueByName=(players:FM24Player[])=>{const m=new Map<string,number>();for(const p of players){const k=normalise(p.fullName||p.name);m.set(k,(m.get(k)||0)+1);}return m;};
const clubKey=(value:string|null|undefined)=>{
 let key=normalise(value||"");
 // Equipas B, reservas e escalões de formação pertencem ao clube-mãe.
 key=key.replace(/(?:b|ii|u(?:19|20|21|23)|reserves?|reservas|sub(?:19|20|21|23))$/,"");
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
 const [minPAForCaNovo,setMinPAForCaNovo]=useState(150);
 const importFields=[["name","Nome"],["birthDate","Data de nascimento"],["nationality","Nacionalidade"],["positions","Posição"],["ca","CA"],["pa","PA / CA potencial"],["caNovo","CA Novo"],["age","Idade"],["club","Clube"]];
 const counts=useMemo(()=>preview?{total:preview.save.players.length,existing:preview.existing,fresh:preview.fresh,ambiguous:preview.ambiguous,unmatched:preview.unmatched,squad:preview.squad,loanedOut:preview.loanedOut,otherClubs:preview.otherClubs,noClub:preview.noClub}:null,[preview]);
 async function inspect(file?:File){
  if(!file)return;
  setBusy(true);setError("");setDone("");setPreview(null);setProgress(0);
  try{
   if(!file.name.toLowerCase().endsWith(".fm"))throw new Error("Seleciona um ficheiro de save com extensão .fm.");
   const bytes=new Uint8Array(await file.arrayBuffer());
   const save=await parseSave(bytes,(p,m)=>{setProgress(Math.round(p));setMessage(m);},{clubName:career?.club_name||''});
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
   const countsByName=uniqueByName(save.players);let existing=0,fresh=0,ambiguous=0,unmatched=0,squad=0,loanedOut=0,otherClubs=0,noClub=0;
   const targetClub=String(career.club_name||"");
   for(const p of save.players){
    const belongsToCareer=sameClub(p.club,targetClub)||sameClub(p.contractClub,targetClub);
    if(!belongsToCareer){if(!p.club)noClub++;else otherClubs++;continue;}
    squad++;
    if(p.contractClub&&p.club&&!sameClub(p.contractClub,p.club))loanedOut++;
    const match=byFmId.get(p.id)||((byName.get(normalise(p.fullName||p.name))||[]).length===1?(byName.get(normalise(p.fullName||p.name))||[])[0]:null);
    if(match){if(linkByPlayer.has(match.id))existing++;else fresh++;}
    else if((byName.get(normalise(p.fullName||p.name))||[]).length>1||(countsByName.get(normalise(p.fullName||p.name))||0)>1)ambiguous++;
    else fresh++;
   }
   unmatched=0;
   setPreview({save,fileName:file.name,existing,fresh,ambiguous,unmatched,squad,loanedOut,otherClubs,noClub});
   setMessage("Análise concluída. Confirma antes de importar.");
  }catch(e:any){setError(e.message||"Não foi possível analisar o save.");}
  setBusy(false);
 }
 async function apply(){
  if(!preview||!db||!career||!session?.user)return;
  setBusy(true);setError("");setDone("");setProgress(0);
  try{
   const {data:people,error:peopleError}=await db.from("players").select("id,full_name,external_ids").eq("owner_id",session.user.id);
   if(peopleError)throw peopleError;
   const {data:links,error:linkError}=await db.from("career_players").select("id,player_id").eq("career_id",career.id);
   if(linkError)throw linkError;
   const byFmId=new Map<number,any>(),byName=new Map<string,any[]>();
   for(const person of people||[]){
    const id=Number(person.external_ids?.fm24?.id);
    if(Number.isFinite(id)&&person.external_ids?.fm24?.id!==undefined)byFmId.set(id,person);
    const k=normalise(person.full_name||"");
    if(k){const a=byName.get(k)||[];a.push(person);byName.set(k,a);}
   }
   const linkByPlayer=new Map((links||[]).map((x:any)=>[x.player_id,x.id]));
   let seasonPayload:any=null;
   if(preview.save.gameDate){
    const gameDate=new Date(preview.save.gameDate);
    if(Number.isFinite(gameDate.getTime())){
     const year=gameDate.getUTCFullYear(),month=gameDate.getUTCMonth()+1;
     const seasonStart=month>=7?year:year-1;
     seasonPayload={label:String(seasonStart)+"/"+String(seasonStart+1).slice(-2),start_date:String(seasonStart)+"-07-01",end_date:String(seasonStart+1)+"-06-30",notes:"Criada automaticamente a partir da data do save FM24."};
    }
   }
   const seen=new Set<string>(),rows:any[]=[];
   let skipped=0,created=0,updated=0;
   const squadPlayers=preview.save.players.filter(p=>sameClub(p.club,String(career.club_name||""))||sameClub(p.contractClub,String(career.club_name||"")));
   if(!squadPlayers.length){
    const detected=[...new Set(preview.save.players.map(p=>p.club).filter(Boolean))].slice(0,20).join(", ");
    throw new Error("Não encontrei correspondência para o clube da carreira ("+(career.club_name||"não definido")+"). Clubes detetados no save: "+(detected||"nenhum identificado")+". Nenhum jogador foi importado.");
   }
   for(let i=0;i<squadPlayers.length;i++){
    const p=squadPlayers[i],key=normalise(p.fullName||p.name),isLoanedOut=!!p.contractClub&&!!p.club&&!sameClub(p.contractClub,p.club);
    if(seen.has(String(p.id))){skipped++;continue;}seen.add(String(p.id));
    const candidates=byName.get(key)||[];
    const existing=byFmId.get(p.id)||(candidates.length===1?candidates[0]:null);
    if(candidates.length>1&&!byFmId.has(p.id)){skipped++;continue;}
    const externalIds={...(existing?.external_ids||{}),fm24:{id:p.id,uid:p.uid,formatVersion:preview.save.formatVersion}};
    const playerPatch:any=existing?{external_ids:externalIds,updated_at:new Date().toISOString()}:{
     full_name:p.fullName||p.name,date_of_birth:p.birthDate,
     nationality:(await import("../lib/fm24-save-parser")).NATIONS[String(p.nationId)]||null,
     positions:p.positions,external_ids:externalIds
    };
    if(existing){
     if(fields.includes("name"))playerPatch.full_name=p.fullName||p.name;
     if(fields.includes("birthDate"))playerPatch.date_of_birth=p.birthDate;
     if(fields.includes("nationality"))playerPatch.nationality=(await import("../lib/fm24-save-parser")).NATIONS[String(p.nationId)]||null;
     if(fields.includes("positions"))playerPatch.positions=p.positions;
    }
    const linkId=existing?linkByPlayer.get(existing.id):null;
    const careerPatch:any=existing?{updated_at:new Date().toISOString(),squad_status:isLoanedOut?"Emprestado":"Plantel principal"}:{
     squad_status:isLoanedOut?"Emprestado":"Plantel principal",
     club_name:p.club||null,position:p.positions.join(", "),ca:p.ca,
     ca_novo:fields.includes("caNovo")&&p.pa>=minPAForCaNovo?p.ca:null,
     pa:p.pa,age:p.age
    };
    if(existing){
     if(fields.includes("ca"))careerPatch.ca=p.ca;
     if(fields.includes("pa"))careerPatch.pa=p.pa;
     if(fields.includes("caNovo")&&p.pa>=minPAForCaNovo)careerPatch.ca_novo=p.ca;
     if(fields.includes("age"))careerPatch.age=p.age;
     if(fields.includes("club"))careerPatch.club_name=p.club||null;
     if(fields.includes("positions"))careerPatch.position=p.positions.join(", ");
    }
    rows.push({
     player_id:existing?.id||null,
     link_id:linkId||null,
     player_patch:playerPatch,
     career_patch:careerPatch,
     snapshot:{
      ca:p.ca,pa:p.pa,
      attributes:{...p.attributes,positionRatings:p.positionRatings,rawAttributes:p.rawAttributes,gameDate:preview.save.gameDate,formatVersion:preview.save.formatVersion},
      source:"Save FM24"
     }
    });
    if(existing)updated++;else created++;
    if(i%10===0){setProgress(Math.round((i+1)/squadPlayers.length*100));setMessage("A preparar importação transacional...");}
   }
   if(!rows.length)throw new Error("Não existem jogadores válidos para importar.");
   setMessage("A guardar todos os registos numa única transação...");
   const result=await db.rpc("apply_fm24_full_save_import",{
    p_career_id:career.id,
    p_season:seasonPayload,
    p_players:rows,
    p_history:preview.save.history,
    p_job:{
     file_name:preview.fileName,
     records_total:preview.save.players.length,
     records_created:created,
     records_updated:updated,
     records_skipped:skipped,
     report:{gameDate:preview.save.gameDate,formatVersion:preview.save.formatVersion,saveName:preview.save.name,warnings:preview.save.warnings,history:{matches:preview.save.history.matches.length,transfers:preview.save.history.transfers.length,seasons:preview.save.history.seasons.length,competitions:preview.save.history.competitions.length,playerSeasonRecords:preview.save.history.playerSeasonRecords.length,trophies:preview.save.history.trophies.length}}
    }
   });
   if(result.error)throw result.error;
   const summary=result.data||{};
   const history=summary.history||{};setDone("Save importado: "+(summary.records_created??created)+" jogadores novos, "+(summary.records_updated??updated)+" atualizados; "+(history.matches_created??0)+" jogos, "+(history.transfers_created??0)+" transferências, "+(history.season_stats_created??0)+" registos estatísticos e "+(history.trophies_created??0)+" troféus.");
   setPreview(null);await onDone();
  }catch(e:any){setError(e.message||"Erro ao guardar os dados importados.");}
  setBusy(false);
 }
 return <section className="panel" style={{marginBottom:20}}>
  <div className="panel-heading"><div><p className="eyebrow">IMPORTAÇÃO AVANÇADA</p><h2>Save Football Manager 2024</h2></div><span className="status-tag">FM24 · 24.3</span></div>
  <p className="intro">Lê o ficheiro .fm e importa o plantel, épocas, jogos, competições, troféus, transferências e estatísticas históricas associadas ao clube da carreira. O parser só valida saves no formato <b>24.3.0+0</b>.</p>
  <input ref={input} type="file" accept=".fm" hidden onChange={e=>void inspect(e.target.files?.[0])}/>
  <div className="panel-actions"><button className="outline-btn" disabled={busy} onClick={()=>input.current?.click()}>{busy?"A analisar...":"Selecionar save .fm"}</button>{preview&&<button className="primary-btn" disabled={busy||fields.length===0} onClick={()=>void apply()}>Importar save completo</button>}</div>
  {preview&&<div className="import-field-picker"><h3>Escolhe o que atualizar nos jogadores existentes</h3><p className="module-description">Os campos desmarcados ficam exatamente como estão. Os jogadores novos recebem os dados disponíveis no ficheiro.</p><div className="form-grid">{importFields.map(([key,label])=><label key={key}><input type="checkbox" checked={fields.includes(key)} onChange={e=>setFields(old=>e.target.checked?[...old,key]:old.filter(x=>x!==key))}/> {label}</label>)}</div>{fields.includes("caNovo")&&<label className="ca-novo-threshold">Atualizar CA Novo apenas em jogadores com PA igual ou superior a <input type="number" min="0" max="200" value={minPAForCaNovo} onChange={e=>setMinPAForCaNovo(Number(e.target.value)||0)}/></label>}</div>}
  {busy&&<div style={{marginTop:14}}><div className="filters"><b>{progress}%</b><span>{message}</span></div><div style={{height:7,background:"var(--line)",borderRadius:8,overflow:"hidden"}}><div style={{height:"100%",width:progress+"%",background:"var(--accent)",transition:"width .2s"}}/></div></div>}
  {preview&&<div className="stat-grid" style={{marginTop:10}}><article><span>JOGOS</span><strong>{preview.save.history.matches.length}</strong></article><article><span>COMPETIÇÕES</span><strong>{preview.save.history.competitions.length}</strong></article><article><span>TROFÉUS</span><strong>{preview.save.history.trophies.length}</strong></article><article><span>TRANSFERÊNCIAS</span><strong>{preview.save.history.transfers.length}</strong></article><article><span>ESTATÍSTICAS POR ÉPOCA</span><strong>{preview.save.history.playerSeasonRecords.length}</strong></article><article><span>ÉPOCAS</span><strong>{preview.save.history.seasons.length}</strong></article></div>}{counts&&<><div className="stat-grid" style={{marginTop:16}}><article><span>JOGADORES NO SAVE</span><strong>{counts.total}</strong></article><article><span>DO TEU CLUBE</span><strong>{counts.squad}</strong></article><article><span>EMPRÉSTIMOS</span><strong>{counts.loanedOut}</strong></article><article><span>OUTROS CLUBES (IGNORADOS)</span><strong>{counts.otherClubs}</strong></article><article><span>SEM CLUBE (IGNORADOS)</span><strong>{counts.noClub}</strong></article></div><div className="stat-grid" style={{marginTop:10}}><article><span>JÁ NA CARREIRA</span><strong>{counts.existing}</strong></article><article><span>REGISTOS NOVOS</span><strong>{counts.fresh}</strong></article><article><span>NOMES AMBÍGUOS</span><strong>{counts.ambiguous}</strong></article><article><span>A IMPORTAR</span><strong>{counts.squad}</strong></article></div></>}
  {preview&&preview.save.warnings.length>0&&<p className="alert">{preview.save.warnings.join(" ")}</p>}
  {error&&<p className="alert error">{error}</p>}{done&&<p className="alert success">{done}</p>}
 </section>;
}

"use client";
import { useEffect, useState } from "react";

type Props={db:any;career:any;session:any;onNavigate:(module:string)=>void};
export default function CareerOverview({db,career,session,onNavigate}:Props){
 const [data,setData]=useState<any>({seasons:[],competitions:[],matches:[],trophies:[],transfers:[],spells:[]});
 const [busy,setBusy]=useState(true),[error,setError]=useState("");
 useEffect(()=>{
  let live=true;
  async function load(){
   if(!career?.id||!session?.user?.id)return;
   setBusy(true);setError("");
   const results=await Promise.all([
    db.from("seasons").select("id,label,is_current,start_date,end_date").eq("career_id",career.id).order("start_date",{ascending:false}),
    db.from("competitions").select("id,name,country,competition_type").eq("career_id",career.id).order("name"),
    db.from("matches").select("id,played_at,home_score,away_score,match_type,competition_id").eq("career_id",career.id).order("played_at",{ascending:false}).limit(5),
    db.from("trophies").select("id,competition_name,won_on,season_id").eq("career_id",career.id).order("won_on",{ascending:false}).limit(5),
    db.from("transfers").select("id,transfer_type,fee,transfer_date").eq("career_id",career.id),
    db.from("career_club_spells").select("id,started_on,ended_on,is_managed_club,clubs(name)").eq("career_id",career.id).order("started_on",{ascending:false}),
    db.from("matches").select("id",{count:"exact",head:true}).eq("career_id",career.id),
    db.from("trophies").select("id",{count:"exact",head:true}).eq("career_id",career.id)
   ]);
   const failed=results.find((r:any)=>r.error);
   if(!live)return;
   if(failed){setError(failed.error.message);setBusy(false);return;}
   setData({seasons:results[0].data||[],competitions:results[1].data||[],matches:results[2].data||[],trophies:results[3].data||[],transfers:results[4].data||[],spells:results[5].data||[],matchesTotal:results[6].count||0,trophiesTotal:results[7].count||0});
   setBusy(false);
  }
  void load();
  return()=>{live=false;};
 },[db,career?.id,session?.user?.id]);
 const current=data.seasons.find((s:any)=>s.is_current);
 const played=data.matches.filter((m:any)=>m.home_score!==null&&m.away_score!==null);
 const wins=played.filter((m:any)=>m.home_score>m.away_score).length;
 return <div className="career-overview">
  {error&&<p className="alert error">{error}</p>}
  <div className="stat-grid">
   <article><span>ÉPOCAS REGISTADAS</span><strong>{busy?"—":data.seasons.length}</strong><small>{current?.label||"Nenhuma época definida como atual"}</small></article>
   <article><span>COMPETIÇÕES</span><strong>{busy?"—":data.competitions.length}</strong><small>Ligas e taças acompanhadas</small></article>
   <article><span>JOGOS REGISTADOS</span><strong>{busy?"—":data.matchesTotal??0}</strong><small>{played.length?wins+" vitórias nos últimos jogos":"Sem resultados importados"}</small></article>
   <article><span>TROFÉUS</span><strong>{busy?"—":data.trophiesTotal??0}</strong><small>Conquistas da carreira</small></article>
  </div>
  <div className="overview-grid">
   <section className="panel"><div className="panel-heading"><div><p className="eyebrow">ÉPOCA EM CURSO</p><h2>{current?.label||"Ainda sem época atual"}</h2></div><button className="outline-btn" onClick={()=>onNavigate("Épocas")}>Gerir épocas</button></div><p className="module-description">{current?.start_date?new Date(current.start_date+"T00:00:00").toLocaleDateString("pt-PT"):"Define uma época para separar estatísticas, jogos, transferências e snapshots."}{current?.end_date?" — "+new Date(current.end_date+"T00:00:00").toLocaleDateString("pt-PT"):""}</p><div className="overview-actions"><button className="outline-btn" onClick={()=>onNavigate("Jogos")}>Calendário e resultados</button><button className="outline-btn" onClick={()=>onNavigate("Estatísticas")}>Estatísticas de época</button><button className="outline-btn" onClick={()=>onNavigate("Competições")}>Competições</button></div></section>
   <section className="panel"><div className="panel-heading"><div><p className="eyebrow">PALMARÉS</p><h2>Últimos troféus</h2></div><button className="outline-btn" onClick={()=>onNavigate("Troféus")}>Ver todos</button></div>{data.trophies.length?<div className="overview-list">{data.trophies.map((t:any)=><div className="overview-list-row" key={t.id}><strong>{t.competition_name}</strong><span>{t.won_on?new Date(t.won_on+"T00:00:00").toLocaleDateString("pt-PT"):"Data por definir"}</span></div>)}</div>:<p className="empty">Ainda não existem títulos registados/importados.</p>}</section>
   <section className="panel"><div className="panel-heading"><div><p className="eyebrow">RESULTADOS</p><h2>Jogos recentes</h2></div><button className="outline-btn" onClick={()=>onNavigate("Jogos")}>Ver jogos</button></div>{data.matches.length?<div className="overview-list">{data.matches.map((m:any)=><div className="overview-list-row" key={m.id}><strong>{m.home_score??"—"} – {m.away_score??"—"}</strong><span>{m.played_at?new Date(m.played_at).toLocaleDateString("pt-PT"):"Data por definir"}</span></div>)}</div>:<p className="empty">Ainda não existem jogos registados.</p>}</section>
   <section className="panel"><div className="panel-heading"><div><p className="eyebrow">PERCURSO DO TREINADOR</p><h2>Clubes orientados</h2></div><button className="outline-btn" onClick={()=>onNavigate("Percurso do treinador")}>Ver percurso</button></div>{data.spells.length?<div className="overview-list">{data.spells.map((s:any)=><div className="overview-list-row" key={s.id}><strong>{s.clubs?.name||"Clube"}</strong><span>{s.started_on?new Date(s.started_on+"T00:00:00").toLocaleDateString("pt-PT"):"Início por definir"}{s.ended_on?" — "+new Date(s.ended_on+"T00:00:00").toLocaleDateString("pt-PT"):" — Atual"}</span></div>)}</div>:<p className="empty">O percurso do treinador ainda não tem registos.</p>}</section>
  </div>
  <section className="panel overview-bottom"><div><p className="eyebrow">MERCADO</p><h2>{data.transfers.length} operações registadas</h2><p className="module-description">Entradas, saídas e empréstimos associados à carreira.</p></div><button className="outline-btn" onClick={()=>onNavigate("Transferências")}>Abrir transferências</button></section>
 </div>;
}

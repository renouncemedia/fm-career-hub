-- Importa o histórico FM24 na mesma transação da importação do plantel.
-- Não apaga nem substitui registos manuais; os registos importados são identificados pela origem FM24.
create or replace function public.apply_fm24_full_save_import(
 p_career_id uuid,
 p_season jsonb,
 p_players jsonb,
 p_history jsonb,
 p_job jsonb
) returns jsonb
language plpgsql
security invoker
set search_path = public, pg_temp
as $$
declare
 v_owner uuid := auth.uid();
 v_base jsonb;
 v_row jsonb;
 v_club_id uuid;
 v_competition_id uuid;
 v_season_id uuid;
 v_player_id uuid;
 v_home_club_id uuid;
 v_away_club_id uuid;
 v_from_club_id uuid;
 v_to_club_id uuid;
 v_managed_club_id uuid;
 v_uid text;
 v_fm_club_id text;
 v_name text;
 v_country text;
 v_label text;
 v_comp_name text;
 v_notes text;
 v_season_start integer;
 v_club_ids jsonb := '{}'::jsonb;
 v_competition_ids jsonb := '{}'::jsonb;
 v_season_ids jsonb := '{}'::jsonb;
 v_competition_names jsonb := '{}'::jsonb;
 v_created_clubs integer := 0;
 v_created_competitions integer := 0;
 v_created_seasons integer := 0;
 v_matches_created integer := 0;
 v_matches_updated integer := 0;
 v_transfers_created integer := 0;
 v_stats_created integer := 0;
 v_stats_updated integer := 0;
 v_trophies_created integer := 0;
 v_manager_spells_created integer := 0;
 v_started_on date;
 v_ended_on date;
 v_start_season_id uuid;
 v_end_season_id uuid;
 v_date date;
begin
 if v_owner is null then
  raise exception 'É necessário iniciar sessão para importar um save.' using errcode='42501';
 end if;
 if not exists(select 1 from public.careers c where c.id=p_career_id and c.owner_id=v_owner) then
  raise exception 'A carreira não existe ou não pertence a esta conta.' using errcode='42501';
 end if;
 if p_history is null or jsonb_typeof(p_history)<>'object' then
  raise exception 'O histórico do save FM24 não tem um formato válido.';
 end if;
 if jsonb_array_length(coalesce(p_history->'clubs','[]'::jsonb))>10000
    or jsonb_array_length(coalesce(p_history->'competitions','[]'::jsonb))>5000
    or jsonb_array_length(coalesce(p_history->'seasons','[]'::jsonb))>250
    or jsonb_array_length(coalesce(p_history->'matches','[]'::jsonb))>50000
    or jsonb_array_length(coalesce(p_history->'transfers','[]'::jsonb))>50000
    or jsonb_array_length(coalesce(p_history->'playerSeasonRecords','[]'::jsonb))>50000
    or jsonb_array_length(coalesce(p_history->'trophies','[]'::jsonb))>10000
    or jsonb_array_length(coalesce(p_history->'managerSpells','[]'::jsonb))>1000 then
  raise exception 'O histórico do save excede os limites de importação.';
 end if;

 -- A importação atual do plantel e a criação da época corrente continuam a ser atómicas.
 v_base := public.apply_fm24_save_import(p_career_id,p_season,p_players,p_job);

 -- Clubes envolvidos nos jogos e transferências.
 for v_row in select value from jsonb_array_elements(coalesce(p_history->'clubs','[]'::jsonb))
 loop
  v_fm_club_id := nullif(v_row->>'fm24ClubId','');
  v_name := nullif(v_row->>'name','');
  v_country := nullif(v_row->>'country','');
  if v_fm_club_id is null or v_name is null then continue; end if;
  select c.id into v_club_id
   from public.clubs c
   where c.owner_id=v_owner and c.metadata->>'fm24ClubId'=v_fm_club_id
   order by c.created_at limit 1 for update;
  if v_club_id is null then
   select c.id into v_club_id
    from public.clubs c
    where c.owner_id=v_owner and c.name=v_name and c.country is not distinct from v_country
    order by c.created_at limit 1 for update;
  end if;
  if v_club_id is null then
   insert into public.clubs(owner_id,name,short_name,country,metadata)
   values(v_owner,v_name,nullif(v_row->>'shortName',''),v_country,
     jsonb_build_object('fm24ClubId',v_fm_club_id,'source','Save FM24'))
   returning id into v_club_id;
   v_created_clubs := v_created_clubs+1;
  else
   update public.clubs set
    short_name=coalesce(nullif(v_row->>'shortName',''),short_name),
    country=coalesce(country,v_country),
    metadata=coalesce(metadata,'{}'::jsonb)||jsonb_build_object('fm24ClubId',v_fm_club_id,'source','Save FM24')
   where id=v_club_id and owner_id=v_owner;
  end if;
  v_club_ids := v_club_ids || jsonb_build_object(v_fm_club_id,v_club_id::text);
 end loop;

 -- Competições (UID FM24; os nomes ficam identificados como tal quando o save não contém a tradução).
 for v_row in select value from jsonb_array_elements(coalesce(p_history->'competitions','[]'::jsonb))
 loop
  v_uid := nullif(v_row->>'uid','');
  v_name := coalesce(nullif(v_row->>'name',''),'Competição FM24 '||coalesce(v_uid,'desconhecida'));
  if v_uid is null then continue; end if;
  select c.id into v_competition_id
   from public.competitions c
   where c.career_id=p_career_id and c.metadata->>'fm24CompetitionUid'=v_uid
   order by c.created_at limit 1 for update;
  if v_competition_id is null then
   select c.id into v_competition_id
    from public.competitions c
    where c.career_id=p_career_id and c.name=v_name
    limit 1 for update;
  end if;
  if v_competition_id is null then
   insert into public.competitions(owner_id,career_id,name,competition_type,metadata)
   values(v_owner,p_career_id,v_name,'FM24',
     jsonb_build_object('fm24CompetitionUid',v_uid,'fm24RawIds',coalesce(v_row->'rawIds','[]'::jsonb),'source','Save FM24'))
   returning id into v_competition_id;
   v_created_competitions := v_created_competitions+1;
  else
   update public.competitions set
    metadata=coalesce(metadata,'{}'::jsonb)||jsonb_build_object('fm24CompetitionUid',v_uid,'source','Save FM24')
   where id=v_competition_id and career_id=p_career_id;
  end if;
  v_competition_ids := v_competition_ids || jsonb_build_object(v_uid,v_competition_id::text);
  v_competition_names := v_competition_names || jsonb_build_object(v_uid,v_name);
 end loop;

 -- Épocas encontradas no histórico. A época atual criada pela função anterior é reutilizada.
 for v_row in select value from jsonb_array_elements(coalesce(p_history->'seasons','[]'::jsonb))
 loop
  v_label := nullif(v_row->>'label','');
  if v_label is null then continue; end if;
  select s.id into v_season_id from public.seasons s
   where s.career_id=p_career_id and s.owner_id=v_owner and s.label=v_label
   limit 1 for update;
  if v_season_id is null then
   insert into public.seasons(owner_id,career_id,label,start_date,end_date,is_current,notes)
   values(v_owner,p_career_id,v_label,nullif(v_row->>'startDate','')::date,
    nullif(v_row->>'endDate','')::date,false,'Importada do histórico do save FM24.')
   returning id into v_season_id;
   v_created_seasons := v_created_seasons+1;
  else
   update public.seasons set
    start_date=coalesce(start_date,nullif(v_row->>'startDate','')::date),
    end_date=coalesce(end_date,nullif(v_row->>'endDate','')::date)
   where id=v_season_id and owner_id=v_owner;
  end if;
  v_season_ids := v_season_ids || jsonb_build_object(v_label,v_season_id::text);
 end loop;

 -- Percurso do treinador, validado contra os resultados da equipa principal.
 for v_row in select value from jsonb_array_elements(coalesce(p_history->'managerSpells','[]'::jsonb))
 loop
  v_club_id := nullif(v_club_ids->>coalesce(v_row->>'clubId',''),'')::uuid;
  v_started_on := nullif(v_row->>'startedOn','')::date;
  v_ended_on := nullif(v_row->>'endedOn','')::date;
  if v_club_id is null or v_started_on is null then continue; end if;
  v_season_start := extract(year from v_started_on)::integer -
    case when extract(month from v_started_on)<7 then 1 else 0 end;
  v_label := v_season_start::text||'/'||right((v_season_start+1)::text,2);
  v_start_season_id := nullif(v_season_ids->>v_label,'')::uuid;
  v_end_season_id := null;
  if v_ended_on is not null then
   v_season_start := extract(year from v_ended_on)::integer -
    case when extract(month from v_ended_on)<7 then 1 else 0 end;
   v_label := v_season_start::text||'/'||right((v_season_start+1)::text,2);
   v_end_season_id := nullif(v_season_ids->>v_label,'')::uuid;
  end if;
  v_notes := 'FM24 manager person='||coalesce(v_row->>'personId','?')||
    '; W-D-L='||coalesce(v_row->>'won','0')||'-'||coalesce(v_row->>'drawn','0')||'-'||coalesce(v_row->>'lost','0')||
    '; reason='||coalesce(v_row->>'reason','?')||
    '; league wins='||coalesce(v_row->>'leagueWins','0')||
    '; cup wins='||coalesce(v_row->>'cupWins','0');
  if exists(select 1 from public.career_club_spells s where s.career_id=p_career_id
    and s.owner_id=v_owner and s.club_id=v_club_id and s.started_on=v_started_on
    and s.ended_on is not distinct from v_ended_on and s.notes=v_notes) then continue; end if;
  insert into public.career_club_spells(owner_id,career_id,club_id,start_season_id,end_season_id,
    started_on,ended_on,is_managed_club,notes)
  values(v_owner,p_career_id,v_club_id,v_start_season_id,v_end_season_id,
    v_started_on,v_ended_on,true,v_notes);
  v_manager_spells_created := v_manager_spells_created+1;
 end loop;

 -- Jogos da equipa: só são atualizados registos previamente importados pelo FM24.
 for v_row in select value from jsonb_array_elements(coalesce(p_history->'matches','[]'::jsonb))
 loop
  v_season_start := nullif(v_row->>'seasonStart','')::integer;
  v_label := case when v_season_start is not null
    then v_season_start::text||'/'||right((v_season_start+1)::text,2) else null end;
  v_season_id := nullif(v_season_ids->>v_label,'')::uuid;
  v_uid := coalesce(nullif(v_row->>'competitionUid',''),nullif(v_row->>'stageId',''));
  v_competition_id := nullif(v_competition_ids->>v_uid,'')::uuid;
  v_home_club_id := nullif(v_club_ids->>coalesce(v_row->>'homeClubId',''),'')::uuid;
  v_away_club_id := nullif(v_club_ids->>coalesce(v_row->>'awayClubId',''),'')::uuid;
  if v_home_club_id is null and v_away_club_id is null then continue; end if;
  v_notes := 'FM24 fixture='||coalesce(v_row->>'fixtureId','?')||
    '; stage='||coalesce(v_row->>'stageId','?')||
    '; homeTeam='||coalesce(v_row->>'homeTeam','?')||
    '; awayTeam='||coalesce(v_row->>'awayTeam','?');
  v_date := nullif(v_row->>'date','')::date;
  if v_date is null then continue; end if;
  if exists(select 1 from public.matches m where m.career_id=p_career_id and m.owner_id=v_owner
    and m.source='Save FM24' and m.notes=v_notes) then
   update public.matches m set
    season_id=coalesce(v_season_id,m.season_id),
    competition_id=coalesce(v_competition_id,m.competition_id),
    played_at=(v_date::timestamp at time zone 'UTC'),
    home_club_id=coalesce(v_home_club_id,m.home_club_id),
    away_club_id=coalesce(v_away_club_id,m.away_club_id),
    home_score=nullif(v_row->>'homeScore','')::integer,
    away_score=nullif(v_row->>'awayScore','')::integer,
    attendance=nullif(v_row->>'attendance','')::integer,
    match_type='Jogo FM24'
   where m.career_id=p_career_id and m.owner_id=v_owner and m.source='Save FM24' and m.notes=v_notes;
   v_matches_updated := v_matches_updated+1;
  else
   insert into public.matches(owner_id,career_id,season_id,competition_id,played_at,
    home_club_id,away_club_id,home_score,away_score,attendance,match_type,notes,source)
   values(v_owner,p_career_id,v_season_id,v_competition_id,(v_date::timestamp at time zone 'UTC'),
    v_home_club_id,v_away_club_id,nullif(v_row->>'homeScore','')::integer,
    nullif(v_row->>'awayScore','')::integer,nullif(v_row->>'attendance','')::integer,
    'Jogo FM24',v_notes,'Save FM24');
   v_matches_created := v_matches_created+1;
  end if;
 end loop;

 -- Transferências dos jogadores associados ao plantel/contrato do clube da carreira.
 for v_row in select value from jsonb_array_elements(coalesce(p_history->'transfers','[]'::jsonb))
 loop
  select p.id into v_player_id from public.players p
   where p.owner_id=v_owner and p.external_ids->'fm24'->>'id'=v_row->>'personId'
   limit 1;
  if v_player_id is null then continue; end if;
  v_from_club_id := nullif(v_club_ids->>coalesce(v_row->>'fromClubId',''),'')::uuid;
  v_to_club_id := nullif(v_club_ids->>coalesce(v_row->>'toClubId',''),'')::uuid;
  v_date := nullif(v_row->>'date','')::date;
  if v_date is null then continue; end if;
  if exists(select 1 from public.transfers t where t.career_id=p_career_id and t.owner_id=v_owner
    and t.player_id=v_player_id and t.transfer_date=v_date and t.transfer_type=v_row->>'type'
    and t.from_club_id is not distinct from v_from_club_id and t.to_club_id is not distinct from v_to_club_id
    and t.fee is not distinct from nullif(v_row->>'fee','')::numeric
    and t.add_ons is not distinct from nullif(v_row->>'addOns','')::numeric and t.source='Save FM24') then
   continue;
  end if;
  insert into public.transfers(owner_id,career_id,player_id,from_club_id,to_club_id,transfer_date,
    transfer_type,fee,add_ons,notes,source)
  values(v_owner,p_career_id,v_player_id,v_from_club_id,v_to_club_id,v_date,
    nullif(v_row->>'type',''),nullif(v_row->>'fee','')::numeric,nullif(v_row->>'addOns','')::numeric,
    'Valor original no save FM24: '||coalesce(v_row->>'originalFee','0')||
      ' / com variáveis: '||coalesce(v_row->>'originalFeeWithAddOns','0')||' GBP',
    'Save FM24');
  v_transfers_created := v_transfers_created+1;
 end loop;

 -- Estatísticas agregadas por jogador e época.
 for v_row in select value from jsonb_array_elements(coalesce(p_history->'playerSeasonRecords','[]'::jsonb))
 loop
  select p.id into v_player_id from public.players p
   where p.owner_id=v_owner and p.external_ids->'fm24'->>'id'=v_row->>'personId'
   limit 1;
  if v_player_id is null then continue; end if;
  v_season_start := nullif(v_row->>'seasonStart','')::integer;
  v_label := case when v_season_start is not null
    then v_season_start::text||'/'||right((v_season_start+1)::text,2) else null end;
  v_season_id := nullif(v_season_ids->>v_label,'')::uuid;
  v_club_id := nullif(v_club_ids->>coalesce(v_row->>'clubId',''),'')::uuid;
  if v_season_id is null then continue; end if;
  if exists(select 1 from public.player_season_records r where r.career_id=p_career_id
    and r.player_id=v_player_id and r.season_id=v_season_id) then
   update public.player_season_records r set
    club_id=coalesce(v_club_id,r.club_id),
    appearances=nullif(v_row->>'appearances','')::integer,
    starts=nullif(v_row->>'starts','')::integer,
    substitute_appearances=nullif(v_row->>'substituteAppearances','')::integer,
    minutes_played=nullif(v_row->>'minutes','')::integer,
    goals=nullif(v_row->>'goals','')::integer,
    assists=nullif(v_row->>'assists','')::integer,
    average_rating=nullif(v_row->>'averageRating','')::numeric,
    attributes=coalesce(r.attributes,'{}'::jsonb)||jsonb_build_object(
      'fm24TeamIds',coalesce(v_row->'teamIds','[]'::jsonb),
      'playerOfMatch',nullif(v_row->>'playerOfMatch','')::integer,
      'goalsConceded',nullif(v_row->>'goalsConceded','')::integer,
      'cleanSheets',nullif(v_row->>'cleanSheets','')::integer,
      'yellowCards',nullif(v_row->>'yellowCards','')::integer,
      'redCards',nullif(v_row->>'redCards','')::integer,
      'ratedAppearances',nullif(v_row->>'ratedAppearances','')::integer,
      'ratingTotal',nullif(v_row->>'ratingTotal','')::integer,
      'kindBreakdown',coalesce(v_row->'kindBreakdown','{}'::jsonb)
    ),
    source='Save FM24',recorded_at=now()
   where r.career_id=p_career_id and r.player_id=v_player_id and r.season_id=v_season_id
    and (r.source='Save FM24' or r.source is null);
   if found then v_stats_updated:=v_stats_updated+1; end if;
  else
   insert into public.player_season_records(owner_id,career_id,player_id,season_id,club_id,
    appearances,starts,substitute_appearances,minutes_played,goals,assists,average_rating,attributes,source)
   values(v_owner,p_career_id,v_player_id,v_season_id,v_club_id,
    nullif(v_row->>'appearances','')::integer,nullif(v_row->>'starts','')::integer,
    nullif(v_row->>'substituteAppearances','')::integer,nullif(v_row->>'minutes','')::integer,
    nullif(v_row->>'goals','')::integer,nullif(v_row->>'assists','')::integer,
    nullif(v_row->>'averageRating','')::numeric,
    jsonb_build_object(
      'fm24TeamIds',coalesce(v_row->'teamIds','[]'::jsonb),
      'playerOfMatch',nullif(v_row->>'playerOfMatch','')::integer,
      'goalsConceded',nullif(v_row->>'goalsConceded','')::integer,
      'cleanSheets',nullif(v_row->>'cleanSheets','')::integer,
      'yellowCards',nullif(v_row->>'yellowCards','')::integer,
      'redCards',nullif(v_row->>'redCards','')::integer,
      'ratedAppearances',nullif(v_row->>'ratedAppearances','')::integer,
      'ratingTotal',nullif(v_row->>'ratingTotal','')::integer,
      'kindBreakdown',coalesce(v_row->'kindBreakdown','{}'::jsonb)
    ),'Save FM24');
   v_stats_created := v_stats_created+1;
  end if;
 end loop;

 -- Palmarés: apenas títulos cujo vencedor é uma equipa do clube gerido no save.
 v_managed_club_id := nullif(v_club_ids->>coalesce(p_history->>'managedClubId',''),'')::uuid;
 for v_row in select value from jsonb_array_elements(coalesce(p_history->'trophies','[]'::jsonb))
 loop
  v_uid := coalesce(v_row->>'competitionUid',v_row->>'competitionKey');
  v_competition_id := nullif(v_competition_ids->>v_uid,'')::uuid;
  v_comp_name := coalesce(v_competition_names->>v_uid,'Competição FM24 '||coalesce(v_uid,'?'));
  v_season_start := nullif(v_row->>'seasonStart','')::integer;
  v_label := case when v_season_start is not null
    then v_season_start::text||'/'||right((v_season_start+1)::text,2) else null end;
  v_season_id := nullif(v_season_ids->>v_label,'')::uuid;
  v_date := nullif(v_row->>'wonOn','')::date;
  if v_managed_club_id is null or v_date is null then continue; end if;
  v_notes := 'FM24 competition key='||coalesce(v_row->>'competitionKey','?')||
    '; competition season='||coalesce(v_row->>'year','?');
  if exists(select 1 from public.trophies t where t.career_id=p_career_id and t.owner_id=v_owner
    and t.club_id=v_managed_club_id and t.notes=v_notes) then continue; end if;
  insert into public.trophies(owner_id,career_id,club_id,season_id,competition_id,competition_name,won_on,notes)
  values(v_owner,p_career_id,v_managed_club_id,v_season_id,v_competition_id,v_comp_name,v_date,v_notes);
  v_trophies_created := v_trophies_created+1;
 end loop;

 update public.import_jobs j set report=coalesce(j.report,'{}'::jsonb)||jsonb_build_object(
  'historyImported',jsonb_build_object(
   'clubsCreated',v_created_clubs,'competitionsCreated',v_created_competitions,
   'seasonsCreated',v_created_seasons,'matchesCreated',v_matches_created,
   'matchesUpdated',v_matches_updated,'transfersCreated',v_transfers_created,
   'seasonStatsCreated',v_stats_created,'seasonStatsUpdated',v_stats_updated,
   'trophiesCreated',v_trophies_created,'managerSpellsCreated',v_manager_spells_created
  )
 )
 where j.id=(select x.id from public.import_jobs x where x.owner_id=v_owner and x.career_id=p_career_id
  and x.source_format='fm24-save' and x.file_name=nullif(p_job->>'file_name','')
  order by x.created_at desc limit 1);

 return v_base||jsonb_build_object('history',jsonb_build_object(
  'clubs_created',v_created_clubs,'competitions_created',v_created_competitions,
  'seasons_created',v_created_seasons,'matches_created',v_matches_created,
  'matches_updated',v_matches_updated,'transfers_created',v_transfers_created,
  'season_stats_created',v_stats_created,'season_stats_updated',v_stats_updated,
  'trophies_created',v_trophies_created,'manager_spells_created',v_manager_spells_created
 ));
end;
$$;

revoke all on function public.apply_fm24_full_save_import(uuid,jsonb,jsonb,jsonb,jsonb) from public;
revoke all on function public.apply_fm24_full_save_import(uuid,jsonb,jsonb,jsonb,jsonb) from anon;
grant execute on function public.apply_fm24_full_save_import(uuid,jsonb,jsonb,jsonb,jsonb) to authenticated;

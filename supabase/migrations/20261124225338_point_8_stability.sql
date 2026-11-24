-- Point 8: integrity, predictable query plans and atomic FM24 save imports.
-- The indexes below support foreign-key joins/deletes and common owner-scoped access patterns.
create index if not exists idx_seasons_owner_id_fk on public.seasons (owner_id);
create index if not exists idx_competitions_owner_id_fk on public.competitions (owner_id);
create index if not exists idx_career_club_spells_career_id_fk on public.career_club_spells (career_id);
create index if not exists idx_career_club_spells_club_id_fk on public.career_club_spells (club_id);
create index if not exists idx_career_club_spells_end_season_id_fk on public.career_club_spells (end_season_id);
create index if not exists idx_career_club_spells_owner_id_fk on public.career_club_spells (owner_id);
create index if not exists idx_career_club_spells_start_season_id_fk on public.career_club_spells (start_season_id);
create index if not exists idx_player_club_history_career_id_fk on public.player_club_history (career_id);
create index if not exists idx_player_club_history_club_id_fk on public.player_club_history (club_id);
create index if not exists idx_player_club_history_owner_id_fk on public.player_club_history (owner_id);
create index if not exists idx_player_club_history_season_id_fk on public.player_club_history (season_id);
create index if not exists idx_player_season_records_club_id_fk on public.player_season_records (club_id);
create index if not exists idx_player_season_records_owner_id_fk on public.player_season_records (owner_id);
create index if not exists idx_player_season_records_season_id_fk on public.player_season_records (season_id);
create index if not exists idx_player_attribute_snapshots_career_id_fk on public.player_attribute_snapshots (career_id);
create index if not exists idx_player_attribute_snapshots_owner_id_fk on public.player_attribute_snapshots (owner_id);
create index if not exists idx_player_attribute_snapshots_season_id_fk on public.player_attribute_snapshots (season_id);
create index if not exists idx_matches_away_club_id_fk on public.matches (away_club_id);
create index if not exists idx_matches_competition_id_fk on public.matches (competition_id);
create index if not exists idx_matches_home_club_id_fk on public.matches (home_club_id);
create index if not exists idx_matches_owner_id_fk on public.matches (owner_id);
create index if not exists idx_matches_season_id_fk on public.matches (season_id);
create index if not exists idx_player_match_stats_club_id_fk on public.player_match_stats (club_id);
create index if not exists idx_player_match_stats_owner_id_fk on public.player_match_stats (owner_id);
create index if not exists idx_transfers_from_club_id_fk on public.transfers (from_club_id);
create index if not exists idx_transfers_owner_id_fk on public.transfers (owner_id);
create index if not exists idx_transfers_player_id_fk on public.transfers (player_id);
create index if not exists idx_transfers_to_club_id_fk on public.transfers (to_club_id);
create index if not exists idx_squad_snapshots_career_id_fk on public.squad_snapshots (career_id);
create index if not exists idx_squad_snapshots_club_id_fk on public.squad_snapshots (club_id);
create index if not exists idx_squad_snapshots_owner_id_fk on public.squad_snapshots (owner_id);
create index if not exists idx_squad_snapshots_season_id_fk on public.squad_snapshots (season_id);
create index if not exists idx_tactics_career_id_fk on public.tactics (career_id);
create index if not exists idx_tactics_club_id_fk on public.tactics (club_id);
create index if not exists idx_tactics_owner_id_fk on public.tactics (owner_id);
create index if not exists idx_tactics_season_id_fk on public.tactics (season_id);
create index if not exists idx_trophies_career_id_fk on public.trophies (career_id);
create index if not exists idx_trophies_club_id_fk on public.trophies (club_id);
create index if not exists idx_trophies_competition_id_fk on public.trophies (competition_id);
create index if not exists idx_trophies_owner_id_fk on public.trophies (owner_id);
create index if not exists idx_trophies_season_id_fk on public.trophies (season_id);
create index if not exists idx_import_jobs_career_id_fk on public.import_jobs (career_id);
create index if not exists idx_career_players_owner_id_fk on public.career_players (owner_id);
create index if not exists idx_career_players_player_id_fk on public.career_players (player_id);

create or replace function public.apply_fm24_save_import(
 p_career_id uuid,
 p_season jsonb,
 p_players jsonb,
 p_job jsonb
) returns jsonb
language plpgsql
security invoker
set search_path = public, pg_temp
as $$
declare
 v_owner uuid := auth.uid();
 v_row jsonb;
 v_player_patch jsonb;
 v_career_patch jsonb;
 v_snapshot jsonb;
 v_player_id uuid;
 v_link_id uuid;
 v_season_id uuid;
 v_season_label text;
 v_season_start date;
 v_season_end date;
 v_has_current boolean;
 v_player_exists boolean;
 v_link_exists boolean;
 v_created integer := 0;
 v_updated integer := 0;
 v_snapshots integer := 0;
 v_game_date text;
begin
 if v_owner is null then
  raise exception 'É necessário iniciar sessão para importar um save.' using errcode = '42501';
 end if;
 if not exists (select 1 from public.careers c where c.id=p_career_id and c.owner_id=v_owner) then
  raise exception 'A carreira não existe ou não pertence a esta conta.' using errcode = '42501';
 end if;
 if jsonb_typeof(p_players) <> 'array' or jsonb_array_length(p_players)=0 or jsonb_array_length(p_players)>5000 then
  raise exception 'A lista de jogadores é inválida ou excede o limite permitido.';
 end if;

 if p_season is not null and jsonb_typeof(p_season)='object' then
  v_season_label := nullif(p_season->>'label','');
  v_season_start := nullif(p_season->>'start_date','')::date;
  v_season_end := nullif(p_season->>'end_date','')::date;
  if v_season_label is not null then
   select s.id into v_season_id from public.seasons s
    where s.career_id=p_career_id and s.label=v_season_label and s.owner_id=v_owner
    limit 1 for update;
   select exists(select 1 from public.seasons s where s.career_id=p_career_id and s.is_current) into v_has_current;
   if v_season_id is null then
    insert into public.seasons(owner_id,career_id,label,start_date,end_date,is_current,notes)
    values(v_owner,p_career_id,v_season_label,v_season_start,v_season_end,not v_has_current,
      coalesce(p_season->>'notes','Criada automaticamente a partir da data do save FM24.'))
    returning id into v_season_id;
   elsif not v_has_current then
    update public.seasons set is_current=true where id=v_season_id and owner_id=v_owner;
   end if;
  end if;
 end if;

 for v_row in select value from jsonb_array_elements(p_players)
 loop
  v_player_id := nullif(v_row->>'player_id','')::uuid;
  v_link_id := nullif(v_row->>'link_id','')::uuid;
  v_player_patch := coalesce(v_row->'player_patch','{}'::jsonb);
  v_career_patch := coalesce(v_row->'career_patch','{}'::jsonb);
  v_snapshot := coalesce(v_row->'snapshot','{}'::jsonb);
  v_player_exists := v_player_id is not null;

  if v_player_exists then
   update public.players p set
    full_name=coalesce(nullif(v_player_patch->>'full_name',''),p.full_name),
    date_of_birth=case when v_player_patch ? 'date_of_birth' then nullif(v_player_patch->>'date_of_birth','')::date else p.date_of_birth end,
    nationality=case when v_player_patch ? 'nationality' then nullif(v_player_patch->>'nationality','') else p.nationality end,
    positions=case when jsonb_typeof(v_player_patch->'positions')='array'
      then array(select jsonb_array_elements_text(v_player_patch->'positions')) else p.positions end,
    external_ids=coalesce(p.external_ids,'{}'::jsonb) || coalesce(v_player_patch->'external_ids','{}'::jsonb),
    updated_at=now()
   where p.id=v_player_id and p.owner_id=v_owner;
   if not found then raise exception 'Um dos jogadores não existe ou não pertence a esta conta.' using errcode='42501'; end if;
  else
   insert into public.players(owner_id,full_name,date_of_birth,nationality,positions,external_ids)
   values(
    v_owner,
    nullif(v_player_patch->>'full_name',''),
    nullif(v_player_patch->>'date_of_birth','')::date,
    nullif(v_player_patch->>'nationality',''),
    case when jsonb_typeof(v_player_patch->'positions')='array'
      then array(select jsonb_array_elements_text(v_player_patch->'positions')) else '{}'::text[] end,
    coalesce(v_player_patch->'external_ids','{}'::jsonb)
   ) returning id into v_player_id;
   v_created := v_created+1;
  end if;

  v_link_exists := false;
  if v_link_id is not null then
   perform 1 from public.career_players cp
    where cp.id=v_link_id and cp.career_id=p_career_id and cp.player_id=v_player_id and cp.owner_id=v_owner
    for update;
   v_link_exists := found;
   if not v_link_exists then raise exception 'A ligação do jogador à carreira é inválida.'; end if;
  else
   select cp.id into v_link_id from public.career_players cp
    where cp.career_id=p_career_id and cp.player_id=v_player_id and cp.owner_id=v_owner
    limit 1 for update;
   v_link_exists := v_link_id is not null;
  end if;

  if v_link_exists then
   update public.career_players cp set
    squad_status=coalesce(nullif(v_career_patch->>'squad_status',''),cp.squad_status),
    club_name=case when v_career_patch ? 'club_name' then nullif(v_career_patch->>'club_name','') else cp.club_name end,
    position=case when v_career_patch ? 'position' then nullif(v_career_patch->>'position','') else cp.position end,
    ca=case when v_career_patch ? 'ca' then nullif(v_career_patch->>'ca','')::integer else cp.ca end,
    ca_novo=case when v_career_patch ? 'ca_novo' then nullif(v_career_patch->>'ca_novo','')::integer else cp.ca_novo end,
    pa=case when v_career_patch ? 'pa' then nullif(v_career_patch->>'pa','')::integer else cp.pa end,
    age=case when v_career_patch ? 'age' then nullif(v_career_patch->>'age','')::integer else cp.age end,
    updated_at=now()
   where cp.id=v_link_id and cp.owner_id=v_owner;
  else
   insert into public.career_players(owner_id,career_id,player_id,squad_status,club_name,position,ca,ca_novo,pa,age)
   values(
    v_owner,p_career_id,v_player_id,
    coalesce(nullif(v_career_patch->>'squad_status',''),'Plantel principal'),
    nullif(v_career_patch->>'club_name',''),nullif(v_career_patch->>'position',''),
    nullif(v_career_patch->>'ca','')::integer,nullif(v_career_patch->>'ca_novo','')::integer,
    nullif(v_career_patch->>'pa','')::integer,nullif(v_career_patch->>'age','')::integer
   ) returning id into v_link_id;
  end if;

  v_game_date := nullif(v_snapshot->'attributes'->>'gameDate','');
  if not exists (
   select 1 from public.player_attribute_snapshots s
    where s.career_id=p_career_id and s.player_id=v_player_id
      and s.season_id is not distinct from v_season_id
      and s.source='Save FM24'
      and coalesce(s.attributes->>'gameDate','')=coalesce(v_game_date,'')
  ) then
   insert into public.player_attribute_snapshots(owner_id,career_id,player_id,season_id,ca,pa,attributes,source)
   values(v_owner,p_career_id,v_player_id,v_season_id,
    nullif(v_snapshot->>'ca','')::integer,nullif(v_snapshot->>'pa','')::integer,
    coalesce(v_snapshot->'attributes','{}'::jsonb),coalesce(v_snapshot->>'source','Save FM24'));
   v_snapshots := v_snapshots+1;
  end if;
  if v_player_exists then v_updated := v_updated+1; end if;
 end loop;

 insert into public.import_jobs(owner_id,career_id,source_format,file_name,status,records_total,records_created,records_updated,records_skipped,report,completed_at)
 values(v_owner,p_career_id,'fm24-save',nullif(p_job->>'file_name',''),'completed',
  coalesce(nullif(p_job->>'records_total','')::integer,0),v_created,v_updated,
  coalesce(nullif(p_job->>'records_skipped','')::integer,0),
  coalesce(p_job->'report','{}'::jsonb),now());

 return jsonb_build_object('records_created',v_created,'records_updated',v_updated,
  'records_skipped',coalesce(nullif(p_job->>'records_skipped','')::integer,0),
  'snapshots_created',v_snapshots,'season_id',v_season_id);
end;
$$;

revoke all on function public.apply_fm24_save_import(uuid,jsonb,jsonb,jsonb) from public;
revoke all on function public.apply_fm24_save_import(uuid,jsonb,jsonb,jsonb) from anon;
grant execute on function public.apply_fm24_save_import(uuid,jsonb,jsonb,jsonb) to authenticated;

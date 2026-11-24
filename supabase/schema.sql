-- 실습실 기자재 불용 정리 : Supabase 스키마
-- 모든 표는 RLS로 막고(정책 없음 = anon 접근 불가), 접속 코드를 확인하는 함수로만 읽고 씁니다.
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.equip_config (
  key   text primary key,
  value jsonb not null
);
create table if not exists public.equip_items (
  id         text primary key,          -- 물품고유번호
  base       jsonb not null,            -- 기자재대장 + 에듀파인 물품목록정보 (읽기 전용)
  rec        jsonb not null default '{}'::jsonb,  -- 학과부장 입력 (실사, 사진 id, 사유, 비고 ...)
  upd        bigint not null default 0, -- 입력 시각(ms) : 늦게 저장한 쪽 우선
  updated_at timestamptz not null default now()
);
create table if not exists public.equip_photos (
  id         text primary key,
  data       text not null,             -- JPEG data URL (앱에서 1280px로 줄여 올림)
  created_at timestamptz not null default now()
);
create index if not exists equip_items_updated_at on public.equip_items(updated_at);

alter table public.equip_config enable row level security;
alter table public.equip_items  enable row level security;
alter table public.equip_photos enable row level security;
revoke all on public.equip_config, public.equip_items, public.equip_photos from anon, authenticated;

-- 접속 코드 확인
create or replace function public.equip_ok(p_code text) returns boolean
language sql stable security definer set search_path = public, extensions as $$
  select exists(select 1 from equip_config where key='passcode'
                and value->>'hash' = extensions.crypt(coalesce(p_code,''), value->>'hash'));
$$;

create or replace function public.equip_check(p_code text) returns boolean
language plpgsql stable security definer set search_path = public, extensions as $$
begin
  if not equip_ok(p_code) then perform pg_sleep(1); return false; end if;
  return true;
end $$;

-- 전체 불러오기 : 메타 + 기자재 + 사진 id 목록
create or replace function public.equip_load(p_code text) returns jsonb
language plpgsql stable security definer set search_path = public, extensions as $$
begin
  if not equip_ok(p_code) then perform pg_sleep(1); raise exception 'bad code'; end if;
  return jsonb_build_object(
    'meta',  (select value from equip_config where key='meta'),
    'now',   (extract(epoch from now())*1000)::bigint,
    'items', (select coalesce(jsonb_agg(jsonb_build_object('id',id,'base',base,'rec',rec,'upd',upd)),'[]'::jsonb) from equip_items),
    'photos',(select coalesce(jsonb_agg(id),'[]'::jsonb) from equip_photos));
end $$;

-- 다른 사람이 바꾼 것만 가져오기
create or replace function public.equip_since(p_code text, p_ms bigint) returns jsonb
language plpgsql stable security definer set search_path = public, extensions as $$
begin
  if not equip_ok(p_code) then raise exception 'bad code'; end if;
  return jsonb_build_object(
    'now',   (extract(epoch from now())*1000)::bigint,
    'items', (select coalesce(jsonb_agg(jsonb_build_object('id',id,'rec',rec,'upd',upd)),'[]'::jsonb)
              from equip_items where updated_at > to_timestamp(p_ms/1000.0) - interval '5 seconds'),
    'photos',(select coalesce(jsonb_agg(id),'[]'::jsonb) from equip_photos
              where created_at > to_timestamp(p_ms/1000.0) - interval '5 seconds'));
end $$;

-- 입력 저장 : [{id, rec, upd}] , 더 나중에 입력한 것만 반영
create or replace function public.equip_save(p_code text, p_items jsonb) returns integer
language plpgsql security definer set search_path = public, extensions as $$
declare n integer;
begin
  if not equip_ok(p_code) then perform pg_sleep(1); raise exception 'bad code'; end if;
  update equip_items t set rec = x.rec, upd = x.upd, updated_at = now()
    from jsonb_to_recordset(p_items) as x(id text, rec jsonb, upd bigint)
   where t.id = x.id and x.upd >= t.upd;
  get diagnostics n = row_count;
  return n;
end $$;

create or replace function public.equip_photo_put(p_code text, p_id text, p_data text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not equip_ok(p_code) then perform pg_sleep(1); raise exception 'bad code'; end if;
  if length(p_data) > 3000000 or p_data not like 'data:image/%' then raise exception 'bad photo'; end if;
  insert into equip_photos(id,data) values (p_id,p_data) on conflict (id) do nothing;
  return true;
end $$;

create or replace function public.equip_photo_get(p_code text, p_ids text[]) returns jsonb
language plpgsql stable security definer set search_path = public, extensions as $$
begin
  if not equip_ok(p_code) then raise exception 'bad code'; end if;
  return (select coalesce(jsonb_object_agg(id,data),'{}'::jsonb) from equip_photos where id = any(p_ids));
end $$;

-- 총괄 화면에서 담당자 이름 공유
create or replace function public.equip_meta_set(p_code text, p_key text, p_value jsonb) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not equip_ok(p_code) then raise exception 'bad code'; end if;
  if p_key not in ('managers') then raise exception 'bad key'; end if;
  update equip_config set value = jsonb_set(value, array[p_key], p_value, true) where key='meta';
  return true;
end $$;

revoke all on function public.equip_ok(text) from public, anon, authenticated;
grant execute on function public.equip_check(text), public.equip_load(text), public.equip_since(text,bigint),
  public.equip_save(text,jsonb), public.equip_photo_put(text,text,text), public.equip_photo_get(text,text[]),
  public.equip_meta_set(text,text,jsonb) to anon, authenticated;

-- ============================================================
-- 會考複習總覽 — 雲端同步＋老師端  001_hk.sql
--
-- 用法：Supabase（跟「統測單字 SRS App」同一個專案）→ SQL Editor → 貼上整份 → Run。
--       整份包在一個交易裡：中途出錯就全部不生效。
--       重複執行是安全的（建表用 if not exists、函式用 create or replace）。
--       只新增 hk_ 開頭的表與函式，不會改動 srs_ 或其他既有的表。
--
-- 前提（沿用既有專案設定，請確認仍成立）：
--   Authentication → Providers → Email →「Allow new users to sign up」是關的。
--   srs_teachers 已存在（統測單字 SRS App 的 001_srs.sql 跑過）。
--
-- 設計摘要（細節見同資料夾 SECURITY.md）：
--   hk_teachers  老師名單（auth 帳號 uid）。執行本檔時，從 srs_teachers 複製過來（同一位老師）；
--                檔尾最後一個查詢會列出名單，請確認只有你自己。
--   hk_students  學生（暱稱＋連結代碼的 SHA-256 雜湊；代碼本身不存）
--   hk_progress  一位學生一節一列：熟悉度 fam（1–5 或空）、複習次數 reviews、最後修改時間 updated_at
--   hk_plan      一張排程卡一列：卡片 id（App 產生）、章節、日期、完成時間、是否刪除（軟刪除）、最後修改時間
--
--   學生（anon，沒登入）：完全不能直接讀寫任何表；只能呼叫
--     hk_load(代碼) / hk_save(代碼, 進度列, 排程列)，函式內部用代碼雜湊找到「自己」才動作。
--   合併規則：每一列各自比 updated_at，新的贏（兩台改不同的列都會留下）。
--   老師（authenticated 且在 hk_teachers 裡）：可讀 hk_students（不含雜湊欄）、hk_progress、hk_plan；
--     建學生、重設連結只能透過 hk_create_student / hk_reset_link。
-- ============================================================

begin;

-- ---------- 表 ----------
create table if not exists public.hk_teachers (
  user_id  uuid primary key references auth.users (id) on delete cascade,
  added_at timestamptz not null default now()
);

create table if not exists public.hk_students (
  id            uuid primary key default gen_random_uuid(),
  nickname      text not null check (char_length(nickname) between 1 and 40),
  token_hash    bytea not null unique,          -- sha256(連結代碼)；代碼只在建立/重設時回傳一次
  created_at    timestamptz not null default now(),
  last_seen_at  timestamptz,                    -- 最後一次成功上傳（hk_save）
  link_reset_at timestamptz
);

create table if not exists public.hk_progress (
  student_id uuid not null references public.hk_students (id) on delete cascade,
  unit_id    text not null check (unit_id ~ '^[a-z0-9-]{1,40}$'),
  fam        smallint check (fam between 1 and 5),
  reviews    integer not null default 0 check (reviews between 0 and 99999),
  updated_at timestamptz not null,              -- App 端的修改時間（毫秒精度），合併時新的贏
  primary key (student_id, unit_id)
);

create table if not exists public.hk_plan (
  student_id uuid not null references public.hk_students (id) on delete cascade,
  id         text not null check (id ~ '^[a-z0-9]{1,40}$'),   -- App 產生的卡片 id；主鍵含 student_id → 不同學生的卡片永遠不會互蓋
  unit_id    text not null check (unit_id ~ '^[a-z0-9-]{1,40}$'),
  date       date not null,
  done_at    timestamptz,
  deleted    boolean not null default false,
  updated_at timestamptz not null,
  primary key (student_id, id)
);

-- ---------- RLS＋權限：預設全部收回，再只開必要的 ----------
alter table public.hk_teachers enable row level security;
alter table public.hk_students enable row level security;
alter table public.hk_progress enable row level security;
alter table public.hk_plan     enable row level security;

revoke all on table public.hk_teachers, public.hk_students, public.hk_progress, public.hk_plan
  from public, anon, authenticated;

-- 老師只需要「讀」；欄位級授權：不給 token_hash
grant select (id, nickname, created_at, last_seen_at, link_reset_at) on public.hk_students to authenticated;
grant select (student_id, unit_id, fam, reviews, updated_at) on public.hk_progress to authenticated;
grant select (student_id, id, unit_id, date, done_at, deleted, updated_at) on public.hk_plan to authenticated;

-- ---------- 老師判定 ----------
create or replace function public.hk_is_teacher()
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (select 1 from public.hk_teachers t where t.user_id = (select auth.uid()));
$$;

drop policy if exists hk_students_teacher_read on public.hk_students;
create policy hk_students_teacher_read on public.hk_students
  for select to authenticated using ((select public.hk_is_teacher()));

drop policy if exists hk_progress_teacher_read on public.hk_progress;
create policy hk_progress_teacher_read on public.hk_progress
  for select to authenticated using ((select public.hk_is_teacher()));

drop policy if exists hk_plan_teacher_read on public.hk_plan;
create policy hk_plan_teacher_read on public.hk_plan
  for select to authenticated using ((select public.hk_is_teacher()));
-- hk_teachers：沒有任何 policy＋沒有授權 → API 完全碰不到

-- ---------- 學生：讀進度 ----------
-- 回傳 {ok, sid, nickname, progress:[{unitId,fam,reviews,updatedAt}], plan:[{id,unitId,date,doneAt,deleted,updatedAt}]}
-- 時間一律用「1970 起算的毫秒數」（跟 App 的 Date.now() 一樣），來回轉換不會差 1 毫秒
create or replace function public.hk_load(p_token text)
returns jsonb
language plpgsql stable security definer
set search_path = ''
as $$
declare
  v_id uuid; v_nick text;
begin
  if p_token is null or p_token !~ '^[0-9a-f]{32}$' then
    return jsonb_build_object('ok', false, 'error', 'invalid_link');
  end if;
  select s.id, s.nickname into v_id, v_nick
    from public.hk_students s
   where s.token_hash = sha256(convert_to(p_token, 'UTF8'));
  if v_id is null then
    return jsonb_build_object('ok', false, 'error', 'invalid_link');
  end if;
  return jsonb_build_object(
    'ok', true, 'sid', v_id, 'nickname', v_nick,
    'progress', coalesce((
      select jsonb_agg(jsonb_build_object(
               'unitId', p.unit_id, 'fam', p.fam, 'reviews', p.reviews,
               'updatedAt', (extract(epoch from p.updated_at) * 1000)::bigint) order by p.unit_id)
        from public.hk_progress p where p.student_id = v_id), '[]'::jsonb),
    'plan', coalesce((
      select jsonb_agg(jsonb_build_object(
               'id', c.id, 'unitId', c.unit_id, 'date', to_char(c.date, 'YYYY-MM-DD'),
               'doneAt', (extract(epoch from c.done_at) * 1000)::bigint, 'deleted', c.deleted,
               'updatedAt', (extract(epoch from c.updated_at) * 1000)::bigint) order by c.date, c.id)
        from public.hk_plan c where c.student_id = v_id), '[]'::jsonb));
end
$$;

-- ---------- 學生：上傳改過的列 ----------
-- p_progress：[{unitId, fam(1–5 或 null), reviews(整數 ≥0), updatedAt(毫秒)}]
-- p_plan：    [{id, unitId, date('YYYY-MM-DD'), doneAt(毫秒或 null), deleted(true/false), updatedAt(毫秒)}]
-- 每一列：雲端沒有 → 新增；雲端有 → 只有 updatedAt 比雲端新才覆蓋（舊的直接忽略，不算錯）。
-- 任何一列格式不對 → 整筆拒收（bad_rows），什麼都不寫。成功時回傳跟 hk_load 一樣的整包（App 順便合併）。
create or replace function public.hk_save(p_token text, p_progress jsonb, p_plan jsonb)
returns jsonb
language plpgsql volatile security definer
set search_path = ''
as $$
declare
  c_max_progress   constant integer := 200;      -- 單次上傳最多幾列進度（數學 58 節）
  c_max_plan       constant integer := 2000;     -- 單次上傳最多幾張卡
  c_total_progress constant integer := 1000;     -- 每位學生進度列總數上限
  c_total_plan     constant integer := 5000;     -- 每位學生排程卡總數上限（含已刪除）
  v_id uuid; v_seen timestamptz;
  v_max_ms bigint := (extract(epoch from now()) * 1000)::bigint + 600000;   -- 時間最多只收到「現在＋10 分鐘」
begin
  if p_token is null or p_token !~ '^[0-9a-f]{32}$' then
    return jsonb_build_object('ok', false, 'error', 'invalid_link');
  end if;
  -- for update：同一位學生的上傳一次只處理一個（兩台同時送也不會算錯總數上限）
  select s.id, s.last_seen_at into v_id, v_seen
    from public.hk_students s
   where s.token_hash = sha256(convert_to(p_token, 'UTF8'))
   for update;
  if v_id is null then
    return jsonb_build_object('ok', false, 'error', 'invalid_link');
  end if;
  -- 簡單節流：同一位學生 1 秒內只收一次寫入（App 本身是改完 2 秒後才送）
  if v_seen is not null and v_seen > now() - interval '1 second' then
    return jsonb_build_object('ok', false, 'error', 'too_fast');
  end if;

  p_progress := coalesce(p_progress, '[]'::jsonb);
  p_plan     := coalesce(p_plan, '[]'::jsonb);
  if jsonb_typeof(p_progress) <> 'array' or jsonb_typeof(p_plan) <> 'array' then
    return jsonb_build_object('ok', false, 'error', 'bad_rows');
  end if;
  if jsonb_array_length(p_progress) > c_max_progress or jsonb_array_length(p_plan) > c_max_plan then
    return jsonb_build_object('ok', false, 'error', 'too_many');
  end if;
  if octet_length(p_progress::text) > 200000 or octet_length(p_plan::text) > 1000000 then
    return jsonb_build_object('ok', false, 'error', 'too_large');
  end if;

  -- 形狀檢查（每個條件本身都不會出錯；不合格整筆拒收）
  if exists (
    select 1 from jsonb_array_elements(p_progress) e(r)
     where case when jsonb_typeof(e.r) <> 'object' then true
           else exists (select 1 from jsonb_object_keys(e.r) k where k not in ('unitId', 'fam', 'reviews', 'updatedAt'))
             or coalesce(jsonb_typeof(e.r -> 'unitId'), '') <> 'string'
             or coalesce((e.r ->> 'unitId') !~ '^[a-z0-9-]{1,40}$', true)
             or not (e.r ? 'fam')
             or (e.r -> 'fam') not in ('null'::jsonb, '1'::jsonb, '2'::jsonb, '3'::jsonb, '4'::jsonb, '5'::jsonb)
             or coalesce(jsonb_typeof(e.r -> 'reviews'), '') <> 'number'
             or coalesce((e.r ->> 'reviews') !~ '^[0-9]{1,5}$', true)
             or coalesce(jsonb_typeof(e.r -> 'updatedAt'), '') <> 'number'
             or coalesce((e.r ->> 'updatedAt') !~ '^[0-9]{1,15}$', true)
           end)
  or exists (
    select 1 from jsonb_array_elements(p_plan) e(r)
     where case when jsonb_typeof(e.r) <> 'object' then true
           else exists (select 1 from jsonb_object_keys(e.r) k where k not in ('id', 'unitId', 'date', 'doneAt', 'deleted', 'updatedAt'))
             or coalesce(jsonb_typeof(e.r -> 'id'), '') <> 'string'
             or coalesce((e.r ->> 'id') !~ '^[a-z0-9]{1,40}$', true)
             or coalesce(jsonb_typeof(e.r -> 'unitId'), '') <> 'string'
             or coalesce((e.r ->> 'unitId') !~ '^[a-z0-9-]{1,40}$', true)
             or coalesce(jsonb_typeof(e.r -> 'date'), '') <> 'string'
             or coalesce((e.r ->> 'date') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$', true)
             or coalesce(jsonb_typeof(e.r -> 'doneAt'), '') not in ('null', 'number')
             or (jsonb_typeof(e.r -> 'doneAt') = 'number' and (e.r ->> 'doneAt') !~ '^[0-9]{1,15}$')
             or coalesce(jsonb_typeof(e.r -> 'deleted'), '') <> 'boolean'
             or coalesce(jsonb_typeof(e.r -> 'updatedAt'), '') <> 'number'
             or coalesce((e.r ->> 'updatedAt') !~ '^[0-9]{1,15}$', true)
           end)
  or (select count(*) <> count(distinct e.r ->> 'unitId') from jsonb_array_elements(p_progress) e(r))
  or (select count(*) <> count(distinct e.r ->> 'id') from jsonb_array_elements(p_plan) e(r)) then
    return jsonb_build_object('ok', false, 'error', 'bad_rows');
  end if;

  -- 寫入（包在子區塊：任何資料錯誤，例如 2026-02-30 這種不存在的日期 → 這一段全部復原、回 bad_rows）
  begin
    insert into public.hk_progress as t (student_id, unit_id, fam, reviews, updated_at)
    select v_id, e.r ->> 'unitId', (e.r ->> 'fam')::smallint, (e.r ->> 'reviews')::integer,
           timestamptz 'epoch' + least((e.r ->> 'updatedAt')::bigint, v_max_ms)::double precision * interval '1 millisecond'
      from jsonb_array_elements(p_progress) e(r)
    on conflict (student_id, unit_id) do update
       set fam = excluded.fam, reviews = excluded.reviews, updated_at = excluded.updated_at
     where excluded.updated_at > t.updated_at;

    insert into public.hk_plan as t (student_id, id, unit_id, date, done_at, deleted, updated_at)
    select v_id, e.r ->> 'id', e.r ->> 'unitId', (e.r ->> 'date')::date,
           case when jsonb_typeof(e.r -> 'doneAt') = 'number'
                then timestamptz 'epoch' + (e.r ->> 'doneAt')::bigint::double precision * interval '1 millisecond' end,
           (e.r ->> 'deleted')::boolean,
           timestamptz 'epoch' + least((e.r ->> 'updatedAt')::bigint, v_max_ms)::double precision * interval '1 millisecond'
      from jsonb_array_elements(p_plan) e(r)
    on conflict (student_id, id) do update
       set unit_id = excluded.unit_id, date = excluded.date, done_at = excluded.done_at,
           deleted = excluded.deleted, updated_at = excluded.updated_at
     where excluded.updated_at > t.updated_at;

    if (select count(*) from public.hk_progress p where p.student_id = v_id) > c_total_progress
       or (select count(*) from public.hk_plan c where c.student_id = v_id) > c_total_plan then
      raise exception using errcode = 'HK001';
    end if;
  exception
    when sqlstate 'HK001' then
      return jsonb_build_object('ok', false, 'error', 'too_many');
    when data_exception or integrity_constraint_violation or cardinality_violation then
      return jsonb_build_object('ok', false, 'error', 'bad_rows');
  end;

  update public.hk_students set last_seen_at = now() where id = v_id;
  return public.hk_load(p_token);
end
$$;

-- ---------- 老師：建學生（回傳連結代碼，只出現這一次） ----------
create or replace function public.hk_create_student(p_nickname text)
returns jsonb
language plpgsql volatile security definer
set search_path = ''
as $$
declare
  v_nick text := btrim(coalesce(p_nickname, ''));
  v_token text; v_id uuid;
begin
  if not public.hk_is_teacher() then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  if char_length(v_nick) not between 1 and 40 or v_nick ~ '[[:cntrl:]]' then
    return jsonb_build_object('ok', false, 'error', 'bad_nickname');
  end if;
  -- gen_random_uuid() 用的是資料庫的強亂數；去掉 - 後 32 個十六進位字＝122 bits 隨機
  v_token := replace(gen_random_uuid()::text, '-', '');
  insert into public.hk_students (nickname, token_hash)
       values (v_nick, sha256(convert_to(v_token, 'UTF8')))
    returning id into v_id;
  return jsonb_build_object('ok', true, 'id', v_id, 'nickname', v_nick, 'token', v_token);
end
$$;

-- ---------- 老師：重設學生連結（舊連結立刻失效；雲端進度不受影響） ----------
create or replace function public.hk_reset_link(p_student uuid)
returns jsonb
language plpgsql volatile security definer
set search_path = ''
as $$
declare
  v_token text;
begin
  if not public.hk_is_teacher() then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  v_token := replace(gen_random_uuid()::text, '-', '');
  update public.hk_students
     set token_hash = sha256(convert_to(v_token, 'UTF8')), link_reset_at = now()
   where id = p_student;
  if not found then
    return jsonb_build_object('ok', false, 'error', 'not_found');
  end if;
  return jsonb_build_object('ok', true, 'token', v_token);
end
$$;

-- ---------- 函式執行權限：先全部收回，再逐一開放 ----------
revoke all on function public.hk_is_teacher()                  from public, anon, authenticated;
revoke all on function public.hk_load(text)                    from public, anon, authenticated;
revoke all on function public.hk_save(text, jsonb, jsonb)      from public, anon, authenticated;
revoke all on function public.hk_create_student(text)          from public, anon, authenticated;
revoke all on function public.hk_reset_link(uuid)              from public, anon, authenticated;

grant execute on function public.hk_is_teacher()             to authenticated;
grant execute on function public.hk_load(text)               to anon, authenticated;
grant execute on function public.hk_save(text, jsonb, jsonb) to anon, authenticated;
grant execute on function public.hk_create_student(text)     to authenticated;
grant execute on function public.hk_reset_link(uuid)         to authenticated;

-- ---------- 老師名單：沿用統測單字 SRS App 的老師（srs_teachers 只有 user_id、added_at 兩欄） ----------
insert into public.hk_teachers (user_id)
select t.user_id from public.srs_teachers t
on conflict (user_id) do nothing;

notify pgrst, 'reload schema';

commit;

-- 執行完請看下面這張表：只應該出現你自己的 email。多出來的帳號請刪掉：
--   delete from public.hk_teachers where user_id = (select id from auth.users where email = '多出來的email');
select u.email as "有老師權限的帳號（會考複習）" from public.hk_teachers t join auth.users u on u.id = t.user_id;

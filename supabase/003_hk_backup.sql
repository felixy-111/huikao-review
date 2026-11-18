-- ============================================================
-- 會考複習總覽 — 每日備份  003_hk_backup.sql
--
-- 用法：001_hk.sql、002_verify_hk.sql 都跑過之後 → SQL Editor → 貼上整份 → Run。
--       整份包在一個交易裡：中途出錯就全部不生效。重複執行是安全的。
--       之後請跑 004_verify_backup.sql 驗證（也建議再跑一次 002，確認 hk_save 原本的規則沒變）。
--
-- 為什麼：學生連結一旦外流，拿到連結的人可以把那位學生的進度亂改；
--         以前沒有備份，只能靠學生自己的裝置改回來。
--
-- 做了什麼：
--   hk_backup  一位學生一天一列：progress、plan 兩包 jsonb（當下雲端的整份），day＝台北日期。
--   hk_save    改成：每位學生「台北時間每天第一次」通過格式檢查、準備寫入之前，
--              先把他雲端現在的進度＋排程整份存進 hk_backup（同一天已經有就不動）。
--              其餘規則（格式檢查、數量上限、節流、時間新的贏、回傳格式）一字不改，只多了這一步。
--
-- 權限：anon（學生端）完全碰不到 hk_backup；老師（hk_teachers）只能「讀」（日後做趨勢圖用）；
--       沒有任何人能透過 API 改或刪備份。救援（退回某天）只能在 SQL Editor 做，步驟見 SECURITY.md。
--
-- 保留：全部保留，不自動刪除。估算：一天一包約 5–60 KB（58 節＋幾百張卡），
--       180 天 × 幾位學生 ≈ 幾十 MB 以內。要清舊的可在 SQL Editor 跑 SECURITY.md 裡的那行 delete。
--
-- 備份內容格式（欄位名跟資料表一樣，方便還原時直接對回資料表）：
--   progress: [{unit_id, fam, reviews, updated_at}]                      依 unit_id 排序
--   plan:     [{id, unit_id, date, done_at, deleted, updated_at}]          依 date, id 排序
--   時間是 ISO 字串（例 "2026-11-17T03:04:05.123+00:00"），日期是 "YYYY-MM-DD"。
-- ============================================================

begin;

-- ---------- 表 ----------
create table if not exists public.hk_backup (
  student_id uuid not null references public.hk_students (id) on delete cascade,
  day        date not null,                     -- 台北日期
  progress   jsonb not null,
  plan       jsonb not null,
  created_at timestamptz not null default now(),
  primary key (student_id, day)
);

-- ---------- RLS＋權限：預設全部收回，再只開老師「讀」 ----------
alter table public.hk_backup enable row level security;

revoke all on table public.hk_backup from public, anon, authenticated;

grant select (student_id, day, progress, plan, created_at) on public.hk_backup to authenticated;

drop policy if exists hk_backup_teacher_read on public.hk_backup;
create policy hk_backup_teacher_read on public.hk_backup
  for select to authenticated using ((select public.hk_is_teacher()));
-- anon：沒有授權＋沒有 policy → 碰不到。authenticated 但不是老師：RLS 回 0 列。
-- 寫入只有 hk_save（security definer）會做；沒有任何 insert/update/delete 授權。

-- ---------- 學生：上傳改過的列（＝ 001 的 hk_save，只多了「每天第一次寫入前先備份」） ----------
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
  c_max_progress   constant integer := 200;      -- 單次上傳最多幾列進度（多科合計約 265 節）
  c_max_plan       constant integer := 2000;     -- 單次上傳最多幾張卡
  c_total_progress constant integer := 1000;     -- 每位學生進度列總數上限
  c_total_plan     constant integer := 5000;     -- 每位學生排程卡總數上限（含已刪除）
  v_id uuid; v_seen timestamptz;
  v_max_ms bigint := (extract(epoch from now()) * 1000)::bigint + 600000;   -- 時間最多只收到「現在＋10 分鐘」
  v_today date := (now() at time zone 'Asia/Taipei')::date;                 -- 003 新增：備份用的台北日期
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

  -- 003 新增：台北時間今天第一次寫入前，先把這位學生雲端現在的整份存一份（同一天已有就不動）
  -- 放在上面所有檢查之後：代碼錯、too_fast、格式不對、單次太多／太大的上傳，不會產生備份。
  -- 放在下面子區塊之外：寫入階段才被拒的（例如 2026-02-30 這種日期、總數超過上限），備份會留著；
  --   內容仍是「寫入前」的樣子，等於今天的起點，留著無害。
  -- 上面已經 for update 鎖住這位學生，同一位學生不會兩筆同時走到這裡。
  if not exists (select 1 from public.hk_backup b where b.student_id = v_id and b.day = v_today) then
    insert into public.hk_backup (student_id, day, progress, plan)
    values (
      v_id, v_today,
      coalesce((
        select jsonb_agg(jsonb_build_object(
                 'unit_id', p.unit_id, 'fam', p.fam, 'reviews', p.reviews, 'updated_at', p.updated_at) order by p.unit_id)
          from public.hk_progress p where p.student_id = v_id), '[]'::jsonb),
      coalesce((
        select jsonb_agg(jsonb_build_object(
                 'id', c.id, 'unit_id', c.unit_id, 'date', c.date, 'done_at', c.done_at,
                 'deleted', c.deleted, 'updated_at', c.updated_at) order by c.date, c.id)
          from public.hk_plan c where c.student_id = v_id), '[]'::jsonb))
    on conflict (student_id, day) do nothing;
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

-- ---------- 函式執行權限：跟 001 一樣 ----------
revoke all on function public.hk_save(text, jsonb, jsonb)      from public, anon, authenticated;
grant execute on function public.hk_save(text, jsonb, jsonb) to anon, authenticated;

notify pgrst, 'reload schema';

commit;

-- ============================================================
-- 會考複習總覽 — 每日備份驗證  004_verify_backup.sql
--
-- 什麼時候跑：003_hk_backup.sql 執行成功之後，在 SQL Editor 貼上這整份 → Run。
--
-- 它會做什麼：建兩個測試學生，假扮學生上傳幾次，確認：
--   每天第一次上傳前會存備份、同一天第二次不會重複也不會覆蓋、備份裡是「改之前」的值、
--   被拒收的上傳不會產生備份、學生端（anon）和「登入但不是老師」的人讀不到備份、老師只能讀不能改，
--   以及 SECURITY.md 裡的「救援 SQL」真的能把進度退回去（而且被改壞的舊版本蓋不回來）。
--
-- 會不會弄髒資料庫：不會。跟 002 一樣，最後一行「故意丟出錯誤」，這個區塊做過的所有事全部復原。
--
-- 怎麼看結果：
--   成功：紅色錯誤，訊息開頭是「備份驗證全部通過」→ 正常（紅字是故意的）。
--   失敗：訊息開頭是「FAIL」或其他任何錯誤 → 把整段訊息截圖給 Claude 看。
--
-- 註：整份在同一個交易裡，時間不會走，所以：
--   - 每次正常上傳前以管理者身分把 last_seen_at 清空（模擬「過了一秒」，同 002）；
--   - 以管理者身分把備份的日期往前挪一天，模擬「過了一天」。
-- ============================================================

do $verify$
declare
  v_teacher uuid; v_tok text; v_tokb text; v_sid uuid; v_sidb uuid;
  v_r jsonb; v_n integer; v_ms bigint;
  v_today date := (now() at time zone 'Asia/Taipei')::date;
  v_log text[] := '{}';
  c_u1 constant text := 'm-kx-7a-1-1';
  c_u2 constant text := 'm-kx-7a-1-2';
  -- 下面三個跟 SECURITY.md 救援 SQL 用的變數同名
  v_day date; v_b public.hk_backup; v_now timestamptz;
begin
  select t.user_id into v_teacher from public.hk_teachers t limit 1;
  if v_teacher is null then raise exception 'FAIL 0：hk_teachers 是空的（沒有老師帳號）'; end if;

  -- ===== 1. 學生端（anon）碰不到 hk_backup =====
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  set local role anon;
  begin perform 1 from public.hk_backup; raise exception 'FAIL 1a：anon 讀得到 hk_backup';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1a 學生端不能讀備份'::text; end;
  begin insert into public.hk_backup (student_id, day, progress, plan) values (gen_random_uuid(), current_date, '[]', '[]');
    raise exception 'FAIL 1b：anon 能寫 hk_backup';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1b 學生端不能寫備份'::text; end;
  reset role;

  -- ===== 2. 老師建兩個測試學生 =====
  perform set_config('request.jwt.claims', json_build_object('sub', v_teacher, 'role', 'authenticated')::text, true);
  set local role authenticated;
  v_r := public.hk_create_student('備份驗證甲');
  v_tok := v_r ->> 'token'; v_sid := (v_r ->> 'id')::uuid;
  v_r := public.hk_create_student('備份驗證乙');
  v_tokb := v_r ->> 'token'; v_sidb := (v_r ->> 'id')::uuid;
  if v_sid is null or v_sidb is null then raise exception 'FAIL 2：建測試學生失敗 %', v_r; end if;
  reset role;

  -- ===== 3. 每日備份的時機與內容 =====
  -- 3a 今天第一次上傳 → 建立今天的備份，內容是上傳「之前」的雲端（新學生＝空的）
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  set local role anon;
  v_r := public.hk_save(v_tok,
    jsonb_build_array(jsonb_build_object('unitId', c_u1, 'fam', 2, 'reviews', 1, 'updatedAt', 1763300001000)),
    jsonb_build_array(jsonb_build_object('id', 'c1', 'unitId', c_u1, 'date', '2026-11-20', 'doneAt', null, 'deleted', false, 'updatedAt', 1763300001000)));
  if (v_r ->> 'ok')::boolean is not true then raise exception 'FAIL 3a：第一次上傳失敗 %', v_r; end if;
  reset role;
  select count(*) into v_n from public.hk_backup b where b.student_id = v_sid;
  if v_n <> 1 or not exists (select 1 from public.hk_backup b
                              where b.student_id = v_sid and b.day = v_today
                                and b.progress = '[]'::jsonb and b.plan = '[]'::jsonb) then
    raise exception 'FAIL 3a：第一次上傳沒有建立今天（%）的備份，或內容不是上傳前的樣子（%）', v_today, v_n;
  end if;
  v_log := v_log || 'PASS 3a 今天第一次上傳前有存備份（台北日期），內容是上傳前的樣子'::text;

  -- 3b 同一天第二次上傳 → 不多一份、也不覆蓋
  update public.hk_students set last_seen_at = null where id in (v_sid, v_sidb);
  set local role anon;
  v_r := public.hk_save(v_tok,
    jsonb_build_array(jsonb_build_object('unitId', c_u1, 'fam', 3, 'reviews', 2, 'updatedAt', 1763300002000)),
    jsonb_build_array(jsonb_build_object('id', 'c2', 'unitId', c_u2, 'date', '2026-11-22', 'doneAt', null, 'deleted', false, 'updatedAt', 1763300002000)));
  if (v_r ->> 'ok')::boolean is not true or (v_r -> 'progress' -> 0 ->> 'fam')::int <> 3 then
    raise exception 'FAIL 3b：第二次上傳失敗 %', v_r;
  end if;
  reset role;
  select count(*) into v_n from public.hk_backup b where b.student_id = v_sid;
  if v_n <> 1 or not exists (select 1 from public.hk_backup b
                              where b.student_id = v_sid and b.day = v_today
                                and b.progress = '[]'::jsonb and b.plan = '[]'::jsonb) then
    raise exception 'FAIL 3b：同一天第二次上傳多存了一份或蓋掉了早上的備份（%）', v_n;
  end if;
  v_log := v_log || 'PASS 3b 同一天第二次上傳：不重複、不覆蓋'::text;

  -- 3c 模擬「過了一天」；這天第一筆是格式不對被拒收的 → 不應該產生備份
  update public.hk_backup set day = day - 1 where student_id = v_sid;
  update public.hk_students set last_seen_at = null where id in (v_sid, v_sidb);
  set local role anon;
  if public.hk_save(v_tok, '[{"unitId":"m-kx-7a-1-1","fam":7,"reviews":0,"updatedAt":1}]'::jsonb, '[]'::jsonb) ->> 'error'
     is distinct from 'bad_rows' then
    raise exception 'FAIL 3c：格式不對的上傳沒有被拒';
  end if;
  reset role;
  if exists (select 1 from public.hk_backup b where b.student_id = v_sid and b.day = v_today) then
    raise exception 'FAIL 3c：被拒收的上傳產生了備份';
  end if;
  v_log := v_log || 'PASS 3c 被拒收的上傳不會產生備份'::text;

  -- 3d 新的一天第一次正常上傳 → 新備份裡是「昨天最後的樣子」（fam 3、2 次、c1 還沒刪），而寫入照常生效
  update public.hk_students set last_seen_at = null where id in (v_sid, v_sidb);
  set local role anon;
  v_r := public.hk_save(v_tok,
    jsonb_build_array(jsonb_build_object('unitId', c_u1, 'fam', 5, 'reviews', 3, 'updatedAt', 1763300003000)),
    jsonb_build_array(jsonb_build_object('id', 'c1', 'unitId', c_u1, 'date', '2026-11-21', 'doneAt', 1763300003000, 'deleted', true, 'updatedAt', 1763300003000)));
  if (v_r ->> 'ok')::boolean is not true or (v_r -> 'progress' -> 0 ->> 'fam')::int <> 5
     or not exists (select 1 from jsonb_array_elements(v_r -> 'plan') x where x ->> 'id' = 'c1' and (x ->> 'deleted')::boolean) then
    raise exception 'FAIL 3d：新的一天上傳沒有生效 %', v_r;
  end if;
  reset role;
  select count(*) into v_n from public.hk_backup b where b.student_id = v_sid;
  select * into v_b from public.hk_backup b where b.student_id = v_sid and b.day = v_today;
  if not found or v_n <> 2
     or jsonb_array_length(v_b.progress) <> 1
     or v_b.progress -> 0 ->> 'unit_id' is distinct from c_u1
     or (v_b.progress -> 0 ->> 'fam')::int is distinct from 3
     or (v_b.progress -> 0 ->> 'reviews')::int is distinct from 2
     or (v_b.progress -> 0 ->> 'updated_at')::timestamptz
          is distinct from timestamptz 'epoch' + 1763300002000::double precision * interval '1 millisecond'
     or jsonb_array_length(v_b.plan) <> 2
     or not exists (select 1 from jsonb_array_elements(v_b.plan) x
                     where x ->> 'id' = 'c1' and x ->> 'unit_id' = c_u1 and x ->> 'date' = '2026-11-20'
                       and x ->> 'done_at' is null and (x ->> 'deleted')::boolean = false)
     or not exists (select 1 from jsonb_array_elements(v_b.plan) x
                     where x ->> 'id' = 'c2' and x ->> 'unit_id' = c_u2 and x ->> 'date' = '2026-11-22') then
    raise exception 'FAIL 3d：新的一天的備份不對（份數 %）：%', v_n, left(row_to_json(v_b)::text, 500);
  end if;
  v_log := v_log || 'PASS 3d 新的一天第一次上傳前存了新備份，內容是改之前的值（分數、次數、時間、卡片都對）'::text;

  -- 3e 同一天再上傳（模擬有人亂改：改分數、多一節、多一張卡）→ 今天的備份一字不變
  update public.hk_students set last_seen_at = null where id in (v_sid, v_sidb);
  set local role anon;
  v_r := public.hk_save(v_tok,
    jsonb_build_array(
      jsonb_build_object('unitId', c_u1, 'fam', 1, 'reviews', 9, 'updatedAt', 1763300004000),
      jsonb_build_object('unitId', c_u2, 'fam', 1, 'reviews', 9, 'updatedAt', 1763300004000)),
    jsonb_build_array(
      jsonb_build_object('id', 'c3', 'unitId', c_u1, 'date', '2026-12-25', 'doneAt', null, 'deleted', false, 'updatedAt', 1763300004000)));
  if (v_r ->> 'ok')::boolean is not true then raise exception 'FAIL 3e：上傳失敗 %', v_r; end if;
  reset role;
  select count(*) into v_n from public.hk_backup b where b.student_id = v_sid;
  if v_n <> 2 or not exists (select 1 from public.hk_backup b
                              where b.student_id = v_sid and b.day = v_today
                                and b.progress = v_b.progress and b.plan = v_b.plan) then
    raise exception 'FAIL 3e：同一天之後的上傳改到了今天的備份（%）', v_n;
  end if;
  v_log := v_log || 'PASS 3e 同一天之後的上傳不會改到今天的備份'::text;

  -- 3f 不同學生互不影響：甲的上傳不會替乙建備份；乙自己上傳才有
  select count(*) into v_n from public.hk_backup b where b.student_id = v_sidb;
  if v_n <> 0 then raise exception 'FAIL 3f：甲的上傳替乙建了備份'; end if;
  set local role anon;
  v_r := public.hk_save(v_tokb,
    jsonb_build_array(jsonb_build_object('unitId', c_u1, 'fam', 4, 'reviews', 1, 'updatedAt', 1763300005000)), '[]'::jsonb);
  if (v_r ->> 'ok')::boolean is not true then raise exception 'FAIL 3f：乙上傳失敗 %', v_r; end if;
  reset role;
  select count(*) into v_n from public.hk_backup b where b.student_id = v_sidb;
  if v_n <> 1 then raise exception 'FAIL 3f：乙的備份數量不對（%）', v_n; end if;
  select count(*) into v_n from public.hk_backup b where b.student_id = v_sid;
  if v_n <> 2 then raise exception 'FAIL 3f：乙的上傳影響到甲的備份（%）', v_n; end if;
  v_log := v_log || 'PASS 3f 每位學生各自備份，互不影響'::text;

  -- ===== 4. 登入了但不是老師：讀不到、寫不了 =====
  perform set_config('request.jwt.claims', json_build_object('sub', gen_random_uuid(), 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into v_n from public.hk_backup;
  if v_n <> 0 then raise exception 'FAIL 4a：非老師帳號讀得到備份（%）', v_n; end if;
  begin insert into public.hk_backup (student_id, day, progress, plan) values (v_sid, date '2000-01-01', '[]', '[]');
    raise exception 'FAIL 4b：非老師帳號能寫 hk_backup';
  exception when insufficient_privilege then null; end;
  v_log := v_log || 'PASS 4 登入但不是老師：讀不到備份、也寫不了'::text;
  reset role;

  -- ===== 5. 老師：讀得到（做趨勢用），但不能改、不能刪、不能新增 =====
  perform set_config('request.jwt.claims', json_build_object('sub', v_teacher, 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into v_n from public.hk_backup b where b.student_id = v_sid;
  if v_n <> 2 then raise exception 'FAIL 5a：老師讀不到甲的備份（%）', v_n; end if;
  select count(*) into v_n from public.hk_backup b
   where b.student_id = v_sid and b.day = v_today and (b.progress -> 0 ->> 'fam')::int = 3 and b.created_at is not null;
  if v_n <> 1 then raise exception 'FAIL 5b：老師讀不到備份內容'; end if;
  begin update public.hk_backup set progress = '[]' where student_id = v_sid; raise exception 'FAIL 5c：老師能改備份';
  exception when insufficient_privilege then null; end;
  begin delete from public.hk_backup where student_id = v_sid; raise exception 'FAIL 5d：老師能刪備份';
  exception when insufficient_privilege then null; end;
  begin insert into public.hk_backup (student_id, day, progress, plan) values (v_sid, date '2000-01-01', '[]', '[]');
    raise exception 'FAIL 5e：老師能新增備份';
  exception when insufficient_privilege then null; end;
  v_log := v_log || 'PASS 5 老師：讀得到備份（日期、內容），不能改、刪、新增'::text;
  reset role;

  -- ===== 6. 救援：把甲退回「今天的備份」（＝ 3e 亂改之前、3d 寫入之前的樣子） =====
  v_day := v_today;
  -- ↓↓↓ 以下到 ↑↑↑ 為止，跟 SECURITY.md「救援」那段 DO 區塊的本體一模一樣（改一邊就要改另一邊）
  v_now := date_trunc('milliseconds', now());
  select * into v_b from public.hk_backup b where b.student_id = v_sid and b.day = v_day;
  if not found then raise exception '找不到這位學生在 % 的備份', v_day; end if;
  perform 1 from public.hk_students s where s.id = v_sid for update;

  insert into public.hk_progress as t (student_id, unit_id, fam, reviews, updated_at)
  select v_sid, r.unit_id, r.fam, r.reviews, v_now
    from jsonb_populate_recordset(null::public.hk_progress, v_b.progress) r
  on conflict (student_id, unit_id) do update
     set fam = excluded.fam, reviews = excluded.reviews,
         updated_at = greatest(excluded.updated_at, t.updated_at + interval '1 millisecond')
   where (t.fam, t.reviews) is distinct from (excluded.fam, excluded.reviews);
  update public.hk_progress t
     set fam = null, reviews = 0, updated_at = greatest(v_now, t.updated_at + interval '1 millisecond')
   where t.student_id = v_sid
     and (t.fam is not null or t.reviews <> 0)
     and not exists (select 1 from jsonb_array_elements(v_b.progress) e(r) where e.r ->> 'unit_id' = t.unit_id);

  insert into public.hk_plan as t (student_id, id, unit_id, date, done_at, deleted, updated_at)
  select v_sid, r.id, r.unit_id, r.date, r.done_at, r.deleted, v_now
    from jsonb_populate_recordset(null::public.hk_plan, v_b.plan) r
  on conflict (student_id, id) do update
     set unit_id = excluded.unit_id, date = excluded.date, done_at = excluded.done_at, deleted = excluded.deleted,
         updated_at = greatest(excluded.updated_at, t.updated_at + interval '1 millisecond')
   where (t.unit_id, t.date, t.done_at, t.deleted) is distinct from (excluded.unit_id, excluded.date, excluded.done_at, excluded.deleted);
  update public.hk_plan t
     set deleted = true, updated_at = greatest(v_now, t.updated_at + interval '1 millisecond')
   where t.student_id = v_sid and not t.deleted
     and not exists (select 1 from jsonb_array_elements(v_b.plan) e(r) where e.r ->> 'id' = t.id);
  -- ↑↑↑

  v_ms := (extract(epoch from v_now) * 1000)::bigint;
  v_r := public.hk_load(v_tok);
  if not exists (select 1 from jsonb_array_elements(v_r -> 'progress') x
                  where x ->> 'unitId' = c_u1 and (x ->> 'fam')::int = 3 and (x ->> 'reviews')::int = 2
                    and (x ->> 'updatedAt')::bigint >= v_ms) then
    raise exception 'FAIL 6a：退回後第 1 節的分數／次數不對，或時間沒有更新成「現在」 %', v_r;
  end if;
  if not exists (select 1 from jsonb_array_elements(v_r -> 'progress') x
                  where x ->> 'unitId' = c_u2 and x -> 'fam' = 'null'::jsonb and (x ->> 'reviews')::int = 0
                    and (x ->> 'updatedAt')::bigint >= v_ms) then
    raise exception 'FAIL 6b：備份之後才出現的那一節沒有被清回「未評分、0 次」 %', v_r;
  end if;
  if not exists (select 1 from jsonb_array_elements(v_r -> 'plan') x
                  where x ->> 'id' = 'c1' and x ->> 'date' = '2026-11-20' and x -> 'doneAt' = 'null'::jsonb
                    and (x ->> 'deleted')::boolean = false and (x ->> 'updatedAt')::bigint >= v_ms)
     or not exists (select 1 from jsonb_array_elements(v_r -> 'plan') x
                     where x ->> 'id' = 'c2' and (x ->> 'deleted')::boolean = false and (x ->> 'updatedAt')::bigint = 1763300002000)
     or not exists (select 1 from jsonb_array_elements(v_r -> 'plan') x
                     where x ->> 'id' = 'c3' and (x ->> 'deleted')::boolean and (x ->> 'updatedAt')::bigint >= v_ms) then
    raise exception 'FAIL 6c：退回後的排程卡不對（c1 要復原、c2 不動、c3 要軟刪除） %', v_r;
  end if;
  if (select (x ->> 'fam')::int from jsonb_array_elements(public.hk_load(v_tokb) -> 'progress') x where x ->> 'unitId' = c_u1)
     is distinct from 4 then
    raise exception 'FAIL 6d：退回甲的時候動到了乙';
  end if;

  -- 6e 亂改的人（或還留著舊資料的裝置）再送一次亂改時的版本 → 時間比較舊，蓋不回來
  update public.hk_students set last_seen_at = null where id in (v_sid, v_sidb);
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  set local role anon;
  v_r := public.hk_save(v_tok,
    jsonb_build_array(jsonb_build_object('unitId', c_u1, 'fam', 1, 'reviews', 9, 'updatedAt', 1763300004000)),
    jsonb_build_array(jsonb_build_object('id', 'c3', 'unitId', c_u1, 'date', '2026-12-25', 'doneAt', null, 'deleted', false, 'updatedAt', 1763300004000)));
  reset role;
  if (v_r ->> 'ok')::boolean is not true
     or not exists (select 1 from jsonb_array_elements(v_r -> 'progress') x where x ->> 'unitId' = c_u1 and (x ->> 'fam')::int = 3)
     or not exists (select 1 from jsonb_array_elements(v_r -> 'plan') x where x ->> 'id' = 'c3' and (x ->> 'deleted')::boolean) then
    raise exception 'FAIL 6e：退回之後，亂改時的舊版本又蓋回來了 %', v_r;
  end if;
  v_log := v_log || 'PASS 6 救援 SQL：分數／次數／卡片退回備份那天、之後多出來的節與卡被清掉、時間更新成現在（所有裝置會跟上）、亂改的舊版本蓋不回來、不影響別的學生'::text;

  raise exception using errcode = 'P0001', message =
    '備份驗證全部通過（' || array_length(v_log, 1) || ' 組）。這行紅字是刻意的：讓剛才的測試學生與測試資料全部自動復原。' || E'\n' ||
    array_to_string(v_log, E'\n');
end
$verify$;

-- ============================================================
-- 會考複習總覽 — 權限驗證  002_verify_hk.sql
--
-- 什麼時候跑：001_hk.sql 執行成功之後，在同一個 SQL Editor 貼上這整份 → Run。
--
-- 它會做什麼：假扮「學生（沒登入）」「老師」「登入但不是老師的人」三種身分，
--   實際去讀表、建兩個測試學生、上傳進度、重設連結……逐項確認權限擋得住、合併規則正確。
--
-- 會不會弄髒資料庫：不會。整份是「一個區塊」，最後一行「故意丟出錯誤」，
--   資料庫碰到錯誤會把這個區塊做過的所有事全部復原（測試學生、測試進度都不會留下）。
--
-- 怎麼看結果：
--   成功：畫面出現紅色錯誤，但訊息開頭是「驗證全部通過」→ 這是正常的（見上一段）。
--   失敗：訊息開頭是「FAIL」或其他任何錯誤 → 把整段訊息截圖給 Claude 看。
--
-- 註：hk_save 有「同一位學生 1 秒內只收一次」的節流，而這整份在同一個交易裡（時間不會走），
--     所以每次正常上傳前會以管理者身分把 last_seen_at 清空，模擬「過了一秒」。
-- ============================================================

do $verify$
declare
  v_teacher uuid; v_tok text; v_tok2 text; v_tokb text; v_sid uuid; v_sidb uuid;
  v_r jsonb; v_n integer; v_ms bigint;
  v_log text[] := '{}';
  c_fake constant text := '0123456789abcdef0123456789abcdef';
  c_u1 constant text := 'm-kx-7a-1-1';
  c_u2 constant text := 'm-kx-7a-1-2';
  v_bad jsonb;
begin
  select t.user_id into v_teacher from public.hk_teachers t limit 1;
  if v_teacher is null then raise exception 'FAIL 0：hk_teachers 是空的（沒有老師帳號）'; end if;

  -- ===== 1. 學生端（anon，沒登入）：不能直接碰任何表、不能用老師功能 =====
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  set local role anon;
  begin perform 1 from public.hk_students; raise exception 'FAIL 1a：anon 讀得到 hk_students';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1a 學生端不能直接讀 hk_students'::text; end;
  begin perform 1 from public.hk_progress; raise exception 'FAIL 1b：anon 讀得到 hk_progress';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1b 學生端不能直接讀 hk_progress'::text; end;
  begin perform 1 from public.hk_plan; raise exception 'FAIL 1c：anon 讀得到 hk_plan';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1c 學生端不能直接讀 hk_plan'::text; end;
  begin perform 1 from public.hk_teachers; raise exception 'FAIL 1d：anon 讀得到 hk_teachers';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1d 學生端不能讀老師名單'::text; end;
  begin insert into public.hk_students (nickname, token_hash) values ('x', '\x00'); raise exception 'FAIL 1e：anon 能新增學生列';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1e 學生端不能直接寫表'::text; end;
  begin perform public.hk_create_student('x'); raise exception 'FAIL 1f：anon 能建學生';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1f 學生端不能呼叫「建學生」'::text; end;
  begin perform public.hk_reset_link(gen_random_uuid()); raise exception 'FAIL 1g：anon 能重設連結';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1g 學生端不能呼叫「重設連結」'::text; end;
  begin perform public.hk_is_teacher(); raise exception 'FAIL 1h：anon 能呼叫 hk_is_teacher';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1h 學生端不能呼叫老師判定'::text; end;
  if public.hk_load(c_fake) ->> 'error' is distinct from 'invalid_link'
     or public.hk_load('<script>') ->> 'error' is distinct from 'invalid_link'
     or public.hk_load(null) ->> 'error' is distinct from 'invalid_link'
     or public.hk_save(c_fake, '[]'::jsonb, '[]'::jsonb) ->> 'error' is distinct from 'invalid_link' then
    raise exception 'FAIL 1i：錯的代碼沒有被拒';
  end if;
  v_log := v_log || 'PASS 1i 錯的／亂打的代碼讀不到也寫不了'::text;
  reset role;

  -- ===== 2. 老師 =====
  perform set_config('request.jwt.claims', json_build_object('sub', v_teacher, 'role', 'authenticated')::text, true);
  set local role authenticated;
  if not public.hk_is_teacher() then raise exception 'FAIL 2a：老師帳號不被認成老師'; end if;
  v_r := public.hk_create_student('驗證用學生甲');
  if (v_r ->> 'ok')::boolean is not true or (v_r ->> 'token') !~ '^[0-9a-f]{32}$' then raise exception 'FAIL 2b：建學生失敗 %', v_r; end if;
  v_tok := v_r ->> 'token'; v_sid := (v_r ->> 'id')::uuid;
  v_r := public.hk_create_student('驗證用學生乙');
  v_tokb := v_r ->> 'token'; v_sidb := (v_r ->> 'id')::uuid;
  if public.hk_create_student('   ') ->> 'error' is distinct from 'bad_nickname'
     or public.hk_create_student(repeat('長', 41)) ->> 'error' is distinct from 'bad_nickname' then
    raise exception 'FAIL 2c：空白或太長的暱稱沒有被拒';
  end if;
  select count(*) into v_n from public.hk_students s where s.id in (v_sid, v_sidb);
  if v_n <> 2 then raise exception 'FAIL 2d：老師讀不到學生'; end if;
  begin perform s.token_hash from public.hk_students s; raise exception 'FAIL 2e：老師讀得到 token_hash 欄';
  exception when insufficient_privilege then null; end;
  begin insert into public.hk_progress (student_id, unit_id, reviews, updated_at) values (v_sid, c_u1, 0, now());
    raise exception 'FAIL 2f：老師能直接寫 hk_progress';
  exception when insufficient_privilege then null; end;
  begin update public.hk_students set nickname = 'x' where id = v_sid; raise exception 'FAIL 2g：老師能直接改 hk_students';
  exception when insufficient_privilege then null; end;
  v_log := v_log || 'PASS 2 老師：被認得、能建學生、暱稱有檢查、讀得到名單、讀不到代碼指紋、不能直接改表'::text;
  reset role;

  -- ===== 3. 學生用自己的代碼：讀寫、每一列新的贏（LWW） =====
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  set local role anon;
  v_r := public.hk_load(v_tok);
  if (v_r ->> 'ok')::boolean is not true or (v_r ->> 'sid')::uuid <> v_sid or v_r ->> 'nickname' <> '驗證用學生甲'
     or jsonb_array_length(v_r -> 'progress') <> 0 or jsonb_array_length(v_r -> 'plan') <> 0 then
    raise exception 'FAIL 3a：用正確代碼讀不到 %', v_r;
  end if;
  v_r := public.hk_save(v_tok,
    jsonb_build_array(jsonb_build_object('unitId', c_u1, 'fam', 2, 'reviews', 1, 'updatedAt', 1763300000123)),
    jsonb_build_array(jsonb_build_object('id', 'c1', 'unitId', c_u1, 'date', '2026-11-20', 'doneAt', null, 'deleted', false, 'updatedAt', 1763300000123)));
  if (v_r ->> 'ok')::boolean is not true or jsonb_array_length(v_r -> 'progress') <> 1
     or (v_r -> 'progress' -> 0 ->> 'updatedAt')::bigint <> 1763300000123
     or v_r -> 'plan' -> 0 ->> 'date' <> '2026-11-20' then
    raise exception 'FAIL 3b：第一次上傳失敗或時間來回不一致 %', v_r;
  end if;
  -- 節流：剛寫完馬上再寫 → too_fast
  if public.hk_save(v_tok, '[]'::jsonb, '[]'::jsonb) ->> 'error' is distinct from 'too_fast' then
    raise exception 'FAIL 3c：1 秒節流沒作用';
  end if;
  reset role; update public.hk_students set last_seen_at = null where id in (v_sid, v_sidb); set local role anon;
  -- 較舊的修改 → 忽略
  v_r := public.hk_save(v_tok,
    jsonb_build_array(jsonb_build_object('unitId', c_u1, 'fam', 5, 'reviews', 9, 'updatedAt', 1763300000000)),
    jsonb_build_array(jsonb_build_object('id', 'c1', 'unitId', c_u1, 'date', '2026-12-31', 'doneAt', null, 'deleted', true, 'updatedAt', 1763300000000)));
  if (v_r ->> 'ok')::boolean is not true or (v_r -> 'progress' -> 0 ->> 'fam')::int <> 2
     or (v_r -> 'plan' -> 0 ->> 'deleted')::boolean is not false or v_r -> 'plan' -> 0 ->> 'date' <> '2026-11-20' then
    raise exception 'FAIL 3d：較舊的修改蓋掉了較新的 %', v_r;
  end if;
  reset role; update public.hk_students set last_seen_at = null where id in (v_sid, v_sidb); set local role anon;
  -- 較新的修改 → 覆蓋（含軟刪除、完成時間）
  v_r := public.hk_save(v_tok,
    jsonb_build_array(jsonb_build_object('unitId', c_u1, 'fam', 4, 'reviews', 2, 'updatedAt', 1763300009999)),
    jsonb_build_array(jsonb_build_object('id', 'c1', 'unitId', c_u1, 'date', '2026-11-21', 'doneAt', 1763300009999, 'deleted', true, 'updatedAt', 1763300009999)));
  if (v_r -> 'progress' -> 0 ->> 'fam')::int <> 4 or (v_r -> 'progress' -> 0 ->> 'reviews')::int <> 2
     or (v_r -> 'progress' -> 0 ->> 'updatedAt')::bigint <> 1763300009999
     or (v_r -> 'plan' -> 0 ->> 'deleted')::boolean is not true or (v_r -> 'plan' -> 0 ->> 'doneAt')::bigint <> 1763300009999
     or v_r -> 'plan' -> 0 ->> 'date' <> '2026-11-21' then
    raise exception 'FAIL 3e：較新的修改沒有生效 %', v_r;
  end if;
  reset role; update public.hk_students set last_seen_at = null where id in (v_sid, v_sidb); set local role anon;
  -- 未來時間（例：手機時鐘亂掉、或有人故意送 9999 年）→ 最多只記到「現在＋10 分鐘」，之後正常修改還蓋得過
  v_r := public.hk_save(v_tok,
    jsonb_build_array(jsonb_build_object('unitId', c_u2, 'fam', 1, 'reviews', 0, 'updatedAt', 999999999999999)), '[]'::jsonb);
  v_ms := (extract(epoch from now()) * 1000)::bigint;
  -- 找不到符合的列時 select into 會把 v_ms 設成 null
  select (x ->> 'updatedAt')::bigint into v_ms from jsonb_array_elements(v_r -> 'progress') x
   where x ->> 'unitId' = c_u2 and (x ->> 'updatedAt')::bigint between v_ms and v_ms + 600000;
  if v_ms is null then raise exception 'FAIL 3f：未來時間沒有被壓回「現在＋10 分鐘」 %', v_r; end if;
  v_log := v_log || 'PASS 3 學生：讀寫自己的、時間來回精準到毫秒、較舊的修改被忽略、較新的蓋過、軟刪除同步、1 秒節流、未來時間被壓回'::text;

  -- ===== 4. 格式檢查：任何一列不對就整筆拒收 =====
  reset role; update public.hk_students set last_seen_at = null where id in (v_sid, v_sidb); set local role anon;
  foreach v_bad in array array[
    '{"a":1}'::jsonb,                                                                             -- 不是陣列
    '[1]'::jsonb,                                                                                 -- 不是物件
    '[{"unitId":"m-kx-7a-1-1","fam":1,"reviews":0,"updatedAt":1,"x":1}]'::jsonb,                   -- 多出欄位
    '[{"unitId":"<img src=x>","fam":1,"reviews":0,"updatedAt":1}]'::jsonb,                         -- 章節 id 怪字
    '[{"unitId":"__proto__","fam":1,"reviews":0,"updatedAt":1}]'::jsonb,
    '[{"unitId":"m-kx-7a-1-1","fam":7,"reviews":0,"updatedAt":1}]'::jsonb,                         -- 分數超出 1–5
    '[{"unitId":"m-kx-7a-1-1","fam":"3","reviews":0,"updatedAt":1}]'::jsonb,                       -- 分數是字串
    '[{"unitId":"m-kx-7a-1-1","reviews":0,"updatedAt":1}]'::jsonb,                                 -- 缺 fam
    '[{"unitId":"m-kx-7a-1-1","fam":1,"reviews":-1,"updatedAt":1}]'::jsonb,                        -- 次數負數
    '[{"unitId":"m-kx-7a-1-1","fam":1,"reviews":1.5,"updatedAt":1}]'::jsonb,                       -- 次數小數
    '[{"unitId":"m-kx-7a-1-1","fam":1,"reviews":0}]'::jsonb,                                       -- 缺時間
    '[{"unitId":"m-kx-7a-1-1","fam":1,"reviews":0,"updatedAt":"1"}]'::jsonb,                       -- 時間是字串
    '[{"unitId":"m-kx-7a-1-1","fam":1,"reviews":0,"updatedAt":1},{"unitId":"m-kx-7a-1-1","fam":2,"reviews":0,"updatedAt":2}]'::jsonb  -- 重複
  ] loop
    if public.hk_save(v_tok, v_bad, '[]'::jsonb) ->> 'error' is distinct from 'bad_rows' then
      raise exception 'FAIL 4a：格式不對的進度列沒有被拒：%', v_bad;
    end if;
  end loop;
  foreach v_bad in array array[
    '[{"id":"C1","unitId":"m-kx-7a-1-1","date":"2026-11-20","doneAt":null,"deleted":false,"updatedAt":1}]'::jsonb,       -- 大寫 id
    '[{"id":"a\"><b","unitId":"m-kx-7a-1-1","date":"2026-11-20","doneAt":null,"deleted":false,"updatedAt":1}]'::jsonb,   -- 怪 id
    '[{"id":"c2","unitId":"m-kx-7a-1-1","date":"2026-02-30","doneAt":null,"deleted":false,"updatedAt":1}]'::jsonb,       -- 不存在的日期
    '[{"id":"c2","unitId":"m-kx-7a-1-1","date":"2026-1-1","doneAt":null,"deleted":false,"updatedAt":1}]'::jsonb,         -- 日期格式
    '[{"id":"c2","unitId":"m-kx-7a-1-1","date":"2026-11-20","doneAt":"x","deleted":false,"updatedAt":1}]'::jsonb,        -- 完成時間是字串
    '[{"id":"c2","unitId":"m-kx-7a-1-1","date":"2026-11-20","doneAt":null,"deleted":"yes","updatedAt":1}]'::jsonb,       -- deleted 不是布林
    '[{"id":"c2","unitId":"m-kx-7a-1-1","date":"2026-11-20","deleted":false,"updatedAt":1}]'::jsonb,                     -- 缺 doneAt
    '[{"id":"c2","unitId":"m-kx-7a-1-1","date":"2026-11-20","doneAt":null,"deleted":false,"updatedAt":1},{"id":"c2","unitId":"m-kx-7a-1-1","date":"2026-11-21","doneAt":null,"deleted":false,"updatedAt":2}]'::jsonb
  ] loop
    if public.hk_save(v_tok, '[]'::jsonb, v_bad) ->> 'error' is distinct from 'bad_rows' then
      raise exception 'FAIL 4b：格式不對的排程卡沒有被拒：%', v_bad;
    end if;
  end loop;
  -- 一筆裡面一列好、一列壞 → 好的那列也不能寫進去
  if public.hk_save(v_tok,
       '[{"unitId":"m-kx-7a-2-1","fam":3,"reviews":0,"updatedAt":5}]'::jsonb,
       '[{"id":"c3","unitId":"m-kx-7a-1-1","date":"2026-02-30","doneAt":null,"deleted":false,"updatedAt":5}]'::jsonb) ->> 'error' is distinct from 'bad_rows'
     or exists (select 1 from jsonb_array_elements(public.hk_load(v_tok) -> 'progress') x where x ->> 'unitId' = 'm-kx-7a-2-1') then
    raise exception 'FAIL 4c：壞掉的一筆裡，好的列被寫進去了';
  end if;
  v_log := v_log || 'PASS 4 格式檢查：怪 id、怪日期、型別不對、缺欄位、多欄位、重複列都整筆拒收，不會寫一半'::text;

  -- ===== 5. 數量上限 =====
  if public.hk_save(v_tok,
       (select jsonb_agg(jsonb_build_object('unitId', 'u-' || g, 'fam', null, 'reviews', 0, 'updatedAt', 1)) from generate_series(1, 201) g),
       '[]'::jsonb) ->> 'error' is distinct from 'too_many' then
    raise exception 'FAIL 5a：一次超過 200 列進度沒有被拒';
  end if;
  if public.hk_save(v_tok, '[]'::jsonb,
       (select jsonb_agg(jsonb_build_object('id', 'p' || g, 'unitId', c_u1, 'date', '2026-12-01', 'doneAt', null, 'deleted', false, 'updatedAt', 1)) from generate_series(1, 2001) g)
     ) ->> 'error' is distinct from 'too_many' then
    raise exception 'FAIL 5b：一次超過 2000 張卡沒有被拒';
  end if;
  reset role;
  -- 以管理者身分先塞到剛好 5000 張（已有 c1，再加 4999 張）
  insert into public.hk_plan (student_id, id, unit_id, date, updated_at)
  select v_sid, 'z' || g, c_u1, date '2026-12-01', now() from generate_series(1, 4999) g;
  set local role anon;
  if public.hk_save(v_tok, '[]'::jsonb,
       '[{"id":"c9","unitId":"m-kx-7a-1-1","date":"2026-12-02","doneAt":null,"deleted":false,"updatedAt":1}]'::jsonb) ->> 'error' is distinct from 'too_many' then
    raise exception 'FAIL 5c：每位學生 5000 張的總上限沒有作用';
  end if;
  -- z1 剛塞進去的時間是 now()；用「現在＋1 秒」（在 10 分鐘上限內）才算較新的修改
  v_ms := (extract(epoch from now()) * 1000)::bigint + 1000;
  v_r := public.hk_save(v_tok, '[]'::jsonb, jsonb_build_array(jsonb_build_object(
       'id', 'z1', 'unitId', c_u1, 'date', '2026-12-03', 'doneAt', null, 'deleted', true, 'updatedAt', v_ms)));
  if (v_r ->> 'ok')::boolean is not true
     or not exists (select 1 from jsonb_array_elements(v_r -> 'plan') x
                     where x ->> 'id' = 'z1' and x ->> 'date' = '2026-12-03'
                       and (x ->> 'deleted')::boolean and (x ->> 'updatedAt')::bigint = v_ms) then
    raise exception 'FAIL 5d：到上限後，修改既有的卡應該還可以（而且要真的改到） %', left(v_r::text, 200);
  end if;
  reset role;
  delete from public.hk_plan where student_id = v_sid and id like 'z%';
  update public.hk_students set last_seen_at = null where id in (v_sid, v_sidb);
  set local role anon;
  v_log := v_log || 'PASS 5 數量上限：單次 200 列／2000 張、每人總數 5000 張；到上限仍可改既有的卡'::text;

  -- ===== 6. 不同學生互不影響（同一個卡片 id 也不會互蓋） =====
  v_r := public.hk_save(v_tokb,
    '[{"unitId":"m-kx-7a-1-1","fam":1,"reviews":7,"updatedAt":1863300000000}]'::jsonb,
    '[{"id":"c1","unitId":"m-kx-9b-3-1","date":"2027-01-01","doneAt":null,"deleted":false,"updatedAt":1863300000000}]'::jsonb);
  if (v_r ->> 'ok')::boolean is not true or (v_r ->> 'sid')::uuid <> v_sidb
     or jsonb_array_length(v_r -> 'progress') <> 1 or jsonb_array_length(v_r -> 'plan') <> 1 then
    raise exception 'FAIL 6a：學生乙上傳失敗或看到別人的資料 %', v_r;
  end if;
  v_r := public.hk_load(v_tok);
  if (select (x ->> 'fam')::int from jsonb_array_elements(v_r -> 'progress') x where x ->> 'unitId' = c_u1) <> 4
     or (select x ->> 'unitId' from jsonb_array_elements(v_r -> 'plan') x where x ->> 'id' = 'c1') <> c_u1
     or jsonb_array_length(v_r -> 'plan') <> 1 then
    raise exception 'FAIL 6b：學生乙的上傳影響到學生甲 %', v_r;
  end if;
  v_log := v_log || 'PASS 6 不同學生互不影響：同一個卡片 id 也不會蓋到別人'::text;
  reset role;

  -- ===== 7. 登入了但不是老師（例如萬一自助註冊被打開） =====
  perform set_config('request.jwt.claims', json_build_object('sub', gen_random_uuid(), 'role', 'authenticated')::text, true);
  set local role authenticated;
  if public.hk_is_teacher() then raise exception 'FAIL 7a：非老師帳號被認成老師'; end if;
  select count(*) into v_n from public.hk_students;
  if v_n <> 0 then raise exception 'FAIL 7b：非老師帳號讀得到學生名單'; end if;
  select count(*) into v_n from public.hk_progress;
  if v_n <> 0 then raise exception 'FAIL 7c：非老師帳號讀得到進度'; end if;
  select count(*) into v_n from public.hk_plan;
  if v_n <> 0 then raise exception 'FAIL 7d：非老師帳號讀得到排程'; end if;
  begin perform public.hk_create_student('x'); raise exception 'FAIL 7e：非老師帳號能建學生';
  exception when insufficient_privilege then null; end;
  begin perform public.hk_reset_link(v_sid); raise exception 'FAIL 7f：非老師帳號能重設連結';
  exception when insufficient_privilege then null; end;
  v_log := v_log || 'PASS 7 登入但不是老師：什麼都讀不到、不能建學生、不能重設連結'::text;
  reset role;

  -- ===== 8. 老師讀得到進度；重設連結：舊的立刻失效、新的可用、進度還在 =====
  perform set_config('request.jwt.claims', json_build_object('sub', v_teacher, 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into v_n from public.hk_progress p where p.student_id = v_sid;
  if v_n <> 2 then raise exception 'FAIL 8a：老師讀不到學生甲的進度（%）', v_n; end if;
  select count(*) into v_n from public.hk_plan c where c.student_id = v_sid;
  if v_n <> 1 then raise exception 'FAIL 8b：老師讀不到學生甲的排程（%）', v_n; end if;
  if public.hk_reset_link(gen_random_uuid()) ->> 'error' is distinct from 'not_found' then raise exception 'FAIL 8c：重設不存在的學生沒回 not_found'; end if;
  v_tok2 := public.hk_reset_link(v_sid) ->> 'token';
  if v_tok2 !~ '^[0-9a-f]{32}$' or v_tok2 = v_tok then raise exception 'FAIL 8d：重設連結沒有產生新代碼'; end if;
  reset role;
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  set local role anon;
  if public.hk_load(v_tok) ->> 'error' is distinct from 'invalid_link' then raise exception 'FAIL 8e：舊連結還能用'; end if;
  v_r := public.hk_load(v_tok2);
  if (v_r ->> 'ok')::boolean is not true or jsonb_array_length(v_r -> 'progress') <> 2 then raise exception 'FAIL 8f：新連結讀不到原本進度 %', v_r; end if;
  v_log := v_log || 'PASS 8 老師讀得到進度；重設連結：舊的失效、新的可用、進度還在'::text;
  reset role;

  raise exception using errcode = 'P0001', message =
    '驗證全部通過（' || array_length(v_log, 1) || ' 組）。這行紅字是刻意的：讓剛才的測試學生與測試資料全部自動復原。' || E'\n' ||
    array_to_string(v_log, E'\n');
end
$verify$;

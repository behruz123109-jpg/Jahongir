-- =====================================================================
-- BilimXona — sxema (foydalanuvchi sxemasi + xavfsizlik tuzatishlari)
-- Supabase → SQL Editor: BUTUN faylni bir marta ishga tushiring.
-- =====================================================================

create table if not exists public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.subjects (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  created_at timestamptz not null default now()
);

create table if not exists public.topics (
  id uuid primary key default gen_random_uuid(),
  subject_id uuid not null references public.subjects(id) on delete cascade,
  name text not null,
  created_at timestamptz not null default now(),
  unique(subject_id, name)
);

create table if not exists public.questions (
  id uuid primary key default gen_random_uuid(),
  subject_id uuid not null references public.subjects(id) on delete cascade,
  topic_id uuid references public.topics(id) on delete set null,
  prompt text not null,
  image_url text,
  explanation text,
  created_at timestamptz not null default now()
);

create table if not exists public.answers (
  id uuid primary key default gen_random_uuid(),
  question_id uuid not null references public.questions(id) on delete cascade,
  label text not null,
  position int not null default 0
);

create table if not exists public.question_solutions (
  question_id uuid primary key references public.questions(id) on delete cascade,
  correct_answer_id uuid not null references public.answers(id) on delete cascade
);

create table if not exists public.attempts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  question_id uuid not null references public.questions(id) on delete cascade,
  answer_id uuid not null references public.answers(id) on delete cascade,
  is_correct boolean not null,
  created_at timestamptz not null default now()
);

alter table public.admins enable row level security;
alter table public.subjects enable row level security;
alter table public.topics enable row level security;
alter table public.questions enable row level security;
alter table public.answers enable row level security;
alter table public.question_solutions enable row level security;
alter table public.attempts enable row level security;

create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;

-- ---------------------------------------------------------------------
-- XAVFSIZLIK: explanation (izoh) javobdan oldin ko'rinmasligi kerak.
-- Jadval darajasidagi o'qish huquqini olib, ustunlarni qayta beramiz.
-- ---------------------------------------------------------------------
revoke select on public.questions from anon, authenticated;
grant select (id, subject_id, topic_id, prompt, image_url, created_at)
  on public.questions to anon, authenticated;
-- admin'ga ham izohni o'qish kerak emas: u admin_get_correct_answer orqali oladi.

drop policy if exists "subjects_read" on public.subjects;
create policy "subjects_read" on public.subjects for select using (true);
drop policy if exists "topics_read" on public.topics;
create policy "topics_read" on public.topics for select using (true);
drop policy if exists "questions_read" on public.questions;
create policy "questions_read" on public.questions for select using (true);
drop policy if exists "answers_read" on public.answers;
create policy "answers_read" on public.answers for select using (true);

drop policy if exists "subjects_admin_all" on public.subjects;
create policy "subjects_admin_all" on public.subjects for all using (public.is_admin()) with check (public.is_admin());
drop policy if exists "topics_admin_all" on public.topics;
create policy "topics_admin_all" on public.topics for all using (public.is_admin()) with check (public.is_admin());
drop policy if exists "questions_admin_all" on public.questions;
create policy "questions_admin_all" on public.questions for all using (public.is_admin()) with check (public.is_admin());
drop policy if exists "answers_admin_all" on public.answers;
create policy "answers_admin_all" on public.answers for all using (public.is_admin()) with check (public.is_admin());

drop policy if exists "attempts_own_read" on public.attempts;
create policy "attempts_own_read" on public.attempts for select using (auth.uid() = user_id);

-- question_solutions: hech qanday policy yo'q → mijoz to'g'ridan-to'g'ri o'qiy olmaydi.
-- admins: hech qanday policy yo'q → mijoz o'qiy olmaydi.

-- ---------------------------------------------------------------------
-- verify_answer: javobni tekshirish (izoh faqat to'g'ri javobda qaytadi)
-- ---------------------------------------------------------------------
create or replace function public.verify_answer(p_question_id uuid, p_answer_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_correct_id uuid;
  v_explanation text;
  v_is_correct boolean;
begin
  select s.correct_answer_id, q.explanation
    into v_correct_id, v_explanation
  from public.question_solutions s
  join public.questions q on q.id = s.question_id
  where s.question_id = p_question_id;

  if v_correct_id is null then
    raise exception 'Savol topilmadi';
  end if;

  if not exists (select 1 from public.answers where id = p_answer_id and question_id = p_question_id) then
    raise exception 'Javob varianti topilmadi';
  end if;

  v_is_correct := (v_correct_id = p_answer_id);

  if auth.uid() is not null then
    insert into public.attempts (user_id, question_id, answer_id, is_correct)
    values (auth.uid(), p_question_id, p_answer_id, v_is_correct);
  end if;

  return jsonb_build_object(
    'correct', v_is_correct,
    'explanation', case when v_is_correct then v_explanation else null end
  );
end;
$$;

-- ---------------------------------------------------------------------
-- admin_save_question: TUZATILDI — tahrirlashda eski urinishlar o'chmaydi.
-- Avval variantlar yangilanadi (id saqlanadi), faqat olib tashlanganlari o'chadi.
-- ---------------------------------------------------------------------
create or replace function public.admin_save_question(
  p_id uuid,
  p_subject_id uuid,
  p_topic_id uuid,
  p_prompt text,
  p_image_url text,
  p_options jsonb,
  p_correct_id uuid,
  p_explanation text default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_qid uuid;
  v_opt jsonb;
  v_idx int := 0;
begin
  if not public.is_admin() then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  if jsonb_typeof(p_options) <> 'array' or jsonb_array_length(p_options) not between 2 and 6 then
    raise exception 'Variantlar soni 2 dan 6 gacha bo''lishi kerak';
  end if;
  if not exists (
    select 1 from jsonb_array_elements(p_options) x where (x->>'id')::uuid = p_correct_id
  ) then
    raise exception 'To''g''ri javob variantlar orasida bo''lishi kerak';
  end if;

  if p_id is null then
    insert into public.questions (subject_id, topic_id, prompt, image_url, explanation)
    values (p_subject_id, p_topic_id, p_prompt, nullif(p_image_url, ''), nullif(p_explanation, ''))
    returning id into v_qid;
  else
    update public.questions
       set subject_id = p_subject_id,
           topic_id = p_topic_id,
           prompt = p_prompt,
           image_url = nullif(p_image_url, ''),
           explanation = nullif(p_explanation, '')
     where id = p_id
    returning id into v_qid;
    if v_qid is null then
      raise exception 'Savol topilmadi';
    end if;
  end if;

  delete from public.answers
   where question_id = v_qid
     and id not in (select (x->>'id')::uuid from jsonb_array_elements(p_options) x);

  for v_opt in select * from jsonb_array_elements(p_options)
  loop
    insert into public.answers (id, question_id, label, position)
    values ((v_opt->>'id')::uuid, v_qid, v_opt->>'label', v_idx)
    on conflict (id) do update
      set label = excluded.label, position = excluded.position;
    v_idx := v_idx + 1;
  end loop;

  insert into public.question_solutions (question_id, correct_answer_id)
  values (v_qid, p_correct_id)
  on conflict (question_id) do update set correct_answer_id = excluded.correct_answer_id;

  return v_qid;
end;
$$;

-- ---------------------------------------------------------------------
-- admin_get_correct_answer: admin uchun to'g'ri javob va izoh
-- ---------------------------------------------------------------------
create or replace function public.admin_get_correct_answer(p_question_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_res jsonb;
begin
  if not public.is_admin() then
    raise exception 'forbidden' using errcode = '42501';
  end if;

  select jsonb_build_object(
    'correct_answer_id', s.correct_answer_id,
    'explanation', q.explanation
  ) into v_res
  from public.questions q
  left join public.question_solutions s on s.question_id = q.id
  where q.id = p_question_id;

  return v_res;
end;
$$;

-- RPC funksiyalarni faqat kerakli rollarga ochamiz
revoke all on function public.verify_answer(uuid, uuid) from public;
grant execute on function public.verify_answer(uuid, uuid) to anon, authenticated;
revoke all on function public.admin_save_question(uuid, uuid, uuid, text, text, jsonb, uuid, text) from public;
grant execute on function public.admin_save_question(uuid, uuid, uuid, text, text, jsonb, uuid, text) to authenticated;
revoke all on function public.admin_get_correct_answer(uuid) from public;
grant execute on function public.admin_get_correct_answer(uuid) to authenticated;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to anon, authenticated;

-- ---------------------------------------------------------------------
-- Birinchi admin: saytda ro'yxatdan o'ting, so'ng o'z emailingiz bilan:
-- insert into public.admins (user_id)
-- select id from auth.users where email = 'SIZNING@EMAILINGIZ';
-- ---------------------------------------------------------------------

-- =====================================================================
-- QO'SHIMCHA: imtihon natijalari, reyting, admin statistikasi
-- =====================================================================
create table if not exists public.exams (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  subject_id uuid references public.subjects(id) on delete set null,
  topic_id uuid references public.topics(id) on delete set null,
  total int not null check (total > 0),
  correct int not null check (correct >= 0 and correct <= total),
  percent numeric(5,2) not null check (percent >= 0 and percent <= 100),
  duration_sec int not null default 0 check (duration_sec >= 0),
  created_at timestamptz not null default now()
);
create index if not exists exams_user_idx on public.exams(user_id, created_at desc);
create index if not exists exams_percent_idx on public.exams(percent desc);

alter table public.exams enable row level security;

drop policy if exists "exams_insert_own" on public.exams;
create policy "exams_insert_own" on public.exams for insert
  with check (auth.uid() = user_id and total >= 1);
drop policy if exists "exams_select_own" on public.exams;
create policy "exams_select_own" on public.exams for select using (auth.uid() = user_id);
drop policy if exists "exams_admin_read" on public.exams;
create policy "exams_admin_read" on public.exams for select using (public.is_admin());

grant select, insert on public.exams to authenticated;
grant usage on all sequences in schema public to authenticated;

-- Reyting: kamida 5 savollik imtihonlar bo'yicha eng yaxshi natija.
-- Ism o'rniga email boshi maskalanadi (maxfiylik).
create or replace function public.leaderboard(p_limit int default 30)
returns table (
  pos int,
  display_name text,
  best_percent numeric,
  exams_count int,
  avg_percent numeric,
  is_me boolean
)
language sql
stable
security definer
set search_path = public
as $$
  select
    dense_rank() over (order by max(e.percent) desc)::int,
    left(split_part(coalesce(u.email, ''), '@', 1), 3) || '***',
    max(e.percent),
    count(*)::int,
    round(avg(e.percent), 1),
    (e.user_id = auth.uid())
  from public.exams e
  join auth.users u on u.id = e.user_id
  where e.total >= 5
  group by e.user_id, u.email
  order by max(e.percent) desc, count(*) desc
  limit least(greatest(coalesce(p_limit, 30), 1), 100);
$$;
revoke all on function public.leaderboard(int) from public;
grant execute on function public.leaderboard(int) to anon, authenticated;

-- Admin statistikasi
create or replace function public.admin_stats()
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare v jsonb;
begin
  if not public.is_admin() then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  select jsonb_build_object(
    'users', (select count(*) from auth.users),
    'subjects', (select count(*) from public.subjects),
    'topics', (select count(*) from public.topics),
    'questions', (select count(*) from public.questions),
    'active_questions', (select count(*) from public.questions),
    'attempts_total', (select count(*) from public.attempts),
    'attempts_7d', (select count(*) from public.attempts where created_at >= now() - interval '7 days'),
    'exams_total', (select count(*) from public.exams),
    'avg_percent', (select round(coalesce(avg(percent), 0), 1) from public.exams),
    'daily', (
      select coalesce(jsonb_agg(jsonb_build_object('day', d::date, 'count', coalesce(c.n, 0)) order by d), '[]'::jsonb)
      from generate_series(current_date - 6, current_date, interval '1 day') d
      left join (
        select created_at::date as day, count(*) as n
        from public.attempts
        where created_at >= current_date - 6
        group by 1
      ) c on c.day = d::date
    )
  ) into v;
  return v;
end;
$$;
revoke all on function public.admin_stats() from public, anon;
grant execute on function public.admin_stats() to authenticated;

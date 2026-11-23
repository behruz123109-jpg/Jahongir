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
  select exists (
    select 1 from public.admins where user_id = auth.uid()
  );
$$;

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

  if p_id is null then
    insert into public.questions (subject_id, topic_id, prompt, image_url, explanation)
    values (p_subject_id, p_topic_id, p_prompt, p_image_url, p_explanation)
    returning id into v_qid;
  else
    update public.questions
       set subject_id = p_subject_id,
           topic_id = p_topic_id,
           prompt = p_prompt,
           image_url = p_image_url,
           explanation = p_explanation
     where id = p_id
    returning id into v_qid;

    delete from public.question_solutions where question_id = v_qid;
    delete from public.answers where question_id = v_qid;
  end if;

  for v_opt in select * from jsonb_array_elements(p_options)
  loop
    insert into public.answers (id, question_id, label, position)
    values ((v_opt->>'id')::uuid, v_qid, v_opt->>'label', v_idx);
    v_idx := v_idx + 1;
  end loop;

  insert into public.question_solutions (question_id, correct_answer_id)
  values (v_qid, p_correct_id);

  return v_qid;
end;
$$;

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
  from public.question_solutions s
  join public.questions q on q.id = s.question_id
  where s.question_id = p_question_id;

  return v_res;
end;
$$;

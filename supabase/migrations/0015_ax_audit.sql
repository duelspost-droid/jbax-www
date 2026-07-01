-- 0015_ax_audit.sql — AX 관리자 접속·행위 감사 로그 + 공개 페이지 방문 로그
-- 누가(actor/email)·언제(created_at)·어디서(ip)·무엇을(action/entity) 했는지 기록.
--  · 쓰기는 SECURITY DEFINER RPC로만(클라이언트 직접 INSERT 정책 없음).
--  · 열람/관리자 로깅은 ax_admins 화이트리스트 계정만(이 프로젝트는 VulnScan과 동일 Supabase라
--    'authenticated=관리자'가 아님 → allowlist로 좁힘). is_ax_admin()로 RLS 자기참조 재귀 회피.
--  · IP/UA는 서버측(request.headers)에서 캡처하지만, x-forwarded-for 최좌측은 신뢰 프록시가
--    재작성하지 않으면 위조될 수 있음 → IP를 보안 판단의 단독 근거로 쓰지 말 것.

-- ---------- 관리자 화이트리스트 ----------
create table if not exists public.ax_admins (
  email      text primary key,
  note       text,
  created_at timestamptz not null default now()
);
alter table public.ax_admins enable row level security;

-- 현재 요청자가 관리자인지 (SECURITY DEFINER → ax_admins RLS 우회 = 정책 자기참조 재귀 방지)
create or replace function public.is_ax_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.ax_admins a where a.email = auth.jwt() ->> 'email');
$$;

-- 목록은 관리자만 열람. (is_ax_admin이 RLS를 우회해 읽으므로 재귀 없음)
drop policy if exists ax_admins_self_read on public.ax_admins;
create policy ax_admins_self_read on public.ax_admins for select to authenticated
  using (public.is_ax_admin());
-- 쓰기 정책 없음 → 관리자 추가는 SQL/service_role로만.

-- 최초 관리자 시드(실제 운영 로그인 이메일로 조정할 것).
insert into public.ax_admins(email, note) values ('duels@jbfg.com', 'AX 최초 관리자')
  on conflict (email) do nothing;

-- ---------- 감사 로그 ----------
create table if not exists public.ax_audit (
  id          bigint generated always as identity primary key,
  kind        text not null default 'admin',        -- 'admin' | 'visit'
  actor       uuid,                                  -- 관리자 uid (방문은 null)
  actor_email text,
  action      text not null,                         -- login/logout/create/update/delete/update_setting/visit ...
  entity      text,                                  -- 테이블명 또는 페이지 경로
  entity_id   text,
  detail      jsonb not null default '{}'::jsonb,
  ip          text,
  user_agent  text,
  created_at  timestamptz not null default now()
);

create index if not exists ax_audit_created_idx on public.ax_audit(created_at desc);
create index if not exists ax_audit_kind_idx    on public.ax_audit(kind, created_at desc);
create index if not exists ax_audit_ip_idx      on public.ax_audit(ip);

alter table public.ax_audit enable row level security;

-- 열람: ax_admins 화이트리스트 계정만. 익명은 SELECT 정책 부재로 차단.
drop policy if exists ax_audit_auth_read on public.ax_audit;
create policy ax_audit_auth_read on public.ax_audit for select to authenticated
  using (public.is_ax_admin());
-- INSERT/UPDATE/DELETE 정책 없음 → 오직 아래 SECURITY DEFINER RPC로만 적재.

-- ---------- 요청 헤더에서 IP/UA 추출(서버측) ----------
create or replace function public._ax_client_ip() returns text
language sql stable set search_path = public as $$
  select nullif(trim(split_part(
    coalesce(current_setting('request.headers', true), '{}')::json ->> 'x-forwarded-for', ',', 1)), '');
$$;

create or replace function public._ax_user_agent() returns text
language sql stable set search_path = public as $$
  select left(coalesce(current_setting('request.headers', true), '{}')::json ->> 'user-agent', 400);
$$;

-- ---------- 로깅 RPC (SECURITY DEFINER) ----------
-- 관리자 행위 로깅(ax_admins 계정만 — 위조 로그 삽입 방지)
create or replace function public.ax_log(
  p_action text,
  p_entity text default null,
  p_entity_id text default null,
  p_detail jsonb default '{}'::jsonb
) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'auth required'; end if;
  if not public.is_ax_admin() then raise exception 'not an authorized admin'; end if;
  if p_action is null or length(p_action) = 0 then raise exception 'action required'; end if;
  insert into public.ax_audit(kind, actor, actor_email, action, entity, entity_id, detail, ip, user_agent)
  values ('admin', auth.uid(), auth.jwt() ->> 'email',
          left(p_action, 60), left(p_entity, 80), left(p_entity_id, 80),
          coalesce(p_detail, '{}'::jsonb), public._ax_client_ip(), public._ax_user_agent());
end $$;

-- 공개 페이지 방문 로깅(익명 허용) — 경로 형식 검증 + 같은 IP·경로 10분 내 중복/스팸 억제.
create or replace function public.ax_log_visit(p_page text default null) returns void
language plpgsql security definer set search_path = public as $$
declare v_ref text; v_ip text; v_page text;
begin
  v_page := left(coalesce(p_page, '/'), 300);
  if v_page !~ '^/[A-Za-z0-9/_.\-]*$' then v_page := '/'; end if;   -- 경로만 허용(임의 텍스트 차단)
  v_ip := public._ax_client_ip();
  -- 같은 IP·경로가 최근 10분 내 이미 있으면 스킵(공개 anon 키 우회 스팸/중복 억제)
  if exists (
    select 1 from public.ax_audit
     where kind = 'visit' and entity = v_page
       and ip is not distinct from v_ip
       and created_at > now() - interval '10 minutes'
  ) then return; end if;
  v_ref := coalesce(current_setting('request.headers', true), '{}')::json ->> 'referer';
  insert into public.ax_audit(kind, action, entity, ip, user_agent, detail)
  values ('visit', 'visit', v_page, v_ip, public._ax_user_agent(),
          case when v_ref is null then '{}'::jsonb else jsonb_build_object('ref', left(v_ref, 300)) end);
end $$;

-- 보존정책: 방문 로그 90일 / 관리 로그 365일 후 정리.
create or replace function public.ax_audit_purge() returns void
language sql security definer set search_path = public as $$
  delete from public.ax_audit
   where (kind = 'visit' and created_at < now() - interval '90 days')
      or (kind = 'admin' and created_at < now() - interval '365 days');
$$;

-- ---------- 실행 권한 ----------
revoke all on function public._ax_client_ip()                   from public, anon, authenticated;
revoke all on function public._ax_user_agent()                  from public, anon, authenticated;
revoke all on function public.ax_audit_purge()                  from public, anon, authenticated;
revoke all on function public.ax_log(text,text,text,jsonb)      from public, anon;
grant  execute on function public.ax_log(text,text,text,jsonb)  to authenticated;
revoke all on function public.ax_log_visit(text)                from public;
grant  execute on function public.ax_log_visit(text)            to anon, authenticated;

-- (선택) pg_cron 확장 활성화 시 자동 정리 스케줄:
--   select cron.schedule('ax_audit_purge_daily', '0 3 * * *', $$ select public.ax_audit_purge(); $$);

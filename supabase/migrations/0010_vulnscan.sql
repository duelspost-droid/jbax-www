-- ============================================================================
-- JBAX 플레이그라운드 — AI 취약점 진단 (VulnScan) 백엔드 스키마
-- secuday Supabase 프로젝트(ref nrdapzgtibbusvoaceuh) 재사용.
-- 테이블: vuln_scans / vuln_findings / vuln_progress / vuln_remediations / vuln_audit
-- 원칙: 모든 이력 보존(삭제 RPC 없음) · 쓰기는 정의자(SECURITY DEFINER) RPC + service_role(Edge)만
--       클라이언트 직접 쓰기 차단 · 익명은 '완료된' 진단 결과만 읽기 · 관리자(authenticated) 전체 읽기
-- 적용: Supabase SQL Editor에 그대로 붙여넣기(멱등) 또는 `supabase db push`.
-- ============================================================================

create extension if not exists pgcrypto;

-- ---------- 테이블 ----------

create table if not exists public.vuln_scans (
  id              uuid primary key default gen_random_uuid(),
  target_id       text not null,
  target_name     text not null,
  target_url      text not null,
  status          text not null default 'pending_approval'
                    check (status in ('pending_approval','approved','running','completed','failed','cancelled')),
  requested_by    uuid default auth.uid(),
  requested_email text,
  approved_by     uuid,
  approved_email  text,
  approved_at     timestamptz,
  started_at      timestamptz,
  finished_at     timestamptz,
  duration_ms     integer,
  score           integer,
  grade           text,
  summary         jsonb not null default '{}'::jsonb,   -- {counts:{critical,..}, total, autofixable, projected_score}
  error           text,
  created_at      timestamptz not null default now()
);

create table if not exists public.vuln_findings (
  id             uuid primary key default gen_random_uuid(),
  scan_id        uuid not null references public.vuln_scans(id) on delete cascade,
  owasp_id       text not null,                          -- A01..A10
  owasp_ko       text not null,
  severity       text not null check (severity in ('critical','high','medium','low','info','pass')),
  title          text not null,
  detail         text not null default '',
  evidence       text not null default '',
  recommendation text not null default '',
  auto_fixable   boolean not null default false,
  fix_summary    text not null default '',
  status         text not null default 'open'
                   check (status in ('open','remediation_generated','resolved','ticket','accepted')),
  meta           jsonb not null default '{}'::jsonb,     -- {resource_url, header, host_kind, ...}
  created_at     timestamptz not null default now()
);

-- 실시간 진행(Realtime로 구독) — '남은 시간(eta_ms)'까지 상세 표시
create table if not exists public.vuln_progress (
  id          bigint generated always as identity primary key,
  scan_id     uuid not null references public.vuln_scans(id) on delete cascade,
  seq         integer not null,
  phase       text not null default 'scan',             -- scan | remediate
  owasp_id    text,
  step        text not null,
  status      text not null default 'running'
                check (status in ('running','ok','warn','bad','done','error')),
  pct         numeric not null default 0,
  eta_ms      integer,
  message     text not null default '',
  created_at  timestamptz not null default now()
);

create table if not exists public.vuln_remediations (
  id             uuid primary key default gen_random_uuid(),
  scan_id        uuid not null references public.vuln_scans(id) on delete cascade,
  finding_id     uuid references public.vuln_findings(id) on delete set null,
  owasp_id       text,
  title          text not null,
  action         text not null default '',
  kind           text not null default 'artifact'       -- artifact | manual_ticket
                   check (kind in ('artifact','manual_ticket')),
  artifact_path  text,                                  -- storage(vuln-fixes) 경로
  artifact_name  text,
  status         text not null default 'generated'
                   check (status in ('generated','manual_ticket','failed')),
  approved_by    uuid,
  approved_email text,
  approved_at    timestamptz,
  detail         jsonb not null default '{}'::jsonb,
  created_at     timestamptz not null default now()
);

-- 전체 감사 추적(누가/언제/무엇을) — 절대 삭제하지 않음
create table if not exists public.vuln_audit (
  id          bigint generated always as identity primary key,
  scan_id     uuid references public.vuln_scans(id) on delete set null,
  actor       uuid default auth.uid(),
  actor_email text,
  action      text not null,
  detail      jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now()
);

create index if not exists vuln_findings_scan_idx     on public.vuln_findings(scan_id);
create index if not exists vuln_progress_scan_idx     on public.vuln_progress(scan_id, seq);
create index if not exists vuln_remediations_scan_idx on public.vuln_remediations(scan_id);
create index if not exists vuln_scans_created_idx     on public.vuln_scans(created_at desc);
create index if not exists vuln_audit_scan_idx        on public.vuln_audit(scan_id, id);

-- ---------- RLS ----------
-- 클라이언트: SELECT만(쓰기는 정의자 RPC + service_role). 익명은 완료분만.

alter table public.vuln_scans        enable row level security;
alter table public.vuln_findings     enable row level security;
alter table public.vuln_progress     enable row level security;
alter table public.vuln_remediations enable row level security;
alter table public.vuln_audit        enable row level security;

-- scans
drop policy if exists vuln_scans_auth_read on public.vuln_scans;
create policy vuln_scans_auth_read on public.vuln_scans for select to authenticated using (true);
drop policy if exists vuln_scans_anon_read on public.vuln_scans;
create policy vuln_scans_anon_read on public.vuln_scans for select to anon using (status = 'completed');

-- findings
drop policy if exists vuln_findings_auth_read on public.vuln_findings;
create policy vuln_findings_auth_read on public.vuln_findings for select to authenticated using (true);
drop policy if exists vuln_findings_anon_read on public.vuln_findings;
create policy vuln_findings_anon_read on public.vuln_findings for select to anon
  using (exists (select 1 from public.vuln_scans s where s.id = scan_id and s.status = 'completed'));

-- progress
drop policy if exists vuln_progress_auth_read on public.vuln_progress;
create policy vuln_progress_auth_read on public.vuln_progress for select to authenticated using (true);
drop policy if exists vuln_progress_anon_read on public.vuln_progress;
create policy vuln_progress_anon_read on public.vuln_progress for select to anon
  using (exists (select 1 from public.vuln_scans s where s.id = scan_id and s.status = 'completed'));

-- remediations
drop policy if exists vuln_remediations_auth_read on public.vuln_remediations;
create policy vuln_remediations_auth_read on public.vuln_remediations for select to authenticated using (true);
drop policy if exists vuln_remediations_anon_read on public.vuln_remediations;
create policy vuln_remediations_anon_read on public.vuln_remediations for select to anon
  using (exists (select 1 from public.vuln_scans s where s.id = scan_id and s.status = 'completed'));

-- audit: 관리자만 열람
drop policy if exists vuln_audit_auth_read on public.vuln_audit;
create policy vuln_audit_auth_read on public.vuln_audit for select to authenticated using (true);

-- ---------- 상태전이 RPC (SECURITY DEFINER · 감사기록 포함) ----------

create or replace function public.vuln_request_scan(
  p_target_id text, p_target_name text, p_target_url text
) returns public.vuln_scans
language plpgsql security definer set search_path = public as $$
declare v_row public.vuln_scans;
begin
  if auth.uid() is null then raise exception 'auth required'; end if;
  if p_target_url is null or p_target_url !~* '^https?://' then
    raise exception 'invalid target url';
  end if;
  insert into public.vuln_scans(target_id, target_name, target_url, status, requested_by, requested_email)
    values (p_target_id, p_target_name, p_target_url, 'pending_approval', auth.uid(), auth.jwt() ->> 'email')
    returning * into v_row;
  insert into public.vuln_audit(scan_id, actor, actor_email, action, detail)
    values (v_row.id, auth.uid(), auth.jwt() ->> 'email', 'request_scan',
            jsonb_build_object('target', p_target_url));
  return v_row;
end $$;

create or replace function public.vuln_approve_scan(p_scan_id uuid)
returns public.vuln_scans
language plpgsql security definer set search_path = public as $$
declare v_row public.vuln_scans;
begin
  if auth.uid() is null then raise exception 'auth required'; end if;
  -- 요청자 본인만 승인 가능(권한 상승/타인 요청 승인 방지)
  update public.vuln_scans
     set status = 'approved', approved_by = auth.uid(),
         approved_email = auth.jwt() ->> 'email', approved_at = now()
   where id = p_scan_id and status = 'pending_approval' and requested_by = auth.uid()
   returning * into v_row;
  if not found then raise exception 'scan not pending_approval or not owned by caller'; end if;
  insert into public.vuln_audit(scan_id, actor, actor_email, action)
    values (p_scan_id, auth.uid(), auth.jwt() ->> 'email', 'approve_scan');
  return v_row;
end $$;

create or replace function public.vuln_approve_remediation(p_scan_id uuid)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'auth required'; end if;
  insert into public.vuln_audit(scan_id, actor, actor_email, action)
    values (p_scan_id, auth.uid(), auth.jwt() ->> 'email', 'approve_remediation');
end $$;

revoke all on function public.vuln_request_scan(text,text,text)  from public, anon;
revoke all on function public.vuln_approve_scan(uuid)            from public, anon;
revoke all on function public.vuln_approve_remediation(uuid)     from public, anon;
grant execute on function public.vuln_request_scan(text,text,text) to authenticated;
grant execute on function public.vuln_approve_scan(uuid)           to authenticated;
grant execute on function public.vuln_approve_remediation(uuid)    to authenticated;

-- ---------- Realtime ----------
-- 진행/상태를 클라이언트가 실시간 구독. (이미 추가돼 있으면 무시)
do $$
begin
  begin execute 'alter publication supabase_realtime add table public.vuln_progress'; exception when others then null; end;
  begin execute 'alter publication supabase_realtime add table public.vuln_scans';    exception when others then null; end;
end $$;

-- ---------- Storage: 조치 산출물(비공개, 서명 URL로만 다운로드) ----------
insert into storage.buckets (id, name, public)
values ('vuln-fixes', 'vuln-fixes', false)
on conflict (id) do nothing;

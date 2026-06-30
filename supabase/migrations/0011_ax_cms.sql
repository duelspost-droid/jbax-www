-- ════════════════════════════════════════════════════════════════════
-- 0011_ax_cms.sql — AX(미래성장본부) 페이지 콘텐츠 관리(CMS)
--   대상 프로젝트: nrdapzgtibbusvoaceuh (secuday/VulnScan과 동일)
--   목적: ax/index.html 콘텐츠를 ax/admin.html에서 편집 가능하게
--   모델: 단일 텍스트 = ax_settings(kv/jsonb), 목록형 = 테이블 5종
--   RLS : 익명 = published만 SELECT · 관리자(authenticated) = 전체 CRUD
--   ⚠ SQL Editor에 그대로 붙여넣어 1회 실행 (db push 대신 수동 권장 — secuday 이력과 분리)
--   ※ 재실행 안전(idempotent): if not exists / drop policy if exists 사용
-- ════════════════════════════════════════════════════════════════════

-- ─────────── 공통: updated_at 자동 갱신 트리거 함수 ───────────
create or replace function public.ax_set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

-- ─────────── 1) 단일 텍스트 블록 (히어로 문구·About·연락처·푸터 등) ───────────
create table if not exists public.ax_settings (
  key        text primary key,
  value      jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

-- ─────────── 2) 지표 (히어로 / 임팩트 밴드) ───────────
create table if not exists public.ax_metrics (
  id         uuid primary key default gen_random_uuid(),
  section    text not null default 'hero' check (section in ('hero','impact')),
  label      text not null,
  value      numeric not null default 0,        -- 카운트업 목표값
  prefix     text not null default '',
  suffix     text not null default '',          -- 예: '+', '%', '/7'
  group_num  boolean not null default true,     -- 천단위 콤마 여부(false=연도 등)
  sort_order int not null default 0,
  published  boolean not null default true,
  updated_at timestamptz not null default now()
);

-- ─────────── 3) 뉴스 / 소식 ───────────
create table if not exists public.ax_news (
  id         uuid primary key default gen_random_uuid(),
  news_date  date,
  category   text not null default '소식',
  title      text not null,
  summary    text not null default '',
  url        text not null default '',
  sort_order int not null default 0,
  published  boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ─────────── 4) 6대 추진전략 (pillars) ───────────
create table if not exists public.ax_pillars (
  id         uuid primary key default gen_random_uuid(),
  icon       text not null default '🔹',         -- 이모지
  en_label   text not null default '',
  title      text not null,
  body       text not null default '',
  tags       jsonb not null default '[]'::jsonb, -- 문자열 배열
  sort_order int not null default 0,
  published  boolean not null default true,
  updated_at timestamptz not null default now()
);

-- ─────────── 5) 조직 (팀 카드) ───────────
create table if not exists public.ax_org (
  id         uuid primary key default gen_random_uuid(),
  tag        text not null default '',
  title      text not null,
  body       text not null default '',
  sort_order int not null default 0,
  published  boolean not null default true,
  updated_at timestamptz not null default now()
);

-- ─────────── 6) 로드맵 단계 ───────────
create table if not exists public.ax_roadmap (
  id          uuid primary key default gen_random_uuid(),
  year_label  text not null default '',
  title       text not null,
  body        text not null default '',
  chips       jsonb not null default '[]'::jsonb,
  sort_order  int not null default 0,
  published   boolean not null default true,
  updated_at  timestamptz not null default now()
);

-- ─────────── updated_at 트리거 부착 ───────────
do $$
declare t text;
begin
  foreach t in array array['ax_settings','ax_metrics','ax_news','ax_pillars','ax_org','ax_roadmap']
  loop
    execute format('drop trigger if exists trg_%1$s_updated on public.%1$s', t);
    execute format('create trigger trg_%1$s_updated before update on public.%1$s
                    for each row execute function public.ax_set_updated_at()', t);
  end loop;
end $$;

-- ════════════════════════════════════════════════════════════════════
-- RLS: 익명=공개분 읽기 / 관리자(로그인)=전체 읽기·쓰기
-- ════════════════════════════════════════════════════════════════════
alter table public.ax_settings enable row level security;
alter table public.ax_metrics  enable row level security;
alter table public.ax_news     enable row level security;
alter table public.ax_pillars  enable row level security;
alter table public.ax_org      enable row level security;
alter table public.ax_roadmap  enable row level security;

-- settings: 공개 읽기(전체) + 관리자 쓰기
drop policy if exists ax_settings_read    on public.ax_settings;
drop policy if exists ax_settings_write   on public.ax_settings;
create policy ax_settings_read  on public.ax_settings for select using (true);
create policy ax_settings_write on public.ax_settings for all to authenticated using (true) with check (true);

-- published 컬럼이 있는 5개 테이블: 동일 정책 일괄 생성
do $$
declare t text;
begin
  foreach t in array array['ax_metrics','ax_news','ax_pillars','ax_org','ax_roadmap']
  loop
    execute format('drop policy if exists %1$s_read_pub  on public.%1$s', t);
    execute format('drop policy if exists %1$s_read_all  on public.%1$s', t);
    execute format('drop policy if exists %1$s_write     on public.%1$s', t);
    -- 익명/로그인 공통: 게시된 행만 읽기
    execute format('create policy %1$s_read_pub on public.%1$s for select using (published = true)', t);
    -- 관리자: 전체 행 읽기(미게시 포함, 관리화면용)
    execute format('create policy %1$s_read_all on public.%1$s for select to authenticated using (true)', t);
    -- 관리자: 전체 쓰기
    execute format('create policy %1$s_write on public.%1$s for all to authenticated using (true) with check (true)', t);
  end loop;
end $$;

-- ════════════════════════════════════════════════════════════════════
-- 완료. 시드 데이터는 0012_ax_seed.sql(연구 검증본)로 별도 INSERT.
-- ════════════════════════════════════════════════════════════════════

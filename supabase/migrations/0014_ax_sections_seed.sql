-- ════════════════════════════════════════════════════════════════════
-- 0014_ax_sections_seed.sql — 섹션 제목/소제목(헤더) 문구 시드
--   ax/index.html 각 섹션 kicker·제목·소제목을 관리자(섹션 제목 탭)에서 편집 가능하게.
--   비파괴: on conflict do nothing (정적 폴백이 기본값 담당)
-- ════════════════════════════════════════════════════════════════════
insert into public.ax_settings (key,value) values
  ('sections', jsonb_build_object(
     'strategy_kicker','STRATEGIC PILLARS',
     'strategy_title','6대 핵심 추진 전략',
     'strategy_sub','AI 전환부터 신사업, 데이터, 거버넌스까지 — 미래성장본부가 그룹의 성장을 견인하는 여섯 개의 축입니다.',
     'impact_kicker','OUR IMPACT',
     'impact_title','숫자로 보는 전환의 속도',
     'impact_sub','미래성장본부가 그룹과 함께 만들어가는 변화의 규모입니다.',
     'roadmap_kicker','ROADMAP',
     'roadmap_title','2024 → 2027 추진 로드맵',
     'roadmap_sub','기반 구축에서 전사 확산, 그리고 AI 네이티브 도약까지 — 단계적으로 전환을 가속합니다.',
     'org_kicker','ORGANIZATION',
     'org_title','본부 조직 구성',
     'org_node','AX·미래성장본부',
     'org_node_en','FUTURE GROWTH DIVISION',
     'news_kicker','NEWS & INSIGHTS',
     'news_title','본부 소식',
     'news_sub','미래성장본부의 최근 활동과 인사이트를 전합니다.'))
on conflict (key) do nothing;

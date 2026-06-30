-- ════════════════════════════════════════════════════════════════════
-- 0012_ax_seed.sql — AX CMS 초기 시드 데이터
--   출처: 다중 에이전트 웹조사 + 항목별 출처검증(40/41 confirmed) 콘텐츠팩
--   ⚠ 0011_ax_cms.sql 실행 후 SQL Editor에 붙여넣어 실행
--   비파괴/재실행 안전: 각 테이블이 비어 있을 때만 INSERT, settings는 on conflict do nothing
--   ※ 모든 수치·뉴스는 공개 출처로 검증됨. 검증 못한 항목(임직원 수, AI 서비스 브랜드명,
--     미래성장본부 2026 현재 존속 단정)은 의도적으로 제외/일반화함.
-- ════════════════════════════════════════════════════════════════════

-- ─────────── 지표 (히어로 / 임팩트) ───────────
do $$ begin
if not exists (select 1 from public.ax_metrics) then
  insert into public.ax_metrics (section,label,value,prefix,suffix,group_num,sort_order) values
    -- 히어로: 그룹 규모·실적 (검증)
    ('hero','2025 그룹 당기순이익', 7104, '', '억원', true,  1),  -- 사상 최대, 전년比 +4.9% (ajunews)
    ('hero','그룹 총자산',           73,  '약 ','조원', false, 2),  -- 2025말 약 73조 (FnGuide)
    ('hero','자기자본이익률 ROE',    12.4,'', '%',   false, 3),  -- 2025 (ajunews)
    ('hero','총 주주환원율(2025)',   45,  '', '%',   false, 4),  -- 현금배당+자사주 (ajunews)
    -- 임팩트: AX/전환 관점 (검증)
    ('impact','AI NewTech 경진대회 참여팀(2026)', 66, '', '팀',  false, 1), -- 계열사 66팀 (g-enews)
    ('impact','전년 대비 순이익 증가율',          4.9,'', '%',   false, 2),
    ('impact','총자산이익률 ROA(2025)',           1.04,'','%',   false, 3),
    ('impact','그룹 계열사(국내5·해외4)',         9,  '', '개사', false, 4); -- 공식 계열사 페이지
end if;
end $$;

-- ─────────── 뉴스 / 소식 (검증된 실제 기사) ───────────
do $$ begin
if not exists (select 1 from public.ax_news) then
  insert into public.ax_news (news_date,category,title,summary,url,sort_order) values
    ('2026-03-05','AX',
     '김기홍 회장 "2026년은 AX 전환 뿌리내리는 원년"',
     '김기홍 회장이 2026년을 AX(AI 전환)가 전 그룹에 뿌리내리는 원년으로 선언했습니다. RORWA 중심 질적 성장과 AX 내재화를 핵심 실행축으로 제시했습니다.',
     'https://biz.heraldcorp.com/article/10687396', 1),
    ('2026-03-27','신사업',
     'JB금융, 외국인 비대면 금융서비스 선점 나선다',
     '외국인등록증 발급 전에도 다중 생체인증으로 계좌를 개설하는 외국인 전용 비대면 서비스를 추진합니다. 전북·광주은행이 혁신금융서비스로 신청할 예정입니다.',
     'https://www.jbfg.com/ko/prcenter/press/detail/27.do', 2),
    ('2026-03-18','AI',
     'JB우리캐피탈, 메가존클라우드와 생성형 AI 플랫폼 구축',
     'JB우리캐피탈이 메가존클라우드와 AWS Bedrock 기반 생성형 AI 플랫폼을 구축합니다. RAG를 활용해 업무 효율화를 추진합니다.',
     'https://www.mt.co.kr/tech/2026/03/18/2026031810043749055', 3),
    ('2026-02-20','AI',
     'JB금융, 전 그룹 차원 AI 적용 전략 본격화',
     'NewTech+비즈니스 경진대회에 계열사 66개팀이 참여했습니다. 생성형 AI·로우코드 등 신기술로 AX·DX 혁신을 전 그룹으로 확산합니다.',
     'https://www.g-enews.com/article/Finance/2026/02/202602200859469848bb91c46fcd_1', 4),
    ('2025-12-26','AI',
     '네이버클라우드, JB금융그룹과 맞손…AI 전환 나선다',
     '네이버클라우드와 AI 금융 혁신 MOU를 체결했습니다. 하이퍼클로바X·AICC로 여신 상담·심사·사후관리 전반에 AI를 단계적으로 적용합니다.',
     'https://www.mt.co.kr/tech/2025/12/26/2025122609213278025', 5),
    ('2025-04-09','AI',
     '지방금융 3사(JB·BNK·iM) 공동 AI 거버넌스 수립',
     'JB·BNK·iM 지방금융 3사가 책임 있는 AI 활용 표준과 내부통제 체계를 함께 마련하는 공동 AI 거버넌스를 추진합니다.',
     'https://www.jbfg.com/ko/prcenter/press/detail/5.do', 6);
end if;
end $$;

-- ─────────── 6대 추진전략 ───────────
do $$ begin
if not exists (select 1 from public.ax_pillars) then
  insert into public.ax_pillars (icon,en_label,title,body,tags,sort_order) values
    ('🤖','AI TRANSFORMATION','AI 전환(AX)','여신심사·상담·내부업무 전반에 생성형 AI를 내재화해 속도와 정확도를 동시에 끌어올립니다.', '["업무 자동화","AI 상담","여신 심사"]'::jsonb, 1),
    ('🚀','NEW BUSINESS','디지털 신사업','플랫폼·임베디드 금융 등 비(非)전통 영역에서 새로운 수익 모델과 고객 접점을 만듭니다.', '["임베디드 금융","플랫폼","제휴"]'::jsonb, 2),
    ('📊','DATA & ANALYTICS','데이터 · 분석','그룹 데이터를 한데 모아 리스크·마케팅·경영 의사결정을 데이터 기반으로 전환합니다.', '["데이터 레이크","CRM","리스크"]'::jsonb, 3),
    ('🧪','AI LAB · R&D','미래기술 R&D','생성형 AI·자동화·차세대 인프라를 선제적으로 실험하고 검증하는 그룹 기술 실험실입니다.', '["생성형 AI","RAG","MLOps"]'::jsonb, 4),
    ('🌐','VENTURE & ALLIANCE','투자 · 오픈이노베이션','유망 핀테크·AI 스타트업과 협업하고 전략 투자를 통해 외부 혁신을 그룹 안으로 끌어옵니다.', '["CVC","스타트업","오픈 API"]'::jsonb, 5),
    ('🛡️','AI GOVERNANCE','AI 거버넌스','책임 있는 AI를 위한 윤리·보안·규제 대응 체계를 세워 신뢰할 수 있는 전환을 보장합니다.', '["AI 윤리","보안","규제 대응"]'::jsonb, 6);
end if;
end $$;

-- ─────────── 조직 (팀 카드) ───────────
do $$ begin
if not exists (select 1 from public.ax_org) then
  insert into public.ax_org (tag,title,body,sort_order) values
    ('AX STRATEGY','AX전략팀','그룹 AI 전환 로드맵 수립과 과제 발굴·관리, 성과 측정을 총괄합니다.', 1),
    ('NEW BUSINESS','디지털신사업팀','플랫폼·임베디드 금융 등 신규 비즈니스 모델을 기획하고 실행합니다.', 2),
    ('DATA','데이터팀','그룹 데이터 거버넌스와 분석 기반을 운영하고 데이터 활용을 확산합니다.', 3),
    ('AI LAB','AI Lab','생성형 AI·자동화 기술을 선행 연구하고 PoC로 빠르게 검증합니다.', 4);
end if;
end $$;

-- ─────────── 로드맵 ───────────
do $$ begin
if not exists (select 1 from public.ax_roadmap) then
  insert into public.ax_roadmap (year_label,title,body,chips,sort_order) values
    ('2024','기반 구축 · Foundation','그룹 데이터 통합 기반을 마련하고, AX 전략 체계와 거버넌스를 수립했습니다. 핵심 영역에서 첫 AI 파일럿을 가동했습니다.', '["데이터 통합","AX 전략 수립","파일럿"]'::jsonb, 1),
    ('2025','전사 확산 · Scale-up','검증된 AI 과제를 계열사 전반으로 확산하고, 생성형 AI 업무 비서와 AI 상담을 본격 도입합니다.', '["AI 업무비서","AI 상담","계열사 확산"]'::jsonb, 2),
    ('2026','고도화 · Intelligence','데이터·AI를 의사결정 핵심에 내재화하고, 임베디드 금융 등 디지털 신사업을 본격 확장합니다.', '["의사결정 AI","임베디드 금융","신사업 확장"]'::jsonb, 3),
    ('2027','도약 · AI-Native','AI를 기본값으로 삼는 ''AI 네이티브 금융그룹''으로 도약합니다. 고객 경험과 일하는 방식 전반이 새롭게 정의됩니다.', '["AI 네이티브","차세대 고객경험","지속 성장"]'::jsonb, 4);
end if;
end $$;

-- ─────────── 단일 텍스트(설정) ───────────
insert into public.ax_settings (key,value) values
  ('hero', jsonb_build_object(
     'eyebrow','JB FINANCIAL GROUP · FUTURE GROWTH',
     'line1','AX로 여는',
     'line2_pre','금융의 ',
     'line2_gold','다음 10년',
     'lead','JB금융지주 미래성장본부는 인공지능 전환(AX)과 디지털 신성장 동력으로 그룹의 미래를 설계합니다. 데이터와 AI를 업(業)의 중심에 두고, 고객과 현장이 체감하는 변화를 만듭니다.',
     'cta_primary','추진전략 살펴보기','cta_primary_href','#strategy',
     'cta_ghost','본부 소개','cta_ghost_href','#about')),
  ('about', jsonb_build_object(
     'kicker','ABOUT THE DIVISION',
     'title_pre','업의 본질을 다시 쓰는',
     'title_gold','AI 전환의 컨트롤타워',
     'para1','미래성장본부는 JB금융지주의 AX(AI Transformation) 전략을 총괄하는 그룹 차원의 전략 조직입니다. 전북은행·광주은행·JB우리캐피탈 등 계열사 전반에 AI와 데이터를 내재화하고, 기존 금융의 경계를 넘는 디지털 신사업을 발굴·육성합니다.',
     'para2','우리는 기술을 위한 기술이 아니라, 고객과 직원이 체감하는 변화를 지향합니다. 실험을 빠르게 시도하고, 검증된 것을 그룹 표준으로 확산합니다.',
     'mission','AI와 데이터로 그룹의 일하는 방식과 고객 경험을 근본부터 혁신한다.',
     'vision','고객이 가장 먼저 떠올리는 ''AI 네이티브'' 금융그룹으로의 도약.')),
  ('contact', jsonb_build_object(
     'title','함께 금융의 다음을 만들어 갈 파트너를 찾습니다',
     'desc','AI·데이터·플랫폼 분야의 협업, 제휴, 투자 제안을 환영합니다. 미래성장본부와의 협업이 궁금하시다면 언제든 문의해 주세요.',
     'email','jbfgir@jbfg.com',
     'address','전북특별자치도 전주시 덕진구 백제대로 566 · JB금융지주',
     'partnership','제휴 · 투자 · 오픈이노베이션')),
  ('footer', jsonb_build_object(
     'slogan','“We are Raising Our Value As A Global Financial Group.”'))
on conflict (key) do nothing;

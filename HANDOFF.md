# JBAX 플레이그라운드 — 인수인계 (HANDOFF)

다른 PC에서 이어서 작업하기 위한 전체 컨텍스트. (최종 업데이트: 2026-07-01 — 섹션 8 AX 페이지 CMS 추가)

## 1. 이 레포가 뭔가
- **jbax-www** = JB×AX 비공식 플레이그라운드. GitHub Pages 정적 사이트.
- 레포: `github.com/duelspost-droid/jbax-www` (기본 브랜치 **master**)
- 라이브: **https://www.jbax.co.kr/** (CNAME `jbax.co.kr`, master push 시 Pages 자동 빌드)
- 슬롯(서비스 카드) 모음 페이지 + 우상단 **🛡️ AI 취약점 진단(VulnScan)** 기능.

## 2. VulnScan 기능 개요
플레이그라운드 페이지에서 슬롯(자기 소유 사이트)을 골라 **OWASP TOP 10 서버측 진단 → 리포트 → 자동 조치(산출물 생성)** 를 수행. 2단계 승인 게이트, Realtime 진행(남은시간 ETA), 전체 이력 보존.

- **백엔드 = secuday와 동일 Supabase 프로젝트 재사용** (project ref **`nrdapzgtibbusvoaceuh`**).
- 진단/승인/조치 실행은 **관리자 로그인 필수**(secuday와 같은 Supabase Auth 계정). 익명은 '완료된' 진단만 열람.
- 자동 조치는 **실제 산출물 생성까지**(CSP / `_headers` / netlify / vercel / nginx / 실 SRI sha384 / patched-index.html / security.txt → Storage `vuln-fixes` 비공개 버킷, 서명 URL). 라이브 사이트 자동 변경은 안 함.

## 3. 구성 파일
| 파일 | 역할 |
|---|---|
| `index.html` | 페이지 + VulnScan 모달/CSS + 스크립트 로딩 |
| `vulnscan.js` | 프런트 로직(로그인·승인·Realtime 진행·리포트·조치·이력) |
| `config.js` | Supabase URL + anon(publishable) 키 (공개값, RLS로 보호) |
| `supabase/migrations/0010_vulnscan.sql` | 테이블5 + RLS + 정의자 RPC + Realtime + Storage |
| `supabase/functions/vuln-scan/` | 서버측 OWASP 점검(헤더/HTML/정찰GET/무해 반사프로브, 비파괴) |
| `supabase/functions/vuln-remediate/` | 조치 산출물 생성 |
| `supabase/config.toml` | 함수 verify_jwt 설정(=true). CLI 배포 시 적용 |
| `DEPLOY_VULNSCAN.md` | 배포 절차 상세 |

**DB 테이블**: `vuln_scans / vuln_findings / vuln_progress / vuln_remediations / vuln_audit`
**RPC(정의자, 감사기록 포함)**: `vuln_request_scan` · `vuln_approve_scan`(요청자 본인만) · `vuln_approve_remediation`

## 4. 배포 상태 (✅ 전부 배포됨 — 2026-06-22)
- ✅ 스키마: SQL Editor에서 `0010` 실행 완료. 5개 테이블 REST 200 확인.
- ✅ Edge Functions: `vuln-scan`, `vuln-remediate` 대시보드 *Via Editor*로 배포 완료. (호출 시 커스텀 에러 응답 확인)
- ✅ 두 함수 "Verify JWT with legacy secret" ON.
- ✅ 프런트: master 머지 → Pages 빌드 완료 → jbax.co.kr 라이브.

### 남은 일 (TODO)
1. **실제 로그인 후 스캔 1건 E2E 실측** — 라이브에서 관리자 로그인 → 슬롯 선택 → 진단 실행 → 진행률/리포트/자동조치/이력 확인.
2. **미사용 PAT 삭제** — 배포 중 발급했다 미사용으로 남은 액세스 토큰 **`claude-vulnscan-deploy`** 를 `supabase.com/dashboard/account/tokens` 에서 Delete(보안 정리).

## 5. 다른 PC에서 이어서 작업하기
```bash
git clone https://github.com/duelspost-droid/jbax-www.git
cd jbax-www
# 정적 사이트라 빌드 불필요. file://로 index.html 직접 열어도 동작(외부 fetch 없음).
```
- 프런트 수정 → `git push origin master` → Pages 자동 반영.
- **백엔드(함수) 수정 후 재배포**: 둘 중 하나
  - CLI: `npx supabase login` → `npx supabase functions deploy vuln-scan --project-ref nrdapzgtibbusvoaceuh` (config.toml의 verify_jwt 적용)
  - 대시보드: Edge Functions → *Deploy a new function → Via Editor* (또는 기존 함수 Code 탭에서 수정 후 배포)
- **스키마 변경**: `supabase/migrations/`에 새 파일 추가 후 SQL Editor에 붙여넣기 실행(secuday 마이그 이력과 섞이지 않게 `db push` 대신 수동 실행 권장).

## 6. 보안 모델 & 주의점(중요)
- **호출 게이팅의 실질 주체는 인증 RPC**: 신규 publishable(anon) 키는 Supabase 신규 키 모델상 `verify_jwt`를 통과한다. 따라서 함수 자체는 anon이 호출해도 열리지만, **스캔 생성·승인은 로그인(auth.uid) 필요한 RPC로만 가능**하고 함수는 'approved' 상태 스캔에만 동작 → 익명은 409/404만 받음(피해 불가).
- ⚠️ **하드닝 권고**: `vuln_request_scan`은 현재 임의 https URL을 받는다(프런트는 5개 고정 슬롯만 노출). 외부 악용(SSRF) 여지를 줄이려면 RPC에 대상 URL allowlist 추가 고려.
- RLS: 클라이언트는 SELECT만, 쓰기는 정의자 RPC + service_role(Edge)만. 익명은 완료분만.

## 7. 검증 이력
- 프런트: jsdom + Supabase mock E2E 통과(오류 0).
- 백엔드: 다중 에이전트 적대적 리뷰(27건 → 11건 확정) 후 수정 — JWT base64url 디코딩, Set-Cookie 다중헤더(getSetCookie), 스캔 시작 원자적 전환, 승인 권한 요청자 한정, SRI 패치 정규식, progress.status CHECK, 대상 도달불가 조기실패. Edge Function TS는 esbuild 파싱 통과.

---

# 8. AX 미래성장본부 페이지 (CMS) — 2026-07-01 작업

## 8.1 개요
- **위치**: 같은 레포의 `ax/` 서브디렉터리. 별도 레포 아님.
- **라이브**: **https://www.jbax.co.kr/ax/** (플레이그라운드 랜딩 `/` 의 **슬롯 0**에서 `/ax/`로 연결)
- **정체**: JB금융지주 'AX·미래성장본부' 소개 페이지. 인트로 모션 → 히어로 → About → 6대 전략 → 임팩트 지표 → 로드맵 → 조직(본부장 포함) → 소식 → 연락처 → 푸터.
- **백엔드**: VulnScan과 **동일 Supabase**(`nrdapzgtibbusvoaceuh`) + **동일 관리자 계정**(secuday/VulnScan). Edge Function 불필요(순수 DB CRUD + RLS).
- **핵심 설계**: 페이지 콘텐츠를 관리자페이지에서 편집(CMS). 공개 페이지는 DB에서 읽어 렌더하되 **실패/빈값/미설정이면 HTML에 박힌 정적 콘텐츠로 폴백** → Supabase가 죽어도 안 깨짐.

## 8.2 구성 파일 (ax/)
| 파일 | 역할 |
|---|---|
| `ax/index.html` | 공개 페이지(인라인 CSS/JS). 섹션마다 `data-ax="키"`(텍스트)·`data-ax-href`/`data-ax-mailto`/`data-ax-src` 바인딩. 카운트업 엔진(소수점 `data-decimals`·접두 `data-prefix` 지원)과 `window.AX.rescan()`(하이드레이션 후 reveal/카운트 재적용) 노출. |
| `ax/ax-content.js` | **공개 페이지 하이드레이션**. Supabase에서 published 행 읽어 섹션 렌더 + `applySettings()`로 단일텍스트 주입. 실패 시 정적 폴백. |
| `ax/admin.html` + `ax/admin.js` | **관리자 CMS**. 로그인(동일 계정) → 탭별 CRUD. 제네릭 엔티티(ENTITIES)+설정그룹(SETTINGS) 구조. 반응형. `noindex`. |
| `ax/assets/ci/` | 공식 JB CI SVG(ci-sig 1~6 등). 히어로 키비주얼은 `ci-sig-5.svg`의 컬러 facet 경로를 인라인. |
| `config.js`(레포 루트) | Supabase URL+anon키. ax/에선 `../config.js`로 로드. |

## 8.3 DB 모델 & 마이그레이션 (⚠ 시드 일부 미실행)
**테이블(0011)**: `ax_settings`(key/jsonb 단일텍스트) · `ax_metrics` · `ax_news` · `ax_pillars` · `ax_org` · `ax_roadmap`. RLS: 익명=published만 SELECT, 로그인(authenticated)=전체 CRUD.
**ax_settings 키**: `hero` · `about` · `contact` · `footer` · `leader`(본부장) · `sections`(섹션 헤더 문구).

| 마이그레이션 | 내용 | 실행 상태 |
|---|---|---|
| `0011_ax_cms.sql` | 테이블 6 + RLS | ✅ 실행됨(SQL Editor) |
| `0012_ax_seed.sql` | 지표·뉴스·전략·조직·로드맵·hero/about/contact/footer 시드 | ✅ 실행됨 |
| `0013_ax_leader_seed.sql` | 본부장(박종춘) settings | ⏳ **미실행** (Supabase 대시보드 장애) |
| `0014_ax_sections_seed.sql` | 섹션 제목/소제목 settings | ⏳ **미실행** (동일) |
> 0013·0014 미실행이어도 **정적 폴백으로 라이브 정상 표시**. 단 관리자 '본부장'·'섹션 제목' 탭은 시드 전엔 빈칸(저장하면 그 값으로 DB 생성·반영). **대시보드 복구 시 0013·0014를 SQL Editor에 붙여 실행할 것.**

## 8.4 배포 상태 (HEAD `9892e25`, master, 라이브 반영 확인)
- `261c653` CMS화 + 히어로 키비주얼 모션그래픽(공식 JB DIAMOND 심볼 + 글로우·회전링·부유·샤인·마우스 패럴랙스).
- `74d1486` 조직 섹션 **본부장 블록**(박종춘 AX·미래성장본부장 부사장).
- `9892e25` **모든 섹션 제목/소제목 CMS화**(`sections.*`).
- 전부 master push → Pages `built` → www.jbax.co.kr/ax 반영 확인.

## 8.5 콘텐츠 출처 (중요 — 창작 금지 원칙)
- 모든 실제 수치·뉴스·본부장 인용은 **다중 에이전트 웹조사 + 항목별 출처검증**(메인 40/41, 본부장 31/32 confirmed)으로 확보. **가짜를 실제로 교체하되 새 가짜를 만들지 않음.**
- 핵심 수치: 2025 순이익 7,104억(사상최대)·총자산 약73조·ROE 12.4%·주주환원 45%·계열사 9·NewTech 66팀.
- 본부장: 박종춘 = JB금융지주 AX·미래성장본부장 부사장(2026.1 전무→부사장, 본부명 미래성장본부→AX미래성장본부). 대표 인용 "10년 뒤를 준비하려면 은행 안에 없는 DNA를 들여와야 합니다"(헤럴드경제 2026-06-11). 1인칭 인사말 원문은 없으므로 **창작 금지**, 인용은 따옴표+출처로만.
- 연락처: `jbfgir@jbfg.com`(가짜 ax@jbax.co.kr 폐기), 전주 본사주소. ※ 현재 라이브 연락처 이메일은 사용자가 관리자에서 `duels@jbfg.com`으로 변경해 둠.

## 8.6 남은 일 (TODO)
1. **0013·0014 시드 실행** — Supabase 대시보드 복구 후 SQL Editor에서 실행(또는 관리자 각 탭에서 저장).
2. **본부장 사진** — 저작권 때문에 뉴스 사진 미게재. 현재 이니셜 플레이스홀더. **JB 홍보팀 공식 프로필 사진 URL**을 관리자 '본부장' 탭 `photo`에 입력하면 반영(`data-ax-src`).
3. (선택) 네비 메뉴 라벨·푸터 하단 링크 라벨·인트로 문구 CMS화 — 아직 하드코딩.
4. (선택) 모바일 실기기 스폿체크. (반응형은 적용·검증됨: 가로 오버플로 0, 그리드 단일열 붕괴, 관리자 탭/카드도 모바일 OK.)

## 8.7 작업/배포 시 주의 (gotcha)
- **master push는 매 변경마다 사용자 승인 필요**(자동 안전분류기가 기본브랜치 push를 차단). 비기능 작업이면 작업브랜치 권장.
- **마이그레이션 수동**: `supabase/migrations/`에 파일만 추가하고 SQL Editor에 붙여 실행(secuday 이력과 분리). GitHub Actions가 자동 적용 안 함.
- **카운트업 소수점**: `animateCount`는 `data-decimals`로 소수 자릿수 처리. 신규 지표 추가 시 ax-content.js가 value의 소수 자리수로 자동 설정.
- **하이드레이션 후 재스캔**: DOM 교체 후 반드시 `window.AX.rescan()` 호출해야 reveal/카운트업 작동(ax-content.js가 처리).
- **단일텍스트 추가법**: ① index.html 요소에 `data-ax="그룹.키"` 추가 ② admin.js `SETTINGS`의 해당 그룹에 필드 추가 ③ (선택) 시드 마이그레이션. 폴백 위해 HTML 기본 텍스트는 남겨둘 것.

## 8.8 로컬 미리보기
```bash
cd jbax-www
npx -y serve -l 4321 .        # 정적 서버
# http://localhost:4321/ax/        공개 페이지 (인트로 스킵: SKIP 버튼 또는 Esc)
# http://localhost:4321/ax/admin.html  관리자 (동일 계정 로그인)
```
- 로컬에서도 같은 Supabase(운영 DB)에 붙으므로 관리자 편집은 **실제 라이브 데이터에 반영**됨(주의).
- 모바일 점검 팁: 일부 도구가 뷰포트를 고정 렌더할 때, 390px 폭 `<iframe src="/ax/">`에 넣으면 실제 모바일 미디어쿼리로 렌더됨(iframe 높이는 폰 높이 ~844로).

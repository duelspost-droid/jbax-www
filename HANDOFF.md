# JBAX 플레이그라운드 — 인수인계 (HANDOFF)

다른 PC에서 이어서 작업하기 위한 전체 컨텍스트. (최종 업데이트: 2026-06-22)

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

# AI 취약점 진단(VulnScan) 배포 가이드

플레이그라운드(jbax-www)의 **AI 취약점 진단** 기능을 Supabase 백엔드(secuday 프로젝트 재사용,
ref `nrdapzgtibbusvoaceuh`)에 배포하는 절차. 정적 프런트엔드 + Edge Functions 2개 + 테이블 5개.

> ⚠️ Supabase 배포(로그인/링크/함수 배포)는 계정 권한이 필요해 **직접 실행**해야 합니다.
> (현재 세션에서 Supabase CLI는 미로그인 상태)

## 0. 사전 준비
- Node ≥ 18 (CLI는 `npx supabase`로 사용, 설치본 2.107).
- 작업 폴더: `C:\Users\duels\Projects\jbax-www`
- Supabase 액세스 토큰: https://supabase.com/dashboard/account/tokens

## 1. 로그인 & 링크
```bash
cd /c/Users/duels/Projects/jbax-www
npx supabase login                                   # 액세스 토큰 붙여넣기
npx supabase link --project-ref nrdapzgtibbusvoaceuh # DB 비밀번호 입력(대시보드 Settings→Database)
```

## 2. 스키마 적용  ⭐ 권장: SQL Editor 붙여넣기
secuday 레포와 마이그레이션 이력이 충돌하지 않도록 **SQL Editor 사용을 권장**합니다.
- Supabase 대시보드 → **SQL Editor** → `supabase/migrations/0010_vulnscan.sql` 전체 붙여넣기 → **Run**.
- (멱등 SQL이라 여러 번 실행해도 안전)

> 대안(이력 일치가 확실할 때만): `npx supabase db push`

## 3. Edge Functions 배포
```bash
npx supabase functions deploy vuln-scan      --project-ref nrdapzgtibbusvoaceuh
npx supabase functions deploy vuln-remediate --project-ref nrdapzgtibbusvoaceuh
```
- 추가 시크릿 불필요. `SUPABASE_URL` / `SUPABASE_SERVICE_ROLE_KEY` 는 런타임 자동 주입.
- 두 함수 모두 `verify_jwt=true` → **로그인한 관리자만** 호출 가능.

## 4. 관리자 계정
- secuday와 **동일한 Supabase Auth 계정**으로 로그인합니다(이미 존재).
- 새 계정이 필요하면 대시보드 → Authentication → Users → Add user.

## 5. 확인 사항(대시보드)
- **Database → Replication → `supabase_realtime`** 에 `vuln_progress`, `vuln_scans` 가 **Enabled** 인지 확인.
  - 마이그레이션이 자동 추가하지만, publication ALTER는 권한/중복 시 **조용히 건너뜁니다**(예외 무시). 목록에 없으면 UI에서 수동으로 ON.
  - Realtime이 꺼져 있어도 프런트는 **1.5초 폴링으로 자동 폴백**하므로 진단은 정상 완료되지만, 실시간 스트리밍을 위해 확인 권장.
- **Storage**에 비공개 버킷 `vuln-fixes` 생성됨.

## 6. 프런트엔드 배포 (GitHub Pages)
```bash
git add index.html vulnscan.js config.js supabase DEPLOY_VULNSCAN.md
git commit -m "feat: AI 취약점 진단(VulnScan) — Supabase 백엔드"
git push origin master      # Pages 자동 빌드 → jbax.co.kr 반영
```
- `config.js`에 Supabase URL/anon(publishable) 키가 들어 있음(공개 가능, RLS로 보호).

## 7. 동작 테스트
1. https://www.jbax.co.kr/ → 우상단 **🛡️ AI 취약점 진단**
2. **🔑 관리자 로그인** (secuday 계정)
3. 대상 선택 → **진단 승인** → 실시간 진행(남은시간 ETA) → 리포트
4. **자동 조치** 승인 → 산출물 다운로드(24h 서명 URL)
5. **📜 이력** — 전체 진단/조치/감사 기록 보존, JSON 내보내기

## 동작/제약 메모
- 스캐너는 **비파괴 수동 점검**만 수행(응답 헤더·HTML·안전한 정찰 GET·무해한 반사 프로브). 침투형 공격 페이로드는 실행하지 않음. **본인 소유 자산만** 진단할 것.
- 자동 조치는 **산출물 생성**만 수행(라이브 사이트 미변경). GitHub Pages는 커스텀 응답 헤더 설정 불가 → `patched-index.html`(메타 가능 항목) 적용 또는 Cloudflare/Netlify/Vercel 이전 후 헤더 파일 사용.
- 익명 방문자는 **완료된** 진단 이력만 열람 가능(RLS). 진단/조치 실행은 로그인 필수.

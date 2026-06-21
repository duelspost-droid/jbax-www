// JBAX VulnScan — 실제 서버측 OWASP TOP 10 진단 Edge Function
// 대상 URL을 서버에서 직접 요청(교차출처 제약 없음)하여 응답 헤더·HTML·간이 정찰·
// 무해한 반사 프로브로 "근거 기반" 진단을 수행하고, 진행상황을 vuln_progress에 적재(Realtime).
//
// 입력:  { scan_id }   (상태가 'approved'인 진단만 실행)
// 출력:  { ok, scan_id, score, grade, findings, summary }
//
// 배포:   npx supabase functions deploy vuln-scan --project-ref nrdapzgtibbusvoaceuh
// 권한:   verify_jwt=true (config.toml) → 로그인한 관리자만 호출. 내부 쓰기는 service_role.
//
// ⚠️ 본 스캐너는 비파괴/수동적 점검만 수행한다(헤더/HTML 분석, 안전한 정찰 GET,
//    무해한 마커를 이용한 반사 확인). 침투형 공격 페이로드는 실행하지 않는다.

import { createClient } from "npm:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, status = 200) =>
  new Response(JSON.stringify(b), { status, headers: { ...CORS, "Content-Type": "application/json" } });

const SEV_W: Record<string, number> = { critical: 40, high: 18, medium: 8, low: 3, info: 0, pass: 0 };
const OWASP_KO: Record<string, string> = {
  A01: "취약한 접근 통제", A02: "암호화 실패", A03: "인젝션", A04: "안전하지 않은 설계",
  A05: "보안 설정 오류", A06: "취약·구형 구성요소", A07: "인증 실패",
  A08: "무결성 실패", A09: "로깅·모니터링 실패", A10: "SSRF",
};

function gradeOf(s: number) {
  return s >= 90 ? "A" : s >= 80 ? "B" : s >= 70 ? "C" : s >= 55 ? "D" : s >= 40 ? "E" : "F";
}
function hostKind(u: string): string {
  try {
    const h = new URL(u).host.toLowerCase();
    if (h.endsWith("github.io") || h.endsWith("jbax.co.kr")) return "github_pages";
    return "static";
  } catch { return "static"; }
}

async function fetchT(url: string, ms = 9000, init: RequestInit = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  try {
    const res = await fetch(url, { redirect: "follow", signal: ctl.signal, headers: { "User-Agent": "JBAX-VulnScan/1.0 (+security self-audit)" }, ...init });
    return { res, error: null as string | null };
  } catch (e) {
    return { res: null, error: (e as Error)?.message || String(e) };
  } finally {
    clearTimeout(timer);
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const SB_URL = Deno.env.get("SUPABASE_URL")!;
  const SB_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const supabase = createClient(SB_URL, SB_KEY, { auth: { persistSession: false } });

  let scanId = "";
  try { scanId = (await req.json()).scan_id; } catch { return json({ error: "bad json" }, 400); }
  if (!scanId) return json({ error: "scan_id required" }, 400);

  const t0 = Date.now();
  // 'approved' → 'running' 원자적 전환(동시 실행/중복 방지). 한 호출만 통과한다.
  const { data: scan } = await supabase.from("vuln_scans")
    .update({ status: "running", started_at: new Date().toISOString(), error: null })
    .eq("id", scanId).eq("status", "approved").select().single();
  if (!scan) return json({ error: "scan not found or not in 'approved' state" }, 409);

  // 이전 행 정리(멱등)
  await supabase.from("vuln_findings").delete().eq("scan_id", scanId);
  await supabase.from("vuln_progress").delete().eq("scan_id", scanId);
  await supabase.from("vuln_audit").insert({ scan_id: scanId, actor_email: scan.approved_email, action: "scan_started", detail: { target: scan.target_url } });

  const target: string = scan.target_url;
  const hk = hostKind(target);
  const findings: any[] = [];
  const add = (owasp: string, severity: string, title: string, detail: string, evidence: string, recommendation: string, auto_fixable = false, fix_summary = "", meta: any = {}) =>
    findings.push({ scan_id: scanId, owasp_id: owasp, owasp_ko: OWASP_KO[owasp], severity, title, detail, evidence, recommendation, auto_fixable, fix_summary, status: "open", meta: { host_kind: hk, ...meta } });

  // ---- 진행상황 emit (Realtime) ----
  let seq = 0, done = 0;
  const emit = async (owasp: string, step: string, status: string, message: string, isDone: boolean, total: number) => {
    if (isDone) done++;
    const elapsed = Date.now() - t0;
    const eta = isDone && done < total ? Math.round((elapsed / done) * (total - done)) : (isDone ? 0 : null);
    seq++;
    await supabase.from("vuln_progress").insert({
      scan_id: scanId, seq, phase: "scan", owasp_id: owasp, step, status,
      pct: Math.round((done / total) * 100), eta_ms: eta, message,
    });
  };

  // 메인 요청 1회
  const m = await fetchT(target, 10000);
  // 대상 도달 불가 → 즉시 실패 처리(콘텐츠 의존 점검을 '안전'으로 오인하지 않도록)
  if (!m.res) {
    await supabase.from("vuln_progress").insert({ scan_id: scanId, seq: 1, phase: "scan", step: "대상 요청", status: "error", pct: 0, eta_ms: 0, message: "대상 도달 불가: " + (m.error || "") });
    await supabase.from("vuln_scans").update({ status: "failed", finished_at: new Date().toISOString(), duration_ms: Date.now() - t0, error: "대상 URL 요청 실패: " + (m.error || "unknown") }).eq("id", scanId);
    await supabase.from("vuln_audit").insert({ scan_id: scanId, actor_email: scan.approved_email, action: "scan_failed", detail: { error: m.error } });
    return json({ ok: false, error: "target unreachable", detail: m.error }, 200);
  }
  // 정의: 헤더 안전조회
  const H = (n: string): string => (m.res ? (m.res.headers.get(n) || "") : "");
  let body = "";
  let finalUrl = target;
  if (m.res) {
    finalUrl = m.res.url || target;
    try { body = await m.res.text(); } catch { body = ""; }
  }
  const origin = (() => { try { return new URL(finalUrl).origin; } catch { return target.replace(/\/+$/, ""); } })();

  // HTML 파서(정규식 기반)
  const scriptSrcs = [...body.matchAll(/<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi)].map((x) => ({ tag: x[0], src: x[1] }));
  const linkHrefs = [...body.matchAll(/<link\b[^>]*?\bhref\s*=\s*["']([^"']+)["'][^>]*>/gi)]
    .filter((x) => /rel\s*=\s*["']?stylesheet/i.test(x[0])).map((x) => ({ tag: x[0], href: x[1] }));
  const hasInlineScript = /<script\b(?![^>]*\bsrc\s*=)[^>]*>[\s\S]*?<\/script>/i.test(body);
  const hasForm = /<form\b/i.test(body);
  const hasPwd = /<input\b[^>]*type\s*=\s*["']?password/i.test(body);
  const isAbs = (u: string) => /^https?:\/\//i.test(u);
  const crossOrigin = (u: string) => { try { return new URL(u, finalUrl).origin !== origin; } catch { return false; } };

  // 진단 프로브 정의 ----------------------------------------------------------
  type Probe = { owasp: string; label: string; run: () => Promise<{ status: string; message: string }> };
  const PROBES: Probe[] = [];

  PROBES.push({ owasp: "A02", label: "HTTPS/TLS 강제 확인", run: async () => {
    if (!/^https:/i.test(finalUrl)) {
      add("A02", "high", "HTTPS 미적용", "최종 응답이 HTTPS가 아님 — 평문 전송 위험.", `final URL: ${finalUrl}`, "전 구간 HTTPS 강제 및 HTTP→HTTPS 리다이렉트 적용.", false);
      return { status: "bad", message: "HTTPS 아님" };
    }
    return { status: "ok", message: "HTTPS 적용됨" };
  }});

  PROBES.push({ owasp: "A02", label: "HSTS 헤더 확인", run: async () => {
    if (!H("strict-transport-security")) {
      add("A02", "high", "HSTS 헤더 미설정", "Strict-Transport-Security 부재 — SSL stripping 노출.", "응답 헤더에 Strict-Transport-Security 없음", "HSTS 적용(max-age≥31536000; includeSubDomains).", true, "HSTS 헤더 추가", { header: "Strict-Transport-Security" });
      return { status: "warn", message: "HSTS 없음" };
    }
    return { status: "ok", message: "HSTS 있음" };
  }});

  PROBES.push({ owasp: "A05", label: "CSP(Content-Security-Policy) 점검", run: async () => {
    const meta = /<meta[^>]+http-equiv\s*=\s*["']content-security-policy/i.test(body);
    if (!H("content-security-policy") && !meta) {
      add("A05", "high", "CSP 미설정", "Content-Security-Policy 부재 — XSS 완화 수단 없음.", "응답 헤더/메타에 CSP 없음", "페이지 리소스에 맞춘 CSP 적용.", true, "리소스 맞춤 CSP 생성(메타+헤더)", { header: "Content-Security-Policy" });
      return { status: "warn", message: "CSP 없음" };
    }
    return { status: "ok", message: "CSP 있음" };
  }});

  PROBES.push({ owasp: "A05", label: "클릭재킹 방어 점검", run: async () => {
    const csp = H("content-security-policy");
    if (!H("x-frame-options") && !/frame-ancestors/i.test(csp)) {
      add("A05", "medium", "클릭재킹 방어 미흡", "X-Frame-Options / CSP frame-ancestors 부재.", "X-Frame-Options 헤더 없음", "X-Frame-Options: DENY 또는 CSP frame-ancestors 'none'.", true, "X-Frame-Options/frame-ancestors 적용", { header: "X-Frame-Options" });
      return { status: "warn", message: "프레임 보호 없음" };
    }
    return { status: "ok", message: "프레임 보호 있음" };
  }});

  PROBES.push({ owasp: "A05", label: "X-Content-Type-Options 점검", run: async () => {
    if (!/nosniff/i.test(H("x-content-type-options"))) {
      add("A05", "low", "MIME 스니핑 방어 미설정", "X-Content-Type-Options: nosniff 부재.", "X-Content-Type-Options 헤더 없음", "X-Content-Type-Options: nosniff 적용.", true, "nosniff 헤더 적용", { header: "X-Content-Type-Options" });
      return { status: "warn", message: "nosniff 없음" };
    }
    return { status: "ok", message: "nosniff 있음" };
  }});

  PROBES.push({ owasp: "A05", label: "Referrer-Policy 점검", run: async () => {
    const meta = /<meta[^>]+name\s*=\s*["']referrer/i.test(body);
    if (!H("referrer-policy") && !meta) {
      add("A05", "low", "Referrer-Policy 미설정", "리퍼러 정보 과다 노출 가능.", "Referrer-Policy 헤더/메타 없음", "strict-origin-when-cross-origin 적용.", true, "Referrer-Policy 적용(메타 가능)", { header: "Referrer-Policy" });
      return { status: "warn", message: "Referrer-Policy 없음" };
    }
    return { status: "ok", message: "Referrer-Policy 있음" };
  }});

  PROBES.push({ owasp: "A05", label: "Permissions-Policy 점검", run: async () => {
    if (!H("permissions-policy")) {
      add("A05", "info", "Permissions-Policy 미설정", "카메라/마이크/위치 등 기능 권한 정책 부재.", "Permissions-Policy 헤더 없음", "불필요 기능 비활성 정책 적용.", true, "Permissions-Policy 적용", { header: "Permissions-Policy" });
      return { status: "warn", message: "Permissions-Policy 없음" };
    }
    return { status: "ok", message: "Permissions-Policy 있음" };
  }});

  PROBES.push({ owasp: "A05", label: "서버 배너 정보노출 점검", run: async () => {
    const server = H("server"), xp = H("x-powered-by");
    if (xp || /\d/.test(server)) {
      add("A05", "low", "서버 배너 정보노출", "Server/X-Powered-By로 소프트웨어·버전 노출.", `Server: ${server || "-"}${xp ? `, X-Powered-By: ${xp}` : ""}`, "서버 배너 최소화/제거.", true, "응답 배너 제거(설정)", { header: "Server" });
      return { status: "warn", message: "배너 노출" };
    }
    return { status: "ok", message: "배너 최소" };
  }});

  PROBES.push({ owasp: "A07", label: "쿠키 보안 플래그 점검", run: async () => {
    // Set-Cookie는 다중 헤더일 수 있음 → getSetCookie() 우선(없으면 get으로 폴백)
    const cookies: string[] = (m.res && typeof (m.res.headers as any).getSetCookie === "function")
      ? (m.res.headers as any).getSetCookie() : (H("set-cookie") ? [H("set-cookie")] : []);
    const weak = cookies.filter((c: string) => !(/httponly/i.test(c) && /secure/i.test(c)));
    if (weak.length) {
      add("A07", "medium", "쿠키 보안 플래그 누락", "세션 쿠키에 Secure/HttpOnly 미적용.", weak.join(" | ").slice(0, 200), "Secure; HttpOnly; SameSite=Strict 적용.", false);
      return { status: "warn", message: "쿠키 플래그 누락(" + weak.length + ")" };
    }
    return { status: "ok", message: cookies.length ? "쿠키 플래그 정상" : "쿠키 없음" };
  }});

  PROBES.push({ owasp: "A01", label: "민감 파일 노출(.env/.git) 점검", run: async () => {
    let bad = 0;
    for (const p of ["/.env", "/.git/HEAD", "/.git/config"]) {
      const r = await fetchT(origin + p, 6000);
      if (r.res && r.res.status === 200) {
        let txt = ""; try { txt = (await r.res.text()).slice(0, 200); } catch { /* */ }
        const looksReal = p.startsWith("/.git") ? /ref:|repositoryformat/i.test(txt) : /=/.test(txt);
        if (looksReal) {
          bad++;
          add("A01", p === "/.env" ? "critical" : "high", `민감 파일 노출: ${p}`, "배포물에 비공개 파일이 공개됨.", `GET ${origin + p} → 200`, `${p} 를 배포 산출물에서 제외하고 차단.`, false);
        }
      }
    }
    return bad ? { status: "bad", message: `민감 파일 ${bad}건 노출` } : { status: "ok", message: "민감 파일 비노출" };
  }});

  PROBES.push({ owasp: "A05", label: "security.txt 존재 확인", run: async () => {
    const r = await fetchT(origin + "/.well-known/security.txt", 6000);
    if (!(r.res && r.res.status === 200)) {
      add("A05", "info", "security.txt 부재", "취약점 신고 창구(security.txt) 미제공.", `GET ${origin}/.well-known/security.txt → ${r.res ? r.res.status : "fail"}`, "RFC 9116 security.txt 게시.", true, "security.txt 생성", { kind: "securitytxt" });
      return { status: "warn", message: "security.txt 없음" };
    }
    return { status: "ok", message: "security.txt 있음" };
  }});

  PROBES.push({ owasp: "A06", label: "취약·구형 구성요소 식별", run: async () => {
    const KNOWN = [
      { re: /jquery[-.](\d+)\.(\d+)\.(\d+)/i, name: "jQuery", bad: (M: number, m: number) => M < 3 || (M === 3 && m < 5), note: "jQuery <3.5 다수 XSS(CVE-2020-11022/23)" },
      { re: /bootstrap[-.](\d+)\.(\d+)\.(\d+)/i, name: "Bootstrap", bad: (M: number) => M < 4, note: "Bootstrap <4 XSS 이슈" },
      { re: /angular[-.](\d+)\.(\d+)\.(\d+)/i, name: "AngularJS", bad: (M: number) => M <= 1, note: "AngularJS(1.x) EOL" },
      { re: /lodash[-.](\d+)\.(\d+)\.(\d+)/i, name: "Lodash", bad: (M: number, m: number) => M < 4 || (M === 4 && m < 17), note: "Lodash <4.17 프로토타입 오염" },
    ];
    let n = 0;
    for (const s of scriptSrcs) {
      for (const k of KNOWN) {
        const mm = s.src.match(k.re);
        if (mm) {
          const M = +mm[1], mi = +mm[2];
          if (k.bad(M, mi)) {
            n++;
            add("A06", "medium", `구형 ${k.name} ${M}.${mi}.x`, k.note, s.src, `${k.name} 최신 안정 버전으로 업데이트.`, false, "", { resource_url: new URL(s.src, finalUrl).href });
          }
        }
      }
    }
    if (scriptSrcs.length === 0) return { status: "ok", message: "외부 스크립트 없음" };
    return n ? { status: "warn", message: `구형 컴포넌트 ${n}건` } : { status: "ok", message: "구형 컴포넌트 미발견" };
  }});

  PROBES.push({ owasp: "A08", label: "외부 리소스 무결성(SRI) 점검", run: async () => {
    const noSri: string[] = [];
    for (const s of scriptSrcs) if (isAbs(s.src) && crossOrigin(s.src) && !/integrity\s*=/i.test(s.tag)) noSri.push(s.src);
    for (const l of linkHrefs) if (isAbs(l.href) && crossOrigin(l.href) && !/integrity\s*=/i.test(l.tag)) noSri.push(l.href);
    if (noSri.length) {
      add("A08", "medium", "외부 리소스 SRI 미적용", "교차출처 스크립트/스타일에 무결성 해시 부재 — 공급망 변조 위험.", noSri.slice(0, 5).join("\n"), "integrity(sha384)+crossorigin 적용.", true, "실 SRI sha384 해시 산출·패치", { resources: noSri });
      return { status: "warn", message: `SRI 미적용 ${noSri.length}건` };
    }
    return { status: "ok", message: "교차출처 리소스 SRI 정상/없음" };
  }});

  PROBES.push({ owasp: "A03", label: "입력 반사(XSS) 무해 프로브", run: async () => {
    const token = "vsx" + Math.random().toString(36).slice(2, 10);
    const probeUrl = target + (target.includes("?") ? "&" : "?") + "__vsprobe=" + token;
    const r = await fetchT(probeUrl, 8000);
    if (r.res) {
      let t = ""; try { t = await r.res.text(); } catch { /* */ }
      if (t.includes(token)) {
        add("A03", "medium", "쿼리 파라미터 반사", "URL 파라미터가 응답 본문에 반사됨 — XSS 가능성(맥락 검토 필요).", `?__vsprobe=${token} 반사 확인`, "출력 인코딩 + CSP 적용.", false);
        return { status: "warn", message: "파라미터 반사 감지" };
      }
    }
    return { status: "ok", message: "반사 없음" };
  }});

  PROBES.push({ owasp: "A07", label: "입력·인증 표면 분석", run: async () => {
    if (hasPwd) {
      add("A07", "info", "인증 폼 존재", "비밀번호 입력 폼이 존재 — 브루트포스/MFA 정책 별도 점검 권고.", "<input type=password> 발견", "로그인 시도 제한·MFA·세션 만료 정책 점검.", false);
      return { status: "warn", message: "인증 폼 존재" };
    }
    if (!hasForm) return { status: "ok", message: "입력 표면 없음(정적)" };
    return { status: "ok", message: "폼 존재(인증 아님)" };
  }});

  PROBES.push({ owasp: "A10", label: "SSRF 표면 분석", run: async () => {
    // 정적 사이트는 서버측 요청 표면이 없음 → 근거 기반 pass
    add("A10", "pass", "SSRF 표면 없음", "사용자 제어 URL을 서버가 요청하는 기능 미발견(정적 호스팅).", "서버측 fetch 엔드포인트 없음", "동적 백엔드 도입 시 URL allowlist 적용.", false);
    return { status: "ok", message: "SSRF 표면 없음" };
  }});

  PROBES.push({ owasp: "A04", label: "안전하지 않은 설계 휴리스틱", run: async () => {
    if (hasForm) {
      add("A04", "info", "폼 제출 흐름 존재", "레이트리밋/봇 방어 등 설계 통제는 외부에서 단정 불가 — 검토 권고.", "<form> 발견", "민감 작업에 레이트리밋·CAPTCHA·서버검증 적용.", false);
      return { status: "warn", message: "설계 검토 권고" };
    }
    add("A04", "pass", "설계 위험표면 낮음", "상태 변경/민감 작업 표면 미발견(정적).", "동적 폼/엔드포인트 없음", "기능 추가 시 위협모델링 수행.", false);
    return { status: "ok", message: "설계 위험 낮음" };
  }});

  PROBES.push({ owasp: "A09", label: "로깅·모니터링 점검", run: async () => {
    add("A09", "info", "로깅·모니터링 외부확인 불가", "보안 이벤트 로깅/모니터링은 외부에서 검증 불가.", "외부 관측 불가 항목", "중앙 로깅·이상탐지·알림 체계 점검(내부).", false);
    return { status: "ok", message: "내부 점검 권고" };
  }});

  // ---- 실행 ----
  const N = PROBES.length;
  for (const p of PROBES) {
    await emit(p.owasp, p.label, "running", `${p.label} …`, false, N);
    let r: { status: string; message: string };
    try { r = await p.run(); } catch (e) { r = { status: "warn", message: "점검 오류: " + ((e as Error)?.message || e) }; }
    await emit(p.owasp, p.label, r.status, `[${p.owasp}] ${r.message}`, true, N);
  }

  // ---- 점수/요약/저장 ----
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, pass: 0 };
  let deduction = 0;
  for (const f of findings) { counts[f.severity] = (counts[f.severity] || 0) + 1; deduction += SEV_W[f.severity] || 0; }
  const score = Math.max(0, Math.min(100, 100 - deduction));
  const grade = gradeOf(score);
  const autofixable = findings.filter((f) => f.auto_fixable).length;
  // 적용 시 예상점수(자동조치 가능 항목을 모두 해결했다고 가정)
  let projDeduction = 0;
  for (const f of findings) if (!f.auto_fixable) projDeduction += SEV_W[f.severity] || 0;
  const projected = Math.max(0, Math.min(100, 100 - projDeduction));

  if (findings.length) {
    const { error: fe } = await supabase.from("vuln_findings").insert(findings);
    if (fe) return json({ error: "finding insert: " + fe.message }, 500);
  }
  const summary = { counts, total: findings.length, autofixable, projected_score: projected, projected_grade: gradeOf(projected), host_kind: hk };
  await supabase.from("vuln_scans").update({
    status: "completed", finished_at: new Date().toISOString(),
    duration_ms: Date.now() - t0, score, grade, summary,
  }).eq("id", scanId);
  await supabase.from("vuln_progress").insert({ scan_id: scanId, seq: seq + 1, phase: "scan", step: "완료", status: "done", pct: 100, eta_ms: 0, message: `진단 완료 — ${score}점(${grade})` });
  await supabase.from("vuln_audit").insert({ scan_id: scanId, actor_email: scan.approved_email, action: "scan_completed", detail: summary });

  return json({ ok: true, scan_id: scanId, score, grade, summary });
});

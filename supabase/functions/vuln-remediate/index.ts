// JBAX VulnScan — 자동 조치(remediation) 산출물 생성 Edge Function
// 진단 결과의 자동조치 가능 항목에 대해 "실제로 적용 가능한" 산출물을 생성한다:
//   · 페이지 리소스 기반 CSP 정책
//   · _headers(Netlify/CF Pages) / netlify.toml / vercel.json / nginx 보안헤더 스니펫
//   · 교차출처 리소스의 실제 SRI sha384 해시를 계산해 패치한 HTML
//   · security.txt
//   · REMEDIATION.md (적용 가이드 · GitHub Pages 제약 명시)
// 산출물은 Storage(vuln-fixes)에 저장하고 서명 URL을 반환한다. (라이브 자동 적용은 하지 않음)
// 진행상황은 vuln_progress(phase='remediate')에 적재하여 Realtime으로 상세 표시한다.
//
// 입력:  { scan_id, finding_ids?:[] }
// 출력:  { ok, artifacts:[{name,url,bytes}], tickets, projected_score, projected_grade }
//
// 배포:  npx supabase functions deploy vuln-remediate --project-ref nrdapzgtibbusvoaceuh
// 권한:  verify_jwt=true → 로그인 관리자만. 내부 쓰기는 service_role.

import { createClient } from "npm:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, status = 200) =>
  new Response(JSON.stringify(b), { status, headers: { ...CORS, "Content-Type": "application/json" } });

const SEV_W: Record<string, number> = { critical: 40, high: 18, medium: 8, low: 3, info: 0, pass: 0 };
const gradeOf = (s: number) => (s >= 90 ? "A" : s >= 80 ? "B" : s >= 70 ? "C" : s >= 55 ? "D" : s >= 40 ? "E" : "F");

async function fetchT(url: string, ms = 9000) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  try { return { res: await fetch(url, { redirect: "follow", signal: ctl.signal }), error: null as string | null }; }
  catch (e) { return { res: null, error: (e as Error)?.message || String(e) }; }
  finally { clearTimeout(timer); }
}

async function sri384(url: string): Promise<string | null> {
  const r = await fetchT(url, 9000);
  if (!r.res || !r.res.ok) return null;
  const buf = await r.res.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-384", buf);
  const bytes = new Uint8Array(digest);
  let bin = ""; for (const b of bytes) bin += String.fromCharCode(b);
  return "sha384-" + btoa(bin);
}

function synthCSP(html: string, finalUrl: string): string {
  const scriptO = new Set<string>(), styleO = new Set<string>(), imgO = new Set<string>(), fontO = new Set<string>();
  const addTo = (set: Set<string>, u: string) => { try { const o = new URL(u, finalUrl); if (o.protocol.startsWith("http")) set.add(o.origin); } catch { /* */ } };
  for (const m of html.matchAll(/<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']/gi)) addTo(scriptO, m[1]);
  for (const m of html.matchAll(/<link\b[^>]*?\bhref\s*=\s*["']([^"']+)["']/gi)) if (/stylesheet/i.test(m[0])) addTo(styleO, m[1]);
  for (const m of html.matchAll(/<img\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']/gi)) addTo(imgO, m[1]);
  for (const m of html.matchAll(/url\(\s*["']?([^"')]+)["']?\s*\)/gi)) if (/\.(woff2?|ttf|otf|eot)/i.test(m[1])) addTo(fontO, m[1]);
  const inlineScript = /<script\b(?![^>]*\bsrc\s*=)[^>]*>[\s\S]*?<\/script>/i.test(html);
  const j = (s: Set<string>) => [...s].join(" ");
  const dirs = [
    `default-src 'self'`,
    `script-src 'self'${scriptO.size ? " " + j(scriptO) : ""}${inlineScript ? " 'unsafe-inline'" : ""}`,
    `style-src 'self' 'unsafe-inline'${styleO.size ? " " + j(styleO) : ""}`,
    `img-src 'self' data:${imgO.size ? " " + j(imgO) : ""}`,
    `font-src 'self' data:${fontO.size ? " " + j(fontO) : ""}`,
    `connect-src 'self' https://*.supabase.co`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `frame-ancestors 'none'`,
    `upgrade-insecure-requests`,
  ];
  return dirs.join("; ");
}

const escAttr = (s: string) => s.replace(/"/g, "&quot;");

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });

  let email = "";
  try {
    // JWT 페이로드는 base64url → 표준 base64로 변환 후 디코딩(atob는 base64url 미지원)
    const tok = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").split(".")[1] || "";
    let b64 = tok.replace(/-/g, "+").replace(/_/g, "/");
    b64 = b64.padEnd(b64.length + (4 - (b64.length % 4)) % 4, "=");
    email = JSON.parse(atob(b64))?.email || "";
  } catch { /* */ }

  let scanId = "", findingIds: string[] | undefined;
  try { const b = await req.json(); scanId = b.scan_id; findingIds = b.finding_ids; } catch { return json({ error: "bad json" }, 400); }
  if (!scanId) return json({ error: "scan_id required" }, 400);

  const { data: scan } = await supabase.from("vuln_scans").select("*").eq("id", scanId).single();
  if (!scan) return json({ error: "scan not found" }, 404);
  if (scan.status !== "completed") return json({ error: "scan not completed" }, 409);

  let q = supabase.from("vuln_findings").select("*").eq("scan_id", scanId);
  if (Array.isArray(findingIds) && findingIds.length) q = q.in("id", findingIds);
  const { data: allFindings } = await q;
  const findings = allFindings || [];
  const autoF = findings.filter((f) => f.auto_fixable && ["open", "remediation_generated"].includes(f.status));
  const manualF = findings.filter((f) => !f.auto_fixable && f.severity !== "pass" && f.severity !== "info" && f.status === "open");

  const sriResources = [...new Set(autoF.filter((f) => f.owasp_id === "A08" && Array.isArray(f.meta?.resources)).flatMap((f) => f.meta.resources as string[]))];

  await supabase.from("vuln_audit").insert({ scan_id: scanId, actor_email: email, action: "remediate_started", detail: { auto: autoF.length, manual: manualF.length } });
  // 이전 조치 진행로그 정리(재실행 대비)
  await supabase.from("vuln_progress").delete().eq("scan_id", scanId).eq("phase", "remediate");

  // ---- 진행상황 emit ----
  const steps = ["대상 HTML 재수집", "CSP 정책 합성", "보안 헤더 산출물 생성",
    ...sriResources.map((u) => `SRI 해시 계산: ${u.replace(/^https?:\/\//, "").slice(0, 40)}`),
    "HTML 패치 생성", "Storage 업로드", "검증·서명 URL 발급"];
  const N = steps.length;
  const t0 = Date.now();
  let seq = 1000, done = 0;
  const emit = async (step: string, status: string, message: string, isDone: boolean) => {
    if (isDone) done++;
    const elapsed = Date.now() - t0;
    const eta = isDone && done < N ? Math.round((elapsed / done) * (N - done)) : (isDone ? 0 : null);
    seq++;
    await supabase.from("vuln_progress").insert({ scan_id: scanId, seq, phase: "remediate", step, status, pct: Math.round((done / N) * 100), eta_ms: eta, message });
  };

  // 1) HTML 재수집
  await emit(steps[0], "running", "대상 HTML 재수집 …", false);
  const mr = await fetchT(scan.target_url, 10000);
  let html = ""; let finalUrl = scan.target_url;
  if (mr.res) { finalUrl = mr.res.url || scan.target_url; try { html = await mr.res.text(); } catch { /* */ } }
  const isGh = scan.summary?.host_kind === "github_pages";
  await emit(steps[0], html ? "ok" : "warn", html ? `HTML ${html.length}바이트 수집` : "HTML 수집 실패(헤더 산출물만 생성)", true);

  // 2) CSP 합성
  await emit(steps[1], "running", "리소스 기반 CSP 합성 …", false);
  const csp = html ? synthCSP(html, finalUrl) : "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests";
  await emit(steps[1], "ok", "CSP 정책 합성 완료", true);

  // 3) 헤더 산출물
  await emit(steps[2], "running", "보안 헤더 파일 생성 …", false);
  const HEADERS: Record<string, string> = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": csp,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), browsing-topics=()",
    "Cross-Origin-Opener-Policy": "same-origin",
  };
  const files: { name: string; body: string; ct: string }[] = [];
  files.push({ name: "_headers", ct: "text/plain; charset=utf-8", body: "/*\n" + Object.entries(HEADERS).map(([k, v]) => `  ${k}: ${v}`).join("\n") + "\n" });
  files.push({ name: "netlify.toml", ct: "text/plain; charset=utf-8", body: `[[headers]]\n  for = "/*"\n  [headers.values]\n` + Object.entries(HEADERS).map(([k, v]) => `    ${k} = "${v.replace(/"/g, '\\"')}"`).join("\n") + "\n" });
  files.push({ name: "vercel.json", ct: "application/json; charset=utf-8", body: JSON.stringify({ headers: [{ source: "/(.*)", headers: Object.entries(HEADERS).map(([key, value]) => ({ key, value })) }] }, null, 2) });
  files.push({ name: "nginx-security.conf", ct: "text/plain; charset=utf-8", body: Object.entries(HEADERS).map(([k, v]) => `add_header ${k} "${v.replace(/"/g, '\\"')}" always;`).join("\n") + "\n" });
  files.push({ name: "csp-meta.html", ct: "text/html; charset=utf-8", body: `<!-- <head>에 삽입 (frame-ancestors/HSTS 등 일부 지시문은 메타에서 무시됨 → 헤더 권장) -->\n<meta http-equiv="Content-Security-Policy" content="${escAttr(csp)}">\n` });
  const wantSecTxt = autoF.some((f) => f.meta?.kind === "securitytxt");
  if (wantSecTxt) {
    const exp = new Date(Date.now() + 365 * 864e5).toISOString().replace(/\.\d+Z$/, "Z");
    files.push({ name: "security.txt", ct: "text/plain; charset=utf-8", body: `Contact: mailto:duels@jbfg.com\nExpires: ${exp}\nPreferred-Languages: ko, en\n# 배포 위치: /.well-known/security.txt\n` });
  }
  await emit(steps[2], "ok", `헤더 산출물 ${files.length}종 생성`, true);

  // 4) SRI 해시(자원별)
  const sriApplied: { url: string; integrity: string }[] = [];
  for (let i = 0; i < sriResources.length; i++) {
    const stepName = steps[3 + i];
    await emit(stepName, "running", "무결성 해시 계산 …", false);
    const url = sriResources[i];
    const abs = (() => { try { return new URL(url, finalUrl).href; } catch { return url; } })();
    const integrity = await sri384(abs);
    if (integrity) sriApplied.push({ url: abs, integrity });
    await emit(stepName, integrity ? "ok" : "warn", integrity ? integrity.slice(0, 24) + "…" : "해시 계산 실패", true);
  }

  // 5) HTML 패치
  const idxPatch = 3 + sriResources.length;
  await emit(steps[idxPatch], "running", "보안 메타 + SRI 패치 …", false);
  let patched = html;
  if (patched) {
    const metas: string[] = [];
    if (!/http-equiv\s*=\s*["']content-security-policy/i.test(patched)) metas.push(`  <meta http-equiv="Content-Security-Policy" content="${escAttr(csp)}">`);
    if (!/name\s*=\s*["']referrer/i.test(patched)) metas.push(`  <meta name="referrer" content="strict-origin-when-cross-origin">`);
    if (metas.length) {
      const block = `\n  <!-- JBAX VulnScan 자동 조치: 보안 메타 -->\n${metas.join("\n")}\n`;
      patched = /<head[^>]*>/i.test(patched) ? patched.replace(/<head[^>]*>/i, (h) => h + block) : block + patched;
    }
    for (const s of sriApplied) {
      const orig = sriResources.find((u) => { try { return new URL(u, finalUrl).href === s.url; } catch { return u === s.url; } }) || s.url;
      const escd = orig.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      // head=태그~URL, mid=나머지 속성(async 등), end='>' 또는 '/>' — 어떤 속성 순서/자가닫힘도 안전 처리
      const re = new RegExp(`(<(?:script|link)\\b[^>]*?(?:src|href)\\s*=\\s*["']${escd}["'])([^>]*?)(\\s*/?>)`, "i");
      patched = patched.replace(re, (_m, head, mid, end) => (/integrity\s*=/i.test(head + mid) ? _m : `${head}${mid} integrity="${s.integrity}" crossorigin="anonymous"${end}`));
    }
    files.push({ name: "patched-index.html", ct: "text/html; charset=utf-8", body: patched });
  }
  await emit(steps[idxPatch], patched ? "ok" : "warn", patched ? "패치 HTML 생성" : "원본 HTML 없음 — 패치 생략", true);

  // REMEDIATION.md
  const mdLines = [
    `# JBAX VulnScan — 자동 조치 가이드`, ``,
    `- 대상: **${scan.target_name}** (${scan.target_url})`,
    `- 생성: ${new Date().toISOString()}`,
    `- 호스팅 추정: ${isGh ? "GitHub Pages (커스텀 응답 헤더 설정 불가)" : "정적/기타"}`, ``,
    `## 산출물`, `| 파일 | 용도 |`, `|---|---|`,
    `| \`_headers\` | Netlify / Cloudflare Pages 보안 헤더 |`,
    `| \`netlify.toml\` | Netlify 설정형 헤더 |`,
    `| \`vercel.json\` | Vercel 헤더 |`,
    `| \`nginx-security.conf\` | Nginx add_header 스니펫 |`,
    `| \`csp-meta.html\` | CSP 메타 태그 |`,
    patched ? `| \`patched-index.html\` | CSP/Referrer 메타 + 교차출처 SRI 적용본 |` : ``,
    wantSecTxt ? `| \`security.txt\` | /.well-known/security.txt 게시용 |` : ``, ``,
    `## 적용 방법`,
    isGh
      ? `> ⚠️ **GitHub Pages는 커스텀 응답 헤더를 설정할 수 없습니다.**\n> - 메타로 가능한 항목(CSP 대부분·Referrer)은 \`patched-index.html\`을 적용하세요.\n> - 헤더 전용 항목(HSTS·X-Frame-Options·X-Content-Type-Options 등)은 메타로 대체 불가합니다. 완전 적용하려면 Cloudflare Pages/Netlify/Vercel로 이전 후 위 헤더 파일을 쓰거나, Cloudflare Transform Rules로 헤더를 주입하세요.`
      : `> 호스팅에 맞는 헤더 파일을 배포에 포함하세요.`, ``,
    sriApplied.length ? `## 적용된 SRI\n` + sriApplied.map((s) => `- \`${s.url}\`\n  - \`${s.integrity}\``).join("\n") + "\n" : ``,
    `## 합성된 CSP`, "```", csp, "```",
  ].filter((x) => x !== ``);
  files.push({ name: "REMEDIATION.md", ct: "text/markdown; charset=utf-8", body: mdLines.join("\n") });

  // 6) 업로드
  await emit(steps[idxPatch + 1], "running", `${files.length}개 파일 업로드 …`, false);
  const stamp = Date.now();
  const artifacts: { name: string; url: string | null; bytes: number }[] = [];
  const remRows: any[] = [];
  for (const f of files) {
    const path = `${scanId}/${stamp}/${f.name}`;
    const bytes = new TextEncoder().encode(f.body);
    const up = await supabase.storage.from("vuln-fixes").upload(path, bytes, { contentType: f.ct, upsert: true });
    let signed: string | null = null;
    if (!up.error) { const s = await supabase.storage.from("vuln-fixes").createSignedUrl(path, 60 * 60 * 24); signed = s.data?.signedUrl || null; }
    artifacts.push({ name: f.name, url: signed, bytes: bytes.length });
    remRows.push({ scan_id: scanId, owasp_id: null, title: f.name, action: "산출물 생성", kind: "artifact", artifact_path: path, artifact_name: f.name, status: up.error ? "failed" : "generated", approved_email: email, approved_at: new Date().toISOString(), detail: { bytes: bytes.length } });
  }
  await emit(steps[idxPatch + 1], "ok", `업로드 완료 ${artifacts.length}개`, true);

  // 7) 검증/마무리
  await emit(steps[idxPatch + 2], "running", "조치안 기록 …", false);
  const tickets: { title: string; owasp: string }[] = [];
  for (const f of manualF) {
    remRows.push({ scan_id: scanId, finding_id: f.id, owasp_id: f.owasp_id, title: f.title, action: "수동 조치 권고", kind: "manual_ticket", status: "manual_ticket", approved_email: email, approved_at: new Date().toISOString(), detail: { recommendation: f.recommendation } });
    tickets.push({ title: f.title, owasp: f.owasp_id });
  }
  if (remRows.length) await supabase.from("vuln_remediations").insert(remRows);
  if (autoF.length) await supabase.from("vuln_findings").update({ status: "remediation_generated" }).in("id", autoF.map((f) => f.id));
  if (manualF.length) await supabase.from("vuln_findings").update({ status: "ticket" }).in("id", manualF.map((f) => f.id));

  let proj = 0;
  for (const f of findings) if (!(f.auto_fixable && ["open", "remediation_generated"].includes(f.status))) proj += SEV_W[f.severity] || 0;
  const projected = Math.max(0, Math.min(100, 100 - proj));
  const newSummary = { ...(scan.summary || {}), remediated_at: new Date().toISOString(), artifacts: artifacts.map((a) => a.name), manual_tickets: tickets.length, projected_score: projected, projected_grade: gradeOf(projected) };
  await supabase.from("vuln_scans").update({ summary: newSummary }).eq("id", scanId);
  await supabase.from("vuln_audit").insert({ scan_id: scanId, actor_email: email, action: "remediate_generated", detail: { artifacts: artifacts.length, tickets: tickets.length, projected } });
  await emit(steps[idxPatch + 2], "done", `조치안 ${artifacts.length}건 생성 · 적용 시 예상 ${projected}점(${gradeOf(projected)})`, true);

  return json({ ok: true, scan_id: scanId, artifacts, tickets, projected_score: projected, projected_grade: gradeOf(projected) });
});

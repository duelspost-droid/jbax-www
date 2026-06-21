/* JBAX 플레이그라운드 — AI 취약점 진단(VulnScan) 프런트엔드
 * Supabase 백엔드(secuday 프로젝트) 연동: 관리자 로그인 → 진단 요청/승인 → Edge Function 실행
 * → Realtime 진행(남은시간 ETA) → 결과 리포트 → 자동 조치(승인) → 산출물 다운로드 → 이력(전체 보존).
 * 익명 사용자는 '완료된' 진단 이력을 읽기 전용으로 열람 가능. */
(function () {
  "use strict";
  var cfg = window.JBAX_CONFIG;
  if (!cfg || !window.supabase) { console.error("VulnScan: supabase-js/config.js 미로딩"); return; }
  var sb = window.supabase.createClient(cfg.SUPABASE_URL, cfg.SUPABASE_ANON_KEY);

  /* ---------- 상수 ---------- */
  var TARGETS = [
    { id: "lunch",   name: "맛집 트래커",        sub: "여의도 JB빌딩 근처",     url: "https://lunch.jbax.co.kr/",                   emoji: "🍽️", color: "#1565c0" },
    { id: "data",    name: "외국인 금융 인사이트", sub: "국내 거주 외국인 데이터", url: "https://data.jbax.co.kr/",                    emoji: "📊", color: "#0891b2" },
    { id: "secuday", name: "정보보호의 날",       sub: "secuday · 보안 인식",    url: "https://secuday.jbax.co.kr/",                 emoji: "🛡️", color: "#155bff" },
    { id: "home",    name: "JBAX 브랜드 홈",      sub: "JB금융그룹 AX 혁신",     url: "https://duelspost-droid.github.io/jbax-home/", emoji: "⚡", color: "#00b8d9" },
    { id: "play",    name: "이 플레이그라운드",    sub: "현재 사이트",            url: location.origin + "/",                          emoji: "🧪", color: "#7c3aed" }
  ];
  var SEV = { critical: { label: "치명", w: 40 }, high: { label: "높음", w: 18 }, medium: { label: "보통", w: 8 }, low: { label: "낮음", w: 3 }, info: { label: "정보", w: 0 }, pass: { label: "양호", w: 0 } };
  var SEV_ORDER = ["critical", "high", "medium", "low", "info", "pass"];
  var OWASP = [
    { id: "A01", ko: "취약한 접근 통제" }, { id: "A02", ko: "암호화 실패" }, { id: "A03", ko: "인젝션" },
    { id: "A04", ko: "안전하지 않은 설계" }, { id: "A05", ko: "보안 설정 오류" }, { id: "A06", ko: "취약·구형 구성요소" },
    { id: "A07", ko: "인증 실패" }, { id: "A08", ko: "무결성 실패" }, { id: "A09", ko: "로깅·모니터링 실패" }, { id: "A10", ko: "SSRF" }
  ];

  /* ---------- 상태 ---------- */
  var session = null;
  var S = { target: null, scan: null, findings: [], fixResult: null, pendingTargetId: null };
  var chan = null, etaTimer = null, etaBase = null, startWall = 0, pollTimer = null, applied = {};

  /* ---------- 유틸 ---------- */
  function $(id) { return document.getElementById(id); }
  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }
  function pad(n) { return n < 10 ? "0" + n : "" + n; }
  function fmt(ms) { var s = Math.max(0, Math.round((ms || 0) / 1000)); return pad(Math.floor(s / 60)) + ":" + pad(s % 60); }
  function fmtDate(iso) { if (!iso) return ""; try { return new Date(iso).toLocaleString("ko-KR", { dateStyle: "short", timeStyle: "short" }); } catch (e) { return iso; } }
  function gradeOf(s) { return s >= 90 ? "A" : s >= 80 ? "B" : s >= 70 ? "C" : s >= 55 ? "D" : s >= 40 ? "E" : "F"; }
  function toast(msg, err) { var t = $("vsToast"); if (!t) { alert(msg); return; } t.textContent = msg; t.className = "vs-toast" + (err ? " err" : "") + " show"; clearTimeout(t._t); t._t = setTimeout(function () { t.className = "vs-toast"; }, 3400); }

  /* ---------- 뷰 ---------- */
  var VIEWS = ["login", "select", "approve", "progress", "report", "approvefix", "progressfix", "reportfix", "history"];
  function buildShellViews() {
    $("vsBody").innerHTML = VIEWS.map(function (v) { return '<section class="vs-view" id="vsView_' + v + '" style="display:none"></section>'; }).join("");
    if (!$("vsToast")) { var t = document.createElement("div"); t.id = "vsToast"; t.className = "vs-toast"; document.body.appendChild(t); }
  }
  function show(view) { VIEWS.forEach(function (v) { var n = $("vsView_" + v); if (n) n.style.display = v === view ? "block" : "none"; }); $("vsBody").scrollTop = 0; }
  function setStep(name) {
    var map = { login: "", select: "select", approve: "approve", progress: "scan", report: "report", approvefix: "fix", progressfix: "fix", reportfix: "fix", history: "" };
    var a = map[name];
    [].forEach.call(document.querySelectorAll("#vsStepper .vs-step"), function (s) { s.classList.toggle("on", s.getAttribute("data-step") === a); });
  }

  /* ---------- 인증 ---------- */
  function initAuth() {
    sb.auth.getSession().then(function (r) { session = r.data.session; renderAuthChip(); });
    sb.auth.onAuthStateChange(function (_e, s) { session = s; renderAuthChip(); });
  }
  function renderAuthChip() {
    var el = $("vsAuth"); if (!el) return;
    if (session) {
      el.innerHTML = '<span class="vs-authchip on">👤 ' + esc(session.user.email || "관리자") + ' <button type="button" id="vsLogout" class="vs-linkbtn">로그아웃</button></span>';
      $("vsLogout").addEventListener("click", function () { sb.auth.signOut().then(function () { toast("로그아웃되었습니다"); renderSelect(); }); });
    } else {
      el.innerHTML = '<button type="button" id="vsLoginBtn" class="vs-tab">🔑 관리자 로그인</button>';
      $("vsLoginBtn").addEventListener("click", function () { renderLogin(null); });
    }
  }
  function renderLogin(returnTo) {
    setStep("login");
    var c = $("vsView_login");
    c.innerHTML = '<div class="vs-gate">'
      + '<div class="vs-gate-ic">🔑</div><div class="vs-gate-t">관리자 로그인</div>'
      + '<div class="vs-gate-d">진단·승인·조치 실행은 로그인한 관리자만 가능합니다. (secuday와 동일 계정)</div>'
      + '<form id="vsLoginForm" class="vs-loginform">'
      + '<input class="vs-input" id="vsEmail" type="email" placeholder="이메일" required autocomplete="username">'
      + '<input class="vs-input" id="vsPw" type="password" placeholder="비밀번호" required autocomplete="current-password">'
      + '<div class="vs-actions"><button type="button" class="vs-btn ghost" id="vsLoginCancel">취소</button>'
      + '<button type="submit" class="vs-btn primary" id="vsLoginSubmit">로그인</button></div>'
      + '<p id="vsLoginErr" class="vs-loginerr" hidden></p></form></div>';
    show("login");
    $("vsLoginCancel").addEventListener("click", function () { renderSelect(); });
    $("vsLoginForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = $("vsLoginSubmit"); btn.disabled = true; btn.textContent = "로그인 중…";
      sb.auth.signInWithPassword({ email: $("vsEmail").value.trim(), password: $("vsPw").value }).then(function (r) {
        btn.disabled = false; btn.textContent = "로그인";
        if (r.error) { var p = $("vsLoginErr"); p.hidden = false; p.textContent = "로그인 실패: " + r.error.message; return; }
        session = r.data.session; renderAuthChip(); toast("로그인되었습니다");
        if (returnTo === "start" && S.pendingTargetId) { S.target = byId(S.pendingTargetId); S.pendingTargetId = null; requestScan(); }
        else renderSelect();
      });
    });
  }
  function byId(id) { return TARGETS.filter(function (t) { return t.id === id; })[0]; }

  /* ---------- ① 대상 선택 ---------- */
  function renderSelect() {
    setStep("select");
    var c = $("vsView_select"); var sel = null;
    c.innerHTML = '<div class="vs-disclaimer">ⓘ 실제 Supabase Edge Function이 대상 URL을 <b>서버에서 직접 점검</b>합니다(헤더·HTML·안전한 정찰·무해 반사 프로브). 침투형 공격은 수행하지 않으며, 본인 소유 자산만 진단하세요.</div>'
      + '<div class="vs-section-t">진단할 대상 페이지를 선택하세요</div>'
      + '<div class="vs-tgrid">' + TARGETS.map(function (t) {
        return '<button class="vs-tcard" data-tid="' + t.id + '" type="button">'
          + '<span class="vs-temoji" style="background:' + t.color + '22;border-color:' + t.color + '66">' + t.emoji + '</span>'
          + '<span class="vs-tmeta"><b>' + esc(t.name) + '</b><span>' + esc(t.sub) + '</span><span class="vs-turl">' + esc(t.url) + '</span></span>'
          + '<span class="vs-tcheck">✓</span></button>';
      }).join("") + '</div>'
      + '<div class="vs-actions"><button class="vs-btn ghost" id="vsToHistory" type="button">📜 이력 보기</button>'
      + '<button class="vs-btn primary" id="vsStartBtn" type="button" disabled>다음: 진단 승인 →</button></div>';
    [].forEach.call(c.querySelectorAll(".vs-tcard"), function (b) {
      b.addEventListener("click", function () { [].forEach.call(c.querySelectorAll(".vs-tcard"), function (x) { x.classList.remove("on"); }); b.classList.add("on"); sel = b.getAttribute("data-tid"); $("vsStartBtn").disabled = false; });
    });
    $("vsToHistory").addEventListener("click", renderHistory);
    $("vsStartBtn").addEventListener("click", function () {
      if (!sel) return;
      S.target = byId(sel); S.scan = null; S.findings = []; S.fixResult = null;
      if (!session) { S.pendingTargetId = sel; toast("관리자 로그인이 필요합니다"); renderLogin("start"); return; }
      requestScan();
    });
    show("select");
  }

  /* 진단 요청(pending) 생성 후 승인 화면 */
  function requestScan() {
    var t = S.target;
    sb.rpc("vuln_request_scan", { p_target_id: t.id, p_target_name: t.name, p_target_url: t.url }).then(function (r) {
      if (r.error) { toast("요청 실패: " + r.error.message, true); return; }
      S.scan = Array.isArray(r.data) ? r.data[0] : r.data;
      renderApprove();
    });
  }

  /* ---------- ② 진단 승인 ---------- */
  function renderApprove() {
    setStep("approve");
    var t = S.target;
    $("vsView_approve").innerHTML = '<div class="vs-gate">'
      + '<div class="vs-gate-ic">🔐</div><div class="vs-gate-t">진단 승인 필요</div>'
      + '<div class="vs-gate-d">아래 대상에 대해 <b>OWASP TOP 10 기준 서버측 진단</b>을 실행합니다. 승인해야 시작됩니다.</div>'
      + '<div class="vs-gate-box">'
      + '<div class="vs-kv"><span>대상</span><b>' + t.emoji + ' ' + esc(t.name) + '</b></div>'
      + '<div class="vs-kv"><span>URL</span><b>' + esc(t.url) + '</b></div>'
      + '<div class="vs-kv"><span>점검</span><b>OWASP A01~A10 · 18개 서버측 점검</b></div>'
      + '<div class="vs-kv"><span>요청자</span><b>' + esc((session && session.user.email) || "-") + '</b></div>'
      + '<div class="vs-kv"><span>방식</span><b>비파괴 수동점검(읽기) · 조치는 별도 승인</b></div></div>'
      + '<label class="vs-consent"><input type="checkbox" id="vsConsent"> 본인은 이 대상의 진단 권한이 있으며 진단 수행에 동의합니다.</label>'
      + '<div class="vs-actions"><button class="vs-btn ghost" id="vsBackSel" type="button">← 대상 변경</button>'
      + '<button class="vs-btn primary" id="vsApproveScan" type="button" disabled>승인하고 진단 시작 ▶</button></div></div>';
    show("approve");
    $("vsConsent").addEventListener("change", function (e) { $("vsApproveScan").disabled = !e.target.checked; });
    $("vsBackSel").addEventListener("click", renderSelect);
    $("vsApproveScan").addEventListener("click", function () {
      var btn = $("vsApproveScan"); btn.disabled = true; btn.textContent = "승인 중…";
      sb.rpc("vuln_approve_scan", { p_scan_id: S.scan.id }).then(function (r) {
        if (r.error) { toast("승인 실패: " + r.error.message, true); btn.disabled = false; btn.textContent = "승인하고 진단 시작 ▶"; return; }
        S.scan = Array.isArray(r.data) ? r.data[0] : r.data;
        startScan();
      });
    });
  }

  /* ---------- 진행 공통 ---------- */
  function progressShell(logTitle, withCats) {
    return '<div class="vs-prog-top">'
      + '<div class="vs-prog-target">' + S.target.emoji + ' <b>' + esc(S.target.name) + '</b><span>' + esc(S.target.url) + '</span></div>'
      + '<div class="vs-prog-stats"><div class="vs-stat"><span>경과</span><b id="vsElapsed">00:00</b></div>'
      + '<div class="vs-stat"><span>남은 시간</span><b id="vsRemain">≈ 계산중</b></div>'
      + '<div class="vs-stat big"><span id="vsPct">0%</span></div></div></div>'
      + '<div class="vs-barwrap"><div class="vs-bar" id="vsBar"></div></div>'
      + '<div class="vs-phaseline"><span class="vs-phase" id="vsPhase">준비</span><span class="vs-subphase" id="vsSub">초기화…</span></div>'
      + '<div class="vs-prog-cols' + (withCats ? '' : ' nocats') + '">'
      + (withCats ? '<div class="vs-cats" id="vsCatRows"></div>' : '')
      + '<div class="vs-logwrap"><div class="vs-logh">' + esc(logTitle) + '</div><div class="vs-log" id="vsLog"></div></div></div>'
      + '<div class="vs-actions"><button class="vs-btn ghost" id="vsBg" type="button">백그라운드로(이력에서 확인)</button></div>';
  }
  function appendLog(html) { var l = $("vsLog"); if (!l) return; var d = document.createElement("div"); d.className = "vs-logline"; d.innerHTML = html; l.appendChild(d); l.scrollTop = l.scrollHeight; }
  function startEta() {
    stopEta();
    etaTimer = setInterval(function () {
      if ($("vsElapsed")) $("vsElapsed").textContent = fmt(Date.now() - startWall);
      if (etaBase && $("vsRemain")) { var rem = Math.max(0, etaBase.ms - (Date.now() - etaBase.at)); $("vsRemain").textContent = "≈ " + fmt(rem); }
    }, 200);
  }
  function stopEta() { if (etaTimer) { clearInterval(etaTimer); etaTimer = null; } }
  function cleanup() { stopEta(); if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } if (chan) { try { sb.removeChannel(chan); } catch (e) { } chan = null; } applied = {}; }

  function applyProgress(r) {
    if (applied[r.seq]) return; applied[r.seq] = 1;
    if ($("vsBar")) $("vsBar").style.width = r.pct + "%";
    if ($("vsPct")) $("vsPct").textContent = Math.floor(r.pct) + "%";
    if (r.eta_ms != null) etaBase = { ms: r.eta_ms, at: Date.now() };
    if ($("vsPhase")) $("vsPhase").textContent = (r.owasp_id ? r.owasp_id + " · " : "") + (r.step || "");
    if ($("vsSub")) $("vsSub").textContent = r.message || "";
    if (r.owasp_id && $("vsCat_" + r.owasp_id)) {
      var st = $("vsCatSt_" + r.owasp_id), row = $("vsCat_" + r.owasp_id);
      var cls = r.status === "ok" ? "ok" : (r.status === "bad" || r.status === "warn") ? "bad" : "";
      if (row) row.classList.toggle("running", r.status === "running");
      if (st && r.status !== "running") { st.textContent = r.status === "ok" ? "안전 ✓" : "주의"; st.className = "vs-cat-st " + cls; }
      else if (st) st.textContent = "점검중";
    }
    var sc = r.status === "ok" ? "ok" : (r.status === "bad" || r.status === "warn") ? "bad" : "run";
    appendLog('<span class="t">' + fmt(Date.now() - startWall) + '</span> <span class="c">[' + (r.owasp_id || r.phase) + ']</span> ' + esc(r.message || r.step) + ' <span class="' + sc + '">●</span>');
  }

  /* 진행 구독(Realtime + 폴링 백업) */
  function subscribeProgress(scanId, phase, onComplete, invokeFn) {
    cleanup(); startWall = Date.now(); etaBase = null; startEta();
    var started = false;
    var fire = function () { if (started) return; started = true; if (invokeFn) invokeFn(); };
    // Realtime
    try {
      chan = sb.channel("vs-" + scanId + "-" + phase)
        .on("postgres_changes", { event: "INSERT", schema: "public", table: "vuln_progress", filter: "scan_id=eq." + scanId }, function (p) { if (p.new && p.new.phase === phase) applyProgress(p.new); })
        .on("postgres_changes", { event: "UPDATE", schema: "public", table: "vuln_scans", filter: "id=eq." + scanId }, function (p) { if (p.new) handleScanUpdate(p.new, phase, onComplete); })
        .subscribe(function (status) { if (status === "SUBSCRIBED") fire(); });
    } catch (e) { /* realtime 불가 시 폴링만 */ }
    // 폴링(백본): realtime 미가용/누락 대비
    var lastSeq = -1;
    pollTimer = setInterval(function () {
      sb.from("vuln_progress").select("*").eq("scan_id", scanId).eq("phase", phase).gt("seq", lastSeq).order("seq", { ascending: true }).then(function (r) {
        if (r.data) r.data.forEach(function (row) { lastSeq = Math.max(lastSeq, row.seq); applyProgress(row); });
      });
      if (phase === "scan") sb.from("vuln_scans").select("status,error").eq("id", scanId).single().then(function (r) { if (r.data) handleScanUpdate(r.data, phase, onComplete); });
    }, 1500);
    // realtime 구독이 늦어도 1.2초 후엔 무조건 invoke
    setTimeout(fire, 1200);
  }
  function handleScanUpdate(row, phase, onComplete) {
    if (phase !== "scan") return;
    if (row.status === "completed") { cleanup(); onComplete(); }
    else if (row.status === "failed") { failProgress(row.error || "진단 실패"); }
  }
  function failProgress(msg) { cleanup(); appendLog('<span class="bad">✕ ' + esc(msg) + '</span>'); toast("실패: " + msg, true); }

  /* ---------- ③ 진단 실행 ---------- */
  function startScan() {
    setStep("progress");
    $("vsView_progress").innerHTML = progressShell("실시간 진행 로그", true);
    $("vsCatRows").innerHTML = OWASP.map(function (o) { return '<div class="vs-cat" id="vsCat_' + o.id + '"><span class="vs-cat-id">' + o.id + '</span><span class="vs-cat-name">' + esc(o.ko) + '</span><span class="vs-cat-st" id="vsCatSt_' + o.id + '">대기</span></div>'; }).join("");
    show("progress");
    $("vsBg").addEventListener("click", function () { cleanup(); renderHistory(); });
    subscribeProgress(S.scan.id, "scan", function () { loadReport(S.scan.id); }, function () {
      sb.functions.invoke("vuln-scan", { body: { scan_id: S.scan.id } }).then(function (r) { if (r.error) failProgress(r.error.message || "함수 호출 실패"); });
    });
  }

  /* ---------- ④ 결과 리포트 ---------- */
  function loadReport(scanId) {
    Promise.all([
      sb.from("vuln_scans").select("*").eq("id", scanId).single(),
      sb.from("vuln_findings").select("*").eq("scan_id", scanId)
    ]).then(function (res) {
      if (res[0].error) { toast(res[0].error.message, true); return; }
      S.scan = res[0].data; S.findings = res[1].data || []; renderReport();
    });
  }
  function findingCard(f) {
    return '<div class="vs-find sev-' + f.severity + '">'
      + '<div class="vs-find-h"><span class="vs-find-sev sev-' + f.severity + '">' + (SEV[f.severity] ? SEV[f.severity].label : f.severity) + '</span>'
      + '<span class="vs-find-cat">' + f.owasp_id + '</span><span class="vs-find-title">' + esc(f.title) + '</span>'
      + (f.auto_fixable ? '<span class="vs-find-auto">자동조치</span>' : '<span class="vs-find-manual">수동</span>')
      + (f.status === "remediation_generated" ? '<span class="vs-find-auto" style="background:#16d39a">조치안✓</span>' : (f.status === "ticket" ? '<span class="vs-find-manual">티켓</span>' : ""))
      + '<span class="vs-find-caret">▾</span></div>'
      + '<div class="vs-find-body">'
      + '<div class="vs-find-row"><span>분류</span><p>' + f.owasp_id + ' · ' + esc(f.owasp_ko) + '</p></div>'
      + '<div class="vs-find-row"><span>설명</span><p>' + esc(f.detail) + '</p></div>'
      + '<div class="vs-find-row"><span>증거</span><code>' + esc(f.evidence) + '</code></div>'
      + '<div class="vs-find-row"><span>권고</span><p>' + esc(f.recommendation) + '</p></div>'
      + (f.auto_fixable && f.fix_summary ? '<div class="vs-find-row"><span>조치</span><p>' + esc(f.fix_summary) + '</p></div>' : '')
      + '</div></div>';
  }
  function renderReport() {
    setStep("report");
    var rec = S.scan, t = S.target || { emoji: rec.summary && "", name: rec.target_name, url: rec.target_url };
    var open = S.findings.filter(function (f) { return f.severity !== "pass"; });
    var passN = S.findings.filter(function (f) { return f.severity === "pass"; }).length;
    var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }; open.forEach(function (f) { if (counts[f.severity] != null) counts[f.severity]++; });
    var autoOpen = S.findings.filter(function (f) { return f.auto_fixable && f.status === "open"; });
    var sorted = open.slice().sort(function (a, b) { return (SEV[b.severity] ? SEV[b.severity].w : 0) - (SEV[a.severity] ? SEV[a.severity].w : 0); });
    var proj = rec.summary && rec.summary.projected_score;
    var html = '<div class="vs-report-head"><div class="vs-scorecard grade-' + rec.grade + '"><div class="vs-grade">' + rec.grade + '</div><div class="vs-score">' + rec.score + '<span>/100</span></div><div class="vs-scorelbl">보안 점수</div></div>'
      + '<div class="vs-report-meta"><div class="vs-rm-t">' + (rec.target_name) + ' 진단 결과</div><div class="vs-rm-url">' + esc(rec.target_url) + '</div>'
      + '<div class="vs-sevbar">' + SEV_ORDER.filter(function (s) { return s !== "pass"; }).map(function (s) { return counts[s] ? '<span class="vs-sevchip sev-' + s + '">' + SEV[s].label + ' ' + counts[s] + '</span>' : ''; }).join("")
      + (passN ? '<span class="vs-sevchip" style="color:#16d39a">✓ 통과 ' + passN + '</span>' : '') + '</div>'
      + '<div class="vs-rm-sub">총 ' + open.length + '건 · 자동조치 가능 ' + autoOpen.length + '건 · 소요 ' + fmt(rec.duration_ms) + ' · ' + fmtDate(rec.finished_at || rec.created_at)
      + (proj != null ? ' · <b>적용 시 예상 ' + proj + '점</b>' : '') + '</div></div></div>';
    html += open.length ? '<div class="vs-findlist">' + sorted.map(findingCard).join("") + '</div>' : '<div class="vs-empty-ok">🎉 주요 취약점이 발견되지 않았습니다.</div>';
    html += '<div class="vs-actions"><button class="vs-btn ghost" id="vsRpHistory" type="button">📜 이력</button>'
      + '<button class="vs-btn ghost" id="vsRpRescan" type="button">다른 대상</button>'
      + (session && autoOpen.length ? '<button class="vs-btn warn" id="vsRpFix" type="button">⚙️ 자동 조치 (' + autoOpen.length + '건) →</button>' : '') + '</div>';
    var c = $("vsView_report"); c.innerHTML = html; show("report");
    [].forEach.call(c.querySelectorAll(".vs-find-h"), function (h) { h.addEventListener("click", function () { h.parentNode.classList.toggle("open"); }); });
    $("vsRpHistory").addEventListener("click", renderHistory);
    $("vsRpRescan").addEventListener("click", renderSelect);
    if ($("vsRpFix")) $("vsRpFix").addEventListener("click", renderApproveFix);
  }

  /* ---------- ⑤ 자동 조치 승인 ---------- */
  function renderApproveFix() {
    setStep("approvefix");
    var auto = S.findings.filter(function (f) { return f.auto_fixable && f.status === "open"; });
    var manual = S.findings.filter(function (f) { return !f.auto_fixable && f.status === "open" && f.severity !== "pass" && f.severity !== "info"; });
    var html = '<div class="vs-gate"><div class="vs-gate-ic warn">⚙️</div><div class="vs-gate-t">자동 조치 승인 필요</div>'
      + '<div class="vs-gate-d">아래 <b>' + auto.length + '건</b>에 대해 실제 적용 가능한 <b>조치 산출물</b>(CSP·보안헤더·SRI 패치 등)을 생성합니다. 라이브 사이트는 변경되지 않으며, 모든 이력은 보존됩니다.</div>'
      + '<div class="vs-fixlist">' + auto.map(function (f) { return '<div class="vs-fixitem"><span class="vs-find-sev sev-' + f.severity + '">' + SEV[f.severity].label + '</span><div><b>' + esc(f.title) + '</b><span>→ ' + esc(f.fix_summary || f.recommendation) + '</span></div><span class="vs-fix-tag">자동</span></div>'; }).join("") + '</div>';
    if (manual.length) html += '<div class="vs-manual-note">⚠ 수동 조치 권고 ' + manual.length + '건은 자동 대상이 아니며 <b>조치 티켓</b>으로 기록됩니다.</div>';
    html += '<label class="vs-consent"><input type="checkbox" id="vsConsentFix"> 위 자동 조치 산출물 생성을 승인합니다.</label>'
      + '<div class="vs-actions"><button class="vs-btn ghost" id="vsFixBack" type="button">← 리포트</button>'
      + '<button class="vs-btn warn" id="vsApproveFix" type="button" disabled>승인하고 조치 실행 ⚙️</button></div></div>';
    $("vsView_approvefix").innerHTML = html; show("approvefix");
    $("vsConsentFix").addEventListener("change", function (e) { $("vsApproveFix").disabled = !e.target.checked; });
    $("vsFixBack").addEventListener("click", renderReport);
    $("vsApproveFix").addEventListener("click", function () {
      var btn = $("vsApproveFix"); btn.disabled = true; btn.textContent = "승인 중…";
      sb.rpc("vuln_approve_remediation", { p_scan_id: S.scan.id }).then(function (r) {
        if (r.error) { toast("승인 실패: " + r.error.message, true); btn.disabled = false; btn.textContent = "승인하고 조치 실행 ⚙️"; return; }
        startFix(auto.map(function (f) { return f.id; }));
      });
    });
  }

  /* ---------- ⑤-b 조치 실행 ---------- */
  function startFix(ids) {
    setStep("progressfix");
    $("vsView_progressfix").innerHTML = progressShell("실시간 조치 로그", false);
    show("progressfix");
    $("vsBg").addEventListener("click", function () { cleanup(); renderHistory(); });
    subscribeProgress(S.scan.id, "remediate", function () { }, function () {
      sb.functions.invoke("vuln-remediate", { body: { scan_id: S.scan.id, finding_ids: ids } }).then(function (r) {
        if (r.error) { failProgress(r.error.message || "조치 함수 실패"); return; }
        S.fixResult = r.data;
        sb.from("vuln_findings").select("*").eq("scan_id", S.scan.id).then(function (fr) { S.findings = fr.data || S.findings; cleanup(); renderReportFix(); });
      });
    });
  }

  /* ---------- ⑤-c 조치 리포트 ---------- */
  function renderReportFix() {
    setStep("reportfix");
    var fr = S.fixResult || {}, before = S.scan.score, after = fr.projected_score != null ? fr.projected_score : before;
    var delta = after - before, arts = (fr.artifacts || []), tickets = (fr.tickets || []);
    var html = '<div class="vs-report-head"><div class="vs-scorecard grade-' + (fr.projected_grade || S.scan.grade) + '"><div class="vs-grade">' + (fr.projected_grade || S.scan.grade) + '</div><div class="vs-score">' + after + '<span>/100</span></div><div class="vs-scorelbl">적용 시 예상</div></div>'
      + '<div class="vs-report-meta"><div class="vs-rm-t">✅ ' + esc(S.scan.target_name) + ' 조치안 생성 완료</div>'
      + '<div class="vs-deltabar"><span>' + before + '</span><span class="vs-arrow">→</span><span class="vs-after">' + after + '</span> <span class="vs-delta ' + (delta >= 0 ? "up" : "down") + '">' + (delta >= 0 ? "+" : "") + delta + '</span></div>'
      + '<div class="vs-rm-sub">산출물 ' + arts.length + '개 · 수동 티켓 ' + tickets.length + '건 · 라이브 미적용(검토 후 반영)</div></div></div>';
    html += '<div class="vs-section-t">📦 생성된 조치 산출물 (24시간 유효 다운로드)</div><div class="vs-fixlist">'
      + (arts.length ? arts.map(function (a) { return '<div class="vs-fixitem done"><span class="vs-fix-tag ok">파일</span><div><b>' + esc(a.name) + '</b><span>' + (a.bytes || 0) + ' bytes</span></div>' + (a.url ? '<a class="vs-btn tiny" href="' + esc(a.url) + '" target="_blank" rel="noopener" download>⬇ 다운로드</a>' : '<span class="vs-muted">URL 없음</span>') + '</div>'; }).join("") : '<div class="vs-muted">생성된 산출물 없음</div>') + '</div>';
    if (tickets.length) html += '<div class="vs-section-t">⚠ 수동 조치 티켓</div><div class="vs-fixlist">' + tickets.map(function (k) { return '<div class="vs-fixitem"><span class="vs-fix-tag">티켓</span><div><b>[' + k.owasp + '] ' + esc(k.title) + '</b></div></div>'; }).join("") + '</div>';
    html += '<div class="vs-actions"><button class="vs-btn ghost" id="vsFxHistory" type="button">📜 이력</button><button class="vs-btn ghost" id="vsFxReport" type="button">결과 리포트</button><button class="vs-btn primary" id="vsFxDone" type="button">다른 대상 진단 →</button></div>';
    $("vsView_reportfix").innerHTML = html; show("reportfix");
    $("vsFxHistory").addEventListener("click", renderHistory);
    $("vsFxReport").addEventListener("click", function () { loadReport(S.scan.id); });
    $("vsFxDone").addEventListener("click", renderSelect);
  }

  /* ---------- 이력 ---------- */
  function renderHistory() {
    setStep("history"); cleanup();
    var c = $("vsView_history");
    c.innerHTML = '<div class="vs-hist-top"><div class="vs-section-t" style="margin:0">진단·조치 이력 <span class="vs-muted">(전체 보존' + (session ? '' : ' · 완료분만') + ')</span></div>'
      + '<div><button class="vs-btn tiny" id="vsHistExport" type="button">⬇ JSON</button> <button class="vs-btn tiny ghost" id="vsHistBack" type="button">새 진단 →</button></div></div>'
      + '<div id="vsHistList" class="vs-histlist"><div class="vs-muted vs-hist-empty">불러오는 중…</div></div>';
    show("history");
    $("vsHistBack").addEventListener("click", renderSelect);
    $("vsHistExport").addEventListener("click", exportHistory);
    sb.from("vuln_scans").select("*").order("created_at", { ascending: false }).limit(50).then(function (r) {
      if (r.error) { $("vsHistList").innerHTML = '<div class="vs-muted vs-hist-empty">' + esc(r.error.message) + '</div>'; return; }
      var rows = r.data || [];
      if (!rows.length) { $("vsHistList").innerHTML = '<div class="vs-muted vs-hist-empty">이력이 없습니다. 진단을 수행하면 모든 기록이 보존됩니다.</div>'; return; }
      $("vsHistList").innerHTML = rows.map(histRow).join("");
      [].forEach.call($("vsHistList").querySelectorAll(".vs-hrow-h"), function (h) { h.addEventListener("click", function () { var row = h.parentNode; row.classList.toggle("open"); if (row.classList.contains("open") && !row.dataset.loaded) loadHistDetail(row); }); });
    });
  }
  function statusBadge(s) {
    var m = { pending_approval: ["승인대기", "#ffd24a"], approved: ["승인됨", "#4fc3f7"], running: ["진행중", "#25c2e6"], completed: ["완료", "#16d39a"], failed: ["실패", "#ff4d6d"], cancelled: ["취소", "#9fb2cb"] };
    var x = m[s] || [s, "#9fb2cb"]; return '<span class="vs-statusbadge" style="color:' + x[1] + ';border-color:' + x[1] + '">' + x[0] + '</span>';
  }
  function histRow(r) {
    var right = r.status === "completed" ? '<span class="vs-hgrade grade-' + r.grade + '"><b class="vs-grade" style="font-size:.9rem">' + r.grade + '</b> ' + r.score + '점</span>' : statusBadge(r.status);
    return '<div class="vs-hrow type-scan" data-id="' + r.id + '"><div class="vs-hrow-h">' + statusBadge(r.status)
      + '<span class="vs-htarget">' + esc(r.target_name) + '</span><span class="vs-hwhen">' + fmtDate(r.created_at) + '</span>' + right + '<span class="vs-find-caret">▾</span></div>'
      + '<div class="vs-hrow-b"><div class="vs-muted">상세 불러오는 중…</div></div></div>';
  }
  function loadHistDetail(row) {
    row.dataset.loaded = "1";
    var id = row.getAttribute("data-id"), box = row.querySelector(".vs-hrow-b");
    Promise.all([
      sb.from("vuln_scans").select("*").eq("id", id).single(),
      sb.from("vuln_findings").select("*").eq("scan_id", id),
      sb.from("vuln_remediations").select("*").eq("scan_id", id)
    ]).then(function (res) {
      var s = res[0].data || {}, fs = res[1].data || [], rem = res[2].data || [];
      var h = '<div class="vs-kv"><span>대상</span><b>' + esc(s.target_url) + '</b></div>'
        + '<div class="vs-kv"><span>요청/승인</span><b>' + esc(s.requested_email || "-") + ' / ' + esc(s.approved_email || "-") + '</b></div>'
        + '<div class="vs-kv"><span>소요/점수</span><b>' + fmt(s.duration_ms) + ' · ' + (s.score != null ? s.score + '점(' + s.grade + ')' : '-') + '</b></div>';
      var nonpass = fs.filter(function (f) { return f.severity !== "pass"; });
      if (nonpass.length) h += '<ul class="vs-hfind">' + nonpass.map(function (f) { return '<li><span class="vs-find-sev sev-' + f.severity + '">' + (SEV[f.severity] ? SEV[f.severity].label : f.severity) + '</span> [' + f.owasp_id + '] ' + esc(f.title) + (f.status !== "open" ? ' <span class="vs-fix-tag ok">' + (f.status === "ticket" ? "티켓" : "조치안") + '</span>' : '') + '</li>'; }).join("") + '</ul>';
      else h += '<div class="vs-muted" style="margin-top:6px">취약점 없음 / 진행중</div>';
      if (rem.length) h += '<div class="vs-section-t" style="margin:10px 0 6px">조치 기록 ' + rem.length + '건</div><ul class="vs-hfind">' + rem.map(function (x) { return '<li><span class="vs-fix-tag ' + (x.kind === "artifact" ? "ok" : "") + '">' + (x.kind === "artifact" ? "산출물" : "티켓") + '</span> ' + esc(x.title) + '</li>'; }).join("") + '</ul>';
      box.innerHTML = h;
    });
  }
  function exportHistory() {
    toast("이력 내보내는 중…");
    Promise.all([
      sb.from("vuln_scans").select("*").order("created_at", { ascending: false }),
      sb.from("vuln_findings").select("*"),
      sb.from("vuln_remediations").select("*"),
      sb.from("vuln_audit").select("*")
    ]).then(function (res) {
      var dump = { exported_at: new Date().toISOString(), scans: res[0].data || [], findings: res[1].data || [], remediations: res[2].data || [], audit: res[3].data || [] };
      var blob = new Blob([JSON.stringify(dump, null, 2)], { type: "application/json" });
      var url = URL.createObjectURL(blob), a = document.createElement("a");
      a.href = url; a.download = "jbax-vulnscan-history.json"; document.body.appendChild(a); a.click();
      setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 150);
    });
  }

  /* ---------- 열기/닫기 ---------- */
  function openModal(view) { $("vsOverlay").classList.add("open"); document.body.style.overflow = "hidden"; (view || renderSelect)(); }
  function closeModal() { cleanup(); $("vsOverlay").classList.remove("open"); document.body.style.overflow = ""; }

  function init() {
    buildShellViews(); initAuth();
    $("vsTrigger").addEventListener("click", function () { openModal(renderSelect); });
    $("vsHistoryBtn").addEventListener("click", function () { openModal(renderHistory); });
    [].forEach.call(document.querySelectorAll("[data-vs-close]"), function (b) { b.addEventListener("click", closeModal); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && $("vsOverlay").classList.contains("open")) closeModal(); });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();

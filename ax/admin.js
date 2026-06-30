/* AX(미래성장본부) 콘텐츠 관리(CMS) — 관리자 전용
 * Supabase(nrdapzgtibbusvoaceuh, secuday/VulnScan과 동일) 연동.
 * 로그인(관리자 계정) → 탭별 CRUD(추가/수정/삭제/게시토글). RLS로 보호.
 * 공개 페이지(ax/index.html)는 여기서 저장한 내용을 읽어 렌더한다. */
(function () {
  "use strict";
  var cfg = window.JBAX_CONFIG;
  var app = document.getElementById("app");
  if (!cfg || !window.supabase) { app.innerHTML = '<div class="empty">supabase-js / config.js 가 로드되지 않았습니다.</div>'; return; }
  var sb = window.supabase.createClient(cfg.SUPABASE_URL, cfg.SUPABASE_ANON_KEY);

  /* ───────── util ───────── */
  function $(id) { return document.getElementById(id); }
  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }
  function el(html) { var d = document.createElement("div"); d.innerHTML = html.trim(); return d.firstChild; }
  function toast(msg, err) { var t = $("toast"); t.textContent = msg; t.className = "toast show" + (err ? " err" : ""); clearTimeout(t._t); t._t = setTimeout(function () { t.className = "toast"; }, 3200); }

  /* ───────── 엔티티(목록형) 정의 ───────── */
  var ENTITIES = {
    news: {
      table: "ax_news", label: "뉴스/소식", icon: "📰", desc: "본부 소식 카드 (제목·날짜·요약·링크)",
      fields: [
        { k: "news_date", t: "date", label: "날짜" },
        { k: "category", t: "text", label: "카테고리", ph: "AX · AI · 디지털 · 신사업" },
        { k: "title", t: "text", label: "제목", full: true, req: true },
        { k: "summary", t: "textarea", label: "요약", full: true },
        { k: "url", t: "url", label: "자세히 링크(URL)", full: true, ph: "https://…" },
        { k: "sort_order", t: "number", label: "정렬(작을수록 먼저)" }
      ],
      blank: { news_date: "", category: "소식", title: "", summary: "", url: "", sort_order: 0, published: true },
      titleOf: function (r) { return r.title || "(제목 없음)"; }
    },
    metrics: {
      table: "ax_metrics", label: "지표", icon: "📊", desc: "히어로·임팩트 카운트업 수치",
      fields: [
        { k: "section", t: "select", label: "위치", options: [["hero", "히어로"], ["impact", "임팩트 밴드"]] },
        { k: "label", t: "text", label: "라벨", full: true, req: true },
        { k: "value", t: "number", label: "값(숫자)" },
        { k: "prefix", t: "text", label: "접두(앞)" },
        { k: "suffix", t: "text", label: "접미(뒤) — 예: + % /7" },
        { k: "group_num", t: "bool", label: "천단위 콤마 표시" },
        { k: "sort_order", t: "number", label: "정렬" }
      ],
      blank: { section: "hero", label: "", value: 0, prefix: "", suffix: "", group_num: true, sort_order: 0, published: true },
      titleOf: function (r) { return (r.label || "(라벨)") + " · " + (r.section === "impact" ? "임팩트" : "히어로"); }
    },
    pillars: {
      table: "ax_pillars", label: "6대 전략", icon: "🧭", desc: "핵심 추진 전략 카드",
      fields: [
        { k: "icon", t: "text", label: "아이콘(이모지)" },
        { k: "en_label", t: "text", label: "영문 라벨" },
        { k: "title", t: "text", label: "제목", full: true, req: true },
        { k: "body", t: "textarea", label: "설명", full: true },
        { k: "tags", t: "taglist", label: "태그(쉼표로 구분)", full: true },
        { k: "sort_order", t: "number", label: "정렬" }
      ],
      blank: { icon: "🔹", en_label: "", title: "", body: "", tags: [], sort_order: 0, published: true },
      titleOf: function (r) { return (r.icon || "") + " " + (r.title || "(제목)"); }
    },
    org: {
      table: "ax_org", label: "조직", icon: "🏢", desc: "조직 팀 카드",
      fields: [
        { k: "tag", t: "text", label: "태그(상단)" },
        { k: "title", t: "text", label: "팀명", full: true, req: true },
        { k: "body", t: "textarea", label: "설명", full: true },
        { k: "sort_order", t: "number", label: "정렬" }
      ],
      blank: { tag: "", title: "", body: "", sort_order: 0, published: true },
      titleOf: function (r) { return r.title || "(팀명)"; }
    },
    roadmap: {
      table: "ax_roadmap", label: "로드맵", icon: "🛣️", desc: "단계별 로드맵",
      fields: [
        { k: "year_label", t: "text", label: "연도/단계 라벨" },
        { k: "title", t: "text", label: "제목", full: true, req: true },
        { k: "body", t: "textarea", label: "설명", full: true },
        { k: "chips", t: "taglist", label: "칩(쉼표로 구분)", full: true },
        { k: "sort_order", t: "number", label: "정렬" }
      ],
      blank: { year_label: "", title: "", body: "", chips: [], sort_order: 0, published: true },
      titleOf: function (r) { return (r.year_label ? r.year_label + " · " : "") + (r.title || "(제목)"); }
    }
  };
  var ENTITY_ORDER = ["news", "metrics", "pillars", "org", "roadmap"];

  /* ───────── 단일 텍스트(설정) 정의 ───────── */
  var SETTINGS = [
    { key: "hero", label: "히어로", icon: "🚀", fields: [
      { k: "eyebrow", t: "text", label: "상단 eyebrow" },
      { k: "line1", t: "text", label: "헤드라인 1행" },
      { k: "line2_pre", t: "text", label: "헤드라인 2행(앞)" },
      { k: "line2_gold", t: "text", label: "헤드라인 2행(골드 강조)" },
      { k: "lead", t: "textarea", label: "리드 문단", full: true },
      { k: "cta_primary", t: "text", label: "기본 버튼 텍스트" },
      { k: "cta_primary_href", t: "text", label: "기본 버튼 링크" },
      { k: "cta_ghost", t: "text", label: "보조 버튼 텍스트" },
      { k: "cta_ghost_href", t: "text", label: "보조 버튼 링크" }
    ] },
    { key: "sections", label: "섹션 제목", icon: "🏷️", fields: [
      { k: "strategy_kicker", t: "text", label: "전략 kicker" },
      { k: "strategy_title", t: "text", label: "전략 제목", full: true },
      { k: "strategy_sub", t: "textarea", label: "전략 소제목", full: true },
      { k: "impact_kicker", t: "text", label: "임팩트 kicker" },
      { k: "impact_title", t: "text", label: "임팩트 제목", full: true },
      { k: "impact_sub", t: "textarea", label: "임팩트 소제목", full: true },
      { k: "roadmap_kicker", t: "text", label: "로드맵 kicker" },
      { k: "roadmap_title", t: "text", label: "로드맵 제목", full: true },
      { k: "roadmap_sub", t: "textarea", label: "로드맵 소제목", full: true },
      { k: "org_kicker", t: "text", label: "조직 kicker" },
      { k: "org_title", t: "text", label: "조직 제목" },
      { k: "org_node", t: "text", label: "조직 노드(본부명)" },
      { k: "org_node_en", t: "text", label: "조직 노드(영문)" },
      { k: "news_kicker", t: "text", label: "소식 kicker" },
      { k: "news_title", t: "text", label: "소식 제목" },
      { k: "news_sub", t: "textarea", label: "소식 소제목", full: true }
    ] },
    { key: "about", label: "About(소개)", icon: "📖", fields: [
      { k: "kicker", t: "text", label: "kicker" },
      { k: "title_pre", t: "text", label: "제목(앞)" },
      { k: "title_gold", t: "text", label: "제목(골드)" },
      { k: "para1", t: "textarea", label: "본문 1", full: true },
      { k: "para2", t: "textarea", label: "본문 2", full: true },
      { k: "mission", t: "textarea", label: "MISSION", full: true },
      { k: "vision", t: "textarea", label: "VISION", full: true }
    ] },
    { key: "leader", label: "본부장", icon: "👤", fields: [
      { k: "name", t: "text", label: "이름" },
      { k: "title", t: "text", label: "직책", full: true },
      { k: "photo", t: "url", label: "사진 URL (공식/허가된 이미지만)", full: true, ph: "https://… (비우면 이니셜 플레이스홀더)" },
      { k: "quote", t: "textarea", label: "대표 인용(따옴표 포함)", full: true },
      { k: "quote_src", t: "text", label: "인용 출처", full: true },
      { k: "vision", t: "textarea", label: "비전 요약", full: true }
    ] },
    { key: "contact", label: "연락처", icon: "✉️", fields: [
      { k: "title", t: "text", label: "제목", full: true },
      { k: "desc", t: "textarea", label: "설명", full: true },
      { k: "email", t: "text", label: "이메일" },
      { k: "address", t: "text", label: "주소" },
      { k: "partnership", t: "text", label: "제휴 문구" }
    ] },
    { key: "footer", label: "푸터", icon: "🔻", fields: [
      { k: "slogan", t: "text", label: "슬로건", full: true }
    ] }
  ];

  /* ───────── 필드 렌더/수집 ───────── */
  function fieldHTML(f, val) {
    if (f.t === "bool") {
      return '<label class="chk col-full"><input type="checkbox" data-k="' + f.k + '"' + (val ? " checked" : "") + "> " + esc(f.label) + "</label>";
    }
    var cls = "field" + (f.full ? " col-full" : "");
    var lab = '<label>' + esc(f.label) + (f.req ? " *" : "") + "</label>";
    var v = val == null ? "" : val, inner;
    if (f.t === "textarea") inner = '<textarea data-k="' + f.k + '" placeholder="' + esc(f.ph || "") + '">' + esc(v) + "</textarea>";
    else if (f.t === "select") inner = '<select data-k="' + f.k + '">' + f.options.map(function (o) { return '<option value="' + esc(o[0]) + '"' + (String(val) === o[0] ? " selected" : "") + ">" + esc(o[1]) + "</option>"; }).join("") + "</select>";
    else if (f.t === "taglist") { var s = Array.isArray(val) ? val.join(", ") : v; inner = '<input type="text" data-k="' + f.k + '" value="' + esc(s) + '" placeholder="' + esc(f.ph || "쉼표로 구분") + '">'; }
    else { var ty = f.t === "number" ? "number" : f.t === "date" ? "date" : f.t === "url" ? "url" : "text"; inner = '<input type="' + ty + '" data-k="' + f.k + '" value="' + esc(v) + '" placeholder="' + esc(f.ph || "") + '">'; }
    return '<div class="' + cls + '">' + lab + inner + "</div>";
  }
  function collectFields(fields, scope) {
    var out = {};
    fields.forEach(function (f) {
      var n = scope.querySelector('[data-k="' + f.k + '"]'); if (!n) return;
      if (f.t === "bool") out[f.k] = n.checked;
      else if (f.t === "number") out[f.k] = n.value === "" ? 0 : Number(n.value);
      else if (f.t === "taglist") out[f.k] = n.value.split(",").map(function (x) { return x.trim(); }).filter(Boolean);
      else out[f.k] = n.value;
    });
    return out;
  }

  /* ───────── 인증 ───────── */
  function initAuth() {
    sb.auth.getSession().then(function (r) { session = r.data.session; renderAuth(); route(); });
    sb.auth.onAuthStateChange(function (_e, s) { session = s; renderAuth(); });
  }
  var session = null, activeTab = "news";

  function renderAuth() {
    var a = $("auth");
    if (session) {
      a.innerHTML = '<a class="viewlink" href="./" target="_blank">사이트 보기 ↗</a>'
        + '<span class="who">👤 ' + esc(session.user.email || "관리자") + "</span>"
        + '<button class="btn ghost sm" id="logout">로그아웃</button>';
      $("logout").onclick = function () { sb.auth.signOut().then(function () { toast("로그아웃되었습니다"); route(); }); };
    } else { a.innerHTML = ""; }
  }
  function route() { if (!session) renderLogin(); else renderApp(); }

  function renderLogin() {
    app.innerHTML = '<div class="gate"><div class="ic">🔑</div><h1>관리자 로그인</h1>'
      + "<p>AX 페이지 콘텐츠 편집은 관리자만 가능합니다.<br>(secuday · VulnScan과 동일 계정)</p>"
      + '<form id="loginForm">'
      + '<div class="field"><label>이메일</label><input id="email" type="email" required autocomplete="username"></div>'
      + '<div class="field"><label>비밀번호</label><input id="pw" type="password" required autocomplete="current-password"></div>'
      + '<button class="btn primary" id="loginBtn" type="submit" style="margin-top:6px;justify-content:center">로그인</button>'
      + '<p class="err" id="loginErr" hidden></p></form></div>';
    $("loginForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var b = $("loginBtn"); b.disabled = true; b.textContent = "로그인 중…";
      sb.auth.signInWithPassword({ email: $("email").value.trim(), password: $("pw").value }).then(function (r) {
        b.disabled = false; b.textContent = "로그인";
        if (r.error) { var p = $("loginErr"); p.hidden = false; p.textContent = "로그인 실패: " + r.error.message; return; }
        session = r.data.session; renderAuth(); toast("로그인되었습니다"); route();
      });
    });
  }

  /* ───────── 앱 셸 + 탭 ───────── */
  function renderApp() {
    var tabs = ENTITY_ORDER.map(function (k) {
      var d = ENTITIES[k];
      return '<button class="tab" data-tab="' + k + '">' + d.icon + " " + esc(d.label) + "</button>";
    }).join("") + '<button class="tab" data-tab="settings">📝 문구·설정</button>';
    app.innerHTML = '<div class="tabs" id="tabs">' + tabs + '</div><div class="panel" id="panel"></div>';
    [].forEach.call(document.querySelectorAll("#tabs .tab"), function (t) {
      t.onclick = function () { selectTab(t.getAttribute("data-tab")); };
    });
    selectTab(activeTab);
  }
  function selectTab(key) {
    activeTab = key;
    [].forEach.call(document.querySelectorAll("#tabs .tab"), function (t) { t.classList.toggle("on", t.getAttribute("data-tab") === key); });
    if (key === "settings") renderSettings(); else renderEntity(ENTITIES[key]);
  }

  /* ───────── 엔티티 패널(목록형 CRUD) ───────── */
  function renderEntity(def) {
    var p = $("panel");
    p.innerHTML = '<div class="panel-head"><div><h2>' + def.icon + " " + esc(def.label) + "</h2><div class=\"desc\">" + esc(def.desc) + "</div></div>"
      + '<button class="btn primary" id="addBtn">＋ 추가</button></div>'
      + '<div class="cards" id="cards"><div class="loading">불러오는 중…</div></div>';
    $("addBtn").onclick = function () {
      var c = $("cards"); var empt = c.querySelector(".empty"); if (empt) empt.remove();
      var blank = JSON.parse(JSON.stringify(def.blank));
      c.insertBefore(rowCard(def, blank, true), c.firstChild);
      c.firstChild.scrollIntoView({ behavior: "smooth", block: "center" });
    };
    var q = sb.from(def.table).select("*");
    if (def.table === "ax_metrics") q = q.order("section", { ascending: true });
    q.order("sort_order", { ascending: true }).order("updated_at", { ascending: false }).then(function (r) {
      var c = $("cards");
      if (r.error) { c.innerHTML = '<div class="empty">불러오기 오류: ' + esc(r.error.message) + "</div>"; return; }
      var rows = r.data || [];
      if (!rows.length) { c.innerHTML = '<div class="empty">아직 항목이 없습니다. 우측 상단 ＋추가 로 만들어 보세요.</div>'; return; }
      c.innerHTML = ""; rows.forEach(function (row) { c.appendChild(rowCard(def, row, false)); });
    });
  }

  function rowCard(def, row, isNew) {
    var card = el('<div class="card' + (row.published ? "" : " unpub") + '"></div>');
    if (row.id) card.setAttribute("data-id", row.id);
    var grid = '<div class="grid">' + def.fields.map(function (f) { return fieldHTML(f, row[f.k]); }).join("") + "</div>";
    var actions = '<div class="row-actions">'
      + '<div class="left-actions">'
      + '<label class="chk"><input type="checkbox" data-pub' + (row.published ? " checked" : "") + "> 게시</label>"
      + '<span class="badge ' + (row.published ? "on\">게시중" : "off\">숨김") + "</span>"
      + "</div>"
      + '<div class="left-actions">'
      + '<button class="btn danger sm" data-del>삭제</button>'
      + '<button class="btn primary sm" data-save>저장</button>'
      + "</div></div>";
    card.innerHTML = grid + actions;

    var pub = card.querySelector("[data-pub]");
    var badge = card.querySelector(".badge");
    pub.addEventListener("change", function () {
      card.classList.toggle("unpub", !pub.checked);
      badge.className = "badge " + (pub.checked ? "on" : "off"); badge.textContent = pub.checked ? "게시중" : "숨김";
    });
    card.querySelector("[data-save]").onclick = function () { saveRow(def, card); };
    card.querySelector("[data-del]").onclick = function () { deleteRow(def, card); };
    return card;
  }

  function saveRow(def, card) {
    var obj = collectFields(def.fields, card);
    obj.published = card.querySelector("[data-pub]").checked;
    var req = def.fields.filter(function (f) { return f.req; });
    for (var i = 0; i < req.length; i++) { if (!String(obj[req[i].k] || "").trim()) { toast(req[i].label + "은(는) 필수입니다", true); return; } }
    var id = card.getAttribute("data-id");
    var btn = card.querySelector("[data-save]"); btn.disabled = true; btn.textContent = "저장 중…";
    var done = function (r) {
      btn.disabled = false; btn.textContent = "저장";
      if (r.error) { toast("저장 실패: " + r.error.message, true); return; }
      if (r.data && r.data[0] && r.data[0].id) card.setAttribute("data-id", r.data[0].id);
      toast("저장되었습니다");
    };
    if (id) sb.from(def.table).update(obj).eq("id", id).select().then(done);
    else sb.from(def.table).insert(obj).select().then(done);
  }

  function deleteRow(def, card) {
    var id = card.getAttribute("data-id");
    if (!id) { card.remove(); return; }
    if (!confirm("이 항목을 삭제할까요? 되돌릴 수 없습니다.")) return;
    var btn = card.querySelector("[data-del]"); btn.disabled = true;
    sb.from(def.table).delete().eq("id", id).then(function (r) {
      if (r.error) { btn.disabled = false; toast("삭제 실패: " + r.error.message, true); return; }
      card.remove(); toast("삭제되었습니다");
      var c = $("cards"); if (c && !c.children.length) c.innerHTML = '<div class="empty">아직 항목이 없습니다.</div>';
    });
  }

  /* ───────── 설정(단일 텍스트) 패널 ───────── */
  function renderSettings() {
    var p = $("panel");
    p.innerHTML = '<div class="panel-head"><div><h2>📝 문구·설정</h2><div class="desc">히어로·소개·연락처·푸터 등 고정 텍스트</div></div></div>'
      + '<div id="setbody"><div class="loading">불러오는 중…</div></div>';
    sb.from("ax_settings").select("*").then(function (r) {
      var map = {}; (r.data || []).forEach(function (row) { map[row.key] = row.value || {}; });
      var body = $("setbody"); body.innerHTML = "";
      SETTINGS.forEach(function (g) {
        var val = map[g.key] || {};
        var box = el('<div class="setgroup"></div>');
        box.innerHTML = "<h3>" + g.icon + " " + esc(g.label) + "</h3>"
          + '<div class="grid">' + g.fields.map(function (f) { return fieldHTML(f, val[f.k]); }).join("") + "</div>"
          + '<div class="row-actions"><span></span><button class="btn primary sm" data-savekey="' + g.key + '">저장</button></div>';
        box.querySelector("[data-savekey]").onclick = function () { saveSetting(g, box); };
        body.appendChild(box);
      });
    });
  }
  function saveSetting(g, box) {
    var obj = collectFields(g.fields, box);
    var btn = box.querySelector("[data-savekey]"); btn.disabled = true; btn.textContent = "저장 중…";
    sb.from("ax_settings").upsert({ key: g.key, value: obj }).then(function (r) {
      btn.disabled = false; btn.textContent = "저장";
      if (r.error) { toast("저장 실패: " + r.error.message, true); return; }
      toast(g.label + " 저장되었습니다");
    });
  }

  initAuth();
})();

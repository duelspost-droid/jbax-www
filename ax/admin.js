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
  function escA(s) { return esc(s).replace(/"/g, "&quot;"); }   // 속성값용(따옴표까지 escape) — 신뢰불가 IP/UA 방어
  function el(html) { var d = document.createElement("div"); d.innerHTML = html.trim(); return d.firstChild; }
  function toast(msg, err) { var t = $("toast"); t.textContent = msg; t.className = "toast show" + (err ? " err" : ""); clearTimeout(t._t); t._t = setTimeout(function () { t.className = "toast"; }, 3200); }
  /* 감사 로깅 — SECURITY DEFINER RPC(서버측 IP 캡처). 실패해도 UI 방해 안 함(fire-and-forget). */
  function logAudit(action, entity, entityId, detail) {
    try {
      sb.rpc("ax_log", { p_action: action, p_entity: entity || null, p_entity_id: entityId != null ? String(entityId) : null, p_detail: detail || {} })
        .then(function () {}, function () {});
    } catch (e) { /* 테이블/RPC 미설치 등 → 무시 */ }
  }

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
      { k: "photo", t: "image", label: "본부장 사진 (공식/허가된 이미지만)", full: true, ph: "파일을 첨부하면 자동으로 축소·압축되어 저장됩니다. 비우면 이니셜 플레이스홀더로 표시됩니다." },
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
    if (f.t === "image") {
      var iv = val == null ? "" : String(val), has = iv.length > 0;
      return '<div class="imgfield' + (f.full ? " col-full" : "") + '" data-image-field>'
        + '<label>' + esc(f.label) + "</label>"
        + '<input type="hidden" data-k="' + f.k + '" value="' + esc(iv) + '">'
        + '<div class="imgprev">' + (has ? '<img src="' + esc(iv) + '" alt="">' : '<span class="imgph">이미지 없음</span>') + "</div>"
        + '<div class="imgbtns">'
        +   '<label class="btn ghost sm imgpick">📎 사진 첨부<input type="file" accept="image/*" hidden></label>'
        +   '<button type="button" class="btn danger sm imgclear"' + (has ? "" : " hidden") + ">제거</button>"
        + "</div>"
        + '<div class="imghint">' + esc(f.ph || "권장: 정면 인물 사진. 첨부 시 자동으로 축소·압축됩니다.") + "</div>"
        + "</div>";
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

  /* ───────── 이미지 첨부: 브라우저에서 축소·압축 → data URL ─────────
   * Supabase Storage 버킷 없이 동작하도록, 첨부 파일을 캔버스로 최대 640px·JPEG로
   * 다운스케일해 data URL로 만들어 기존 photo 필드(jsonb)에 저장한다. 공개 페이지의
   * data-ax-src 핸들러가 그대로 img.src에 넣는다. (원본 대용량 파일은 그대로 저장 안 함) */
  function downscaleImage(file, maxDim, quality) {
    return new Promise(function (resolve, reject) {
      if (file.size > 15 * 1024 * 1024) { reject(new Error("too-large")); return; }
      var fr = new FileReader();
      fr.onerror = function () { reject(new Error("read")); };
      fr.onload = function () {
        var img = new Image();
        img.onerror = function () { reject(new Error("decode")); };
        img.onload = function () {
          var w = img.naturalWidth || img.width, h = img.naturalHeight || img.height;
          if (!w || !h) { reject(new Error("empty")); return; }
          var scale = Math.min(1, maxDim / Math.max(w, h));
          var cw = Math.max(1, Math.round(w * scale)), ch = Math.max(1, Math.round(h * scale));
          var c = document.createElement("canvas"); c.width = cw; c.height = ch;
          var ctx = c.getContext("2d");
          ctx.fillStyle = "#ffffff"; ctx.fillRect(0, 0, cw, ch);   // 투명 PNG → 검은 배경 방지
          ctx.drawImage(img, 0, 0, cw, ch);
          var out; try { out = c.toDataURL("image/jpeg", quality); } catch (e) { out = String(fr.result); }
          resolve(out);
        };
        img.src = String(fr.result);
      };
      fr.readAsDataURL(file);
    });
  }
  function wireImageFields(scope) {
    [].forEach.call(scope.querySelectorAll("[data-image-field]"), function (fld) {
      if (fld._wired) return; fld._wired = true;
      var hidden = fld.querySelector('input[type="hidden"]');
      var prev = fld.querySelector(".imgprev");
      var file = fld.querySelector('input[type="file"]');
      var pick = fld.querySelector(".imgpick");
      var clear = fld.querySelector(".imgclear");
      function setVal(url) {
        hidden.value = url || "";
        if (url) { prev.innerHTML = '<img src="' + esc(url) + '" alt="">'; if (clear) clear.hidden = false; }
        else { prev.innerHTML = '<span class="imgph">이미지 없음</span>'; if (clear) clear.hidden = true; }
      }
      file.addEventListener("change", function () {
        var f = file.files && file.files[0]; if (!f) return;
        if (!/^image\//.test(f.type || "")) { toast("이미지 파일만 첨부할 수 있습니다", true); file.value = ""; return; }
        var old = pick.textContent; pick.style.pointerEvents = "none"; pick.textContent = "처리 중…";
        downscaleImage(f, 640, 0.82).then(function (url) {
          setVal(url); pick.textContent = old; pick.style.pointerEvents = "";
          toast("사진이 첨부되었습니다 — 저장을 눌러 반영하세요");
        }).catch(function (err) {
          pick.textContent = old; pick.style.pointerEvents = "";
          toast(err && err.message === "too-large" ? "파일이 너무 큽니다 (15MB 이하)" : "이미지를 읽지 못했습니다", true);
        });
        file.value = "";
      });
      if (clear) clear.addEventListener("click", function () { setVal(""); });
    });
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
      $("logout").onclick = function () { logAudit("logout", "auth", null, {}); sb.auth.signOut().then(function () { toast("로그아웃되었습니다"); route(); }); };
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
        session = r.data.session; renderAuth(); toast("로그인되었습니다");
        logAudit("login", "auth", (r.data.user && r.data.user.email) || null, {}); route();
      });
    });
  }

  /* ───────── 앱 셸 + 탭 ───────── */
  function renderApp() {
    var tabs = ENTITY_ORDER.map(function (k) {
      var d = ENTITIES[k];
      return '<button class="tab" data-tab="' + k + '">' + d.icon + " " + esc(d.label) + "</button>";
    }).join("") + '<button class="tab" data-tab="settings">📝 문구·설정</button>'
      + '<button class="tab" data-tab="audit">📊 로그·감사</button>';
    app.innerHTML = '<div class="tabs" id="tabs">' + tabs + '</div><div class="panel" id="panel"></div>';
    [].forEach.call(document.querySelectorAll("#tabs .tab"), function (t) {
      t.onclick = function () { selectTab(t.getAttribute("data-tab")); };
    });
    selectTab(activeTab);
  }
  function selectTab(key) {
    activeTab = key;
    [].forEach.call(document.querySelectorAll("#tabs .tab"), function (t) { t.classList.toggle("on", t.getAttribute("data-tab") === key); });
    if (key === "settings") renderSettings(); else if (key === "audit") renderAudit(); else renderEntity(ENTITIES[key]);
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
    wireImageFields(card);
    return card;
  }

  function saveRow(def, card) {
    var obj = collectFields(def.fields, card);
    obj.published = card.querySelector("[data-pub]").checked;
    var req = def.fields.filter(function (f) { return f.req; });
    for (var i = 0; i < req.length; i++) { if (!String(obj[req[i].k] || "").trim()) { toast(req[i].label + "은(는) 필수입니다", true); return; } }
    var id = card.getAttribute("data-id"), wasNew = !id;
    var btn = card.querySelector("[data-save]"); btn.disabled = true; btn.textContent = "저장 중…";
    var done = function (r) {
      btn.disabled = false; btn.textContent = "저장";
      if (r.error) { toast("저장 실패: " + r.error.message, true); return; }
      if (r.data && r.data[0] && r.data[0].id) card.setAttribute("data-id", r.data[0].id);
      toast("저장되었습니다");
      logAudit(wasNew ? "create" : "update", def.table, (r.data && r.data[0] && r.data[0].id) || id, { label: def.titleOf ? def.titleOf(obj) : "", published: !!obj.published });
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
      logAudit("delete", def.table, id, {});
      var c = $("cards"); if (c && !c.children.length) c.innerHTML = '<div class="empty">아직 항목이 없습니다.</div>';
    });
  }

  /* ───────── 공개 페이지 정적 기본값 → 설정 폼 pre-fill ─────────
   * ax_settings에 아직 저장 안 된 그룹(예: 섹션 제목)은 index.html에 박혀 있는
   * 현재 문구를 그대로 읽어와 폼을 채운다. 그래야 "현재 값 위에서 수정 → 저장"이
   * 자연스럽고, 저장 시 해당 key 행이 올바른 값들로 새로 생성된다.
   * (fetch/parse 실패 시 조용히 빈 기본값 → 기존 동작으로 폴백) */
  var _defaults = null;
  function loadDefaults() {
    if (_defaults) return Promise.resolve(_defaults);
    return fetch("index.html", { cache: "no-store" })
      .then(function (res) { return res.ok ? res.text() : ""; })
      .then(function (html) {
        var d = {};
        if (html && window.DOMParser) {
          var doc = new DOMParser().parseFromString(html, "text/html");
          var put = function (key, v) {
            if (v == null) return; v = String(v).trim(); if (v === "") return;
            var p = key.split("."); if (p.length !== 2) return;
            (d[p[0]] || (d[p[0]] = {}))[p[1]] = v;
          };
          [].forEach.call(doc.querySelectorAll("[data-ax]"), function (n) { put(n.getAttribute("data-ax"), n.textContent); });
          [].forEach.call(doc.querySelectorAll("[data-ax-href]"), function (n) { put(n.getAttribute("data-ax-href"), n.getAttribute("href")); });
          [].forEach.call(doc.querySelectorAll("[data-ax-mailto]"), function (n) { put(n.getAttribute("data-ax-mailto"), (n.getAttribute("href") || "").replace(/^mailto:/, "")); });
          [].forEach.call(doc.querySelectorAll("[data-ax-src]"), function (n) { put(n.getAttribute("data-ax-src"), n.getAttribute("src")); });
        }
        _defaults = d; return d;
      })
      .catch(function () { _defaults = {}; return _defaults; });
  }
  function mergeVals(def, dbv) {
    var out = {}, k; def = def || {}; dbv = dbv || {};
    for (k in def) if (Object.prototype.hasOwnProperty.call(def, k)) out[k] = def[k];
    for (k in dbv) if (Object.prototype.hasOwnProperty.call(dbv, k)) { var v = dbv[k]; if (v != null && v !== "") out[k] = v; }
    return out;
  }

  /* ───────── 설정(단일 텍스트) 패널 ───────── */
  function renderSettings() {
    var p = $("panel");
    p.innerHTML = '<div class="panel-head"><div><h2>📝 문구·설정</h2><div class="desc">히어로·소개·연락처·푸터 등 고정 텍스트 — 빈 칸은 현재 사이트 문구로 자동 채워집니다</div></div></div>'
      + '<div id="setbody"><div class="loading">불러오는 중…</div></div>';
    Promise.all([sb.from("ax_settings").select("*"), loadDefaults()]).then(function (res) {
      var r = res[0], defs = res[1] || {};
      var map = {}; ((r && r.data) || []).forEach(function (row) { map[row.key] = row.value || {}; });
      var body = $("setbody"); body.innerHTML = "";
      SETTINGS.forEach(function (g) {
        var val = mergeVals(defs[g.key], map[g.key]);
        var box = el('<div class="setgroup"></div>');
        box.innerHTML = "<h3>" + g.icon + " " + esc(g.label) + "</h3>"
          + '<div class="grid">' + g.fields.map(function (f) { return fieldHTML(f, val[f.k]); }).join("") + "</div>"
          + '<div class="row-actions"><span></span><button class="btn primary sm" data-savekey="' + g.key + '">저장</button></div>';
        box.querySelector("[data-savekey]").onclick = function () { saveSetting(g, box); };
        body.appendChild(box);
        wireImageFields(box);
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
      logAudit("update_setting", "ax_settings", g.key, { label: g.label });
    });
  }

  /* ───────── 로그·감사 패널 ───────── */
  function auditTime(s) {
    var d = new Date(s); if (isNaN(d.getTime())) return esc(s);
    function p(n) { return (n < 10 ? "0" : "") + n; }
    return d.getFullYear() + "." + p(d.getMonth() + 1) + "." + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }
  function auditStatsHTML(rows) {
    var now = Date.now(), ips = {}, users = {}, actions = {}, visits = 0, admins = 0, day = 0;
    rows.forEach(function (x) {
      if (x.ip) ips[x.ip] = (ips[x.ip] || 0) + 1;
      if (x.actor_email) users[x.actor_email] = (users[x.actor_email] || 0) + 1;
      actions[x.action] = (actions[x.action] || 0) + 1;
      if (x.kind === "visit") visits++; else admins++;
      if (now - new Date(x.created_at).getTime() < 864e5) day++;
    });
    var topIps = Object.keys(ips).map(function (k) { return [k, ips[k]]; }).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 6);
    var actList = Object.keys(actions).map(function (k) { return [k, actions[k]]; }).sort(function (a, b) { return b[1] - a[1]; });
    var maxAct = actList.reduce(function (m, x) { return Math.max(m, x[1]); }, 1);
    function card(lab, val) { return '<div class="stat-card"><div class="sc-val">' + val + '</div><div class="sc-lab">' + esc(lab) + "</div></div>"; }
    var cards = '<div class="stat-cards">'
      + card("총 기록(최근 1000)", rows.length) + card("최근 24시간", day)
      + card("고유 접속 IP", Object.keys(ips).length) + card("관리 행위", admins)
      + card("공개 방문", visits) + card("고유 관리자", Object.keys(users).length) + "</div>";
    var bars = '<div class="audit-block"><h4>액션별 분포</h4><div class="bars">'
      + (actList.length ? actList.map(function (a) {
        return '<div class="bar-row"><span class="bar-lab" title="' + escA(a[0]) + '">' + esc(a[0]) + '</span>'
          + '<span class="bar-track"><span class="bar-fill" style="width:' + Math.round(a[1] / maxAct * 100) + '%"></span></span>'
          + '<span class="bar-num">' + a[1] + "</span></div>";
      }).join("") : '<div class="muted">기록 없음</div>') + "</div></div>";
    var iplist = '<div class="audit-block"><h4>상위 접속 IP</h4><div class="iplist">'
      + (topIps.length ? topIps.map(function (x) { return '<div class="ip-row"><code>' + esc(x[0]) + "</code><span>" + x[1] + "회</span></div>"; }).join("") : '<div class="muted">기록 없음</div>')
      + "</div></div>";
    return cards + '<div class="audit-2col">' + bars + iplist + "</div>";
  }
  function auditRowsHTML(rows) {
    if (!rows.length) return '<tr><td colspan="7" class="muted" style="text-align:center;padding:24px">기록이 없습니다.</td></tr>';
    return rows.map(function (x) {
      var isVisit = x.kind === "visit";
      var who = isVisit ? '<span class="muted">익명 방문자</span>' : esc(x.actor_email || "(관리자)");
      var badge = isVisit ? '<span class="badge-visit">방문</span>' : '<span class="badge-admin">관리</span>';
      var tgt = [x.entity, x.entity_id].filter(Boolean).map(esc).join(" · ") || '<span class="muted">-</span>';
      var ua = x.user_agent ? esc(String(x.user_agent).slice(0, 64)) : "";
      return '<tr class="ar ' + (isVisit ? "ar-visit" : "ar-admin") + '">'
        + '<td class="ar-time">' + auditTime(x.created_at) + "</td>"
        + "<td>" + badge + "</td>"
        + "<td>" + who + "</td>"
        + '<td><code>' + esc(x.ip || "-") + "</code></td>"
        + "<td>" + esc(x.action || "") + "</td>"
        + '<td class="ar-tgt">' + tgt + "</td>"
        + '<td class="ar-ua" title="' + escA(x.user_agent || "") + '">' + ua + "</td></tr>";
    }).join("");
  }
  function renderAudit() {
    var p = $("panel");
    p.innerHTML = '<div class="panel-head"><div><h2>📊 로그·감사</h2><div class="desc">관리자 활동 · 공개 방문 접속 기록 — 누가 · 언제 · 어디서(IP) · 무엇을 <b style="color:var(--muted)">(통계·표는 최근 1000건 기준)</b></div></div>'
      + '<button class="btn ghost sm" id="auditRefresh">↻ 새로고침</button></div>'
      + '<div id="auditBody"><div class="loading">불러오는 중…</div></div>';
    $("auditRefresh").onclick = renderAudit;
    sb.from("ax_audit").select("*").order("created_at", { ascending: false }).limit(1000).then(function (r) {
      var body = $("auditBody");
      if (r.error) {
        body.innerHTML = '<div class="empty">감사 로그 테이블이 아직 설치되지 않았습니다.<br>Supabase에서 <b>0015_ax_audit.sql</b> 마이그레이션을 실행하면 활성화됩니다.'
          + '<br><span style="opacity:.55;font-size:.82em">(' + esc(r.error.message) + ")</span></div>";
        return;
      }
      var rows = r.data || [];
      body.innerHTML = auditStatsHTML(rows)
        + '<div class="audit-filter"><label class="chk"><input type="radio" name="afk" value="all" checked> 전체</label>'
        + '<label class="chk"><input type="radio" name="afk" value="admin"> 관리 행위</label>'
        + '<label class="chk"><input type="radio" name="afk" value="visit"> 방문</label>'
        + '<input type="search" id="afq" class="afsearch" placeholder="IP · 사용자 · 액션 검색"></div>'
        + '<div class="audit-tablewrap"><table class="audit-table"><thead><tr>'
        + "<th>시간</th><th>유형</th><th>사용자</th><th>IP</th><th>액션</th><th>대상</th><th>User-Agent</th>"
        + '</tr></thead><tbody id="auditRows">' + auditRowsHTML(rows) + "</tbody></table></div>";
      var kind = "all", q = "";
      function apply() {
        var f = rows.filter(function (x) {
          if (kind !== "all" && x.kind !== kind) return false;
          if (q) { var hay = ((x.actor_email || "") + " " + (x.ip || "") + " " + (x.action || "") + " " + (x.entity || "") + " " + (x.user_agent || "")).toLowerCase(); if (hay.indexOf(q) < 0) return false; }
          return true;
        });
        var box = $("auditRows"); if (box) box.innerHTML = auditRowsHTML(f);
      }
      [].forEach.call(document.querySelectorAll('input[name="afk"]'), function (rd) { rd.onchange = function () { kind = rd.value; apply(); }; });
      var s = $("afq"); if (s) s.oninput = function () { q = s.value.trim().toLowerCase(); apply(); };
    });
  }

  initAuth();
})();

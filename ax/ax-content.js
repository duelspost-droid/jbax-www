/* AX(미래성장본부) 공개 페이지 — 콘텐츠 하이드레이션
 * Supabase(ax_settings / ax_metrics / ax_news / ax_pillars / ax_org / ax_roadmap)에서
 * 관리자페이지(admin.html)로 저장한 내용을 읽어 화면을 채운다.
 * ⚠ 폴백 원칙: 로드 실패·빈 결과·미설정 항목은 HTML에 박혀 있는 정적 콘텐츠를 그대로 둔다.
 *    (Supabase가 죽어도 페이지는 절대 깨지지 않는다.) */
(function () {
  "use strict";
  var cfg = window.JBAX_CONFIG;
  if (!cfg || !window.supabase) return;           // 라이브러리/설정 없음 → 정적 유지
  var sb;
  try { sb = window.supabase.createClient(cfg.SUPABASE_URL, cfg.SUPABASE_ANON_KEY); }
  catch (e) { return; }

  /* 방문 로깅(익명) — 세션당 경로별 1회. 서버측(request.headers)에서 IP 캡처하는 RPC.
     실패(테이블/RPC 미설치, 네트워크)해도 페이지에 영향 없음(fire-and-forget). */
  try {
    var _vk = "ax_visit_" + location.pathname;
    if (!sessionStorage.getItem(_vk)) {
      sessionStorage.setItem(_vk, "1");
      sb.rpc("ax_log_visit", { p_page: location.pathname }).then(function () {}, function () {});
    }
  } catch (e) { /* sessionStorage 차단 등 → 무시 */ }

  /* ───────── util ───────── */
  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }
  function q(sel) { return document.querySelector(sel); }
  function decimalsOf(v) { var p = String(v).split("."); return p.length > 1 ? p[1].length : 0; }
  function fmtDate(d) { if (!d) return ""; var p = String(d).split("T")[0].split("-"); return p.length === 3 ? p[0] + "." + p[1] + "." + p[2] : String(d); }
  function stagger(i, max) { var n = i % (max || 4); return n ? " d" + n : ""; }
  function arr(v) { return Array.isArray(v) ? v : []; }

  /* ───────── 렌더러 ───────── */
  function countAttrs(m) {
    return 'data-to="' + esc(m.value) + '"'
      + (m.prefix ? ' data-prefix="' + esc(m.prefix) + '"' : "")
      + ' data-group="' + (m.group_num ? "true" : "false") + '"'
      + ' data-decimals="' + decimalsOf(m.value) + '"';
  }
  function renderMetrics(rows) {
    var hero = rows.filter(function (m) { return m.section === "hero"; });
    var impact = rows.filter(function (m) { return m.section === "impact"; });
    var heroBox = q(".hero-stats");
    if (heroBox && hero.length) {
      heroBox.innerHTML = hero.map(function (m) {
        return '<div class="hs"><b class="count" ' + countAttrs(m) + (m.suffix ? ' data-suffix="' + esc(m.suffix) + '"' : "") + ">0</b><span>" + esc(m.label) + "</span></div>";
      }).join("");
    }
    var impBox = q("#impact .stat-grid");
    if (impBox && impact.length) {
      impBox.innerHTML = impact.map(function (m, i) {
        return '<div class="stat reveal' + stagger(i) + '"><div class="num"><span class="count" ' + countAttrs(m) + ">0</span>"
          + (m.suffix ? '<span class="unit">' + esc(m.suffix) + "</span>" : "") + "</div><div class=\"lab\">" + esc(m.label) + "</div></div>";
      }).join("");
    }
  }
  function renderNews(rows) {
    var box = q("#news .news-grid"); if (!box || !rows.length) return;
    box.innerHTML = rows.map(function (n, i) {
      var thumb = i % 3 === 1 ? "thumb t2" : i % 3 === 2 ? "thumb t3" : "thumb";
      var inner = '<div class="' + thumb + '"><span class="cat">' + esc(n.category || "소식") + "</span></div>"
        + '<div class="body"><div class="date">' + esc(fmtDate(n.news_date)) + "</div>"
        + "<h4>" + esc(n.title) + "</h4><p>" + esc(n.summary) + "</p>"
        + (n.url ? '<span class="more">자세히 <span class="arrow">→</span></span>' : "") + "</div>";
      if (n.url) return '<a class="news reveal' + stagger(i, 3) + '" href="' + esc(n.url) + '" target="_blank" rel="noopener">' + inner + "</a>";
      return '<article class="news reveal' + stagger(i, 3) + '">' + inner + "</article>";
    }).join("");
  }
  function renderPillars(rows) {
    var box = q(".pillars"); if (!box || !rows.length) return;
    box.innerHTML = rows.map(function (p, i) {
      var tags = arr(p.tags).map(function (t) { return "<span>" + esc(t) + "</span>"; }).join("");
      return '<div class="pcard reveal' + stagger(i, 3) + '"><div class="ic">' + esc(p.icon) + '</div><div class="en">' + esc(p.en_label) + "</div>"
        + "<h3>" + esc(p.title) + "</h3><p>" + esc(p.body) + "</p>"
        + (tags ? '<div class="tags">' + tags + "</div>" : "") + "</div>";
    }).join("");
  }
  function renderOrg(rows) {
    var box = q(".org-grid"); if (!box || !rows.length) return;
    box.innerHTML = rows.map(function (o, i) {
      return '<div class="team reveal' + stagger(i, 4) + '"><div class="tag">' + esc(o.tag) + "</div><h4>" + esc(o.title) + "</h4><p>" + esc(o.body) + "</p></div>";
    }).join("");
  }
  function renderRoadmap(rows) {
    var box = q(".road"); if (!box || !rows.length) return;
    box.innerHTML = rows.map(function (r, i) {
      var chips = arr(r.chips).map(function (c) { return "<span>" + esc(c) + "</span>"; }).join("");
      return '<div class="phase reveal' + stagger(i, 4) + '"><div class="yr"></div><div class="ylab display">' + esc(r.year_label) + "</div>"
        + '<div class="ptitle">' + esc(r.title) + "</div><p>" + esc(r.body) + "</p>"
        + (chips ? '<div class="chips">' + chips + "</div>" : "") + "</div>";
    }).join("");
  }
  function applySettings(map) {
    function look(key) { var p = key.split("."); var o = map[p[0]]; return o ? o[p[1]] : undefined; }
    [].forEach.call(document.querySelectorAll("[data-ax]"), function (el) {
      var v = look(el.getAttribute("data-ax")); if (v != null && v !== "") el.textContent = v;
    });
    [].forEach.call(document.querySelectorAll("[data-ax-href]"), function (el) {
      var v = look(el.getAttribute("data-ax-href")); if (v) el.setAttribute("href", v);
    });
    [].forEach.call(document.querySelectorAll("[data-ax-mailto]"), function (el) {
      var v = look(el.getAttribute("data-ax-mailto")); if (v) el.setAttribute("href", "mailto:" + v);
    });
    [].forEach.call(document.querySelectorAll("[data-ax-src]"), function (el) {
      var v = look(el.getAttribute("data-ax-src"));
      if (v) { el.src = v; el.style.display = "block"; var ph = el.parentElement && el.parentElement.querySelector(".ph"); if (ph) ph.style.display = "none"; }
    });
  }

  /* ───────── fetch & hydrate ───────── */
  function pub(t) { return sb.from(t).select("*").eq("published", true).order("sort_order", { ascending: true }); }
  Promise.all([
    sb.from("ax_settings").select("*"),
    pub("ax_metrics"),
    pub("ax_news"),
    pub("ax_pillars"),
    pub("ax_org"),
    pub("ax_roadmap")
  ]).then(function (res) {
    var set = res[0], met = res[1], news = res[2], pil = res[3], org = res[4], road = res[5];
    try {
      if (set && set.data && set.data.length) {
        var map = {}; set.data.forEach(function (row) { map[row.key] = row.value || {}; }); applySettings(map);
      }
      if (met && met.data && met.data.length) renderMetrics(met.data);
      if (news && news.data && news.data.length) renderNews(news.data);
      if (pil && pil.data && pil.data.length) renderPillars(pil.data);
      if (org && org.data && org.data.length) renderOrg(org.data);
      if (road && road.data && road.data.length) renderRoadmap(road.data);
      if (window.AX && window.AX.rescan) window.AX.rescan();
    } catch (e) { /* 렌더 실패 → 정적 폴백 유지 */ }
  }).catch(function () { /* 네트워크/RLS 오류 → 정적 폴백 유지 */ });
})();

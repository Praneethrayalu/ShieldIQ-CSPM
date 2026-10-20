/* ShieldIQ front-end: no framework, CSP-safe (no inline handlers). */
(function () {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const csrf = () => ($('meta[name="csrf-token"]') || {}).content || "";
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const jsonData = (id) => { const el = document.getElementById(id); try { return el ? JSON.parse(el.textContent) : null; } catch (e) { return null; } };

  // ---------- theme ----------
  // The new theme spreads as a circle from the toggle you pressed (shows where the change came from).
  const root = document.documentElement;
  const setThemeIcon = () => $$("[data-theme-toggle]").forEach((b) => {
    const dark = root.dataset.theme === "dark";
    b.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
    b.title = dark ? "Light theme" : "Dark theme";
    b.innerHTML = dark
      ? '<svg class="svg-ic" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>'
      : '<svg class="svg-ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
  });
  const setMeta = () => { const m = $('meta[name="theme-color"]'); if (m) m.content = root.dataset.theme === "dark" ? "#0f100d" : "#0d0e0b"; };
  setThemeIcon(); setMeta();
  const applyTheme = (t) => {
    root.dataset.theme = t;
    try { localStorage.setItem("shieldiq-theme", t); } catch (e) {}
    setThemeIcon(); setMeta();
    if (document.querySelector(".app")) {  // signed in: remember it on the account too
      fetch("/settings/theme", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRFToken": csrf() },
        body: JSON.stringify({ theme: t }) }).then(() => { const r = $('input[name="theme"][value="' + t + '"]'); if (r) r.checked = true; }).catch(() => {});
    }
  };
  const reduced = () => window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  $$("[data-theme-toggle]").forEach((b) => b.addEventListener("click", (ev) => {
    const next = root.dataset.theme === "dark" ? "light" : "dark";
    if (!document.startViewTransition || reduced()) { applyTheme(next); return; }
    const r = b.getBoundingClientRect(), x = r.left + r.width / 2, y = r.top + r.height / 2;
    const rad = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
    root.style.setProperty("--vt-x", x + "px"); root.style.setProperty("--vt-y", y + "px"); root.style.setProperty("--vt-r", rad + "px");
    root.classList.add("theme-vt");
    const t = document.startViewTransition(() => applyTheme(next));
    t.finished.finally(() => root.classList.remove("theme-vt"));
  }));

  // ---------- sidebar / menus / flashes ----------
  $$("[data-toggle-sidebar]").forEach((b) => b.addEventListener("click", (e) => { e.stopPropagation(); $("#sidebar").classList.toggle("open"); }));
  document.addEventListener("click", (e) => { const sb = $("#sidebar"); if (sb && sb.classList.contains("open") && !sb.contains(e.target)) sb.classList.remove("open"); });
  const um = $("[data-user-menu]");
  if (um) {
    $("button.avatar", um).addEventListener("click", (e) => { e.stopPropagation(); um.classList.toggle("open"); });
    document.addEventListener("click", (e) => { if (!um.contains(e.target)) um.classList.remove("open"); });
  }
  const dismiss = (f) => { f.classList.add("out"); setTimeout(() => f.remove(), 360); };
  $$("[data-flash]").forEach((f) => {
    $("[data-dismiss]", f).addEventListener("click", () => dismiss(f));
    if (!f.classList.contains("error")) setTimeout(() => dismiss(f), 7000);
  });

  // ---------- forms: confirm + loading state ----------
  $$("form[data-confirm]").forEach((f) => f.addEventListener("submit", (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));
  $$("form[data-loading]").forEach((f) => f.addEventListener("submit", (e) => {
    if (e.defaultPrevented) return;
    const b = $('button[type="submit"]', f);
    if (b) { setTimeout(() => { b.classList.add("loading"); b.innerHTML = '<span class="spinner"></span> ' + esc(f.dataset.loading); }, 0); }
  }));
  $$("[data-autosubmit-select]").forEach((s) => s.addEventListener("change", () => s.form.submit()));
  $$("form[data-autosubmit] select").forEach((s) => s.addEventListener("change", () => s.form.submit()));

  // ---------- bulk select ----------
  const all = $("[data-check-all]");
  const updateCount = () => { const n = $$("[data-row-check]:checked").length; const c = $("[data-selected-count]"); if (c) c.textContent = n + " selected"; };
  if (all) all.addEventListener("change", () => { $$("[data-row-check]").forEach((c) => (c.checked = all.checked)); updateCount(); });
  $$("[data-row-check]").forEach((c) => c.addEventListener("change", updateCount));

  // ---------- tabs ----------
  $$("[data-tabs]").forEach((tabs) => {
    const scope = tabs.parentElement;
    $$("[data-tab]", tabs).forEach((t) => t.addEventListener("click", () => {
      $$("[data-tab]", tabs).forEach((x) => x.classList.toggle("active", x === t));
      $$("[data-panel]", scope).forEach((p) => p.classList.toggle("active", p.dataset.panel === t.dataset.tab));
    }));
  });

  // ---------- copy buttons on code blocks ----------
  $$("pre[data-copy]").forEach((pre) => {
    const b = document.createElement("button");
    b.className = "copy-btn"; b.type = "button"; b.textContent = "Copy";
    b.addEventListener("click", async () => {
      const txt = pre.innerText.replace(/Copy(ed)?$/, "").trim();
      try { await navigator.clipboard.writeText(txt); } catch (e) {
        const ta = document.createElement("textarea"); ta.value = txt; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove();
      }
      b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1500);
    });
    pre.appendChild(b);
  });

  // ---------- modals ----------
  const openModal = (m) => { m.classList.add("open"); const i = $("input:not([type=hidden]), select", m); if (i) setTimeout(() => i.focus(), 50); };
  const closeModal = (m) => m.classList.remove("open");
  $$("[data-open-modal]").forEach((b) => b.addEventListener("click", () => openModal(document.getElementById(b.dataset.openModal))));
  $$("[data-modal]").forEach((m) => {
    m.addEventListener("click", (e) => { if (e.target === m) closeModal(m); });
    $$("[data-close-modal]", m).forEach((b) => b.addEventListener("click", () => closeModal(m)));
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") $$("[data-modal].open").forEach(closeModal); });

  // ---------- dropzones ----------
  $$("[data-dropzone]").forEach((dz) => {
    const input = $("input[type=file]", dz), label = $("[data-dz-label]", dz);
    const show = () => { if (input.files.length) label.textContent = "Selected: " + input.files[0].name; };
    input.addEventListener("change", show);
    ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
    ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("drag"); }));
    dz.addEventListener("drop", (e) => { if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; show(); } });
  });

  // ---------- connect integration form ----------
  const cf = $("#connect-form");
  if (cf) {
    const prov = $("#cf-provider"), templates = jsonData("template-urls") || {};
    const sync = () => {
      const opt = prov.selectedOptions[0], live = opt && opt.dataset.live === "1";
      const liveLabel = $("[data-live-only]", cf);
      liveLabel.style.display = live ? "" : "none";
      let mode = ($('input[name="mode"]:checked', cf) || {}).value;
      if (!live && mode === "live") { $('input[value="demo"]', cf).checked = true; mode = "demo"; }
      $$("[data-mode-panel]", cf).forEach((p) => (p.hidden = p.dataset.modePanel !== mode));
      $$("[data-live-provider]", cf).forEach((p) => (p.hidden = p.dataset.liveProvider !== prov.value));
      const tl = $("[data-template-link]", cf); if (tl) tl.href = templates[prov.value] || "#";
    };
    prov.addEventListener("change", sync);
    $$('input[name="mode"]', cf).forEach((r) => r.addEventListener("change", sync));
    sync();
  }

  // ---------- attack path filter ----------
  $$("[data-path-filter]").forEach((b) => b.addEventListener("click", () => {
    $$("[data-path-filter]").forEach((x) => x.classList.toggle("active", x === b));
    $$("[data-path-sev]").forEach((p) => (p.style.display = !b.dataset.pathFilter || p.dataset.pathSev === b.dataset.pathFilter ? "" : "none"));
  }));

  // ---------- command palette ----------
  const pal = $("#palette"), pin = $("#palette-input"), plist = $("#palette-list");
  const nav = jsonData("nav-data") || {};
  let items = [], sel = 0, timer = null, lastFindings = [];
  const render = (findings) => {
    lastFindings = findings || [];
    const q = (pin.value || "").toLowerCase();
    const pages = Object.entries(nav).filter(([k]) => k.toLowerCase().includes(q)).map(([k, v]) => ({ label: k, url: v, kind: "Go to" }));
    items = pages.concat((findings || []).map((f) => ({ label: "#" + f.id + " " + f.title, sub: f.resource, url: "/findings/" + f.id, kind: f.severity })));
    sel = Math.min(sel, Math.max(items.length - 1, 0));
    let html = "";
    if (pages.length) html += '<div class="pal-sec">Pages</div>';
    items.forEach((it, i) => {
      if (i === pages.length && findings && findings.length) html += '<div class="pal-sec">Findings</div>';
      html += '<div class="pal-item' + (i === sel ? " sel" : "") + '" data-i="' + i + '">' +
        (it.kind === "Go to" ? '<span class="tag">Go to</span>' : '<span class="badge sev-' + esc(it.kind) + '">' + esc(it.kind) + "</span>") +
        '<div style="min-width:0"><div class="ellipsis">' + esc(it.label) + "</div>" + (it.sub ? '<div class="res">' + esc(it.sub) + "</div>" : "") + "</div></div>";
    });
    plist.innerHTML = html || '<div class="empty small">No matches</div>';
    $$(".pal-item", plist).forEach((el) => el.addEventListener("click", () => (location.href = items[+el.dataset.i].url)));
  };
  const search = () => {
    clearTimeout(timer);
    const q = pin.value.trim();
    if (q.length < 2) return render([]);
    timer = setTimeout(() => fetch("/api/v1/search?q=" + encodeURIComponent(q), { credentials: "same-origin" })
      .then((r) => (r.ok ? r.json() : { results: [] })).then((d) => render(d.results)).catch(() => render([])), 160);
  };
  const openPalette = () => { if (!pal) return; pin.value = ""; sel = 0; render([]); openModal(pal); };
  $$("[data-open-palette]").forEach((b) => b.addEventListener("click", openPalette));
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); }
  });
  if (pin) {
    pin.addEventListener("input", () => { sel = 0; render(lastFindings); search(); });
    pin.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { sel = Math.min(sel + 1, items.length - 1); render(lastFindings); e.preventDefault(); }
      if (e.key === "ArrowUp") { sel = Math.max(sel - 1, 0); render(lastFindings); e.preventDefault(); }
      if (e.key === "Enter" && items[sel]) location.href = items[sel].url;
    });
  }

  // ---------- copilot ----------
  const cfg = jsonData("copilot-cfg");
  if (cfg) {
    const box = $("#messages"), form = $("#composer"), input = $("#chat-input");
    const history = [];
    const md = (text) => {
      let s = esc(text);
      s = s.replace(/^(\s*)[-*] (?=\S)/gm, "$1• ");
      s = s.replace(/```(?:\w+)?\n([\s\S]*?)```/g, (m, c) => "<pre><code>" + c + "</code></pre>");
      s = s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/`([^`]+)`/g, "<code>$1</code>");
      s = s.replace(/#(\d+)\b/g, '<a class="link" href="/findings/$1">#$1</a>');
      return s.split(/(<pre>[\s\S]*?<\/pre>)/).map((p) => (p.startsWith("<pre>") ? p : p.replace(/\n/g, "<br>"))).join("");
    };
    const add = (role, html) => {
      const el = document.createElement("div"); el.className = "msg" + (role === "user" ? " user" : "");
      el.innerHTML = '<div class="who">' + (role === "user" ? "You" : "Copilot") + '</div><div class="bubble">' + html + "</div>";
      box.appendChild(el); box.scrollTop = box.scrollHeight; return el;
    };
    const ask = async (q) => {
      if (!q.trim() || busy) return;
      busy = true;
      add("user", esc(q)); input.value = "";
      const pending = add("bot", '<span class="typing" role="status" aria-label="Reading your findings"></span>');
      try {
        const r = await fetch(cfg.url, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRFToken": csrf() },
          body: JSON.stringify({ message: q, history }) });
        const d = await r.json();
        const ans = r.ok ? d.answer : "Error: " + (d.error || r.status);
        const foot = d.engine ? '<div class="foot">engine: ' + esc(d.engine) + (d.note ? " · " + esc(d.note) : "") + "</div>" : "";
        history.push({ role: "user", content: q }, { role: "assistant", content: ans });
        await stream($(".bubble", pending), ans, foot);
      } catch (e) { $(".bubble", pending).textContent = "Network error, please try again."; }
      busy = false; box.scrollTop = box.scrollHeight;
    };
    // Stream the answer in, word by word, fast (~90 words/s, time-based so refresh rate does not matter):
    // you start reading the first line at once while longer answers unfold. Click the answer to show it all.
    const stream = (el, text, foot) => new Promise((resolve) => {
      const M = window.SiqMotion;
      if (!M || reduced()) { el.innerHTML = md(text) + foot; resolve(); return; }
      const words = text.split(/(\s+)/), total = words.length; let shown = -1, t0 = null, done = false;
      const finish = () => { if (done) return; done = true; el.innerHTML = md(text) + foot; box.scrollTop = box.scrollHeight; resolve(); };
      el.addEventListener("click", finish, { once: true });
      M.tick((now) => {
        if (done) return false;
        if (t0 === null) t0 = now;
        const n = Math.min(total, Math.floor((now - t0) / 1000 * 180));
        if (n !== shown) { shown = n; el.innerHTML = md(words.slice(0, n).join("")) + '<span class="caret" aria-hidden="true"></span>'; box.scrollTop = box.scrollHeight; }
        if (n >= total) { finish(); return false; }
      });
    });
    let busy = false;
    form.addEventListener("submit", (e) => { e.preventDefault(); ask(input.value); });
    $$("[data-suggest]").forEach((b) => b.addEventListener("click", () => ask(b.dataset.suggest)));
  }

  // ---------- state change: after a successful action, mark what changed (once, 900 ms) ----------
  if ($(".flash.success")) $$(".page-head .badge[class*='st-']").forEach((b) => b.classList.add("changed"));

  // ---------- page-level progress ----------
  // thin progress bar while the next page loads
  const DOWNLOAD = /\/(export\/|reports\/\d+\/download|findings\/\d+\/script|integrations\/(\d+\/inventory|template\/)|scanners\/sample\/)/;
  const startLoading = () => { root.classList.add("is-loading"); clearTimeout(startLoading.t); startLoading.t = setTimeout(() => root.classList.remove("is-loading"), 9000); };
  document.addEventListener("click", (e) => {
    const a = e.target.closest && e.target.closest("a[href]");
    if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const href = a.getAttribute("href");
    if (!href || href.startsWith("#") || a.target === "_blank" || a.hasAttribute("download") || a.origin !== location.origin || DOWNLOAD.test(a.pathname)) return;
    if (a.pathname === location.pathname && a.search === location.search && a.hash) return;
    startLoading();
  });
  document.addEventListener("submit", (e) => { if (!e.defaultPrevented && !(e.target.method || "").toLowerCase().includes("dialog")) setTimeout(() => { if (!e.defaultPrevented && !e.target.closest("#composer")) startLoading(); }, 0); });
  window.addEventListener("pageshow", () => root.classList.remove("is-loading"));

  // saving "Default theme" in Settings also updates this browser's remembered theme
  $$('input[name="theme"]').forEach((r) => r.form && r.form.addEventListener("submit", () => {
    const c = $('input[name="theme"]:checked', r.form); if (c) { try { localStorage.setItem("shieldiq-theme", c.value); } catch (e) {} }
  }));

  // demo credentials helper on the sign-in page
  $$("[data-fill-demo]").forEach((b) => b.addEventListener("click", () => {
    const em = $("#email"), pw = $("#password");
    if (!em || !pw) return;
    em.value = b.dataset.email; pw.value = b.dataset.password;
    const box = b.closest(".demo-box"); if (box) box.classList.add("filled");
    const submit = $('form button[type="submit"]'); if (submit) submit.focus();
  }));
})();

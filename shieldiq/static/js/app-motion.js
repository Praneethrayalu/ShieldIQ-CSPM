/* ShieldIQ in-app motion (on top of motion.js). Subtle, purposeful, time-based:
   - data blocks reveal in reading order          - bars grow to their value
   - counts roll on odometers                      - the score dial sweeps to its position
   - attack-path hops appear in attack order       - the nav marker glides from the last page
   - a fixed finding is struck through             - copilot answers stream (app.js)
   All of it collapses to the end state under prefers-reduced-motion. */
(function () {
  "use strict";
  var M = window.SiqMotion; if (!M) return;
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var $ = function (s, r) { return (r || document).querySelector(s); };
  if (document.body.classList.contains("lp")) return;

  /* nav marker: glides from where you were to where you are (orientation between pages) */
  var nav = $(".sidebar .nav"), active = nav && $("a.active", nav);
  if (nav && active) {
    var ind = document.createElement("span"); ind.className = "nav-ind no-anim"; ind.setAttribute("aria-hidden", "true");
    nav.appendChild(ind);
    var y = active.offsetTop + (active.offsetHeight - 20) / 2, prev = null;
    try { prev = sessionStorage.getItem("siq-nav-y"); sessionStorage.setItem("siq-nav-y", String(y)); } catch (e) {}
    ind.style.setProperty("--y", (prev != null && !M.reduced ? prev : y) + "px");
    requestAnimationFrame(function () { requestAnimationFrame(function () { ind.classList.remove("no-anim"); ind.style.setProperty("--y", y + "px"); }); });
  }

  /* page title: words rise out of a mask (the one moment of emphasis per page) */
  $$("[data-split-h], .page-head h1").slice(0, 1).forEach(function (h) { if (!h.children.length) M.reveal(h, { stagger: 50, dur: 900 }); });

  function activate(el) {
    if (el.__done) return; el.__done = true;
    el.classList.add("in");
    $$("[data-grow]", el).forEach(function (g, i) { g.style.setProperty("--d", (120 + i * 70) + "ms"); g.classList.add("in"); });
    $$("[data-stagger]", el).forEach(function (s, i) { s.style.setProperty("--d", (80 + i * 55) + "ms"); s.classList.add("in"); });
    $$("[data-odo]", el).forEach(function (o) { var v = o.getAttribute("data-odo"); if (!o.__noOdo && /^\d+$/.test(v)) M.odometer(o, v, { dur: 1400, loops: 1 }); });
    $$("[data-spark]", el).forEach(function (s) { s.classList.add("in"); });
    $$("[data-gauge]", el).forEach(gauge);
    $$(".chain", el).forEach(chain);
  }
  function gauge(g) {
    var v = +g.getAttribute("data-gauge") || 0, arc = $("[data-gauge-arc]", g); if (!arc) return;
    var A = +arc.dataset.a, C = +arc.dataset.c;
    arc.setAttribute("stroke-dasharray", "0 " + C);
    M.tween({ dur: 1700, delay: 150, ease: "outExpo", update: function (e) { arc.setAttribute("stroke-dasharray", (A * v / 100 * e).toFixed(2) + " " + C); } });
  }
  function chain(c) {
    $$(":scope > *", c).forEach(function (k, i) { k.style.setProperty("--d", (i * 90) + "ms"); });
    c.classList.add("in");
  }

  /* reveal order: everything already on screen goes in reading order with a short stagger,
     the rest as it scrolls in */
  var blocks = $$("[data-reveal]");
  var vh = window.innerHeight, first = [], later = [];
  blocks.forEach(function (b) { (b.getBoundingClientRect().top < vh * .92 ? first : later).push(b); });
  first.forEach(function (b, i) { b.style.setProperty("--d", (i * 90) + "ms"); requestAnimationFrame(function () { requestAnimationFrame(function () { activate(b); }); }); });
  M.inView(later, activate, { margin: "0px 0px -8% 0px" });
  /* charts and chains that are not inside a reveal block still animate when seen */
  M.inView($$(".chain, [data-gauge], [data-spark]").filter(function (el) { return !el.closest("[data-reveal]"); }), function (el) { if (el.classList.contains("chain")) chain(el); else if (el.hasAttribute("data-gauge")) gauge(el); else el.classList.add("in"); });
  M.inView($$("[data-grow]").filter(function (el) { return !el.closest("[data-reveal]"); }), function (el) { el.classList.add("in"); });

  /* bulk "mark resolved": selected rows are struck through and slide out before the page
     reloads without them (cause -> effect) */
  $$("form[data-bulk]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      var sel = form.querySelector("select[name=status]"), rows = $$("input[data-row-check]:checked", form).map(function (c) { return c.closest("tr"); });
      if (!sel || sel.value !== "resolved" || !rows.length || M.reduced || form.__go) return;
      e.preventDefault(); form.__go = true;
      rows.forEach(function (r, i) {
        var cell = r.querySelector(".title-cell a"); if (cell) cell.classList.add("resolving");
        setTimeout(function () { r.style.transition = "opacity .45s var(--ease), transform .55s var(--ease)"; r.style.opacity = "0"; r.style.transform = "translateX(24px)"; }, 380 + i * 40);
      });
      setTimeout(function () { HTMLFormElement.prototype.submit.call(form); }, 380 + rows.length * 40 + 420);
    });
  });

  /* tracked counts (open attack paths): if the number dropped since you last saw it, it rolls down
     from the old value and says how many paths were cut (cause -> effect across pages) */
  $$("[data-track]").forEach(function (el) {
    var key = "siq-track-" + el.getAttribute("data-track"), now = +el.getAttribute("data-value"), before = null;
    try { before = sessionStorage.getItem(key); sessionStorage.setItem(key, String(now)); } catch (e) {}
    if (before == null || +before === now) return;
    before = +before;
    var chip = el.parentNode.querySelector("[data-track-delta]");
    el.removeAttribute("data-odo"); el.__noOdo = true;
    el.textContent = before;
    setTimeout(function () { M.count(el, before, now, { dur: 1600, ease: "outExpo" }); }, 500);
    if (chip) { chip.hidden = false; chip.className = "track-delta " + (now < before ? "good" : "bad"); chip.textContent = now < before ? "−" + (before - now) + " cut since last look" : "+" + (now - before) + " new since last look"; }
  });

  /* auto-fix came back verified: strike the finding's title and stamp it (the fix removed it) */
  var ok = $$(".flash.success span").some(function (s) { return /verified by re-scan/i.test(s.textContent); });
  if (ok) {
    var h = $(".page-head h1");
    if (h && !M.reduced) {
      var span = document.createElement("span"); span.className = "strike-text"; span.textContent = h.textContent; h.textContent = ""; h.appendChild(span);
      requestAnimationFrame(function () { requestAnimationFrame(function () { span.classList.add("on"); }); });
    } else if (h) { h.classList.add("is-struck"); }
  }
})();

/* Setup guides: provider tabs (deep-linkable: /guides#aws) and scroll motion.
   - step numbers draw their ring as each step arrives (you see which step you have reached)
   - the vertical line through the steps fills with scroll (progress through the setup)
   - after-connect screenshots slide in beside their text (the screen that matches the words) */
(function () {
  "use strict";
  var M = window.SiqMotion; if (!M) return;
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var tabs = $$("[data-gd-tab]"), panels = $$("[data-gd-panel]"), ind = document.querySelector("[data-gd-ind]");
  function place(btn, instant) {
    if (!ind || !btn) return;
    ind.style.transition = instant ? "none" : "";
    ind.style.width = btn.offsetWidth + "px";
    ind.style.transform = "translate3d(" + btn.offsetLeft + "px," + btn.offsetTop + "px,0)";
    ind.style.height = btn.offsetHeight + "px";
  }
  function select(key, instant, focus) {
    var found = false;
    tabs.forEach(function (t) { var on = t.dataset.gdTab === key; t.setAttribute("aria-selected", on ? "true" : "false"); t.tabIndex = on ? 0 : -1; if (on) { found = true; place(t, instant); if (focus) t.focus(); } });
    if (!found) return select(tabs[0].dataset.gdTab, instant);
    panels.forEach(function (p) {
      var on = p.dataset.gdPanel === key; p.hidden = !on;
      if (on) { $$("[data-gs]", p).forEach(function (s) { if (!s.__seen && !M.reduced && !instant) { s.classList.remove("in"); } }); M.refresh(); observe(p); }
    });
  }
  tabs.forEach(function (t, i) {
    t.addEventListener("click", function () { select(t.dataset.gdTab); try { history.replaceState(null, "", "#" + t.dataset.gdTab); } catch (e) {} });
    t.addEventListener("keydown", function (e) {
      var k = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0; if (!k) return;
      e.preventDefault(); var n = tabs[(i + k + tabs.length) % tabs.length]; select(n.dataset.gdTab, false, true);
    });
  });
  window.addEventListener("resize", function () { place(tabs.filter(function (t) { return t.getAttribute("aria-selected") === "true"; })[0], true); });
  var observed = new Set();
  function observe(panel) {
    if (observed.has(panel)) return; observed.add(panel);
    M.inView($$("[data-gs]", panel), function (s) { s.__seen = true; s.classList.add("in"); }, { margin: "0px 0px -15% 0px" });
    var list = panel.querySelector("[data-gsteps]"), fill = panel.querySelector("[data-gs-fill]");
    if (list && fill) M.scrollSmooth(list, function (p) { fill.style.transform = "scaleY(" + M.clamp(p * 1.6 - .25, 0, 1).toFixed(4) + ")"; }, "through", .14);
  }
  var start = (location.hash || "").slice(1);
  select(start && tabs.some(function (t) { return t.dataset.gdTab === start; }) ? start : tabs[0].dataset.gdTab, true);
  if (document.fonts) document.fonts.ready.then(function () { place(tabs.filter(function (t) { return t.getAttribute("aria-selected") === "true"; })[0], true); });
  M.inView($$("[data-af]"), function (el) { el.classList.add("in"); }, { margin: "0px 0px -18% 0px" });
})();

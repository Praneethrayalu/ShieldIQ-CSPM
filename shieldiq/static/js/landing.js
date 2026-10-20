/* ShieldIQ landing — round 5 "industrial blueprint". Runs on the shared time-based engine (motion.js):
   every animation is driven by rAF timestamps, CSS transitions or the Web Animations API, so it plays at the same
   speed on 60, 120 or 144 Hz screens. Only transform and opacity animate (plus one-shot SVG line draws).
   prefers-reduced-motion shows each end state at once. See docs/DESIGN.md "Motion". */
(function () {
  "use strict";
  var M = window.SiqMotion; if (!M) return;
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var raf2 = function (fn) { requestAnimationFrame(function () { requestAnimationFrame(fn); }); };
  var canAnim = !!Element.prototype.animate;

  /* sticky nav: denser once the page moves under it */
  var nav = $("[data-nav]");
  if (nav) {
    var navQ = false, setNav = function () { navQ = false; nav.classList.toggle("scrolled", (window.scrollY || 0) > 8); };
    window.addEventListener("scroll", function () { if (!navQ) { navQ = true; requestAnimationFrame(setNav); } }, { passive: true }); setNav();
  }

  /* hero: blueprint lines draw, the headline rises line by line out of its mask, then the rest settles in */
  var h1 = $(".x-h1");
  if (h1) {
    $$(".ln", h1).forEach(function (ln, i) {
      var s = document.createElement("span"); while (ln.firstChild) s.appendChild(ln.firstChild); ln.appendChild(s);
      s.style.setProperty("--d", (180 + i * 110) + "ms");
    });
  }
  $$(".x-lines i").forEach(function (l, i) { l.style.setProperty("--d", (i * 90) + "ms"); });
  $$("[data-a]").forEach(function (el) { el.style.setProperty("--d", (+el.getAttribute("data-a") * 90 + 120) + "ms"); });
  raf2(function () {
    if (h1) h1.classList.add("in");
    var ls = $(".x-lines"); if (ls) ls.classList.add("in");
    $$("[data-a]").forEach(function (el) { el.classList.add("in"); });
    var oi = $("[data-obj-img]"); if (oi) oi.classList.add("in");
    $$(".module.assemble").forEach(function (m) { m.classList.add("in"); });
  });

  /* hero object: scroll-scrubbed (it turns and sinks as you leave the hero) plus a slow idle float */
  var hero = $("[data-hero]"), objImg = $("[data-obj-img]"), modSvg = objImg && $(".module", objImg);
  if (hero && objImg && !M.reduced) {
    var sp = 0, visible = true, dt = M.dt();
    M.scrollSmooth(hero, function (p) { sp = p; }, "leave", .12);
    if ("IntersectionObserver" in window) new IntersectionObserver(function (e) { visible = e[0].isIntersecting; }).observe(hero);
    var t0 = null;
    M.tick(function (now) {
      if (!visible) return;
      if (t0 === null) t0 = now;
      var t = (now - t0) / 1000, fl = Math.sin(t * 0.9) * 6;
      objImg.style.setProperty("--oy", (fl + sp * 120).toFixed(2) + "px");
      objImg.style.setProperty("--or8", (Math.sin(t * 0.6) * 0.6 - sp * 8).toFixed(3) + "deg");
      objImg.style.setProperty("--os", (1 - sp * 0.08).toFixed(4));
      /* exploded view: the layers breathe apart slightly at rest and separate fully as you scroll away */
      var intro = M.ease.outExpo ? M.ease.outExpo(M.clamp((t - 0.9) / 1.6, 0, 1)) : 1;
      if (modSvg) modSvg.style.setProperty("--ex", (intro * (0.32 + Math.sin(t * 1.1) * 0.06) + sp * 1.3).toFixed(4));
    });
  }

  /* hazard band: a time-based marquee (px per second), paused off-screen */
  $$("[data-marquee]").forEach(function (track) {
    if (M.reduced) return;
    var x = 0, w = 0, on = true, last = null, speed = 46;
    var measure = function () { var row = track.firstElementChild; w = row ? row.getBoundingClientRect().width : 0; };
    measure(); window.addEventListener("resize", measure);
    if ("IntersectionObserver" in window) new IntersectionObserver(function (e) { on = e[0].isIntersecting; last = null; }).observe(track);
    M.tick(function (now) {
      if (!on || !w) return;
      var d = last === null ? 0 : Math.min(64, now - last); last = now;
      x -= speed * d / 1000; if (x <= -w) x += w;
      track.style.transform = "translate3d(" + x.toFixed(2) + "px,0,0)";
    });
  });

  /* statement: words light up as you read down the page (scroll-scrubbed) */
  $$("[data-words]").forEach(function (el) {
    var words = [];
    var walk = function (node) {
      Array.prototype.slice.call(node.childNodes).forEach(function (n) {
        if (n.nodeType === 3) {
          var frag = document.createDocumentFragment();
          n.textContent.split(/(\s+)/).forEach(function (w) {
            if (!w) return;
            if (/^\s+$/.test(w)) { frag.appendChild(document.createTextNode(" ")); return; }
            var s = document.createElement("span"); s.className = "wd"; s.textContent = w; frag.appendChild(s); words.push(s);
          });
          node.replaceChild(frag, n);
        } else if (n.nodeType === 1) walk(n);
      });
    };
    walk(el);
    if (M.reduced) { words.forEach(function (w) { w.classList.add("on"); }); return; }
    var lit = 0;
    M.scroll(el, function (p) {
      var n = Math.round(M.clamp((p - 0.18) / 0.42, 0, 1) * words.length);
      if (n === lit) return;
      for (var i = Math.min(n, lit); i < Math.max(n, lit); i++) words[i].classList.toggle("on", i < n);
      lit = n;
    }, "through");
  });

  /* reveals: groups stagger their cells in; numbers count up once */
  M.inView($$("[data-rs]"), function (g) {
    $$(":scope > *", g).forEach(function (c, i) { c.style.setProperty("--d", (i * 70) + "ms"); raf2(function () { c.classList.add("in"); }); });
  }, { margin: "0px 0px -8% 0px" });
  M.inView($$("[data-r]"), function (el) { el.classList.add("in"); });
  M.inView($$("[data-count]"), function (el) {
    var to = +el.getAttribute("data-count"); if (!isFinite(to)) return;
    M.count(el, 0, to, { dur: 1400 });
  }, { margin: "0px 0px -10% 0px" });

  /* round 6: section labels settle their tracking; the CTA headline rises out of its mask */
  M.inView($$(".x-sec-meta"), function (el) { el.classList.add("in"); }, { margin: "0px 0px -10% 0px" });
  var ctaH = $(".x-cta-h");
  if (ctaH) {
    var cw = document.createElement("span"); cw.className = "cw";
    while (ctaH.firstChild) cw.appendChild(ctaH.firstChild);
    ctaH.appendChild(cw);
    M.inView(ctaH, function (el) { el.classList.add("in"); }, { margin: "0px 0px -14% 0px" });
  }

  /* magnetic primary buttons (desktop pointers only) */
  if (M.magnetic) $$(".x-btn:not(.ghost), .x-pill").forEach(function (b) { M.magnetic(b, .22); });

  /* exploded stack: the four plates pull apart as the section scrolls through */
  var stackWrap = $("[data-stack]"), stackSvg = stackWrap && $("svg", stackWrap);
  if (stackSvg) {
    if (M.reduced) stackSvg.style.setProperty("--ex", "1");
    else M.scrollSmooth(stackWrap, function (p) { stackSvg.style.setProperty("--ex", M.clamp((p - .12) / .5, 0, 1).toFixed(4)); }, "through", .1);
  }

  /* ---------------------------------------------------------------- pinned story */
  var story = $("[data-story]"); if (!story) return;
  var svg = $("#estate"), steps = $$("[data-step]", story), bar = $("[data-story-bar]"), stage = $("[data-stage]");
  var label = $("[data-scene-label]"), roIssues = $("[data-ro-issues]"), roScore = $("[data-ro-score]"), roStatus = $("[data-ro-status]");
  var NAMES = ["", "Connect", "Scan", "Prioritise", "Fix", "Prove"];
  var STATUS = ["", "Connecting", "Scanning", "Path found", "Path cut", "Verified"];
  var pf = roIssues ? +roIssues.getAttribute("data-from") : 0;
  var sb = roScore ? +roScore.getAttribute("data-from") : 0, sa = roScore ? +roScore.getAttribute("data-to") : 0;
  var desktop = window.matchMedia("(min-width: 1101px)");

  /* which blocks carry issues: path blocks with a live issue badge, plus two estate blocks (the demo has issues
     all over the account, not just on this path) */
  var blocks = svg ? $$(".blk", svg) : [];
  var hotPath = [];
  if (svg) {
    $$(".bdg", svg).forEach(function (b) {
      var k = b.getAttribute("data-b"), blk = $('.blk[data-b="' + k + '"]', svg), lb = $('.lbl[data-l="' + k + '"]', svg);
      if (blk) { blk.classList.add("hot"); hotPath.push(blk); }
      if (lb) lb.classList.add("hot");
    });
    ["db", "k8s"].forEach(function (k) { var b = $('.blk[data-b="' + k + '"]', svg); if (b) b.classList.add("hot", "hot-decor"); });
    /* assembly order and scan timing follow each block's position, left to right */
    var xs = blocks.map(function (b) { try { return b.getBBox().x; } catch (e) { return 0; } });
    var mn = Math.min.apply(null, xs), mx = Math.max.apply(null, xs) || 1;
    blocks.forEach(function (b, i) {
      var f = (xs[i] - mn) / Math.max(1, mx - mn);
      b.style.setProperty("--bd", Math.round(f * 520) + "ms");
      b.style.setProperty("--od", Math.round(120 + f * 1300) + "ms");
      var bd = $('.bdg[data-b="' + b.getAttribute("data-b") + '"]', svg); if (bd) bd.style.setProperty("--od", Math.round(260 + f * 1300) + "ms");
    });
  }

  /* flow packets: small squares running along the attack path (WAAPI transforms) */
  var flowAnims = [];
  function startFlow() {
    if (!svg || flowAnims.length || M.reduced || !canAnim) return;
    var pts = (svg.getAttribute("data-path") || "").trim().split(/\s+/).map(function (p) { var a = p.split(","); return [+a[0], +a[1]]; });
    if (pts.length < 2) return;
    var lens = [], tot = 0;
    for (var i = 1; i < pts.length; i++) { var l = Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]); lens.push(l); tot += l; }
    var kf = [{ transform: "translate(" + pts[0][0] + "px," + pts[0][1] + "px)", offset: 0, opacity: 0 }], acc = 0;
    kf.push({ transform: "translate(" + pts[0][0] + "px," + pts[0][1] + "px)", offset: 0.001, opacity: 1 });
    for (var j = 1; j < pts.length; j++) { acc += lens[j - 1]; kf.push({ transform: "translate(" + pts[j][0] + "px," + pts[j][1] + "px)", offset: Math.min(1, acc / tot), opacity: j === pts.length - 1 ? 0 : 1 }); }
    var g = $(".ap-flow", svg), NS = "http://www.w3.org/2000/svg";
    for (var k = 0; k < 3; k++) {
      var r = document.createElementNS(NS, "rect");
      r.setAttribute("x", "-3"); r.setAttribute("y", "-3"); r.setAttribute("width", "6"); r.setAttribute("height", "6");
      g.appendChild(r);
      flowAnims.push(r.animate(kf, { duration: 2600, iterations: Infinity, delay: k * 870, easing: "linear", fill: "backwards" }));
    }
  }
  function stopFlow() { flowAnims.forEach(function (a) { a.cancel(); }); flowAnims = []; var g = svg && $(".ap-flow", svg); if (g) g.textContent = ""; }

  function sweep(proof) {
    if (!svg || M.reduced || !canAnim) return;
    var sc = $(".scan", svg), v = (svg.getAttribute("data-scan") || "0,0").split(",");
    svg.classList.toggle("proof", !!proof);
    sc.animate([
      { transform: "translate(0px,0px)", opacity: 0 }, { opacity: 1, offset: .08 }, { opacity: 1, offset: .88 },
      { transform: "translate(" + v[0] + "px," + v[1] + "px)", opacity: 0 }
    ], { duration: 1700, easing: "cubic-bezier(.65,0,.35,1)" });
  }

  var counters = {};
  function roll(el, key, to) {
    if (!el) return;
    var from = +el.textContent || 0; if (from === to) return;
    if (counters[key]) counters[key].stop();
    counters[key] = M.count(el, from, to, { dur: 900 });
  }

  /* pixel diagrams under the scene: Read → Check → Chain → Cut → Prove */
  var PX = {
    1: { a: "all", o: [] },
    2: { a: "all", o: [3, 7, 11, 18, 22] },
    3: { a: [], o: [0, 6, 12, 18, 24] },
    4: { a: [18, 24], o: [0, 6] },
    5: { a: [2, 6, 8, 10, 12, 14, 16, 18, 22], o: [] }
  };
  var pxs = $$("[data-px]", story);
  pxs.forEach(function (p) { $$("i", p).forEach(function (c, i) { c.style.setProperty("--d", (i * 14) + "ms"); }); });
  function paintPx(n) {
    pxs.forEach(function (p) {
      var k = +p.getAttribute("data-px"), on = k <= n, pat = PX[k], cells = $$("i", p);
      p.classList.toggle("on", k === n);
      cells.forEach(function (c, i) {
        var a = on && (pat.a === "all" || pat.a.indexOf(i) >= 0), o = on && pat.o.indexOf(i) >= 0;
        c.classList.toggle("a", a && !o); c.classList.toggle("o", o);
      });
    });
  }

  var cur = -1;
  function apply(n) {
    if (n === cur) return;
    var prev = cur; cur = n;
    steps.forEach(function (s) { var k = +s.getAttribute("data-step"); s.classList.toggle("on", k === n); s.classList.toggle("done", k < n); });
    $$("[data-seg]", story).forEach(function (c) { var k = +c.getAttribute("data-seg"); c.classList.toggle("on", k === Math.max(1, n)); c.classList.toggle("done", k < n); });
    steps.forEach(function (s) { if (n < 1 && +s.getAttribute("data-step") === 1) s.classList.add("on"); });
    if (label) label.textContent = "[0" + Math.max(1, n) + "] " + NAMES[Math.max(1, n)].toUpperCase();
    if (roStatus) { roStatus.textContent = STATUS[Math.max(1, n)]; roStatus.classList.toggle("hot", n === 2 || n === 3); }
    roll(roIssues, "i", n >= 4 ? 0 : pf);
    roll(roScore, "s", n >= 5 ? sa : sb);
    paintPx(n);
    if (!svg) return;
    svg.classList.toggle("s0", n < 1);
    svg.classList.toggle("hot-on", n >= 2);
    svg.classList.toggle("path-on", n >= 3);
    svg.classList.toggle("fixed", n >= 4);
    hotPath.forEach(function (b) { b.classList.toggle("hot", n < 4); });
    $$(".lbl.hot, .lbl.was-hot", svg).forEach(function (l) { l.classList.add("was-hot"); l.classList.toggle("hot", n < 4); });
    $$(".hot-decor", svg).forEach(function (b) { b.classList.toggle("hot", n < 5); });
    if (n >= 3 && n < 4) startFlow(); else stopFlow();
    if (n === 2 && prev < 2) sweep(false);
    if (n === 5 && prev < 5) sweep(true);
  }

  var stepFor = function (p) { return Math.min(5, Math.floor(p * 5 * 0.999) + 1); };
  if (desktop.matches) {
    apply(0);
    var started = false;
    M.inView(story, function () { started = true; }, { margin: "0px 0px -30% 0px" });
    M.scroll(story, function (p) {
      if (bar) bar.style.setProperty("--p", p.toFixed(4));
      var top = story.getBoundingClientRect().top;
      apply(top > window.innerHeight * 0.55 ? 0 : stepFor(p));
    }, "pin");
    if (stage && !M.reduced) {
      M.scrollSmooth(story, function (p) {
        var ss = $(".iso", stage); if (!ss) return;
        ss.style.setProperty("--rx", (10 - p * 14).toFixed(3) + "deg");
        ss.style.setProperty("--rz", (-1.5 + p * 3).toFixed(3) + "deg");
        ss.style.setProperty("--sc", (.96 + p * .05).toFixed(4));
      }, "pin", .1);
    }
    $$("[data-seg]", story).forEach(function (s) {
      s.addEventListener("click", function () {
        var k = +s.getAttribute("data-seg"), r = story.getBoundingClientRect(), y = window.scrollY + r.top;
        var span = story.offsetHeight - (window.innerHeight - 64);
        window.scrollTo({ top: y - 64 + span * ((k - 0.5) / 5), behavior: M.reduced ? "auto" : "smooth" });
      });
    });
  } else {
    /* small screens: no pinning; the scene steps through on its own while it is on screen */
    apply(0);
    var timer = null, k = 0;
    M.inView(story.querySelector("[data-scene]") || story, function () {
      if (M.reduced) { apply(5); return; }
      var next = function () { k = k % 5 + 1; apply(k); };
      next(); timer = setInterval(next, 2600);
    }, { margin: "0px 0px -20% 0px" });
  }
})();

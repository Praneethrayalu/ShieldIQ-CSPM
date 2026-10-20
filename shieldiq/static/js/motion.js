/* ShieldIQ motion — a small hand-rolled engine (no dependencies).
   One shared rAF ticker, eased tweens, seekable timelines, scroll progress, split text,
   odometer tickers, magnetic buttons and an accent cursor. Every helper collapses to its
   end state under prefers-reduced-motion. See docs/DESIGN.md "Motion" for why each exists. */
(function (w) {
  "use strict";
  var mq = w.matchMedia ? w.matchMedia("(prefers-reduced-motion: reduce)") : { matches: false };
  var M = { reduced: mq.matches };
  if (mq.addEventListener) mq.addEventListener("change", function (e) { M.reduced = e.matches; });

  /* ---------- math */
  M.clamp = function (v, a, b) { return v < a ? a : v > b ? b : v; };
  M.lerp = function (a, b, t) { return a + (b - a) * t; };
  M.map = function (v, a, b, c, d) { return c + (d - c) * M.clamp((v - a) / (b - a), 0, 1); };
  /* local progress of t inside [a, b] */
  M.seg = function (t, a, b) { return M.clamp((t - a) / (b - a), 0, 1); };
  /* frame-rate independent smoothing: k is the fraction closed per 60 Hz frame; dt in ms.
     The same k gives identical motion at 60, 120, 144 or 165 Hz. */
  M.damp = function (a, b, k, dt) { return M.lerp(a, b, 1 - Math.pow(1 - k, (dt || 16.667) / 16.667)); };
  M.dt = function () { var last = 0; return function (now) { var d = last ? Math.min(64, now - last) : 16.667; last = now; return d; }; };

  /* ---------- easing (Penner / expo family, the "expensive" feel comes from long expo tails) */
  var E = M.ease = {
    linear: function (t) { return t; },
    inCubic: function (t) { return t * t * t; },
    outCubic: function (t) { return 1 - Math.pow(1 - t, 3); },
    inOutCubic: function (t) { return t < .5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; },
    outQuart: function (t) { return 1 - Math.pow(1 - t, 4); },
    outExpo: function (t) { return t === 1 ? 1 : 1 - Math.pow(2, -10 * t); },
    inExpo: function (t) { return t === 0 ? 0 : Math.pow(2, 10 * t - 10); },
    inOutExpo: function (t) { return t === 0 ? 0 : t === 1 ? 1 : t < .5 ? Math.pow(2, 20 * t - 10) / 2 : (2 - Math.pow(2, -20 * t + 10)) / 2; },
    outBack: function (t) { var c1 = 1.70158, c3 = c1 + 1; return 1 + c3 * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2); },
    outElastic: function (t) { var c4 = (2 * Math.PI) / 3; return t === 0 ? 0 : t === 1 ? 1 : Math.pow(2, -10 * t) * Math.sin((t * 10 - .75) * c4) + 1; }
  };
  function ease(e) { return typeof e === "function" ? e : (E[e] || E.outExpo); }

  /* ---------- one ticker for everything (fewer rAF callbacks = no jank) */
  var subs = [], running = false;
  function frame(now) {
    var t0 = w.__siqProfile ? performance.now() : 0;
    var list = subs.slice();
    for (var i = 0; i < list.length; i++) { if (list[i](now) === false) { var k = subs.indexOf(list[i]); if (k > -1) subs.splice(k, 1); } }
    if (w.__siqProfile) w.__siqProfile.push(performance.now() - t0);
    if (subs.length) w.requestAnimationFrame(frame); else running = false;
  }
  M.tick = function (fn) {
    subs.push(fn);
    if (!running) { running = true; w.requestAnimationFrame(frame); }
    return function () { var k = subs.indexOf(fn); if (k > -1) subs.splice(k, 1); };
  };

  /* ---------- tween: M.tween({dur, ease, delay, update(p), done}) -> {stop, promise} */
  M.tween = function (o) {
    var dur = o.dur == null ? 600 : o.dur, delay = o.delay || 0, ef = ease(o.ease), t0 = null, stopped = false, resolve;
    var promise = new Promise(function (r) { resolve = r; });
    if (M.reduced || dur === 0) { o.update && o.update(1); o.done && o.done(); resolve(); return { stop: function () {}, promise: promise }; }
    M.tick(function (now) {
      if (stopped) return false;
      if (t0 === null) t0 = now + delay;
      var p = M.clamp((now - t0) / dur, 0, 1);
      if (now >= t0) o.update && o.update(ef(p), p);
      if (p >= 1) { o.done && o.done(); resolve(); return false; }
    });
    return { stop: function () { stopped = true; resolve(); }, promise: promise };
  };

  /* ---------- timeline: tracks of (start, dur, ease, fn(p)); play / seek / loop. Seekable so a
     reduced-motion user, a screenshot, or a "replay" all land on exactly the same frames. */
  M.timeline = function (opts) {
    opts = opts || {};
    var tracks = [], cues = [], len = 0, t = 0, playing = false, stop = null, tl = {};
    tl.add = function (start, dur, fn, e) { tracks.push({ s: start, d: dur, f: fn, e: ease(e || "outExpo") }); len = Math.max(len, start + dur); return tl; };
    tl.cue = function (at, fn) { cues.push({ at: at, f: fn }); return tl; };
    tl.duration = function () { return Math.max(len, opts.length || 0); };
    tl.seek = function (to) {
      var prev = t; t = M.clamp(to, 0, tl.duration());
      for (var i = 0; i < tracks.length; i++) { var k = tracks[i], p = M.clamp((t - k.s) / k.d, 0, 1); k.f(k.e(p), p, t); }
      for (var j = 0; j < cues.length; j++) { var c = cues[j]; if ((prev < c.at && t >= c.at) || (to === 0 && c.at === 0)) c.f(t); }
      opts.onUpdate && opts.onUpdate(t, tl.duration());
      return tl;
    };
    tl.play = function (from) {
      if (stop) stop();
      if (M.reduced) { tl.seek(tl.duration()); opts.onEnd && opts.onEnd(); return tl; }
      var start = null, base = from == null ? t : from; playing = true; tl.seek(base);
      stop = M.tick(function (now) {
        if (!playing) return false;
        if (start === null) start = now;
        var cur = base + (now - start) / 1000;
        tl.seek(cur);
        if (cur >= tl.duration()) { playing = false; stop = null; opts.onEnd && opts.onEnd(); return false; }
      });
      return tl;
    };
    tl.pause = function () { playing = false; if (stop) { stop(); stop = null; } return tl; };
    tl.time = function () { return t; };
    tl.isPlaying = function () { return playing; };
    return tl;
  };

  /* ---------- in view (once by default) */
  M.inView = function (els, cb, o) {
    o = o || {};
    els = typeof els === "string" ? document.querySelectorAll(els) : (els.length != null ? els : [els]);
    if (!("IntersectionObserver" in w)) { Array.prototype.forEach.call(els, function (el) { cb(el); }); return; }
    var io = new IntersectionObserver(function (ents) {
      ents.forEach(function (en) {
        if (en.isIntersecting) { cb(en.target, en); if (!o.repeat) io.unobserve(en.target); }
        else if (o.out) o.out(en.target, en);
      });
    }, { rootMargin: o.margin || "0px 0px -12% 0px", threshold: o.threshold || 0 });
    Array.prototype.forEach.call(els, function (el) { io.observe(el); });
    return io;
  };

  /* ---------- scroll progress of an element through the viewport (0 when its top hits the
     top of the viewport, 1 when its bottom hits the bottom: the range a pinned section uses) */
  var scrollers = [], scrollQueued = false, vh = w.innerHeight;
  /* geometry is measured on resize/load only, so the per-frame work is arithmetic on scrollY
     (no layout reads inside the animation loop). */
  function measure() {
    vh = w.innerHeight;
    var y = w.scrollY || w.pageYOffset;
    for (var i = 0; i < scrollers.length; i++) { var r = scrollers[i].el.getBoundingClientRect(); scrollers[i].top = r.top + y; scrollers[i].h = r.height; }
  }
  function runScroll() {
    scrollQueued = false;
    var y = w.scrollY || w.pageYOffset;
    for (var i = 0; i < scrollers.length; i++) {
      var s = scrollers[i], top = s.top - y, p;
      if (s.mode === "pin") p = M.clamp(-top / Math.max(1, s.h - vh), 0, 1);
      else if (s.mode === "leave") p = M.clamp(-top / Math.max(1, s.h), 0, 1); /* 0 at rest, 1 when it has scrolled away */
      else p = M.clamp((vh - top) / (vh + s.h), 0, 1); /* through: enters bottom -> leaves top */
      if (p !== s.last) { s.last = p; s.fn(p); }
    }
  }
  function queue() { if (!scrollQueued) { scrollQueued = true; w.requestAnimationFrame(runScroll); } }
  function remeasure() { measure(); queue(); }
  w.addEventListener("scroll", queue, { passive: true });
  w.addEventListener("resize", remeasure);
  w.addEventListener("load", remeasure);
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(remeasure);
  if ("ResizeObserver" in w) { var ro = new ResizeObserver(function () { remeasure(); }); ro.observe(document.documentElement); }
  M.scroll = function (el, fn, mode) { scrollers.push({ el: el, fn: fn, mode: mode || "through", last: -1, top: 0, h: 0 }); measure(); queue(); };
  M.refresh = remeasure;

  /* smoothed scroll progress: the value eases toward the real scroll position every frame, which
     gives scrubbed scenes their inertia (Apple-like) without hijacking native scrolling. */
  M.scrollSmooth = function (el, fn, mode, k) {
    k = k || .14;
    var target = 0, cur = -1, stop = null, dt = M.dt();
    function loop(now) {
      var d = dt(now);
      if (cur < 0) cur = target;
      cur = M.reduced ? target : M.damp(cur, target, k, d);
      if (Math.abs(cur - target) < .0004) cur = target;
      fn(cur);
      if (cur === target) { stop = null; return false; }
    }
    M.scroll(el, function (p) { target = p; if (!stop) { dt = M.dt(); stop = M.tick(loop); } }, mode);
  };

  /* ---------- split text into masked words (and optionally chars) for line/word reveals */
  M.split = function (el, chars) {
    if (el.__split) return el.__split;
    var text = el.textContent, out = [], frag = document.createDocumentFragment();
    el.setAttribute("aria-label", text.replace(/\s+/g, " ").trim());
    var nodes = Array.prototype.slice.call(el.childNodes);
    el.textContent = "";
    nodes.forEach(function (n) {
      if (n.nodeType === 1 && n.tagName === "BR") { frag.appendChild(document.createElement("br")); return; }
      var parent = frag, cls = "";
      if (n.nodeType === 1) { var wrap = n.cloneNode(false); frag.appendChild(wrap); parent = wrap; cls = ""; }
      (n.textContent || "").split(/(\s+)/).forEach(function (word) {
        if (!word) return;
        if (/^\s+$/.test(word)) { parent.appendChild(document.createTextNode(" ")); return; }
        var m = document.createElement("span"); m.className = "w-mask" + cls; m.setAttribute("aria-hidden", "true");
        var inner = document.createElement("span"); inner.className = "w";
        if (chars) word.split("").forEach(function (ch) { var c = document.createElement("span"); c.className = "ch"; c.textContent = ch; inner.appendChild(c); out.push(c); });
        else { inner.textContent = word; out.push(inner); }
        m.appendChild(inner); parent.appendChild(m);
      });
    });
    el.appendChild(frag);
    el.__split = out;
    return out;
  };
  /* reveal split pieces: each rises out of its mask, staggered */
  M.reveal = function (el, o) {
    o = o || {};
    var parts = M.split(el, o.chars), stagger = o.stagger == null ? 45 : o.stagger, dur = o.dur || 900;
    el.classList.add("is-split");
    parts.forEach(function (p, i) {
      p.style.transform = "translate3d(0,110%,0)";
      M.tween({ dur: dur, delay: (o.delay || 0) + i * stagger, ease: o.ease || "outExpo",
        update: function (e) { p.style.transform = e >= 1 ? "" : "translate3d(0," + (110 * (1 - e)).toFixed(2) + "%,0)"; } });
    });
    return dur + parts.length * stagger;
  };

  /* ---------- odometer: digits roll on vertical strips to a target number (no layout shift:
     each digit cell has a fixed width from tabular figures) */
  M.odometer = function (el, to, o) {
    o = o || {};
    to = String(to);
    if (M.reduced) { el.textContent = to; return; }
    el.setAttribute("aria-label", to);
    el.textContent = "";
    el.classList.add("odo");
    to.split("").forEach(function (ch, i) {
      if (!/\d/.test(ch)) { var s = document.createElement("span"); s.className = "odo-sep"; s.textContent = ch; el.appendChild(s); return; }
      var cell = document.createElement("span"); cell.className = "odo-cell"; cell.setAttribute("aria-hidden", "true");
      var strip = document.createElement("span"); strip.className = "odo-strip";
      var loops = (o.loops == null ? 1 : o.loops), target = +ch + 10 * loops, html = "";
      for (var k = 0; k <= target; k++) html += "<span>" + (k % 10) + "</span>";
      strip.innerHTML = html; cell.appendChild(strip); el.appendChild(cell);
      M.tween({ dur: (o.dur || 1600) + i * 160, delay: o.delay || 0, ease: "outExpo", update: function (e) {
        strip.style.transform = "translate3d(0," + (-e * target * 100 / (target + 1)).toFixed(3) + "%,0)"; } });
    });
  };
  /* simple number roll (for values that change from a to b, e.g. a score after a fix) */
  M.count = function (el, from, to, o) {
    o = o || {};
    return M.tween({ dur: o.dur || 1200, delay: o.delay || 0, ease: o.ease || "outExpo", update: function (e) {
      el.textContent = Math.round(M.lerp(from, to, e)) + (o.suffix || ""); } });
  };

  /* ---------- magnetic: a control leans toward the pointer, so the primary action feels alive
     and is easy to hit. Desktop pointers only. */
  M.magnetic = function (el, strength) {
    if (M.reduced || !w.matchMedia("(hover: hover) and (pointer: fine)").matches) return;
    strength = strength || .32;
    var tx = 0, ty = 0, cx = 0, cy = 0, active = false, stop = null, dt = M.dt();
    function loop(now) { var d = dt(now); cx = M.damp(cx, tx, .18, d); cy = M.damp(cy, ty, .18, d); el.style.transform = "translate3d(" + cx.toFixed(2) + "px," + cy.toFixed(2) + "px,0)";
      if (!active && Math.abs(cx) < .05 && Math.abs(cy) < .05) { el.style.transform = ""; stop = null; return false; } }
    el.addEventListener("pointermove", function (e) { var r = el.getBoundingClientRect(); tx = (e.clientX - r.left - r.width / 2) * strength; ty = (e.clientY - r.top - r.height / 2) * strength; active = true; if (!stop) { dt = M.dt(); stop = M.tick(loop); } });
    el.addEventListener("pointerleave", function () { tx = 0; ty = 0; active = false; if (!stop) { dt = M.dt(); stop = M.tick(loop); } });
  };

  /* ---------- accent cursor: a ring trailing the real pointer (which stays visible) that
     grows over things you can act on and shows a word for the hero ("replay"). */
  M.cursor = function () {
    if (M.reduced || !w.matchMedia("(hover: hover) and (pointer: fine)").matches || document.querySelector(".cursor")) return;
    var c = document.createElement("div"); c.className = "cursor is-out"; c.setAttribute("aria-hidden", "true");
    c.innerHTML = '<span class="cursor-ring"></span><span class="cursor-label"></span>';
    document.body.appendChild(c);
    var x = -100, y = -100, cx = -100, cy = -100, label = c.querySelector(".cursor-label"), stop = null, dt = M.dt();
    function loop(now) { var d = dt(now); cx = M.damp(cx, x, .22, d); cy = M.damp(cy, y, .22, d); c.style.transform = "translate3d(" + cx.toFixed(1) + "px," + cy.toFixed(1) + "px,0)";
      if (Math.abs(cx - x) < .1 && Math.abs(cy - y) < .1) { stop = null; return false; } }
    w.addEventListener("pointermove", function (e) {
      if (c.classList.contains("is-out") && x === -100) { cx = e.clientX; cy = e.clientY; c.classList.remove("is-out"); }
      x = e.clientX; y = e.clientY; if (!stop) { dt = M.dt(); stop = M.tick(loop); }
      var t = e.target.closest ? e.target.closest("a,button,[data-cursor],input,select,textarea,label") : null;
      var word = t && t.getAttribute("data-cursor");
      c.classList.toggle("is-hot", !!t); c.classList.toggle("has-label", !!word);
      if (word && label.textContent !== word) label.textContent = word;
      c.classList.toggle("on-ink", !!(e.target.closest && e.target.closest(".ink, [data-ink]")));
    }, { passive: true });
    document.addEventListener("pointerleave", function () { c.classList.add("is-out"); });
    document.addEventListener("pointerenter", function () { c.classList.remove("is-out"); });
  };

  /* SVG line drawing helper: prepare a path so p 0..1 draws it */
  M.drawable = function (path) {
    var L = path.getTotalLength ? path.getTotalLength() : 100;
    path.style.strokeDasharray = L + " " + L;
    path.__len = L;
    return function (p) { path.style.strokeDashoffset = (L * (1 - p)).toFixed(2); };
  };

  w.SiqMotion = M;
})(window);

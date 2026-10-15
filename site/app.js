/* spillscan landing: an absorbent pad laid over a real-looking agent transcript.
   Fake secrets bleed leak-tracer dye; wiping / tapping / scrolling soaks them into
   the pad and the token becomes [REDACTED:<rule>], exactly what `spillscan redact` writes. */
(function () {
  "use strict";
  var RM = matchMedia("(prefers-reduced-motion: reduce)").matches;
  var LOG = [
    ["user", "u", "deploy to staging keeps failing with 403, can you check the env?"],
    ["assistant", "", "I'll look at the environment the deploy script sees first."],
    ["tool_use", "t", 'Bash {"command": "echo checking; env | sort"}'],
    ["tool_result", "t", ""],
    ["", "env", "AWS_ACCESS_KEY_ID=", ["AKIAIOSFODNN7EXAMPLE", "aws-akia"]],
    ["", "env", "AWS_SECRET_ACCESS_KEY=", ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws-secret"]],
    ["", "env", "DATABASE_URL=postgres://app:", ["Hunter2-FAKE-pw", "url-cred"], "@db.staging.internal/shop"],
    ["", "env", "GITHUB_TOKEN=", ["ghp_FAKEfakeFAKEfake0123456789abcdABCD", "github-pat"]],
    ["", "env", "HOME=/Users/dev"],
    ["", "env", "OPENAI_API_KEY=", ["sk-proj-FAKE000000000000000000demo", "openai-sk"]],
    ["", "env", "PATH=/opt/homebrew/bin:/usr/bin:/bin"],
    ["assistant", "", "Found it: DATABASE_URL still points at the old staging host. Updating deploy.sh."]
  ];

  var log = document.getElementById("log"), pad = document.getElementById("pad");
  if (!log || !pad) return;
  var leaks = [];

  function blob(seed, w, h, drips) {
    // smooth closed blob with downward drips, in a w*h box centred on the token
    var r = function () { seed = (seed * 9301 + 49297) % 233280; return seed / 233280; };
    var cx = w / 2, cy = h * 0.42, n = 14, pts = [];
    for (var i = 0; i < n; i++) {
      var a = (i / n) * Math.PI * 2, k = 0.62 + r() * 0.38;
      var rx = (w * 0.46) * k, ry = (h * 0.30) * k;
      if (drips && Math.sin(a) > 0.82 && r() > 0.25) ry *= 1.9 + r();
      pts.push([cx + Math.cos(a) * rx, cy + Math.sin(a) * ry]);
    }
    var d = "M" + mid(pts[n - 1], pts[0]);
    for (var j = 0; j < n; j++) d += " Q" + pts[j][0].toFixed(1) + " " + pts[j][1].toFixed(1) + " " + mid(pts[j], pts[(j + 1) % n]);
    return d + "Z";
  }
  function drops(i, w, h) {
    var o = "", sd = i * 53 + 3;
    for (var k = 0; k < 6; k++) { sd = (sd * 9301 + 49297) % 233280; var u = sd / 233280; sd = (sd * 9301 + 49297) % 233280; var v = sd / 233280;
      o += '<circle cx="' + (w * (0.05 + u * 0.9)).toFixed(1) + '" cy="' + (h * (0.1 + v * 0.95)).toFixed(1) + '" r="' + (2 + u * 5).toFixed(1) + '"/>'; }
    return o;
  }
  function mid(a, b) { return ((a[0] + b[0]) / 2).toFixed(1) + " " + ((a[1] + b[1]) / 2).toFixed(1); }

  LOG.forEach(function (row, i) {
    var li = document.createElement("li");
    if (row[1] === "env") li.className = "env";
    var who = document.createElement("span");
    who.className = "who " + row[1];
    who.textContent = row[0] ? row[0] : "";
    if (row[1] === "env") who.setAttribute("aria-hidden", "true");
    var txt = document.createElement("span");
    txt.className = "txt";
    txt.appendChild(document.createTextNode(row[2]));
    if (row[3]) {
      var b = document.createElement("button");
      b.type = "button"; b.className = "leak";
      var s = document.createElement("span"); s.className = "s"; s.textContent = row[3][0];
      b.appendChild(s);
      b.setAttribute("aria-label", "Leaked " + row[3][1] + " (fake). Soak it up");
      var w = Math.min(420, 90 + row[3][0].length * 7), h = 120 + (i % 3) * 18;
      b.style.setProperty("--w", w + "px"); b.style.setProperty("--h", h + "px");
      var svg = '<svg viewBox="0 0 ' + w + " " + h + '" preserveAspectRatio="none" aria-hidden="true"><path d="' + blob(i * 77 + 13, w, h, true) + '"/><path class="core" d="' + blob(i * 31 + 5, w * 0.7, h * 0.6, false) + '" transform="translate(' + (w * 0.15) + " " + (h * 0.14) + ')"/>' + drops(i, w, h) + '</svg>';
      b._svg = svg; b._w = w; b._h = h;
      b.dataset.rule = row[3][1];
      b.addEventListener("click", function () { soak(b); });
      leaks.push(b);
      txt.appendChild(b);
      if (row[4]) txt.appendChild(document.createTextNode(row[4]));
    }
    li.appendChild(who); li.appendChild(txt);
    log.appendChild(li);
  });

  var stains = document.getElementById("stains");
  function place() {
    var pr = pad.getBoundingClientRect(), ang = -0; // pad rotation is applied to children too
    leaks.forEach(function (b) {
      if (!b._el) { stains.insertAdjacentHTML("beforeend", b._svg); b._el = stains.lastElementChild; }
      var q = b.querySelector(".s"), x = q.offsetLeft, y = q.offsetTop, el = q, cx, cy;
      // offset relative to pad (unrotated layout coords)
      var o = q, ox = 0, oy = 0;
      while (o && o !== pad) { ox += o.offsetLeft; oy += o.offsetTop; o = o.offsetParent; }
      cx = ox + q.offsetWidth / 2; cy = oy + q.offsetHeight / 2;
      var w = Math.max(b._w, q.offsetWidth + 60);
      b._el.style.cssText = "left:" + (cx - w / 2) + "px;top:" + (cy - b._h * 0.42) + "px;width:" + w + "px;height:" + b._h + "px";
    });
  }
  place(); addEventListener("resize", place);
  if (document.fonts) document.fonts.ready.then(place);
  var bleedEl = document.getElementById("bleeding"), soakEl = document.getElementById("soaked");
  var done = document.getElementById("done"), respill = document.getElementById("respill"), soakall = document.getElementById("soakall");
  function count() {
    var n = leaks.filter(function (l) { return l.classList.contains("soaked"); }).length;
    bleedEl.textContent = leaks.length - n; soakEl.textContent = n;
    var all = n === leaks.length;
    done.hidden = !all; respill.hidden = !all; soakall.hidden = all;
    if (all && document.activeElement && document.activeElement.classList.contains("leak")) respill.focus();
  }
  function scramble(el, to, ms) {
    if (RM) { el.textContent = to; return; }
    var from = el.textContent, t0 = performance.now(), G = "▓▒░#%*";
    (function f(t) {
      var p = Math.min(1, (t - t0) / ms), len = Math.round(from.length + (to.length - from.length) * p), out = "";
      for (var i = 0; i < len; i++) out += i < to.length * p ? to[i] : G[(Math.random() * G.length) | 0];
      el.textContent = out;
      if (p < 1) requestAnimationFrame(f); else el.textContent = to;
    })(t0);
  }
  function soak(b) {
    if (b.classList.contains("soaked")) return;
    b.classList.add("soaked"); b._el && b._el.classList.add("soaked");
    var s = b.querySelector(".s");
    b.dataset.orig = s.textContent;
    scramble(s, "[REDACTED:" + b.dataset.rule + "]", 520);
    b.setAttribute("aria-label", "Soaked: replaced with REDACTED " + b.dataset.rule);
    count();
  }
  function reset() {
    leaks.forEach(function (b) {
      b.classList.remove("soaked"); b._el && b._el.classList.remove("soaked");
      if (b.dataset.orig) b.querySelector(".s").textContent = b.dataset.orig;
      b.setAttribute("aria-label", "Leaked " + b.dataset.rule + " (fake). Soak it up");
    });
    pad.classList.remove("bled"); void pad.offsetWidth;
    requestAnimationFrame(function () { pad.classList.add("bled"); });
    scrollArmed = window.scrollY + 1;
    count(); soakall.focus();
  }
  soakall.addEventListener("click", function () {
    leaks.forEach(function (b, i) { setTimeout(function () { soak(b); }, RM ? 0 : i * 140); });
  });
  respill.addEventListener("click", reset);
  document.addEventListener("keydown", function (e) {
    if (e.target.closest && e.target.closest("input,textarea") || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "s" || e.key === "S") soakall.hidden || soakall.click();
    if (e.key === "r" || e.key === "R") respill.hidden || respill.click();
  });

  // bleed in on load
  requestAnimationFrame(function () { setTimeout(function () { pad.classList.add("bled"); }, RM ? 0 : 250); });

  // pointer: wipe a scrap of pad over the stains
  var blotter = document.getElementById("blotter");
  if (matchMedia("(hover:hover) and (pointer:fine)").matches && !RM) {
    pad.addEventListener("pointerenter", function () { pad.classList.add("wiping"); });
    pad.addEventListener("pointerleave", function () { pad.classList.remove("wiping"); });
    pad.addEventListener("pointermove", function (e) {
      if (e.target.closest(".btn,.pad-foot")) { pad.classList.remove("wiping"); return; }
      pad.classList.add("wiping");
      var r = pad.getBoundingClientRect();
      blotter.style.left = (e.clientX - r.left) + "px"; blotter.style.top = (e.clientY - r.top) + "px";
      var hit = false;
      leaks.forEach(function (b) {
        if (b.classList.contains("soaked")) return;
        var q = b.getBoundingClientRect();
        if (e.clientX > q.left - 30 && e.clientX < q.right + 30 && e.clientY > q.top - 34 && e.clientY < q.bottom + 34) { soak(b); hit = true; }
      });
      if (hit) { blotter.classList.add("drink"); setTimeout(function () { blotter.classList.remove("drink"); }, 500); }
    });
  }

  // scroll: as the pad is pressed past the upper third of the screen, it drinks line by line
  var scrollArmed = 0;
  addEventListener("scroll", function () {
    if (window.scrollY < scrollArmed + 40) return;
    var lim = innerHeight * 0.34;
    leaks.forEach(function (b) { if (b.getBoundingClientRect().top < lim) soak(b); });
  }, { passive: true });

  // copy buttons
  document.querySelectorAll(".copy").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var t = document.getElementById(btn.dataset.copy).textContent;
      (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).then(function () {
        btn.textContent = "Copied"; btn.classList.add("ok");
      }, function () { btn.textContent = "Select ⌘C"; }).then(function () {
        setTimeout(function () { btn.textContent = "Copy"; btn.classList.remove("ok"); }, 1600);
      });
    });
  });

  // sock boom: ink casing + pad fill + knit stitches
  document.querySelectorAll(".boom path").forEach(function (p) {
    var a = p.cloneNode(), c = p.cloneNode();
    p.setAttribute("style", "stroke:#14130f;stroke-width:38;stroke-dasharray:none");
    a.setAttribute("style", "stroke:#e3e6ea;stroke-width:30;stroke-dasharray:none");
    c.setAttribute("style", "stroke:#c3c8cf;stroke-width:22;stroke-dasharray:2 7;stroke-linecap:butt");
    p.after(a); a.after(c);
  });
  count();
})();

/* Live Geiger survey demo — canned fixture scan (JS port of a few detectors). */
(function () {
  const FIXTURE = [
    { agent: "claude-code", line: 3, text: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD" },
    { agent: "claude-code", line: 3, text: "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345 ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD" },
    { agent: "codex", line: 1, text: "xoxp-TESTONLY00-spillscanfixture000001 npm_abcdefghijklmnopqrstuvwxyz0123456789ABCD" },
    { agent: "cursor", line: 1, text: "-----BEGIN PRIVATE KEY-----\\nMIIEFAKE\\n-----END PRIVATE KEY-----" },
  ];

  const RULES = [
    { id: "aws-akia", re: /\b(AKIA[0-9A-Z]{16})\b/g },
    { id: "github-pat", re: /\b(ghp_[A-Za-z0-9_]{36,})\b/g },
    { id: "openai-sk", re: /\b(sk-(?!ant-)[A-Za-z0-9\-]{20,})\b/g },
    { id: "anthropic-sk", re: /\b(sk-ant-api03-[A-Za-z0-9\-_]{20,})\b/g },
    { id: "stripe-live", re: new RegExp('\\b(sk_' + 'live_[A-Za-z0-9]{20,})\\b', 'g') },
    { id: "slack-token", re: /\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b/g },
    { id: "npm-token", re: /\b(npm_[A-Za-z0-9]{36,})\b/g },
    { id: "pem-private", re: /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/g },
  ];

  function preview(s) {
    if (s.length <= 8) return "****";
    return s.slice(0, 4) + "…" + s.slice(-4);
  }

  function detectAll() {
    const hits = [];
    for (const row of FIXTURE) {
      for (const rule of RULES) {
        rule.re.lastIndex = 0;
        let m;
        while ((m = rule.re.exec(row.text))) {
          hits.push({ rule: rule.id, preview: preview(m[1]), agent: row.agent, line: row.line });
        }
      }
    }
    return hits;
  }

  const needle = document.getElementById("needle");
  const cps = document.getElementById("cps");
  const contam = document.getElementById("contam");
  const filesEl = document.getElementById("files");
  const status = document.getElementById("status");
  const list = document.getElementById("findings");
  const btn = document.getElementById("survey-btn");
  const dialFace = document.getElementById("dial-face");

  let runId = 0; // bumped by ZERO so an in-flight sweep stops instead of fighting the reset
  function renderHit(h) {
    const div = document.createElement("div");
    div.className = "hit";
    for (const [cls, text] of [["rule", h.rule], ["prev", h.preview], ["", `${h.agent}:${h.line}`]]) {
      const span = document.createElement("span");
      if (cls) span.className = cls;
      span.textContent = text;
      div.appendChild(span);
    }
    list.appendChild(div);
    list.scrollTop = list.scrollHeight;
  }
  function finalStatus(n) {
    const cmd = document.createElement("span");
    cmd.className = "nowrap";
    cmd.textContent = "spillscan redact --write";
    status.replaceChildren(`CONTAMINATION — ${n} secret-shaped hits in 3 sample transcripts. Rotate, then: `, cmd);
    status.classList.add("contam");
    status.classList.remove("done");
    void status.offsetWidth; // restart the blink
    status.classList.add("done");
  }

  let angle = -60; // degrees from vertical-up-ish; map 0..100 cps → -90..90
  function setNeedle(deg, spike) {
    angle = deg;
    if (needle) {
      needle.style.transform = `rotate(${deg}deg)`;
      needle.classList.toggle("spike", !!spike);
    }
  }

  function setClean() {
    cps.textContent = "0";
    cps.className = "val ok";
    contam.textContent = "0";
    contam.className = "val ok";
    filesEl.textContent = "3";
    status.textContent = "READY — press SURVEY to sweep sample transcripts.";
    status.classList.remove("contam", "done");
    list.replaceChildren();
    if (dialFace) dialFace.setAttribute("fill", "#8b9a4a");
    setNeedle(-70, false);
  }

  async function runSurvey() {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const hits = detectAll();
    const my = ++runId;
    btn.disabled = true;
    list.replaceChildren();
    status.textContent = "SURVEYING ~/.claude · ~/.codex · ~/.cursor …";
    status.classList.remove("contam", "done");
    cps.textContent = "—";
    cps.className = "val";
    contam.textContent = "0";
    contam.className = "val";
    if (dialFace) dialFace.setAttribute("fill", "#8b9a4a");

    if (reduced) {
      for (const h of hits) renderHit(h);
      cps.textContent = String(hits.length * 12);
      cps.className = "val hot";
      contam.textContent = String(hits.length);
      contam.className = "val hot";
      finalStatus(hits.length);
      if (dialFace) dialFace.setAttribute("fill", "#c45c2a");
      setNeedle(75, true);
      btn.disabled = false;
      return;
    }

    // Sweep needle while "scanning"
    let found = 0;
    for (let i = 0; i < hits.length; i++) {
      // sweep
      for (let s = 0; s < 8; s++) {
        setNeedle(-70 + Math.random() * 100, false);
        await sleep(40);
        if (my !== runId) return;
      }
      found++;
      setNeedle(40 + found * 8, true);
      cps.textContent = String(found * 12 + Math.floor(Math.random() * 5));
      cps.className = "val hot";
      contam.textContent = String(found);
      contam.className = "val hot";
      if (dialFace) dialFace.setAttribute("fill", "#c45c2a");
      status.textContent = `CLICK — ${hits[i].rule} @ ${hits[i].agent}`;
      status.classList.add("contam");
      renderHit(hits[i]);
      await sleep(280);
      if (my !== runId) return;
      setNeedle(20 + found * 5, false);
    }
    finalStatus(hits.length);
    setNeedle(70, false);
    btn.disabled = false;
  }

  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

  btn?.addEventListener("click", runSurvey);
  document.getElementById("reset-btn")?.addEventListener("click", () => {
    runId++;
    setClean();
    btn.disabled = false;
  });

  // Keyboard: S = survey, Z = zero (ignored while typing or with modifiers).
  document.addEventListener("keydown", (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey || /INPUT|TEXTAREA/.test(e.target.tagName)) return;
    if (e.key === "s" || e.key === "S") { if (!btn.disabled) runSurvey(); }
    else if (e.key === "z" || e.key === "Z") document.getElementById("reset-btn")?.click();
  });

  // COPY buttons on install commands.
  for (const b of document.querySelectorAll("button.copy")) {
    b.addEventListener("click", async () => {
      const src = document.getElementById(b.dataset.copy);
      try {
        await navigator.clipboard.writeText(src.textContent);
        b.textContent = "COPIED";
      } catch {
        getSelection().selectAllChildren(src);
        b.textContent = "⌘C";
      }
      b.classList.add("done");
      setTimeout(() => { b.textContent = "COPY"; b.classList.remove("done"); }, 1600);
    });
  }

  setClean();
  // Auto-start once so strangers see the wow within 5s
  if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    setTimeout(() => runSurvey(), 600);
  } else {
    runSurvey();
  }
})();

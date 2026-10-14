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
    status.classList.remove("contam");
    list.innerHTML = "";
    if (dialFace) dialFace.setAttribute("fill", "#8b9a4a");
    setNeedle(-70, false);
  }

  async function runSurvey() {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const hits = detectAll();
    btn.disabled = true;
    list.innerHTML = "";
    status.textContent = "SURVEYING ~/.claude · ~/.codex · ~/.cursor …";
    status.classList.remove("contam");
    cps.textContent = "—";
    cps.className = "val";
    contam.textContent = "0";
    contam.className = "val";
    if (dialFace) dialFace.setAttribute("fill", "#8b9a4a");

    if (reduced) {
      for (const h of hits) {
        const div = document.createElement("div");
        div.className = "hit";
        div.innerHTML = `<span class="rule">${h.rule}</span><span class="prev">${h.preview}</span><span>${h.agent}:${h.line}</span>`;
        list.appendChild(div);
      }
      cps.textContent = String(hits.length * 12);
      cps.className = "val hot";
      contam.textContent = String(hits.length);
      contam.className = "val hot";
      status.textContent = `CONTAMINATION — ${hits.length} live keys in sample transcripts. Run: spillscan redact --write`;
      status.classList.add("contam");
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
      const div = document.createElement("div");
      div.className = "hit";
      div.innerHTML = `<span class="rule">${hits[i].rule}</span><span class="prev">${hits[i].preview}</span><span>${hits[i].agent}:${hits[i].line}</span>`;
      list.appendChild(div);
      list.scrollTop = list.scrollHeight;
      await sleep(280);
      setNeedle(20 + found * 5, false);
    }
    status.textContent = `CONTAMINATION — ${hits.length} live keys in sample transcripts. Rotate them, then: spillscan redact --write`;
    setNeedle(70, false);
    btn.disabled = false;
  }

  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

  btn?.addEventListener("click", runSurvey);
  document.getElementById("reset-btn")?.addEventListener("click", () => {
    setClean();
    btn.disabled = false;
  });

  setClean();
  // Auto-start once so strangers see the wow within 5s
  if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    setTimeout(() => runSurvey(), 600);
  } else {
    runSurvey();
  }
})();

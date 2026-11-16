(() => {
  "use strict";

  // Same rule as the server uses: one domain or IP, no ranges or spaces
  const TARGET_RE = /^[A-Za-z0-9]([A-Za-z0-9.\-:]*[A-Za-z0-9])?$/;
  const PANELS = ["dns", "whois", "geo","subdomains", "nmap"];

  let currentTarget = null;

  const $ = (id) => document.getElementById(id);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // ---------- Helpers ----------
  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  async function getJSON(url, options) {
    const res = await fetch(url, options);
    let data = {};
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  }

  let messageTimer = null;
  function showMessage(text, type = "info") {
    const box = $("message");
    box.textContent = text;
    box.className = `message ${type}`;
    clearTimeout(messageTimer);
    if (type !== "error") {
      messageTimer = setTimeout(hideMessage, 6000);
    }
  }
  function hideMessage() {
    $("message").className = "message hidden";
  }

  function setStatus(name, state, text) {
    const el = $(`status-${name}`);
    el.className = `status ${state}`;
    el.textContent = text;
  }

  function setBody(name, html) {
    $(`result-${name}`).innerHTML = html;
  }

  function resetPanels() {
    PANELS.forEach((name) => {
      setStatus(name, "", "Not run");
      setBody(name, '<p class="empty">No results yet.</p>');
    });
    setStatus("findings", "", "Not run");
    setBody("findings", '<p class="empty">Findings appear here automatically as you run modules.</p>');
  }

  // ---------- Renderers ----------
  function kvTable(obj) {
    const rows = Object.entries(obj)
      .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`)
      .join("");
    return `<table class="data">${rows}</table>`;
  }

  function renderDns(records) {
    const found = Object.entries(records).filter(([, values]) => values.length);
    if (!found.length) {
      return '<p class="empty">No DNS records found.</p>';
    }
    const rows = found
      .map(([type, values]) =>
        `<tr><th>${esc(type)}</th><td>${values.map(esc).join("<br>")}</td></tr>`)
      .join("");
    return `<table class="data">${rows}</table>`;
  }

  function renderNmap(r) {
    let html = `<p class="meta"><b>Host:</b> ${esc(r.Hostname)} (${esc(r.Address)}) is <b>${esc(r["Host State"])}</b>`;
    if (r.OS && r.OS !== "N/A") {
      html += ` &nbsp;|&nbsp; <b>OS:</b> ${esc(r.OS)}`;
    }
    html += `</p><p class="meta"><b>Command:</b> ${esc(r.Command)}</p>`;

    const ports = r.Ports || [];
    if (!ports.length) {
      return html + '<p class="empty">No ports found.</p>';
    }

    const rows = ports.map((p) => {
      const known = ["open", "closed", "filtered"].includes(p.State) ? p.State : "";
      return `<tr>
        <td>${esc(p.Port)}</td>
        <td><span class="tag ${known}">${esc(p.State)}</span></td>
        <td>${esc(p.Service)}</td>
        <td>${esc(p.Version)}</td>
      </tr>`;
    }).join("");

    return html + `<table class="data">
      <tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
      ${rows}
    </table>`;
  }

  // ---------- Target ----------
    // Mirrors the server rule: names made only of digits, dots and hyphens
  // must be a real IPv4 address, so ranges like 10.0.0.1-5 are rejected.
  function isValidTarget(value) {
    if (!value || value.length > 253 || !TARGET_RE.test(value)) return false;
    if (/^[0-9.\-]+$/.test(value)) {
      const parts = value.split(".");
      return parts.length === 4 &&
             parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
    }
    return true;
  }
  
  function setTarget() {
    hideMessage();
    const value = $("target-input").value.trim();

    if (!isValidTarget(value)) {
      showMessage("Invalid target. Use a single domain or IP, such as scanme.nmap.org.", "error");
      return;
    }
    if (!$("consent").checked) {
      showMessage("Tick the authorization box to confirm you are allowed to test this target.", "error");
      return;
    }

    if (value !== currentTarget) {
      resetPanels();   // new target = fresh results, same as the CLI
    }
    currentTarget = value;

    const label = $("current-target");
    label.textContent = `Target: ${currentTarget}`;
    label.className = "current set";
    showMessage(`Target set to ${currentTarget}`, "success");
  }

  function requireReady() {
    hideMessage();
    if (!currentTarget) {
      showMessage("Set a target first.", "error");
      return false;
    }
    if (!$("consent").checked) {
      showMessage("Tick the authorization box to confirm you are allowed to test this target.", "error");
      return false;
    }
    return true;
  }

  // ---------- Modules ----------
  async function runSimple(name) {
    const q = `?target=${encodeURIComponent(currentTarget)}`;

    if (name === "dns") {
      const data = await getJSON(`/api/dns${q}`);
      setBody("dns", renderDns(data.records));
    } else if (name === "whois") {
      const data = await getJSON(`/api/whois${q}`);
      setBody("whois", kvTable(data.result));
    } else if (name === "geo") {
      const data = await getJSON(`/api/geo${q}`);
      setBody("geo", kvTable(data.result));
    }
  }

    function renderSubdomains(r) {
    let html = (r.Notes || [])
      .map((n) => `<div class="note">${esc(n)}</div>`)
      .join("");

    const subs = r.Subdomains || [];
    if (!subs.length) {
      return html + '<p class="empty">No subdomains found.</p>';
    }

    const live = subs.filter((s) => s.Resolves).length;
    html += `<p class="meta"><b>${subs.length}</b> found, <b>${live}</b> resolving`
          + (r["Brute Force"] ? " (brute force on)" : " (passive only)") + `</p>`;

    const rows = subs.map((s) => `<tr>
        <td>${esc(s.Subdomain)}</td>
        <td>${s.Resolves
              ? s.IPs.map(esc).join("<br>")
              : '<span class="tag filtered">no DNS record</span>'}</td>
        <td>${esc(s.Source)}</td>
      </tr>`).join("");

    return html + `<table class="data">
      <tr><th>Subdomain</th><th>IP address</th><th>Source</th></tr>
      ${rows}
    </table>`;
  }

    function renderFindings(data) {
    const list = data.findings || [];
    const counts = data.counts || {};

    const chips = ["High", "Medium", "Low", "Info"].map((s) => {
      const n = counts[s] || 0;
      return `<span class="chip ${s.toLowerCase()}${n ? "" : " zero"}">${s}: ${n}</span>`;
    }).join("");

    if (!list.length) {
      return `<div class="chips">${chips}</div>
              <p class="empty">No findings for the modules run so far.</p>`;
    }

    const rows = list.map((f) => `<tr>
        <td><span class="sev ${esc(f.Severity.toLowerCase())}">${esc(f.Severity)}</span></td>
        <td><b>${esc(f.Title)}</b><br>
            <span class="detail">${esc(f.Detail)}</span><br>
            <span class="fix">Fix: ${esc(f.Recommendation)}</span></td>
        <td>${esc(f.Source)}</td>
      </tr>`).join("");

    return `<div class="chips">${chips}</div>
      <table class="data findings">
        <tr><th>Severity</th><th>Finding</th><th>Source</th></tr>
        ${rows}
      </table>`;
  }

  async function loadFindings() {
    if (!currentTarget) return;
    try {
      const data = await getJSON(`/api/findings?target=${encodeURIComponent(currentTarget)}`);
      setBody("findings", renderFindings(data));
      const total = (data.findings || []).length;
      setStatus("findings", total ? "done" : "", total ? `${total} found` : "No findings");
    } catch (err) {
      setStatus("findings", "error", "Error");
      setBody("findings", `<p class="empty">${esc(err.message)}</p>`);
    }
  }

  async function runSubdomains() {
    const brute = $("brute").checked;
    setBody("subdomains",
      `<p class="empty">Searching certificate logs${brute ? " and brute forcing common names" : ""}. This can take up to a minute.</p>`);

    const { job_id } = await getJSON("/api/subdomains", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: currentTarget, brute }),
    });

    const started = Date.now();
    while (true) {
      await sleep(2000);
      const seconds = Math.round((Date.now() - started) / 1000);
      setStatus("subdomains", "running", `Running ${seconds}s`);

      const job = await getJSON(`/api/subdomains/${job_id}`);
      if (job.status === "done") {
        setBody("subdomains", renderSubdomains(job.result));
        return;
      }
      if (job.status === "error") {
        throw new Error(job.error);
      }
      if (Date.now() - started > 5 * 60 * 1000) {
        throw new Error("The search is taking too long. Check the server terminal.");
      }
    }
  }

  async function runNmap() {
    const scan = $("scan-type").value;
    setBody("nmap", '<p class="empty">Scan in progress. This can take from a few seconds to several minutes.</p>');

    const { job_id } = await getJSON("/api/nmap", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: currentTarget, scan }),
    });

    const started = Date.now();
    while (true) {
      await sleep(2000);
      const seconds = Math.round((Date.now() - started) / 1000);
      setStatus("nmap", "running", `Running ${seconds}s`);

      const job = await getJSON(`/api/nmap/${job_id}`);
      if (job.status === "done") {
        setBody("nmap", renderNmap(job.result));
        return;
      }
      if (job.status === "error") {
        throw new Error(job.error);
      }
      if (Date.now() - started > 20 * 60 * 1000) {
        throw new Error("The scan is taking too long. Check the server terminal.");
      }
    }
  }

    async function runModule(name, button) {
    if (!requireReady()) return;

    button.disabled = true;
    setStatus(name, "running", "Running...");
    if (name !== "nmap" && name !== "subdomains") {
      setBody(name, '<p class="empty">Working...</p>');
    }

    try {
      if (name === "nmap") {
        await runNmap();
      } else if (name === "subdomains") {
        await runSubdomains();
      } else {
        await runSimple(name);
      }
      setStatus(name, "done", "Done");
      loadFindings();          // refresh the Findings panel
    } catch (err) {
      setStatus(name, "error", "Error");
      setBody(name, `<p class="empty">${esc(err.message)}</p>`);
    } finally {
      button.disabled = false;
    }
  }

  // ---------- Report ----------
  async function generateReport() {
    if (!requireReady()) return;

    const button = $("report-btn");
    button.disabled = true;
    try {
      const res = await fetch(`/api/report?target=${encodeURIComponent(currentTarget)}`);
      if (!res.ok) {
        let msg = `Report failed (${res.status})`;
        try { msg = (await res.json()).error || msg; } catch (e) { /* not JSON */ }
        throw new Error(msg);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `RAT_Report_${currentTarget.replace(/[^\w.-]/g, "_")}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      showMessage("Report downloaded. Check your Downloads folder.", "success");
    } catch (err) {
      showMessage(err.message, "error");
    } finally {
      button.disabled = false;
    }
  }

  // ---------- Wire up the page ----------
  $("set-target-btn").addEventListener("click", setTarget);
  $("target-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") setTarget();
  });

  document.querySelectorAll("[data-module]").forEach((btn) => {
    btn.addEventListener("click", () => runModule(btn.dataset.module, btn));
  });

  $("report-btn").addEventListener("click", generateReport);
})();
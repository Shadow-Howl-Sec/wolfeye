(() => {
  const $ = (id) => document.getElementById(id);
  const message = (text, kind = "success") => {
    $("operations-message").innerHTML = text
      ? `<div class="alert alert-${kind} py-2">${text}</div>` : "";
  };
  const escape = (value) => String(value ?? "—").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[char]));
  const api = async (url, options = {}) => {
    const response = await fetch(url, options);
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status})`);
    return result;
  };

  async function loadHealth() {
    const result = await api("/api/system/health");
    $("ops-health").textContent = result.status.toUpperCase();
    $("ops-db").textContent = result.database.connected ? "Database connected" : "Database unavailable";
    $("ops-alerts").textContent = result.counts.open_alerts ?? "—";
    const scoring = result.scheduler?.scoring?.last_result;
    const plane = result.data_plane || {};
    $("ops-model-mode").textContent = plane.flow_model_mode?.toUpperCase() || (scoring ? "SCHEDULED" : "SHADOW");
    $("ops-node").textContent = plane.node_name || "—";
    $("ops-mode").textContent = plane.mode || "—";
    $("ops-inline").textContent = plane.inline_enabled ? "ENABLED" : "DISABLED";
    $("ops-blocking").textContent = plane.blocking_enabled ? "ENABLED" : "DISABLED";
    $("ops-dry-run").textContent = plane.dry_run ? "ON" : "OFF";
    $("ops-capture").textContent = plane.capture_enabled ? (plane.capture_interface || "ON") : "DISABLED";
    $("ops-features").textContent = plane.flow_feature_count || "—";
  }

  async function loadLists() {
    const result = await api("/api/enforcement/lists");
    $("ops-list-version").textContent = `v${result.version}`;
    const render = (items, action, color) => items.length
      ? items.map((item) => `<div class="enforcement-row"><div><span class="badge text-bg-secondary me-2">${escape(item.kind)}</span><span class="font-monospace">${escape(item.value)}</span><small>${escape(item.reason)}</small></div><button class="btn btn-sm btn-outline-${color}" data-remove="${action}" data-id="${item.id}">Remove</button></div>`).join("")
      : '<div class="text-muted small">No active entries.</div>';
    $("enforcement-lists").innerHTML =
      `<h3 class="ops-list-heading">BLOCKLIST (${result.blocklist.length})</h3>${render(result.blocklist, "blocks", "danger")}` +
      `<h3 class="ops-list-heading mt-3">ALLOWLIST (${result.allowlist.length})</h3>${render(result.allowlist, "allows", "success")}`;
    $("enforcement-lists").querySelectorAll("[data-remove]").forEach((button) => {
      button.addEventListener("click", async () => {
        if (!window.confirm("Remove this enforcement entry?")) return;
        try {
          await api(`/api/enforcement/${button.dataset.remove}/${button.dataset.id}`, {method: "DELETE"});
          await loadLists();
          message("Enforcement list updated.");
        } catch (error) { message(error.message, "danger"); }
      });
    });
  }

  async function loadReviews() {
    const status = $("review-status").value;
    const result = await api(`/api/review${status ? `?status=${encodeURIComponent(status)}` : ""}`);
    const body = $("review-table");
    body.innerHTML = result.data.length ? result.data.map((item) => {
      const danger = ["critical", "high"].includes(item.severity);
      return `<tr><td class="font-monospace">${escape(item.subject)}</td><td><span class="badge text-bg-${danger ? "danger" : "warning"}">${escape(item.severity)}</span></td><td>${Number(item.risk_score || 0).toFixed(2)}</td><td>${new Date(item.created_at).toLocaleString()}</td><td>${item.status === "open" ? `<button class="btn btn-sm btn-outline-danger me-1" data-review-block="${item.id}">Block</button><button class="btn btn-sm btn-outline-success" data-review-clear="${item.id}">Allow</button>` : `<span class="text-muted">${escape(item.status)}</span>`}</td></tr>`;
    }).join("") : '<tr><td colspan="5" class="text-center text-muted py-4">No review items found.</td></tr>';
    body.querySelectorAll("[data-review-block]").forEach((button) => decideReview(button, "block"));
    body.querySelectorAll("[data-review-clear]").forEach((button) => decideReview(button, "clear"));
  }

  function decideReview(button, action) {
    button.addEventListener("click", async () => {
      const reason = window.prompt(action === "block" ? "Why should this be blocked?" : "Why is this safe?", "Decision from operations");
      if (reason === null) return;
      button.disabled = true;
      try {
        await api(`/api/review/${button.dataset[`review${action === "block" ? "Block" : "Clear"}`]}/${action}`, {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({reason, allow: action === "clear"})
        });
        await Promise.all([loadReviews(), loadLists()]);
        message(`Review item ${action === "block" ? "blocked" : "cleared"}.`);
      } catch (error) { button.disabled = false; message(error.message, "danger"); }
    });
  }

  $("entry-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const payload = Object.fromEntries(form.entries());
    if (!payload.ttl) delete payload.ttl;
    try {
      await api(`/api/enforcement/${payload.action}`, {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload)
      });
      event.currentTarget.reset();
      await loadLists();
      message("Enforcement entry saved.");
    } catch (error) { message(error.message, "danger"); }
  });

  $("packet-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const payload = Object.fromEntries(form.entries());
    ["dst_port", "packets", "bytes_out", "duration_ms"].forEach((key) => { payload[key] = Number(payload[key]); });
    try {
      const result = await api("/api/detections/analyze", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload)
      });
      $("packet-result").textContent = JSON.stringify(result.results?.[0] || result, null, 2);
      $("packet-result").classList.remove("d-none");
      message("Flow analyzed.");
    } catch (error) { message(error.message, "danger"); }
  });

  async function refresh() {
    try { await Promise.all([loadHealth(), loadLists(), loadReviews()]); }
    catch (error) { message(error.message, "danger"); }
  }
  $("review-status")?.addEventListener("change", loadReviews);
  $("operations-refresh")?.addEventListener("click", refresh);
  refresh();
})();

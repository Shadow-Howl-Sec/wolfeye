async function loadDetections() {
  const body = document.getElementById("detections-table");
  try {
    const response = await fetch("/api/detections?limit=100");
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to load detections");
    body.innerHTML = result.data.length ? result.data.map(d => {
      const danger = d.severity === "critical" || d.severity === "high";
      const action = d.blocked
        ? '<span class="badge text-bg-success">blocked</span>'
        : d.destination_ip
          ? `<button class="btn btn-sm btn-outline-danger" data-block-id="${d.id}">Block destination</button>`
          : '<span class="text-muted">No destination</span>';
      return `<tr><td><span class="badge text-bg-${danger ? "danger" : "warning"}">${d.severity}</span></td><td class="font-monospace">${d.source_ip}</td><td class="font-monospace">${d.destination_ip || "—"}</td><td>${d.threat_type}</td><td>${Number(d.score).toFixed(2)}</td><td>${d.decision}</td><td>${action}</td></tr>`;
    }).join("") : '<tr><td colspan="7" class="text-center text-muted py-5">No packet detections found.</td></tr>';
    body.querySelectorAll("[data-block-id]").forEach(button => {
      button.addEventListener("click", async () => {
        button.disabled = true;
        const result = await fetch(`/api/detections/${button.dataset.blockId}/block`, {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({reason: "Blocked from packet detections"})
        });
        if (!result.ok) {
          button.disabled = false;
          const error = await result.json();
          window.alert(error.error || "Blocking failed. Sign in as an analyst or administrator.");
          return;
        }
        await loadDetections();
      });
    });
  } catch (error) {
    body.innerHTML = '<tr><td colspan="7" class="text-center text-danger py-5">Unable to load detections.</td></tr>';
    console.error(error);
  }
}
loadDetections();

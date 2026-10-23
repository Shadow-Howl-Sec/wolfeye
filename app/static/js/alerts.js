async function loadAlerts() {
  const body = document.getElementById("alerts-table");
  try {
    const response = await fetch("/api/alerts?per_page=100");
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to load alerts");
    body.innerHTML = result.data.length ? result.data.map((a) => `<tr>
      <td><span class="badge text-bg-${a.severity === "critical" || a.severity === "high" ? "danger" : "warning"}">${a.severity}</span></td>
      <td class="font-monospace">${a.ioc?.value || `IOC #${a.ioc_id}`}</td>
      <td>${Number(a.risk_score ?? a.anomaly_score ?? 0).toFixed(2)}</td><td>${a.status}</td>
      <td>${new Date(a.created_at).toLocaleString()}</td>
      <td><button class="btn btn-sm btn-outline-warning me-1" data-review-alert="${a.id}">Review</button><a class="btn btn-sm btn-outline-primary" href="/api/alerts/${a.id}/report">PDF</a></td>
    </tr>`).join("") : '<tr><td colspan="6" class="text-center text-muted py-5">No alerts found.</td></tr>';
    body.querySelectorAll("[data-review-alert]").forEach((button) => button.addEventListener("click", async () => {
      button.disabled = true;
      const review = await fetch(`/api/review/alerts/${button.dataset.reviewAlert}`, {
        method: "POST", headers: {"Content-Type": "application/json"}
      });
      const data = await review.json();
      if (!review.ok) {
        button.disabled = false;
        window.alert(data.error || "Unable to create review item. Sign in as an analyst.");
        return;
      }
      button.textContent = "Queued";
      button.classList.replace("btn-outline-warning", "btn-outline-success");
    }));
  } catch (e) {
    body.innerHTML = '<tr><td colspan="6" class="text-center text-danger py-5">Unable to load alerts.</td></tr>';
    console.error(e);
  }
}
loadAlerts();

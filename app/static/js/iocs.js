async function loadIocs() {
  const body = document.getElementById("iocs-table");
  try { const result = await fetch("/api/iocs?per_page=100").then(r=>r.json()); body.innerHTML = result.data.length ? result.data.map(i=>`<tr><td class="font-monospace text-break">${i.value}</td><td>${i.type}</td><td>${i.source}</td><td>${i.anomaly_score == null ? "—" : Number(i.anomaly_score).toFixed(2)}</td><td><span class="badge bg-secondary">${i.status}</span></td><td>${new Date(i.first_seen).toLocaleString()}</td></tr>`).join("") : '<tr><td colspan="6" class="text-center text-muted py-5">No indicators found.</td></tr>'; } catch (e) { body.innerHTML = '<tr><td colspan="6" class="text-center text-danger py-5">Unable to load indicators.</td></tr>'; console.error(e); }
}
document.getElementById("ioc-search")?.addEventListener("input", e => document.querySelectorAll("#iocs-table tr").forEach(row => row.style.display = row.textContent.toLowerCase().includes(e.target.value.toLowerCase()) ? "" : "none"));
loadIocs();

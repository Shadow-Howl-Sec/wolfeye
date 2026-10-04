async function getJson(url) { const response = await fetch(url); if (!response.ok) throw new Error(`Request failed: ${response.status}`); return response.json(); }
function chart(id, config) { const canvas = document.getElementById(id); if (canvas && window.Chart) new Chart(canvas, config); }
async function loadDashboard() {
  try {
    const summary = await getJson("/api/stats/summary");
    document.getElementById("kpi-total-iocs").textContent = summary.total_iocs;
    document.getElementById("kpi-active-alerts").textContent = summary.open_alerts;
    document.getElementById("kpi-high-severity").textContent = summary.critical_alerts;
    document.getElementById("kpi-resolved-today").textContent = "—";
    const [trends, severity, types] = await Promise.all([getJson("/api/stats/trends?days=7"), getJson("/api/stats/severity-mix"), getJson("/api/stats/ioc-type-mix")]);
    chart("chart-trend", { type:"line", data:{ labels:trends.map(x=>x.date), datasets:[{label:"IOCs", data:trends.map(x=>x.count), borderColor:"#43d9b1", backgroundColor:"rgba(67,217,177,.15)", fill:true, tension:.35}] }, options:{ plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true}} }});
    chart("chart-severity", { type:"doughnut", data:{ labels:severity.map(x=>x.severity), datasets:[{data:severity.map(x=>x.count), backgroundColor:["#43d9b1","#facc15","#fb923c","#f43f5e"]}] }, options:{ plugins:{legend:{position:"bottom"}} }});
    chart("chart-ioc-types", { type:"doughnut", data:{ labels:types.map(x=>x.type), datasets:[{data:types.map(x=>x.count), backgroundColor:["#38bdf8","#818cf8","#c084fc","#fb7185","#4ade80"]}] }, options:{ plugins:{legend:{position:"bottom"}} }});
    const alerts = await getJson("/api/alerts?per_page=5");
    const list = document.getElementById("recent-alerts-list");
    list.innerHTML = alerts.data.length ? alerts.data.map(a=>`<li class="px-3 py-3 border-bottom border-secondary"><span class="badge text-bg-${a.severity === "critical" ? "danger" : "warning"}">${a.severity}</span> <span class="ms-2">${a.ioc?.value || `IOC #${a.ioc_id}`}</span></li>`).join("") : '<li class="text-muted text-center py-4">No alerts yet.</li>';
  } catch (error) { console.error(error); document.querySelectorAll(".kpi-value").forEach(el=>el.textContent="Unavailable"); }
}
loadDashboard();

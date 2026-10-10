async function getJson(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return response.json();
}

function updateClock() {
  const clock = document.getElementById("briefing-clock");
  if (clock) clock.textContent = `UTC ${new Date().toISOString().slice(11, 19)}`;
}

function renderNetworkChart() {
  const canvas = document.getElementById("chart-network-anomalies");
  if (!canvas || !window.Chart) return;
  new Chart(canvas, {
    type: "line",
    data: {
      labels: ["16:45", "16:48", "16:51", "16:54", "16:57", "17:00", "17:03", "17:06", "17:09", "17:12", "17:15", "NOW"],
      datasets: [{
        data: [6200, 6800, 6400, 7200, 6900, 9100, 8700, 11200, 10400, 15100, 13400, 18420],
        borderColor: "#d97706",
        borderWidth: 1,
        pointRadius: 0,
        stepped: true,
        tension: 0,
      }],
    },
    options: {
      animation: false,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: {
        x: { display: false },
        y: { display: false, beginAtZero: true },
      },
    },
  });
}

async function loadDashboard() {
  try {
    const summary = await getJson("/api/stats/summary");
    document.getElementById("kpi-total-iocs").textContent = summary.total_iocs;
    document.getElementById("kpi-active-alerts").textContent = summary.open_alerts;
    document.getElementById("kpi-high-severity").textContent = summary.high_severity_alerts;
    document.getElementById("kpi-resolved-today").textContent = summary.resolved_alerts_24h;
  } catch (error) {
    console.error(error);
    document.querySelectorAll(".metric-cell strong").forEach((el) => { el.textContent = "—"; });
  }
  renderNetworkChart();
  updateClock();
  window.setInterval(updateClock, 1000);
}

loadDashboard();

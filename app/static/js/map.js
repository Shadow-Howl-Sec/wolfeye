async function loadMap() {
  const map = L.map("threat-map").setView([20, 0], 2);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { attribution:"&copy; OpenStreetMap contributors" }).addTo(map);
  try { const data = await fetch("/api/stats/top-countries?limit=20").then(r=>r.json()); data.forEach(item => { if (item.latitude && item.longitude) L.marker([item.latitude, item.longitude]).addTo(map).bindPopup(`${item.country}: ${item.count}`); }); } catch (error) { console.error(error); }
}
loadMap();

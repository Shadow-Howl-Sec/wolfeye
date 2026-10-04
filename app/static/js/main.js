(() => {
  const sidebar = document.getElementById("sidebar");
  document.getElementById("sidebar-toggle")?.addEventListener("click", () => sidebar?.classList.toggle("open"));
  const refresh = document.getElementById("refresh-btn");
  refresh?.addEventListener("click", () => window.location.reload());
  const sync = document.getElementById("sync-indicator");
  if (sync) sync.textContent = `Updated ${new Date().toLocaleTimeString()}`;
})();

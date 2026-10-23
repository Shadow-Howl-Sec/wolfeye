document.getElementById("login-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const message = document.getElementById("login-message");
  const payload = {
    username: document.getElementById("login-username").value.trim(),
    password: document.getElementById("login-password").value
  };
  try {
    const response = await fetch("/api/auth/login", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Sign in failed");
    window.location.href = "/operations";
  } catch (error) {
    message.className = "small mt-3 text-danger";
    message.textContent = error.message;
  }
});

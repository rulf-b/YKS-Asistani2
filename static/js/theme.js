document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("themeToggle");
  if (!toggle) return;
  // Load saved
  const saved = localStorage.getItem("theme");
  if (saved === "dark") {
    document.documentElement.setAttribute("data-theme", "dark");
    toggle.checked = true;
  }
  toggle.addEventListener("change", () => {
    if (toggle.checked) {
      document.documentElement.setAttribute("data-theme", "dark");
      localStorage.setItem("theme", "dark");
    } else {
      document.documentElement.removeAttribute("data-theme");
      localStorage.setItem("theme", "light");
    }
  });
}); 
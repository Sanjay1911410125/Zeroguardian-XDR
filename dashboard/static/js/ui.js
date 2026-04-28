const sidebar = document.getElementById("sidebar");
const toggleBtn = document.getElementById("toggleBtn");

function applyState() {
  const collapsed = localStorage.getItem("zg_sidebar") === "1";
  if (collapsed) sidebar.classList.add("zg-collapsed");
  else sidebar.classList.remove("zg-collapsed");
}

toggleBtn?.addEventListener("click", () => {
  sidebar.classList.toggle("zg-collapsed");
  localStorage.setItem("zg_sidebar", sidebar.classList.contains("zg-collapsed") ? "1" : "0");
});

applyState();


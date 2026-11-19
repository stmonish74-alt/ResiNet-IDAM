const pageTitles = {
  dashboard: "Security Dashboard", detection: "AI Intrusion Detection",
  datasets: "IT Dataset Explorer", identity: "Identity & Access",
  "zero-trust": "Zero-Trust Security", monitoring: "Adaptive Monitoring",
  reports: "Reports & Audit Logs"
};
let currentEvents = [];

function toast(message) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(window.toastTimeout);
  window.toastTimeout = setTimeout(() => el.classList.remove("show"), 2600);
}

function navigate(page) {
  if (!pageTitles[page]) return;
  document.querySelectorAll(".page").forEach(el => el.classList.remove("active"));
  document.getElementById(`page-${page}`).classList.add("active");
  document.querySelectorAll(".nav-item").forEach(el => el.classList.toggle("active", el.dataset.page === page));
  document.getElementById("breadcrumb-current").textContent = pageTitles[page];
  document.getElementById("sidebar").classList.remove("open");
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (page === "monitoring" || page === "reports") renderEventLists();
}

document.querySelectorAll(".nav-item").forEach(button => {
  button.addEventListener("click", () => navigate(button.dataset.page));
});
document.querySelectorAll("[data-goto]").forEach(button => {
  button.addEventListener("click", () => navigate(button.dataset.goto));
});
document.getElementById("menu-toggle").addEventListener("click", () => {
  document.getElementById("sidebar").classList.toggle("open");
});

function severityClass(value) {
  const v = value.toLowerCase();
  if (v === "high") return "severity-high";
  if (v === "medium" || v === "suspicious") return "severity-medium";
  return "severity-info";
}
function eventRows(events) {
  if (!events.length) return '<tr><td colspan="5" class="empty-cell">No events available.</td></tr>';
  return events.map(e => `<tr><td>${escapeHtml(e.time)}</td><td>${escapeHtml(e.event)}</td><td><span class="severity ${severityClass(e.severity)}">${escapeHtml(e.severity)}</span></td><td>${escapeHtml(e.source)}</td><td class="action-text">${escapeHtml(e.action)}</td></tr>`).join("");
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function renderEventLists() {
  document.getElementById("events-body").innerHTML = eventRows(currentEvents);
  document.getElementById("audit-body").innerHTML = eventRows(currentEvents);
  document.getElementById("monitor-event-list").innerHTML = currentEvents.map(e =>
    `<div class="monitor-item"><span class="monitor-bullet" style="background:${e.severity === "Info" ? "var(--green)" : e.severity === "High" ? "var(--red)" : "var(--amber)"}"></span><div class="monitor-copy"><b>${escapeHtml(e.event)}</b><small>${escapeHtml(e.source)} · ${escapeHtml(e.severity)} severity</small></div><span class="monitor-time">${escapeHtml(e.time)}</span></div>`
  ).join("");
}
function drawTraffic(points) {
  const svg = document.getElementById("traffic-chart");
  const w = 700, h = 205, max = 65;
  const coords = points.map((p, i) => {
    const x = i * (w / (points.length - 1));
    const y = h - (p.value / max) * (h - 12) - 4;
    return [x, y];
  });
  const line = coords.map((p, i) => `${i ? "L" : "M"} ${p[0]} ${p[1]}`).join(" ");
  const area = `${line} L ${w} ${h} L 0 ${h} Z`;
  svg.innerHTML = `<defs><linearGradient id="areaFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#36c8ee" stop-opacity=".28"/><stop offset="100%" stop-color="#36c8ee" stop-opacity="0"/></linearGradient></defs><path d="${area}" fill="url(#areaFill)"/><path d="${line}" fill="none" stroke="#42cbea" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>${coords.map(p => `<circle cx="${p[0]}" cy="${p[1]}" r="4" fill="#0e1827" stroke="#63def6" stroke-width="2"/>`).join("")}`;
}
async function loadDashboard() {
  try {
    const [healthRes, dataRes, eventsRes] = await Promise.all([
      fetch("/api/health"), fetch("/api/dashboard"), fetch("/api/events")
    ]);
    if (!healthRes.ok || !dataRes.ok || !eventsRes.ok) throw new Error("API request failed");
    const health = await healthRes.json();
    const data = await dataRes.json();
    const eventData = await eventsRes.json();
    document.getElementById("backend-status").textContent = health.status === "ok" ? "Backend connected" : "Backend unavailable";
    document.getElementById("metric-events").textContent = data.network_events.toLocaleString();
    document.getElementById("metric-threats").textContent = data.threats_detected.toLocaleString();
    document.getElementById("metric-allowed").textContent = data.access_allowed.toLocaleString();
    document.getElementById("metric-denied").textContent = data.access_denied.toLocaleString();
    currentEvents = eventData.events || [];
    drawTraffic(data.traffic);
    renderEventLists();
  } catch (error) {
    document.getElementById("backend-status").textContent = "Backend disconnected";
    toast("Could not connect to Flask API. Check that app.py is running.");
  }
}
document.getElementById("refresh-dashboard").addEventListener("click", async () => {
  await loadDashboard();
  toast("Dashboard view refreshed.");
});

document.getElementById("current-date").textContent = new Intl.DateTimeFormat("en-IN", {
  day: "2-digit", month: "short", year: "numeric"
}).format(new Date());

document.getElementById("csv-file").addEventListener("change", event => {
  const file = event.target.files[0];
  if (!file) return;
  if (!file.name.toLowerCase().endsWith(".csv")) {
    toast("Please choose a CSV file.");
    event.target.value = "";
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    toast("For this browser preview, choose a CSV smaller than 10 MB.");
    event.target.value = "";
    return;
  }
  const reader = new FileReader();
  reader.onload = e => previewCsv(String(e.target.result || ""), file.name);
  reader.onerror = () => toast("Unable to read this file.");
  reader.readAsText(file);
});
function parseCsvLine(line) {
  const result = [];
  let cell = "", quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && quoted && line[i + 1] === '"') { cell += '"'; i++; }
    else if (ch === '"') quoted = !quoted;
    else if (ch === "," && !quoted) { result.push(cell); cell = ""; }
    else cell += ch;
  }
  result.push(cell);
  return result;
}
function previewCsv(content, filename) {
  const lines = content.replace(/^\uFEFF/, "").split(/\r?\n/).filter(line => line.trim()).slice(0, 101);
  if (lines.length < 2) { toast("CSV needs a header and at least one data row."); return; }
  const headers = parseCsvLine(lines[0]).slice(0, 10);
  const records = lines.slice(1, 11).map(parseCsvLine);
  document.getElementById("preview-head").innerHTML = `<tr>${headers.map(h => `<th>${escapeHtml(h)}</th>`).join("")}</tr>`;
  document.getElementById("preview-body").innerHTML = records.map(row => `<tr>${headers.map((_, i) => `<td>${escapeHtml(row[i] ?? "")}</td>`).join("")}</tr>`).join("");
  document.getElementById("dataset-summary").textContent = `${filename} · ${lines.length - 1} preview rows read · ${headers.length} columns shown`;
  const status = document.getElementById("dataset-status");
  status.textContent = "PREVIEW LOADED";
  status.className = "status-pill";
  status.style.cssText = "color:#5cdbad;background:#15372f;border:1px solid #285b4c";
  document.getElementById("upload-hint").textContent = `${filename} · Browser preview only · First 10 records displayed`;
  toast("CSV preview loaded successfully.");
}

document.getElementById("access-form").addEventListener("submit", event => {
  event.preventDefault();
  const user = document.getElementById("zt-user").value.trim();
  const device = document.getElementById("zt-device").value;
  const identity = document.getElementById("zt-identity").value;
  const resource = document.getElementById("zt-resource").value;
  const allowed = Boolean(user) && device === "trusted" && identity === "verified";
  const panel = document.getElementById("decision-panel");
  const reason = allowed
    ? "Demo checks passed: identity marked verified and device marked trusted. This is not a real authorization decision."
    : "Demo policy denied the request because the identity is unverified, the device is not trusted, or the username is missing.";
  panel.innerHTML = `<div class="decision-result ${allowed ? "allowed" : "denied"}"><div class="decision-icon"><i data-lucide="${allowed ? "shield-check" : "shield-x"}"></i></div><h3>${allowed ? "DEMO · ALLOW" : "DEMO · DENY"}</h3><p>Access request evaluation completed for <b>${escapeHtml(user || "unknown user")}</b>.</p><div class="decision-reason">${escapeHtml(reason)}<br><br><b>Resource:</b> ${escapeHtml(resource)}</div></div>`;
  if (window.lucide) lucide.createIcons();
});

document.getElementById("download-events").addEventListener("click", () => {
  if (!currentEvents.length) { toast("There are no events to export."); return; }
  const headers = ["time", "event", "severity", "source", "action"];
  const csv = [headers.join(","), ...currentEvents.map(row => headers.map(k => `"${String(row[k] ?? "").replace(/"/g, '""')}"`).join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "resinet_demo_audit_events.csv"; a.click();
  URL.revokeObjectURL(url);
  toast("Demo event CSV exported.");
});

if (window.lucide) lucide.createIcons();
loadDashboard();

function riskClass(score) {
  if (score >= 51) return "risk-high";
  if (score >= 21) return "risk-medium";
  return "risk-low";
}

function riskBadge(score) {
  const cls = score >= 51 ? "text-bg-danger" : (score >= 21 ? "text-bg-warning text-dark" : "text-bg-success");
  return `<span class="badge ${cls}">${score}</span>`;
}

function resultBadge(result) {
  const map = {
    allowed: "text-bg-success",
    mfa_required: "text-bg-warning text-dark",
    blocked: "text-bg-danger",
    invalid_credentials: "text-bg-secondary",
    account_blocked: "text-bg-danger",
  };
  const cls = map[result] || "text-bg-secondary";
  return `<span class="badge ${cls}">${result}</span>`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

async function refreshLog() {
  try {
    const res = await fetch("/admin/api/logs");
    if (!res.ok) return;
    const rows = await res.json();
    const body = document.getElementById("logTableBody");
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="8" class="text-center text-secondary py-3">No login attempts yet.</td></tr>';
      return;
    }
    body.innerHTML = rows.map(r => `
      <tr class="${riskClass(r.risk_score)}">
        <td class="small">${escapeHtml(r.timestamp ? new Date(r.timestamp).toLocaleString() : "-")}</td>
        <td>${escapeHtml(r.user_id)}</td>
        <td>${escapeHtml(r.ip)}</td>
        <td class="small">${escapeHtml(r.device)}</td>
        <td class="small">${escapeHtml(r.location || "-")}</td>
        <td>${riskBadge(r.risk_score)}</td>
        <td>${resultBadge(r.result)}</td>
        <td class="small text-secondary">${escapeHtml((r.risk_signals_triggered || []).join(", "))}</td>
      </tr>
    `).join("");
  } catch (e) {
    console.error("Failed to refresh log", e);
  }
}

async function refreshBlocked() {
  try {
    const res = await fetch("/admin/api/users");
    if (!res.ok) return;
    const users = await res.json();
    const blocked = users.filter(u => u.is_blocked);
    const body = document.getElementById("blockedTableBody");
    if (!blocked.length) {
      body.innerHTML = '<tr><td colspan="4" class="text-center text-secondary py-3">No blocked accounts.</td></tr>';
      return;
    }
    body.innerHTML = blocked.map(u => `
      <tr>
        <td class="fw-semibold">${escapeHtml(u.username)}</td>
        <td><span class="badge text-bg-secondary text-uppercase">${escapeHtml(u.role)}</span></td>
        <td>${escapeHtml(u.typical_location || "-")}</td>
        <td class="text-end">
          <button class="btn btn-sm btn-success" onclick="unblockUser('${u.username}')">
            <i class="bi bi-unlock-fill"></i> Unblock
          </button>
        </td>
      </tr>
    `).join("");
  } catch (e) {
    console.error("Failed to refresh blocked list", e);
  }
}

async function unblockUser(username) {
  try {
    const res = await fetch(`/admin/api/users/${encodeURIComponent(username)}/unblock`, { method: "POST" });
    if (res.ok) {
      refreshBlocked();
      refreshLog();
    }
  } catch (e) {
    console.error("Failed to unblock user", e);
  }
}

function refreshAll() {
  refreshLog();
  refreshBlocked();
}

refreshAll();
setInterval(refreshAll, 5000);

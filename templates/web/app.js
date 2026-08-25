"use strict";
// Dashboard front end. No frameworks, no CDN — the CSP forbids both, and the
// box should not need a build step to serve its own status page.

let csrf = null;
let pollTimer = null;

const $ = (id) => document.getElementById(id);
const show = (el, on) => el.classList.toggle("hidden", !on);

async function api(path, options = {}) {
  const opts = { credentials: "same-origin", headers: {}, ...options };
  if (opts.body) {
    opts.headers["Content-Type"] = "application/json";
    opts.headers["X-CSRF-Token"] = csrf || "";
  }
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (e) { /* empty body */ }
  if (res.status === 401 && path !== "/api/login") { toLogin(); throw new Error("signed out"); }
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data;
}

// ------------------------------------------------------------------ format --
function duration(sec) {
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600),
        m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}
function bytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1);
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
}
function text(el, value) { el.textContent = value; }

// ------------------------------------------------------------------ render --
function renderStatus(s) {
  const card = $("card-tunnel");
  card.className = "card state-" + (s.tunnel === "up" ? "up"
                    : s.tunnel === "down" ? "down" : "unknown");
  text($("tunnel-state"), s.tunnel === "up" ? "Up"
                        : s.tunnel === "down" ? "Down" : "Unknown");
  let sub = "";
  if (s.tunnel === "down") sub = `${s.fails} consecutive failed probes`;
  else if (s.tunnel === "unknown") sub = "health check has not run yet";
  if (s.lifeline) sub += (sub ? " · " : "") + "lifeline engaged";
  text($("tunnel-sub"), sub);

  text($("default-policy"), s.default_policy);
  text($("killswitch"), (s.firewall.killswitch_drops ?? 0).toLocaleString());

  const sys = s.system || {};
  text($("uptime"), duration(sys.uptime || 0));
  const memUsed = (sys.mem_total || 0) - (sys.mem_available || 0);
  text($("sysload"),
    `load ${(sys.load || [0])[0].toFixed(2)} · ` +
    `mem ${bytes(memUsed)}/${bytes(sys.mem_total)} · ` +
    `disk ${bytes(sys.disk_free)} free`);

  const rows = Object.entries(s.services || {}).map(([unit, v]) => {
    const good = v.active === "active";
    const boot = v.enabled === "enabled";
    return `<tr><td>${unit.replace(/\.(service|target|timer)$/, "")}</td>
      <td><span class="badge ${good ? "ok" : "bad"}">${v.active}</span></td>
      <td class="muted small">${boot ? "starts on boot" : "NOT enabled at boot"}</td></tr>`;
  });
  $("services").querySelector("tbody").innerHTML =
    rows.join("") || `<tr><td class="muted">no services reported</td></tr>`;

  const traffic = Object.entries(s.traffic || {});
  $("traffic").querySelector("tbody").innerHTML = traffic.length
    ? traffic.map(([tag, t]) =>
        `<tr><td>${tag}</td><td>↑ ${bytes(t.uplink || 0)}</td>
         <td>↓ ${bytes(t.downlink || 0)}</td></tr>`).join("")
    : `<tr><td class="muted">no counters yet</td></tr>`;
}

const POLICY_HINT = {
  proxy:  "force through the tunnel",
  direct: "bypass the tunnel",
  block:  "drop at the gateway",
};

function renderPolicyOptions(data) {
  // Built from the config's actual policies, so profiles appear here without
  // the page knowing anything about them.
  const sel = $("add-policy");
  const current = sel.value;
  const profiles = new Set(data.profiles || []);
  sel.innerHTML = (data.policies || ["proxy", "direct", "block"])
    .map((p) => {
      const hint = profiles.has(p) ? "profile" : POLICY_HINT[p] || "";
      return `<option value="${escapeHtml(p)}">${escapeHtml(p)}${hint ? " — " + hint : ""}</option>`;
    }).join("");
  if (current) sel.value = current;
}

function renderClients(data) {
  renderPolicyOptions(data);
  const body = $("clients").querySelector("tbody");
  text($("clients-note"),
    `Default is "${data.default_policy}" — any device that points its gateway at ` +
    `this box gets that without being listed. Entries below are overrides.`);

  if (!data.clients.length) {
    body.innerHTML = `<tr><td colspan="4" class="muted">no overrides — every device gets the default</td></tr>`;
    return;
  }
  body.innerHTML = data.clients.map((c) => `
    <tr>
      <td class="addr">${escapeHtml(c.ip)}</td>
      <td>${escapeHtml(c.name)}</td>
      <td><span class="badge ${c.policy}">${c.policy}</span></td>
      <td style="text-align:right">
        <button class="danger" data-rm="${escapeHtml(c.ip)}">Remove</button>
      </td>
    </tr>`).join("");

  body.querySelectorAll("[data-rm]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const ip = btn.getAttribute("data-rm");
      if (!confirm(`Remove the override for ${ip}? It will fall back to the default policy.`)) return;
      await guard(async () => {
        const r = await api("/api/clients/delete", {
          method: "POST", body: JSON.stringify({ ip }) });
        markPending(r);
        await loadClients();
      });
    });
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function markPending(r) { if (r && r.pending_apply) show($("pending"), true); }

async function guard(fn) {
  const err = $("client-error");
  show(err, false);
  try { await fn(); }
  catch (e) { text(err, e.message); show(err, true); }
}

// ------------------------------------------------------------------- flow --
async function loadStatus() { renderStatus(await api("/api/status")); }
async function loadClients() { renderClients(await api("/api/clients")); }

function startPolling() {
  const tick = () => loadStatus().catch(() => {});
  tick();
  clearInterval(pollTimer);
  pollTimer = setInterval(tick, 5000);
}

function toLogin() {
  clearInterval(pollTimer);
  csrf = null;
  show($("app"), false);
  show($("login"), true);
}

async function toApp() {
  show($("login"), false);
  show($("app"), true);
  startPolling();
  await guard(loadClients);
}

// ------------------------------------------------------------------ events --
$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("login-error");
  show(err, false);
  try {
    const r = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ password: $("password").value }),
    });
    csrf = r.csrf;
    $("password").value = "";
    await toApp();
  } catch (ex) { text(err, ex.message); show(err, true); }
});

$("logout").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST", body: "{}" }); } catch (e) {}
  toLogin();
});

$("add-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await guard(async () => {
    const r = await api("/api/clients", {
      method: "POST",
      body: JSON.stringify({
        ip: $("add-ip").value.trim(),
        name: $("add-name").value.trim(),
        policy: $("add-policy").value,
      }),
    });
    markPending(r);
    $("add-ip").value = ""; $("add-name").value = "";
    await loadClients();
  });
});

$("apply-btn").addEventListener("click", async () => {
  const btn = $("apply-btn");
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = "Applying…";
  await guard(async () => {
    await api("/api/apply", { method: "POST", body: "{}" });
    show($("pending"), false);
    await loadClients();
    await loadStatus();
  });
  btn.disabled = false;
  btn.textContent = original;
});

$("probe-btn").addEventListener("click", async () => {
  const btn = $("probe-btn"), out = $("probe-result");
  btn.disabled = true;
  out.textContent = "Checking…";
  try {
    const r = await api("/api/probe", { method: "POST", body: "{}" });
    const tun = r.tunnel_ip || "unreachable";
    const real = r.real_ip || "unreachable";
    out.innerHTML =
      `through the tunnel: <strong>${escapeHtml(tun)}</strong><br>` +
      `direct (your ISP):  <strong>${escapeHtml(real)}</strong><br>` +
      (r.leaking
        ? `<span class="badge bad">same address — traffic is NOT being proxied</span>`
        : r.tunnel_ip
          ? `<span class="badge ok">addresses differ — the tunnel is carrying traffic</span>`
          : `<span class="badge bad">the tunnel did not answer</span>`);
  } catch (e) { out.textContent = e.message; }
  btn.disabled = false;
});

setInterval(() => {
  text($("clock"), new Date().toLocaleTimeString());
}, 1000);

(async function init() {
  try {
    const s = await api("/api/session");
    if (!s.password_set) {
      text($("login-hint"), "No password is set yet. Run `sudo gw web-passwd` on the box.");
    }
    if (s.authenticated) { csrf = s.csrf; await toApp(); }
    else toLogin();
  } catch (e) { toLogin(); }
})();

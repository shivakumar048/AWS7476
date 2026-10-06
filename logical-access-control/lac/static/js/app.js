import { get, hasToken, post, setToken } from "./api.js";
import { errorCard, h, loading, mount } from "./ui.js";
import * as dashboard from "./views/dashboard.js";
import * as users from "./views/users.js";
import * as userDetail from "./views/user-detail.js";
import * as principals from "./views/principals.js";
import * as policies from "./views/policies.js";
import * as policyEditor from "./views/policy-editor.js";
import * as endpointRules from "./views/endpoint-rules.js";
import * as endpointEvents from "./views/endpoint-events.js";
import * as simulator from "./views/simulator.js";
import * as audit from "./views/audit.js";
import * as me from "./views/me.js";

const $ = (id) => document.getElementById(id);

// Permissions probed once at sign-in to decide what to show.
// The server still enforces every call; this only hides what you can't use.
const PROBES = {
  listUsers: ["lac:ListUsers", "lac:user/*"],
  createUser: ["lac:CreateUser", "lac:user/*"],
  listGroups: ["lac:ListGroups", "lac:group/*"],
  createGroup: ["lac:CreateGroup", "lac:group/*"],
  listRoles: ["lac:ListRoles", "lac:role/*"],
  createRole: ["lac:CreateRole", "lac:role/*"],
  listPolicies: ["lac:ListPolicies", "lac:policy/*"],
  createPolicy: ["lac:CreatePolicy", "lac:policy/*"],
  updatePolicy: ["lac:UpdatePolicy", "lac:policy/*"],
  deletePolicy: ["lac:DeletePolicy", "lac:policy/*"],
  attachGroup: ["lac:AttachPolicy", "lac:group/*"],
  listSod: ["lac:ListSoDRules", "lac:sod/*"],
  createSod: ["lac:CreateSoDRule", "lac:sod/*"],
  readAudit: ["lac:ReadAuditLog", "lac:audit"],
  endpointEvents: ["lac:ReadEndpointEvents", "lac:endpoint-events"],
  simulate: ["lac:SimulatePrincipalPolicy", "lac:user/*"],
};

const NAV = [
  { section: "Overview" },
  { path: "", label: "Dashboard", icon: "▦" },
  { path: "check", label: "Access check", icon: "✓" },
  { section: "Identity" },
  { path: "users", label: "Users", icon: "👤", cap: "listUsers" },
  { path: "groups", label: "Groups", icon: "👥", cap: "listGroups" },
  { path: "roles", label: "Roles & duties", icon: "🎭", cap: "listRoles" },
  { path: "policies", label: "Policies", icon: "📜", cap: "listPolicies" },
  { section: "Endpoint Guard" },
  { path: "endpoint", label: "Endpoint rules", icon: "🖥", cap: ["listGroups", "listPolicies", "createPolicy", "attachGroup"] },
  { path: "endpoint-events", label: "Blocked actions", icon: "⛔", cap: "endpointEvents" },
  { section: "Governance" },
  { path: "audit", label: "Audit trail", icon: "🧾", cap: "readAudit" },
  { path: "me", label: "My access", icon: "🔑" },
];

const ROUTES = [
  { pattern: /^$/, view: dashboard, title: "Dashboard" },
  { pattern: /^users$/, view: users, title: "Users" },
  { pattern: /^users\/([^/]+)$/, view: userDetail, title: "User" },
  { pattern: /^groups$/, view: principals, title: "Groups", params: { kind: "group" } },
  { pattern: /^roles$/, view: principals, title: "Roles & separation of duties", params: { kind: "role" } },
  { pattern: /^policies$/, view: policies, title: "Policies" },
  { pattern: /^policies\/new$/, view: policyEditor, title: "New policy", params: { isNew: true } },
  { pattern: /^policies\/([^/]+)$/, view: policyEditor, title: "Policy" },
  { pattern: /^endpoint$/, view: endpointRules, title: "Endpoint rules" },
  { pattern: /^endpoint-events$/, view: endpointEvents, title: "Blocked endpoint actions" },
  { pattern: /^check$/, view: simulator, title: "Access check" },
  { pattern: /^audit$/, view: audit, title: "Audit trail" },
  { pattern: /^me$/, view: me, title: "My access" },
];

const ctx = {
  user: null,
  can: {},
  navigate: (path) => { location.hash = `#/${path}`; },
  refresh: () => render(),
};

function allowed(cap) {
  if (!cap) return true;
  return (Array.isArray(cap) ? cap : [cap]).every((c) => ctx.can[c]);
}

async function loadSession() {
  const self = await get("/api/me");
  ctx.user = self.user;
  ctx.self = self;
  const keys = Object.keys(PROBES);
  const results = await post("/api/me/permissions", {
    checks: keys.map((k) => ({ action: PROBES[k][0], resource: PROBES[k][1] })),
  });
  ctx.can = Object.fromEntries(keys.map((k, i) => [k, results[i]]));
}

function renderNav(current) {
  const items = [];
  let pendingSection = null;
  for (const item of NAV) {
    if (item.section) { pendingSection = item.section; continue; }
    if (!allowed(item.cap)) continue;
    if (pendingSection) { items.push(h("div", { class: "nav-section" }, pendingSection)); pendingSection = null; }
    const active = current === item.path || (item.path && current.startsWith(item.path + "/"));
    items.push(h("a", { class: `nav-link ${active ? "active" : ""}`, href: `#/${item.path}`, "aria-current": active ? "page" : null },
      h("span", { class: "nav-icon", "aria-hidden": "true" }, item.icon), item.label));
  }
  mount($("nav"), items);
}

let renderSeq = 0;
async function render() {
  if (!ctx.user) return;
  const path = decodeURI(location.hash.replace(/^#\/?/, ""));
  const route = ROUTES.find((r) => r.pattern.test(path));
  const content = $("content");
  $("app-view").classList.remove("nav-open");
  renderNav(path);
  if (!route) {
    $("page-title").textContent = "Not found";
    mount(content, errorCard(new Error("This page doesn't exist.")));
    return;
  }
  const match = path.match(route.pattern);
  const params = { ...(route.params || {}), id: match[1] ? decodeURIComponent(match[1]) : undefined };
  $("page-title").textContent = params.id || route.title;
  document.title = `${params.id || route.title} · Access Control`;
  const seq = ++renderSeq;
  mount(content, loading());
  try {
    const node = await route.view.render(params, ctx);
    if (seq !== renderSeq) return; // a newer navigation won
    mount(content, node);
  } catch (err) {
    if (seq === renderSeq) mount(content, errorCard(err));
  }
  content.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

function showLogin(message = "") {
  ctx.user = null;
  $("boot").classList.add("hidden");
  $("app-view").classList.add("hidden");
  $("login-view").classList.remove("hidden");
  $("login-error").textContent = message;
  $("login-user").focus();
}

async function showApp() {
  await loadSession();
  $("boot").classList.add("hidden");
  $("login-view").classList.add("hidden");
  $("app-view").classList.remove("hidden");
  $("current-user").textContent = ctx.user;
  await render();
}

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector("button[type=submit]");
  const username = $("login-user").value.trim();
  const password = $("login-pass").value;
  if (!username || !password) { $("login-error").textContent = "Enter your username and password."; return; }
  btn.disabled = true;
  try {
    const { token } = await post("/api/login", { username, password });
    setToken(token);
    $("login-pass").value = "";
    await showApp();
  } catch (err) {
    $("login-error").textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

$("logout").addEventListener("click", async () => {
  try { await post("/api/logout"); } catch { /* already gone */ }
  setToken(null);
  showLogin();
});

window.addEventListener("auth:expired", () => showLogin("Your session expired. Please sign in again."));
window.addEventListener("hashchange", render);
$("menu-toggle").addEventListener("click", () => $("app-view").classList.toggle("nav-open"));
$("scrim").addEventListener("click", () => $("app-view").classList.remove("nav-open"));

// Theme: follows the OS unless the user picks one.
const THEME_KEY = "lac.theme";
function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}
try { applyTheme(localStorage.getItem(THEME_KEY)); } catch { /* storage blocked */ }
$("theme-toggle").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem(THEME_KEY, next); } catch { /* storage blocked */ }
});

if (hasToken()) showApp().catch(() => showLogin());
else showLogin();

import { enc, get } from "../api.js";
import { badge, card, fmtTime, h, pageHead, table, tile } from "../ui.js";

const DAY = 86400 * 1000;
const recent = (iso) => Date.now() - new Date(iso).getTime() < DAY;

function bars(counts) {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return h("div", { class: "empty" }, "No blocked actions in the last 24 hours.");
  const max = entries[0][1];
  return h("div", { class: "bars" }, entries.map(([label, n]) => {
    const fill = h("div", { class: "bar-fill" });
    fill.style.width = `${Math.max(4, (n / max) * 100)}%`;
    return h("div", { class: "bar-row" }, h("span", {}, label), h("div", { class: "bar-track" }, fill), h("span", { class: "num" }, n));
  }));
}

export async function render(_params, ctx) {
  const { can } = ctx;
  const [users, sod, auditRows, integrity, events] = await Promise.all([
    can.listUsers ? get("/api/users") : null,
    can.listSod ? get("/api/sod-violations") : null,
    can.readAudit ? get("/api/audit?limit=2000") : null,
    can.readAudit ? get("/api/audit/verify") : null,
    can.endpointEvents ? get("/api/endpoint/events?limit=5000") : null,
  ]);

  const tiles = [];
  if (users) {
    const locked = users.filter((u) => u.locked).length;
    const disabled = users.filter((u) => u.disabled).length;
    const noMfa = users.filter((u) => !u.mfa_enabled && !u.disabled).length;
    tiles.push(
      tile("Users", users.length, { note: `${disabled} disabled` }),
      tile("Locked accounts", locked, { kind: locked ? "warn" : "ok", note: "after repeated failed logins" }),
      tile("Active users without MFA", noMfa, { kind: noMfa ? "warn" : "ok" }),
    );
  }
  if (sod) tiles.push(tile("Separation-of-duty conflicts", sod.length, { kind: sod.length ? "bad" : "ok" }));
  let denials = [], failedLogins = [];
  if (auditRows) {
    denials = auditRows.filter((r) => r.event === "authz.decision" && !r.details.allowed && recent(r.timestamp));
    failedLogins = auditRows.filter((r) => r.event === "auth.failure" && recent(r.timestamp));
    tiles.push(
      tile("Access denials (24 h)", denials.length, { kind: denials.length ? "warn" : "" }),
      tile("Failed logins (24 h)", failedLogins.length, { kind: failedLogins.length > 5 ? "bad" : "" }),
    );
  }
  let blocked24 = [];
  if (events) {
    blocked24 = events.filter((e) => recent(e.timestamp || e.received));
    tiles.push(tile("Blocked endpoint actions (24 h)", blocked24.length, {
      note: `${new Set(blocked24.map((e) => e.host)).size} computers`,
    }));
  }

  const sections = [];
  if (integrity) {
    sections.push(integrity.intact
      ? h("div", { class: "banner ok" }, "✓ Audit trail intact: no entries have been altered or removed.")
      : h("div", { class: "banner bad", role: "alert" }, `⚠ Audit trail tampering detected at entry ${integrity.first_bad_entry}.`));
  }

  const grid = [];
  if (events) {
    const byControl = {};
    for (const e of blocked24) byControl[e.control || "unknown"] = (byControl[e.control || "unknown"] || 0) + 1;
    grid.push(card("Blocked on endpoints (24 h)", bars(byControl), {
      actions: [h("a", { href: "#/endpoint-events" }, "View all")],
    }));
  }
  if (auditRows) {
    grid.push(card("Recent access denials", table([
      { label: "When", render: (r) => fmtTime(r.timestamp) },
      { label: "Who", render: (r) => h("a", { href: `#/users/${enc(r.actor)}` }, r.actor) },
      { label: "Action", render: (r) => h("code", {}, r.details.action) },
      { label: "Resource", render: (r) => h("code", {}, r.details.resource) },
    ], denials.slice(-8).reverse(), { empty: "No denials in the last 24 hours." }), { flush: true }));
  }
  if (sod && sod.length) {
    grid.push(card("Separation-of-duty conflicts", table([
      { label: "User", render: (v) => h("a", { href: `#/users/${enc(v.user)}` }, v.user) },
      { label: "Rule", render: (v) => v.rule },
      { label: "Conflicting roles", render: (v) => v.roles.map((r) => badge(r, "bad")) },
    ], sod), { flush: true }));
  }
  if (users) {
    const attention = users.filter((u) => u.locked || (!u.mfa_enabled && !u.disabled));
    grid.push(card("Accounts needing attention", table([
      { label: "User", render: (u) => h("a", { href: `#/users/${enc(u.username)}` }, u.username) },
      { label: "Issue", render: (u) => [u.locked ? badge("locked", "warn") : null, !u.mfa_enabled ? badge("no MFA", "warn") : null] },
      { label: "Last login", render: (u) => fmtTime(u.last_login) },
    ], attention.slice(0, 8), { empty: "Every account looks healthy." }), { flush: true }));
  }

  if (!tiles.length && !grid.length) {
    const s = ctx.self;
    return h("div", {},
      pageHead(`Welcome, ${ctx.user}`, "You have a standard account. Here's a summary of your access."),
      h("div", { class: "tiles" },
        tile("Groups", s.groups.length), tile("Roles", s.roles.length), tile("Policies", s.policies.length),
        tile("MFA", s.mfa_enabled ? "On" : "Off", { kind: s.mfa_enabled ? "ok" : "warn" })),
      h("p", {}, h("a", { href: "#/me" }, "See exactly what you can access →")));
  }

  return h("div", {},
    pageHead("Overview", "Health of identities, permissions and endpoint restrictions at a glance."),
    sections,
    h("div", { class: "tiles" }, tiles),
    h("div", { class: "grid grid-2" }, grid));
}

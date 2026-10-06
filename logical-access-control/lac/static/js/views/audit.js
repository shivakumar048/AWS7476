import { enc, get } from "../api.js";
import { badge, button, card, debounce, downloadFile, fmtDateTime, h, pageHead, table } from "../ui.js";

function eventBadge(r) {
  if (r.event === "authz.decision") return badge(r.details.allowed ? "allowed" : "denied", r.details.allowed ? "ok" : "bad");
  if (r.event === "auth.failure" || r.event.endsWith("_blocked")) return badge(r.event, "bad");
  if (r.event === "auth.success") return badge(r.event, "ok");
  return badge(r.event, "info");
}

function summary(r) {
  const d = r.details || {};
  if (r.event === "authz.decision") return h("span", {}, h("code", {}, d.action), " on ", h("code", {}, d.resource), d.policy ? ` (${d.policy})` : "");
  const parts = Object.entries(d).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`);
  return h("span", { class: "mono" }, parts.join(" · "));
}

export async function render() {
  const [integrity, initial] = await Promise.all([get("/api/audit/verify"), get("/api/audit?limit=1000")]);
  let rows = initial;
  const holder = h("div");
  const actor = h("input", { type: "search", placeholder: "Actor", "aria-label": "Filter by actor" });
  const text = h("input", { type: "search", placeholder: "Search details", "aria-label": "Search details" });
  const kinds = [...new Set(rows.map((r) => r.event))].sort();
  const kind = h("select", { "aria-label": "Filter by event" }, h("option", { value: "" }, "All events"), kinds.map((k) => h("option", { value: k }, k)));
  const hideAuthz = h("input", { type: "checkbox" });
  let filtered = [];

  const draw = () => {
    const a = actor.value.toLowerCase(), t = text.value.toLowerCase(), k = kind.value;
    filtered = rows.filter((r) =>
      (!a || String(r.actor).toLowerCase().includes(a)) &&
      (!k || r.event === k) &&
      (!hideAuthz.checked || r.event !== "authz.decision") &&
      (!t || JSON.stringify(r.details).toLowerCase().includes(t))).slice().reverse();
    holder.replaceChildren(table([
      { label: "When", render: (r) => fmtDateTime(r.timestamp) },
      { label: "Actor", render: (r) => r.actor ? h("a", { href: `#/users/${enc(r.actor)}` }, r.actor) : "—" },
      { label: "Event", render: eventBadge },
      { label: "Details", render: summary },
    ], filtered.slice(0, 500), { empty: "No entries match." }));
  };
  [actor, text].forEach((el) => el.addEventListener("input", debounce(draw, 150)));
  kind.addEventListener("change", draw);
  hideAuthz.addEventListener("change", draw);
  draw();

  return h("div", {},
    pageHead("Audit trail", "Every sign-in, change and access decision. Entries are hash-chained, so any edit or deletion is detected.",
      button("Export JSON", () => downloadFile("audit.json", JSON.stringify(filtered, null, 2), "application/json"))),
    integrity.intact
      ? h("div", { class: "banner ok" }, `✓ Integrity verified across the whole log. Showing the latest ${rows.length} entries.`)
      : h("div", { class: "banner bad", role: "alert" }, `⚠ The log has been tampered with, starting at entry ${integrity.first_bad_entry}.`),
    card(null, [
      h("div", { class: "toolbar" }, actor, kind, text, h("label", { class: "check" }, hideAuthz, "Hide access decisions")),
      holder,
    ], { flush: true }));
}

import { enc, get } from "../api.js";
import { badge, button, card, debounce, h, pageHead, plural, table } from "../ui.js";

export async function usage(ctx) {
  const [users, groups, roles] = await Promise.all([
    ctx.can.listUsers ? get("/api/users") : [],
    ctx.can.listGroups ? get("/api/groups") : {},
    ctx.can.listRoles ? get("/api/roles") : {},
  ]);
  const map = {};
  const add = (policy, label) => (map[policy] = map[policy] || []).push(label);
  for (const u of users) u.policies.forEach((p) => add(p, `user:${u.username}`));
  for (const [g, v] of Object.entries(groups)) v.policies.forEach((p) => add(p, `group:${g}`));
  for (const [r, v] of Object.entries(roles)) v.policies.forEach((p) => add(p, `role:${r}`));
  return map;
}

export async function render(_params, ctx) {
  const [policies, used] = await Promise.all([get("/api/policies"), usage(ctx)]);
  const rows = Object.entries(policies).map(([name, p]) => ({ name, ...p })).sort((a, b) => a.name.localeCompare(b.name));
  const holder = h("div");
  const search = h("input", { type: "search", placeholder: "Search policies, actions…", "aria-label": "Search policies" });

  const draw = () => {
    const q = search.value.toLowerCase();
    const filtered = rows.filter((r) => !q || (r.name + r.description + JSON.stringify(r.document)).toLowerCase().includes(q));
    holder.replaceChildren(table([
      { label: "Policy", render: (r) => h("div", {}, h("strong", {}, r.name), r.description ? h("div", { class: "muted small" }, r.description) : null) },
      { label: "Effects", render: (r) => {
          const effects = r.document.Statement.map((s) => s.Effect);
          return [
            effects.includes("Allow") ? badge(`${effects.filter((e) => e === "Allow").length} allow`, "ok") : null,
            effects.includes("Deny") ? badge(`${effects.filter((e) => e === "Deny").length} deny`, "bad") : null,
          ];
        } },
      { label: "Used by", render: (r) => (used[r.name] || []).length
          ? (used[r.name]).map((u) => badge(u, "info"))
          : badge("unused", "warn") },
    ], filtered, { empty: "No policies match.", onRowClick: (r) => ctx.navigate(`policies/${enc(r.name)}`) }));
  };
  search.addEventListener("input", debounce(draw, 120));
  draw();

  return h("div", {},
    pageHead("Policies", `${plural(rows.length, "policy", "policies")}. A policy lists what is allowed or denied; an explicit deny always wins, and anything not allowed is denied.`,
      ctx.can.createPolicy ? button("+ New policy", () => ctx.navigate("policies/new"), { kind: "primary" }) : null),
    card(null, [h("div", { class: "toolbar" }, search), holder], { flush: true }));
}

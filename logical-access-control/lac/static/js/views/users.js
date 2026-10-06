import { get, post } from "../api.js";
import { badge, button, card, debounce, fmtTime, formModal, h, pageHead, plural, table, toast } from "../ui.js";

export function statusBadges(u) {
  return [
    u.disabled ? badge("disabled", "bad") : u.locked ? badge("locked", "warn") : badge("active", "ok"),
    u.mfa_enabled ? badge("MFA", "info") : null,
  ];
}

export function parseTags(text) {
  const tags = {};
  for (const part of text.split(",").map((s) => s.trim()).filter(Boolean)) {
    const i = part.indexOf("=");
    if (i < 1) throw new Error(`Tag "${part}" must look like key=value`);
    tags[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return tags;
}

export async function render(_params, ctx) {
  const [users, groups] = await Promise.all([
    get("/api/users"),
    ctx.can.listGroups ? get("/api/groups") : {},
  ]);

  const tableHolder = h("div");
  const search = h("input", { type: "search", placeholder: "Search users, groups, roles…", "aria-label": "Search users" });
  const status = h("select", { "aria-label": "Filter by status" },
    ["all", "active", "locked", "disabled", "no MFA"].map((s) => h("option", { value: s }, s === "all" ? "All statuses" : s)));

  const draw = () => {
    const q = search.value.toLowerCase();
    const s = status.value;
    const rows = users.filter((u) => {
      const text = [u.username, ...u.groups, ...u.roles, ...Object.values(u.tags)].join(" ").toLowerCase();
      if (q && !text.includes(q)) return false;
      if (s === "active") return !u.disabled && !u.locked;
      if (s === "locked") return u.locked;
      if (s === "disabled") return u.disabled;
      if (s === "no MFA") return !u.mfa_enabled;
      return true;
    });
    tableHolder.replaceChildren(table([
      { label: "User", render: (u) => h("strong", {}, u.username) },
      { label: "Groups", render: (u) => u.groups.join(", ") || "—" },
      { label: "Roles", render: (u) => u.roles.join(", ") || "—" },
      { label: "Tags", render: (u) => Object.entries(u.tags).map(([k, v]) => badge(`${k}=${v}`)) },
      { label: "Status", render: statusBadges },
      { label: "Last login", render: (u) => fmtTime(u.last_login) },
    ], rows, { empty: "No users match.", onRowClick: (u) => ctx.navigate(`users/${encodeURIComponent(u.username)}`) }));
  };
  search.addEventListener("input", debounce(draw, 120));
  status.addEventListener("change", draw);
  draw();

  const create = () => formModal({
    title: "New user",
    submitLabel: "Create user",
    fields: [
      { name: "username", label: "Username", required: true, placeholder: "e.g. jsmith" },
      { name: "password", label: "Initial password", type: "password", required: true,
        help: "At least 12 characters with upper and lower case letters, a digit and a symbol." },
      { name: "groups", label: "Groups", type: "checklist", options: Object.keys(groups) },
      { name: "tags", label: "Attributes (tags)", placeholder: "team=platform, department=finance",
        help: "Used by attribute-based rules, e.g. “only stop servers tagged with your team”." },
    ],
    onSubmit: async (v) => {
      await post("/api/users", { username: v.username, password: v.password, groups: v.groups, tags: parseTags(v.tags) });
      toast(`User ${v.username} created`, "ok");
      ctx.navigate(`users/${encodeURIComponent(v.username)}`);
    },
  });

  return h("div", {},
    pageHead("Users", `${plural(users.length, "account")}. Select a user to manage their access.`,
      ctx.can.createUser ? button("+ New user", create, { kind: "primary" }) : null),
    card(null, [h("div", { class: "toolbar" }, search, status), tableHolder], { flush: true }));
}

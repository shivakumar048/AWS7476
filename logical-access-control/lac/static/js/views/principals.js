// Groups and roles share one screen; roles also manage separation-of-duties rules.
import { del, enc, get, post } from "../api.js";
import { attempt, badge, button, card, chip, confirmDialog, formModal, h, pageHead, plural, select, table, toast } from "../ui.js";

async function permissions(kind) {
  const actions = ["AttachPolicy", "DetachPolicy", `Delete${kind === "group" ? "Group" : "Role"}`];
  const res = await post("/api/me/permissions", { checks: actions.map((a) => ({ action: `lac:${a}`, resource: `lac:${kind}/*` })) });
  return { attach: res[0], detach: res[1], remove: res[2] };
}

function sodSection(ctx, roles, rules, violations) {
  if (!ctx.can.listSod) return null;
  const create = () => formModal({
    title: "New separation-of-duties rule",
    submitLabel: "Create rule",
    fields: [
      { name: "name", label: "Rule name", required: true, placeholder: "e.g. payments-maker-checker" },
      { name: "roles", label: "Mutually exclusive roles", type: "checklist", options: Object.keys(roles),
        help: "Nobody may hold more than one of the selected roles." },
    ],
    onSubmit: async (v) => {
      if (v.roles.length < 2) throw new Error("Pick at least two roles.");
      await post("/api/sod-rules", v);
      toast("Rule created", "ok");
      ctx.refresh();
    },
  });
  return h("div", {},
    violations.length ? h("div", { class: "banner bad", role: "alert" },
      `⚠ ${plural(violations.length, "user")} already break a rule: `,
      violations.map((v) => `${v.user} (${v.roles.join(" + ")})`).join(", ")) : null,
    card("Separation of duties", table([
      { label: "Rule", render: (r) => h("strong", {}, r.name) },
      { label: "A person may hold only one of", render: (r) => r.roles.map((x) => badge(x, "info")) },
      { label: "Violations", render: (r) => {
          const n = violations.filter((v) => v.rule === r.name).length;
          return n ? badge(String(n), "bad") : badge("none", "ok");
        } },
    ], rules, { empty: "No rules yet. Add one to stop a single person holding conflicting roles, like requesting and approving payments." }),
    { flush: true, actions: ctx.can.createSod ? [button("+ New rule", create, { size: "sm" })] : [] }));
}

export async function render({ kind }, ctx) {
  const plural_ = `${kind}s`;
  const [items, users, policies, may, rules, violations] = await Promise.all([
    get(`/api/${plural_}`),
    ctx.can.listUsers ? get("/api/users") : null,
    ctx.can.listPolicies ? get("/api/policies") : {},
    permissions(kind),
    kind === "role" && ctx.can.listSod ? get("/api/sod-rules") : [],
    kind === "role" && ctx.can.listSod ? get("/api/sod-violations") : [],
  ]);
  const membersOf = (name) => (users || []).filter((u) => (kind === "group" ? u.groups : u.roles).includes(name)).map((u) => u.username);
  const canCreate = kind === "group" ? ctx.can.createGroup : ctx.can.createRole;

  const create = () => formModal({
    title: `New ${kind}`,
    submitLabel: `Create ${kind}`,
    fields: [
      { name: "name", label: "Name", required: true },
      kind === "role" ? { name: "description", label: "Description", placeholder: "What this role is for" } : null,
      { name: "policies", label: "Policies", type: "checklist", options: Object.keys(policies) },
    ].filter(Boolean),
    onSubmit: async (v) => {
      await post(`/api/${plural_}`, v);
      toast(`${kind[0].toUpperCase() + kind.slice(1)} ${v.name} created`, "ok");
      ctx.refresh();
    },
  });

  const cards = Object.entries(items).sort(([a], [b]) => a.localeCompare(b)).map(([name, item]) => {
    const base = `/api/${plural_}/${enc(name)}`;
    const members = membersOf(name);
    const run = async (fn, msg) => { if (await attempt(fn, msg) !== undefined) ctx.refresh(); };
    const available = Object.keys(policies).filter((p) => !item.policies.includes(p));
    const sel = select(available, { placeholder: "Attach a policy…" });
    sel.setAttribute("aria-label", `Attach a policy to ${name}`);
    return card(name, [
      item.description ? h("p", { class: "muted" }, item.description) : null,
      h("h3", {}, "Policies"),
      h("div", { class: "chips" }, item.policies.length
        ? item.policies.map((p) => chip(p, may.detach ? () => run(() => del(`${base}/policies/${enc(p)}`), `Detached ${p}`) : null))
        : h("span", { class: "muted" }, "No policies (grants nothing)")),
      may.attach && available.length ? h("div", { class: "add-row" }, sel,
        button("Attach", () => sel.value && run(() => post(`${base}/policies`, { policy: sel.value }), `Attached ${sel.value}`), { size: "sm" })) : null,
      users ? [h("h3", { class: "add-row" }, `Members (${members.length})`),
        h("div", { class: "chips" }, members.length
          ? members.map((m) => h("a", { class: "chip static", href: `#/users/${enc(m)}` }, m))
          : h("span", { class: "muted" }, "Nobody yet. Add people from their user page."))] : null,
    ], {
      actions: may.remove ? [button("Delete", async () => {
        const warn = members.length ? ` ${plural(members.length, "member")} will lose the access it grants.` : "";
        if (await confirmDialog(`Delete ${kind} ${name}?${warn}`, { confirmLabel: "Delete", danger: true })) {
          run(() => del(base), `Deleted ${name}`);
        }
      }, { kind: "danger", size: "sm" })] : [],
    });
  });

  const description = kind === "group"
    ? "Groups bundle people who need the same access, like a department or team. Attach policies here; add people from their user page."
    : "Roles represent job functions. Roles can be declared mutually exclusive so no single person can, for example, both request and approve a payment.";

  return h("div", {},
    pageHead(kind === "group" ? "Groups" : "Roles", description,
      canCreate ? button(`+ New ${kind}`, create, { kind: "primary" }) : null),
    kind === "role" ? sodSection(ctx, items, rules, violations) : null,
    cards.length ? h("div", { class: "grid grid-2" }, cards) : card(null, h("div", { class: "empty" }, `No ${plural_} yet.`)));
}

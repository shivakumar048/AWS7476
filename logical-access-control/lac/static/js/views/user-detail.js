import { del, enc, get, post } from "../api.js";
import { attempt, badge, button, card, chip, confirmDialog, fmtDateTime, fmtTime, formModal, h, pageHead, select, table, toast } from "../ui.js";
import { parseTags, statusBadges } from "./users.js";
import { decisionCard } from "./simulator.js";

const USER_ACTIONS = ["DisableUser", "EnableUser", "UnlockUser", "ChangePassword", "SetMFA", "TagUser", "DeleteUser", "ReviewAccess"];

async function permissionsFor(name) {
  const checks = [
    ...USER_ACTIONS.map((a) => ({ action: `lac:${a}`, resource: `lac:user/${name}` })),
    { action: "lac:AttachPolicy", resource: `lac:user/${name}` },
    { action: "lac:DetachPolicy", resource: `lac:user/${name}` },
    { action: "lac:AddUserToGroup", resource: "lac:group/*" },
    { action: "lac:RemoveUserFromGroup", resource: "lac:group/*" },
    { action: "lac:AssignRole", resource: "lac:role/*" },
    { action: "lac:RevokeRole", resource: "lac:role/*" },
  ];
  const res = await post("/api/me/permissions", { checks });
  const names = [...USER_ACTIONS, "AttachPolicy", "DetachPolicy", "AddUserToGroup", "RemoveUserFromGroup", "AssignRole", "RevokeRole"];
  return Object.fromEntries(names.map((n, i) => [n, res[i]]));
}

function addRow(options, placeholder, label, onAdd) {
  if (!options.length) return null;
  const sel = select(options, { placeholder });
  sel.setAttribute("aria-label", placeholder);
  return h("div", { class: "add-row" }, sel, button(label, () => sel.value && onAdd(sel.value), { size: "sm" }));
}

export async function render({ id: name }, ctx) {
  const userPath = `/api/users/${enc(name)}`;
  const [user, may] = await Promise.all([get(userPath), permissionsFor(name)]);
  const [groups, roles, policies, review, activity] = await Promise.all([
    ctx.can.listGroups ? get("/api/groups") : {},
    ctx.can.listRoles ? get("/api/roles") : {},
    ctx.can.listPolicies ? get("/api/policies") : {},
    may.ReviewAccess ? get(`${userPath}/access-review`) : null,
    ctx.can.readAudit ? get(`/api/audit?limit=15&actor=${enc(name)}`) : null,
  ]);
  const reload = () => ctx.refresh();
  const run = async (fn, msg) => { if (await attempt(fn, msg) !== undefined) reload(); };

  // ----- header actions
  const actions = [];
  if (user.locked && may.UnlockUser) actions.push(button("Unlock", () => run(() => post(`${userPath}/unlock`), "Account unlocked")));
  if (user.disabled && may.EnableUser) actions.push(button("Enable", () => run(() => post(`${userPath}/enable`), "Account enabled")));
  if (!user.disabled && may.DisableUser) {
    actions.push(button("Disable", async () => {
      if (await confirmDialog(`Disable ${name}? They'll be signed out everywhere and every access request will be denied.`, { confirmLabel: "Disable", danger: true })) {
        run(() => post(`${userPath}/disable`), "Account disabled");
      }
    }, { kind: "danger" }));
  }
  if (may.ChangePassword) {
    actions.push(button("Reset password", () => formModal({
      title: `Reset password for ${name}`,
      submitLabel: "Set password",
      fields: [{ name: "password", label: "New password", type: "password", required: true,
        help: "The user's sessions will be ended." }],
      onSubmit: async (v) => { await post(`${userPath}/password`, { password: v.password }); toast("Password changed", "ok"); },
    })));
  }
  if (may.DeleteUser) {
    actions.push(button("Delete", async () => {
      if (await confirmDialog(`Permanently delete ${name}? This can't be undone.`, { confirmLabel: "Delete user", danger: true })) {
        if (await attempt(() => del(userPath), "User deleted") !== undefined) ctx.navigate("users");
      }
    }, { kind: "danger" }));
  }

  // ----- profile
  const mfaToggle = may.SetMFA
    ? h("label", { class: "check" }, h("input", {
        type: "checkbox", checked: user.mfa_enabled,
        onchange: (e) => run(() => post(`${userPath}/mfa`, { enabled: e.target.checked }), e.target.checked ? "MFA enabled" : "MFA disabled"),
      }), user.mfa_enabled ? "Enabled" : "Disabled")
    : (user.mfa_enabled ? "Enabled" : "Disabled");

  const profile = card("Profile", h("dl", { class: "kv" },
    h("dt", {}, "Status"), h("dd", {}, statusBadges(user)),
    h("dt", {}, "MFA"), h("dd", {}, mfaToggle),
    h("dt", {}, "Created"), h("dd", {}, fmtDateTime(user.created)),
    h("dt", {}, "Last login"), h("dd", {}, fmtTime(user.last_login)),
    h("dt", {}, "Failed logins"), h("dd", {}, String(user.failed_logins)),
  ));

  // ----- tags
  const tagChips = Object.entries(user.tags).map(([k, v]) => chip(`${k} = ${v}`));
  const tagsCard = card("Attributes (tags)", [
    h("div", { class: "chips" }, tagChips.length ? tagChips : h("span", { class: "muted" }, "No tags")),
    may.TagUser ? h("div", { class: "add-row" }, button("Add or change tags", () => formModal({
      title: "Set tags",
      fields: [{ name: "tags", label: "Tags", required: true, placeholder: "team=platform, location=london",
        help: "Existing keys are overwritten." }],
      onSubmit: async (v) => { await post(`${userPath}/tags`, { tags: parseTags(v.tags) }); reload(); },
    }), { size: "sm" })) : null,
  ]);

  // ----- memberships
  const groupCard = card("Groups", [
    h("div", { class: "chips" }, user.groups.length
      ? user.groups.map((g) => chip(g, may.RemoveUserFromGroup ? () => run(() => del(`${userPath}/groups/${enc(g)}`), `Removed from ${g}`) : null))
      : h("span", { class: "muted" }, "Not in any group")),
    may.AddUserToGroup ? addRow(Object.keys(groups).filter((g) => !user.groups.includes(g)), "Choose a group…", "Add",
      (g) => run(() => post(`${userPath}/groups`, { group: g }), `Added to ${g}`)) : null,
  ]);

  const roleCard = card("Roles", [
    h("div", { class: "chips" }, user.roles.length
      ? user.roles.map((r) => chip(r, may.RevokeRole ? () => run(() => del(`${userPath}/roles/${enc(r)}`), `Role ${r} revoked`) : null))
      : h("span", { class: "muted" }, "No roles")),
    may.AssignRole ? addRow(Object.keys(roles).filter((r) => !user.roles.includes(r)), "Choose a role…", "Assign",
      (r) => run(() => post(`${userPath}/roles`, { role: r }), `Role ${r} assigned`)) : null,
    h("p", { class: "muted small" }, "Assignments that break a separation-of-duties rule are refused."),
  ]);

  const policyCard = card("Policies attached directly", [
    h("div", { class: "chips" }, user.policies.length
      ? user.policies.map((p) => chip(p, may.DetachPolicy ? () => run(() => del(`${userPath}/policies/${enc(p)}`), `Detached ${p}`) : null))
      : h("span", { class: "muted" }, "None. Access usually comes from groups and roles.")),
    may.AttachPolicy ? addRow(Object.keys(policies).filter((p) => !user.policies.includes(p)), "Choose a policy…", "Attach",
      (p) => run(() => post(`${userPath}/policies`, { policy: p }), `Attached ${p}`)) : null,
  ]);

  // ----- effective access
  const effective = review ? card("Effective access", table([
    { label: "Policy", render: (p) => ctx.can.listPolicies ? h("a", { href: `#/policies/${enc(p.policy)}` }, p.policy) : p.policy },
    { label: "Granted through", render: (p) => badge(p.source, p.source === "user" ? "" : "info") },
    { label: "Statements", render: (p) => p.document.Statement.map((s) =>
        h("div", {}, badge(s.Effect, s.Effect === "Allow" ? "ok" : "bad"), " ",
          h("code", {}, [].concat(s.Action || s.NotAction || []).join(", ")))) },
  ], review.policies, { empty: "No policies apply, so everything is denied." }), { flush: true }) : null;

  // ----- quick test
  const testOut = h("div");
  const action = h("input", { placeholder: "Action, e.g. s3:GetObject", "aria-label": "Action" });
  const resource = h("input", { placeholder: "Resource, e.g. arn:aws:s3:::bucket/key", "aria-label": "Resource" });
  const tester = ctx.can.simulate || name === ctx.user ? card("Test this user's access", [
    h("div", { class: "form-row" }, action, resource),
    h("div", { class: "add-row" }, button("Evaluate", async () => {
      if (!action.value || !resource.value) return;
      const d = await attempt(() => post("/api/authorize", { principal: name, action: action.value, resource: resource.value }));
      if (d) testOut.replaceChildren(decisionCard(d));
    }, { kind: "primary", size: "sm" })),
    testOut,
  ]) : null;

  const activityCard = activity ? card("Recent activity", table([
    { label: "When", render: (r) => fmtTime(r.timestamp) },
    { label: "Event", render: (r) => r.event },
    { label: "Details", render: (r) => h("code", {}, JSON.stringify(r.details)) },
  ], activity.slice().reverse(), { empty: "No activity recorded." }), { flush: true }) : null;

  return h("div", {},
    pageHead(name, null, ...actions),
    h("p", {}, h("a", { href: "#/users" }, "← All users")),
    h("div", { class: "grid grid-2" }, profile, tagsCard, groupCard, roleCard, policyCard, tester),
    effective,
    activityCard);
}

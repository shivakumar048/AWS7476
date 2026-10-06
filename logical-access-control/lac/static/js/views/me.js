import { enc, get, post } from "../api.js";
import { badge, button, card, chip, fmtTime, formModal, h, pageHead, table, toast } from "../ui.js";
import { statementPreview } from "./policy-editor.js";

export async function render(_params, ctx) {
  const [self, [canChangePassword]] = await Promise.all([
    get("/api/me"),
    post("/api/me/permissions", { checks: [{ action: "lac:ChangePassword", resource: `lac:user/${ctx.user}` }] }),
  ]);
  const changePassword = () => formModal({
    title: "Change your password",
    submitLabel: "Change password",
    fields: [
      { name: "password", label: "New password", type: "password", required: true, help: "You'll need to sign in again." },
      { name: "confirm", label: "Confirm new password", type: "password", required: true },
    ],
    onSubmit: async (v) => {
      if (v.password !== v.confirm) throw new Error("The passwords don't match.");
      await post(`/api/users/${enc(ctx.user)}/password`, { password: v.password });
      toast("Password changed. Please sign in again.", "ok");
      setTimeout(() => window.dispatchEvent(new CustomEvent("auth:expired")), 800);
    },
  });

  return h("div", {},
    pageHead("My access", "Everything you're allowed to do, and where each permission comes from.",
      canChangePassword ? button("Change password", changePassword) : null),
    h("div", { class: "grid grid-2" },
      card("Account", h("dl", { class: "kv" },
        h("dt", {}, "User"), h("dd", {}, self.user),
        h("dt", {}, "MFA"), h("dd", {}, self.mfa_enabled ? badge("enabled", "ok") : badge("not enabled", "warn")),
        h("dt", {}, "Last login"), h("dd", {}, fmtTime(self.last_login)),
        h("dt", {}, "Groups"), h("dd", {}, h("div", { class: "chips" }, self.groups.length ? self.groups.map((g) => chip(g)) : "—")),
        h("dt", {}, "Roles"), h("dd", {}, h("div", { class: "chips" }, self.roles.length ? self.roles.map((r) => chip(r)) : "—")))),
      card("Need more access?", h("p", {},
        "Ask an administrator to add you to the right group or role. You can check what you can do right now on the ",
        h("a", { href: "#/check" }, "Access check"), " page."))),
    card("Policies that apply to you", self.policies.length
      ? table([
          { label: "Policy", render: (p) => h("strong", {}, p.policy) },
          { label: "Through", render: (p) => badge(p.source, "info") },
          { label: "What it says", render: (p) => statementPreview(p.document) },
        ], self.policies)
      : h("div", { class: "empty" }, "No policies apply to you, so every request is denied."), { flush: true }));
}

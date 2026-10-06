import { post } from "../api.js";
import { attempt, button, card, h, pageHead } from "../ui.js";

const EXAMPLES = [
  { label: "Stop a team's EC2 instance", action: "ec2:StopInstances", resource: "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc", context: { "resource:tag/team": "platform", "request:ip": "10.0.0.5" } },
  { label: "Read own S3 home folder", action: "s3:GetObject", resource: "arn:aws:s3:::company-data/home/${me}/report.xlsx", context: { "request:ip": "10.0.0.5" } },
  { label: "Access from outside the office", action: "s3:GetObject", resource: "arn:aws:s3:::company-data/home/${me}/x", context: { "request:ip": "203.0.113.7" } },
  { label: "Deploy to production", action: "deploy:Release", resource: "app:prod/web", context: {} },
  { label: "Copy on a computer (Endpoint Guard)", action: "endpoint:Copy", resource: "endpoint:host/FIN-PC01", context: {} },
];

export function decisionCard(d) {
  const allow = d.allowed;
  const why = {
    "explicit allow": "A policy explicitly allows this.",
    "explicit deny": "A policy explicitly denies this. Denies always win over allows.",
    "implicit deny (no matching allow)": "No policy allows this, so it's denied by default.",
    "principal disabled": "The account is disabled.",
    "unknown principal": "There's no such user.",
  }[d.reason] || d.reason;
  return h("div", { class: `verdict ${allow ? "allow" : "deny"}`, role: "status" },
    h("div", { class: "verdict-word" }, allow ? "ALLOW" : "DENY"),
    h("div", { class: "verdict-detail" },
      h("div", {}, why),
      d.matched_policy ? h("div", { class: "small" }, "Decided by policy ",
        h("a", { href: `#/policies/${encodeURIComponent(d.matched_policy)}` }, d.matched_policy),
        d.matched_sid ? ` (statement ${d.matched_sid})` : "") : null));
}

export async function render(_params, ctx) {
  const principal = h("input", { value: ctx.user, "aria-label": "User", disabled: !ctx.can.simulate });
  const action = h("input", { placeholder: "e.g. s3:GetObject", "aria-label": "Action" });
  const resource = h("input", { placeholder: "e.g. arn:aws:s3:::bucket/key", "aria-label": "Resource" });
  const context = h("textarea", { placeholder: '{ "request:ip": "10.0.0.5", "resource:tag/team": "platform" }', "aria-label": "Request context (JSON)" });
  const out = h("div");
  const error = h("p", { class: "form-error", role: "alert" });

  const evaluate = async (e) => {
    if (e) e.preventDefault();
    error.textContent = "";
    if (!action.value.trim() || !resource.value.trim()) { error.textContent = "Enter an action and a resource."; return; }
    let ctxObj = {};
    if (context.value.trim()) {
      try { ctxObj = JSON.parse(context.value); } catch { error.textContent = "Context must be valid JSON."; return; }
    }
    const d = await attempt(() => post("/api/authorize", {
      principal: principal.value.trim() || ctx.user, action: action.value.trim(), resource: resource.value.trim(), context: ctxObj,
    }));
    if (d) out.replaceChildren(decisionCard(d));
  };

  const examples = h("div", { class: "chips" }, EXAMPLES.map((ex) => button(ex.label, () => {
    action.value = ex.action;
    resource.value = ex.resource.replace("${me}", principal.value || ctx.user);
    context.value = Object.keys(ex.context).length ? JSON.stringify(ex.context, null, 2) : "";
    evaluate();
  }, { size: "sm" })));

  const form = h("form", { class: "form-grid", onsubmit: evaluate },
    h("div", { class: "form-row" },
      h("label", { class: "field" }, h("span", {}, "User"), principal,
        !ctx.can.simulate ? h("span", { class: "help" }, "You can test your own access only.") : null),
      h("label", { class: "field" }, h("span", {}, "Action"), action)),
    h("label", { class: "field" }, h("span", {}, "Resource"), resource),
    h("label", { class: "field" }, h("span", {}, "Request context (optional)"), context,
      h("span", { class: "help" }, "Attributes of the request: source IP, resource tags, amounts… User attributes are filled in automatically.")),
    error,
    h("div", {}, button("Evaluate", null, { kind: "primary", type: "submit" })));

  return h("div", {},
    pageHead("Access check", "Ask “may this person do this action on this resource?” and see which policy decides, without actually doing anything."),
    card("Try an example", examples),
    card("Request", [form, out]));
}

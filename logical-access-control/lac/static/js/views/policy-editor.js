import { del, enc, get, post, put } from "../api.js";
import { attempt, badge, button, card, confirmDialog, h, pageHead, select, toast } from "../ui.js";
import { usage } from "./policies.js";

const TEMPLATES = {
  "Read-only access": {
    Statement: [{ Sid: "ReadOnly", Effect: "Allow", Action: ["s3:Get*", "s3:List*", "ec2:Describe*"], Resource: "*" }],
  },
  "Own home folder": {
    Statement: [{ Sid: "OwnHome", Effect: "Allow", Action: ["s3:GetObject", "s3:PutObject"], Resource: "arn:aws:s3:::company-data/home/${user:name}/*" }],
  },
  "Office network only (guardrail)": {
    Statement: [{ Sid: "OfficeOnly", Effect: "Deny", Action: "*", Resource: "*", Condition: { NotIpAddress: { "request:ip": ["10.0.0.0/8"] } } }],
  },
  "Business hours only": {
    Statement: [{ Sid: "BusinessHours", Effect: "Allow", Action: "deploy:*", Resource: "app:prod/*", Condition: { TimeOfDayBetween: { "request:timeofday": "08:00-18:00" } } }],
  },
  "Require MFA for destructive actions": {
    Statement: [{ Sid: "MfaForDelete", Effect: "Deny", Action: ["*:Delete*", "ec2:Terminate*"], Resource: "*", Condition: { Bool: { "user:mfa": "false" } } }],
  },
  "Team-tagged resources only": {
    Statement: [{ Sid: "OwnTeam", Effect: "Allow", Action: ["ec2:StartInstances", "ec2:StopInstances"], Resource: "*", Condition: { StringEquals: { "resource:tag/team": "${user:tag/team}" } } }],
  },
  "Endpoint: allow copy & paste": {
    Statement: [{ Sid: "EndpointCopyPaste", Effect: "Allow", Action: ["endpoint:Copy", "endpoint:Paste", "endpoint:Clipboard"], Resource: "endpoint:host/*" }],
  },
};

const list = (v) => [].concat(v ?? []);

export function statementPreview(doc) {
  return h("div", {}, list(doc.Statement).map((s) => h("div", { class: "statement" },
    h("div", {}, badge(s.Effect || "?", s.Effect === "Allow" ? "ok" : s.Effect === "Deny" ? "bad" : "warn"), " ",
      s.Sid ? h("strong", {}, s.Sid) : h("span", { class: "muted" }, "(no Sid)")),
    h("div", {}, h("span", { class: "muted" }, s.NotAction ? "All actions except: " : "Actions: "),
      h("code", {}, list(s.Action || s.NotAction).join(", "))),
    h("div", {}, h("span", { class: "muted" }, "Resources: "), h("code", {}, list(s.Resource ?? "*").join(", "))),
    s.Condition ? h("div", {}, h("span", { class: "muted" }, "Only when: "),
      Object.entries(s.Condition).map(([op, checks]) => Object.entries(checks).map(([k, v]) =>
        h("div", {}, h("code", {}, `${k} ${op} ${list(v).join(" | ")}`))))) : null)));
}

export async function render({ id, isNew }, ctx) {
  const [existing, used] = await Promise.all([
    isNew ? null : get("/api/policies").then((all) => {
      if (!all[id]) throw new Error(`Policy ${id} not found.`);
      return all[id];
    }),
    isNew ? {} : usage(ctx),
  ]);
  const editable = isNew ? ctx.can.createPolicy : ctx.can.updatePolicy;
  const nameInput = h("input", { placeholder: "e.g. FinanceReadOnly", "aria-label": "Policy name" });
  const descInput = h("input", { placeholder: "What does this policy allow or prevent?", "aria-label": "Description" });
  const editor = h("textarea", {
    class: "code", spellcheck: "false", "aria-label": "Policy document (JSON)", readonly: !editable,
    value: JSON.stringify(existing ? existing.document : TEMPLATES["Read-only access"], null, 2),
  });
  const status = h("div");
  const preview = h("div");

  const parse = () => {
    try {
      const doc = JSON.parse(editor.value);
      if (!doc || !Array.isArray(doc.Statement) && typeof doc.Statement !== "object") throw new Error("Needs a \"Statement\" list.");
      for (const s of list(doc.Statement)) {
        if (!["Allow", "Deny"].includes(s.Effect)) throw new Error("Every statement needs \"Effect\": \"Allow\" or \"Deny\".");
        if (!s.Action && !s.NotAction) throw new Error("Every statement needs \"Action\" or \"NotAction\".");
      }
      status.replaceChildren(badge("Valid JSON", "ok"));
      preview.replaceChildren(statementPreview(doc));
      return doc;
    } catch (err) {
      status.replaceChildren(h("span", { class: "form-error" }, err.message));
      return null;
    }
  };
  editor.addEventListener("input", parse);
  editor.addEventListener("keydown", (e) => {
    if (e.key === "Tab") { // indent instead of leaving the field
      e.preventDefault();
      editor.setRangeText("  ", editor.selectionStart, editor.selectionEnd, "end");
    }
  });
  parse();

  const template = select(Object.keys(TEMPLATES), { placeholder: "Start from a template…" });
  template.setAttribute("aria-label", "Templates");
  template.addEventListener("change", () => {
    if (!template.value) return;
    editor.value = JSON.stringify(TEMPLATES[template.value], null, 2);
    parse();
  });

  const save = async () => {
    const doc = parse();
    if (!doc) return toast("Fix the policy errors first.", "bad");
    if (isNew) {
      const name = nameInput.value.trim();
      if (!name) return toast("Give the policy a name.", "bad");
      const ok = await attempt(() => post("/api/policies", { name, description: descInput.value.trim(), document: doc }), "Policy created");
      if (ok !== undefined) ctx.navigate(`policies/${enc(name)}`);
    } else {
      if (await attempt(() => put(`/api/policies/${enc(id)}`, { document: doc }), "Policy saved") !== undefined) ctx.refresh();
    }
  };

  const remove = async () => {
    const n = (used[id] || []).length;
    const msg = n ? `${id} is attached to ${n} user(s)/group(s)/role(s); deleting it removes that access.` : `Delete ${id}?`;
    if (await confirmDialog(msg, { confirmLabel: "Delete policy", danger: true })) {
      if (await attempt(() => del(`/api/policies/${enc(id)}`), "Policy deleted") !== undefined) ctx.navigate("policies");
    }
  };

  const help = card("How policies work", h("ul", {},
    h("li", {}, "Anything not explicitly allowed is ", h("strong", {}, "denied"), "."),
    h("li", {}, "An explicit ", h("strong", {}, "Deny"), " overrides every Allow. Use it for guardrails."),
    h("li", {}, h("code", {}, "*"), " and ", h("code", {}, "?"), " are wildcards in actions and resources."),
    h("li", {}, "Variables: ", h("code", {}, "${user:name}"), ", ", h("code", {}, "${user:tag/team}"), "."),
    h("li", {}, "Conditions: StringEquals, StringLike, IpAddress, NotIpAddress, NumericLessThan, DateLessThan, Bool, TimeOfDayBetween… (add ",
      h("code", {}, "IfExists"), " to any)."),
    h("li", {}, "Endpoint Guard actions: ", h("code", {}, "endpoint:Copy, Cut, Paste, Delete, DragDrop, Clipboard, Screenshot"), " on ",
      h("code", {}, "endpoint:host/<computer>"), "."),
  ));

  return h("div", {},
    pageHead(isNew ? "New policy" : id, existing?.description || null,
      !isNew && ctx.can.deletePolicy ? button("Delete", remove, { kind: "danger" }) : null,
      editable ? button(isNew ? "Create policy" : "Save changes", save, { kind: "primary" }) : null),
    h("p", {}, h("a", { href: "#/policies" }, "← All policies")),
    !isNew && (used[id] || []).length ? h("div", { class: "banner info" }, `Applies through: ${used[id].join(", ")}`) : null,
    isNew ? card("Details", h("div", { class: "form-row" },
      h("label", { class: "field" }, h("span", {}, "Name"), nameInput),
      h("label", { class: "field" }, h("span", {}, "Description"), descInput))) : null,
    h("div", { class: "grid grid-2" },
      card("Policy document", [editor, h("div", { class: "add-row" }, status)],
        { actions: editable ? [template] : [] }),
      h("div", {}, card("In plain words", preview), help)));
}

// Grid of groups × Endpoint Guard controls. A tick means "this group is
// allowed to do it", i.e. Endpoint Guard lifts that restriction for its members.
// Each group's ticks are stored as a policy named EndpointAccess-<group>.
import { del, enc, get, post, put } from "../api.js";
import { attempt, button, card, h, pageHead, toast } from "../ui.js";

export const CONTROLS = [
  { key: "Copy", label: "Copy", hint: "Ctrl+C, Ctrl+Insert" },
  { key: "Cut", label: "Cut", hint: "Ctrl+X, Shift+Delete" },
  { key: "Paste", label: "Paste", hint: "Ctrl+V, Shift+Insert, Win+V" },
  { key: "Clipboard", label: "Clipboard menus", hint: "Right-click / Edit menu copy & paste" },
  { key: "Delete", label: "Delete", hint: "Delete key, Ctrl+D" },
  { key: "DragDrop", label: "Drag & drop", hint: "Dragging with the mouse" },
  { key: "Screenshot", label: "Screenshot", hint: "PrintScreen, Win+Shift+S" },
];
const PREFIX = "EndpointAccess-";

function readPolicy(policy) {
  const allowed = new Set();
  let host = "*";
  for (const s of policy?.document?.Statement || []) {
    if (s.Effect !== "Allow") continue;
    for (const a of [].concat(s.Action || [])) {
      const m = /^endpoint:(.+)$/i.exec(a);
      if (m) {
        const c = CONTROLS.find((x) => x.key.toLowerCase() === m[1].toLowerCase());
        if (c) allowed.add(c.key);
        if (m[1] === "*") CONTROLS.forEach((x) => allowed.add(x.key));
      }
    }
    const r = [].concat(s.Resource || [])[0];
    if (r && r.startsWith("endpoint:host/")) host = r.slice("endpoint:host/".length);
  }
  return { allowed, host };
}

export async function render(_params, ctx) {
  const [groups, policies] = await Promise.all([get("/api/groups"), get("/api/policies")]);
  const names = Object.keys(groups).sort();
  const rows = names.map((g) => {
    const policyName = PREFIX + g;
    const state = readPolicy(policies[policyName]);
    return { group: g, policyName, exists: Boolean(policies[policyName]), attached: groups[g].policies.includes(policyName), ...state };
  });

  const saveRow = async (row, boxes, hostInput, tr) => {
    const allowed = CONTROLS.filter((c) => boxes[c.key].checked).map((c) => c.key);
    const host = hostInput.value.trim() || "*";
    if (!/^[\w.*?-]+$/.test(host)) return toast("Computer pattern may contain letters, digits, - . * and ? only.", "bad");
    const doc = { Statement: [{ Sid: "EndpointGuardExceptions", Effect: "Allow", Action: allowed.map((a) => `endpoint:${a}`), Resource: `endpoint:host/${host}` }] };
    const ok = await attempt(async () => {
      if (!allowed.length) {
        if (row.exists) await del(`/api/policies/${enc(row.policyName)}`);
        return true;
      }
      if (row.exists) await put(`/api/policies/${enc(row.policyName)}`, { document: doc });
      else await post("/api/policies", { name: row.policyName, description: `Endpoint Guard exceptions for group ${row.group}`, document: doc });
      if (!row.attached) await post(`/api/groups/${enc(row.group)}/policies`, { policy: row.policyName });
      return true;
    }, `Saved endpoint rules for ${row.group}`);
    if (ok !== undefined) {
      Object.assign(row, { exists: allowed.length > 0, attached: allowed.length > 0, allowed: new Set(allowed), host });
      tr.classList.remove("dirty");
    }
  };

  const body = rows.map((row) => {
    const boxes = {};
    const hostInput = h("input", { class: "host", value: row.host, "aria-label": `Computers for ${row.group}`, title: "Computer-name pattern, e.g. FIN-* (wildcards allowed)" });
    const saveBtn = button("Save", null, { size: "sm" });
    const tr = h("tr", {},
      h("td", {}, h("strong", {}, row.group)),
      CONTROLS.map((c) => {
        boxes[c.key] = h("input", { type: "checkbox", checked: row.allowed.has(c.key), "aria-label": `${row.group}: allow ${c.label}` });
        return h("td", {}, boxes[c.key]);
      }),
      h("td", {}, hostInput),
      h("td", {}, saveBtn));
    const markDirty = () => tr.classList.add("dirty");
    tr.addEventListener("change", markDirty);
    hostInput.addEventListener("input", markDirty);
    saveBtn.addEventListener("click", () => saveRow(row, boxes, hostInput, tr));
    return tr;
  });

  const matrix = rows.length ? h("div", { class: "table-wrap" }, h("table", { class: "matrix" },
    h("thead", {}, h("tr", {},
      h("th", { scope: "col" }, "Group"),
      CONTROLS.map((c) => h("th", { scope: "col", title: c.hint }, c.label)),
      h("th", { scope: "col" }, "On computers"),
      h("th", { scope: "col" }, h("span", { class: "hidden" }, "Save")))),
    h("tbody", {}, body)))
    : h("div", { class: "empty" }, "Create a group first, then choose what its members may do on their computers.");

  const config = {
    controls: { copy: true, cut: true, paste: true, delete: true, drag_drop: true, clipboard: true, screenshot: false },
    log_file: "C:\\ProgramData\\EndpointGuard\\events.jsonl",
    policy_server: { url: location.origin, refresh_seconds: 300 },
  };

  return h("div", {},
    pageHead("Endpoint rules",
      "Endpoint Guard blocks copy, paste, delete and drag & drop on every computer by default. Tick a box to let a group's members do that action, optionally only on certain computers. Unticked actions stay blocked."),
    h("div", { class: "banner info" }, "Changes reach computers within the Endpoint Guard refresh interval (5 minutes by default). Rows you've changed are highlighted until saved."),
    card("Allowed actions by group", matrix, { flush: true }),
    h("div", { class: "grid grid-2" },
      card("What each action covers", h("dl", { class: "kv" },
        CONTROLS.flatMap((c) => [h("dt", {}, c.label), h("dd", {}, c.hint)]))),
      card("Connect Endpoint Guard to this console", [
        h("p", {}, "Put this in each computer's Endpoint Guard config and set ", h("code", {}, "LAC_USERNAME"), " / ",
          h("code", {}, "LAC_PASSWORD"), " for a service account that has ", h("code", {}, "lac:SimulatePrincipalPolicy"),
          " and ", h("code", {}, "lac:ReportEndpointEvents"), "."),
        h("pre", { class: "json" }, JSON.stringify(config, null, 2)),
      ])));
}

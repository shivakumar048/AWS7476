// Small DOM helpers. All text goes through textContent, never innerHTML,
// so data coming from the server can't inject markup.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") el.className = value;
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === "dataset") Object.assign(el.dataset, value);
    else if (key === "value") el.value = value;
    else if (key === "checked" || key === "selected") el[key] = Boolean(value);
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function mount(container, ...children) {
  container.replaceChildren();
  append(container, children);
}

export const plural = (n, word, many = word + "s") => `${n} ${n === 1 ? word : many}`;

export function fmtTime(iso) {
  if (!iso) return "never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} h ago`;
  return d.toLocaleString();
}

export function fmtDateTime(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso ?? "") : d.toLocaleString();
}

export function badge(text, kind = "") {
  return h("span", { class: `badge ${kind}` }, text);
}

export function chip(text, onRemove, title) {
  if (!onRemove) return h("span", { class: "chip static" }, text);
  return h("span", { class: "chip" }, text,
    h("button", { type: "button", "aria-label": title || `Remove ${text}`, title: title || "Remove", onclick: onRemove }, "×"));
}

export function pageHead(title, description, ...actions) {
  return h("div", { class: "page-head" },
    h("div", {}, h("h2", {}, title), description ? h("p", {}, description) : null),
    actions.length ? h("div", { class: "actions" }, actions) : null);
}

export function card(title, body, { actions = [], flush = false } = {}) {
  return h("section", { class: "card" },
    title ? h("div", { class: "card-head" }, h("h2", {}, title), actions.length ? h("div", { class: "actions" }, actions) : null) : null,
    h("div", { class: `card-body ${flush ? "flush" : ""}` }, body));
}

export function tile(label, value, { kind = "", note = "" } = {}) {
  return h("div", { class: `tile ${kind}` },
    h("div", { class: "tile-label" }, label),
    h("div", { class: "tile-value" }, value),
    note ? h("div", { class: "tile-note" }, note) : null);
}

export function button(label, onClick, { kind = "", size = "", type = "button", disabled = false, title } = {}) {
  const cls = ["btn", kind && `btn-${kind}`, size && `btn-${size}`].filter(Boolean).join(" ");
  return h("button", { class: cls, type, disabled, title, onclick: onClick }, label);
}

export function table(columns, rows, { empty = "Nothing here yet.", onRowClick } = {}) {
  if (!rows.length) return h("div", { class: "empty" }, empty);
  return h("div", { class: "table-wrap" },
    h("table", {},
      h("thead", {}, h("tr", {}, columns.map((c) => h("th", { class: c.class || "", scope: "col" }, c.label)))),
      h("tbody", {}, rows.map((row) => {
        const tr = h("tr", { class: onRowClick ? "clickable" : "" },
          columns.map((c) => h("td", { class: c.class || "" }, c.render(row))));
        if (onRowClick) {
          tr.tabIndex = 0;
          tr.addEventListener("click", (e) => { if (!e.target.closest("button, a, input, select")) onRowClick(row); });
          tr.addEventListener("keydown", (e) => { if (e.key === "Enter") onRowClick(row); });
        }
        return tr;
      }))));
}

export function loading() {
  return h("div", { class: "card" }, h("div", { class: "card-body" },
    h("div", { class: "skeleton" }), h("div", { class: "skeleton" }), h("div", { class: "skeleton" })));
}

export function errorCard(err) {
  return h("div", { class: "banner bad", role: "alert" }, err.message || String(err));
}

export function emptyState(text, action) {
  return h("div", { class: "empty" }, h("p", {}, text), action || null);
}

// ------------------------------------------------------------- toasts

export function toast(message, kind = "") {
  const el = h("div", { class: `toast ${kind}`, role: kind === "bad" ? "alert" : "status" }, message);
  document.getElementById("toasts").append(el);
  setTimeout(() => el.remove(), kind === "bad" ? 6000 : 3500);
}

// ------------------------------------------------------------- modals

export function modal({ title, body, actions = [], wide = false }) {
  const root = document.getElementById("modal-root");
  const previous = document.activeElement;
  const close = () => {
    backdrop.remove();
    document.removeEventListener("keydown", onKey);
    if (previous && previous.focus) previous.focus();
  };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  const dialog = h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title },
    h("div", { class: "modal-head" }, h("h2", {}, title), h("button", { class: "icon-btn", "aria-label": "Close", onclick: close }, "×")),
    h("div", { class: "modal-body" }, body),
    actions.length ? h("div", { class: "modal-foot" }, actions.map((a) => a(close))) : null);
  if (wide) dialog.style.maxWidth = "760px";
  const backdrop = h("div", { class: "modal-backdrop" }, dialog);
  backdrop.addEventListener("mousedown", (e) => { if (e.target === backdrop) close(); });
  document.addEventListener("keydown", onKey);
  root.append(backdrop);
  const first = dialog.querySelector("input, select, textarea, .modal-foot .btn-primary");
  if (first) first.focus();
  return close;
}

export function confirmDialog(message, { title = "Are you sure?", confirmLabel = "Confirm", danger = false } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v, close) => { if (!done) { done = true; resolve(v); } close(); };
    modal({
      title,
      body: h("p", {}, message),
      actions: [
        (close) => button("Cancel", () => finish(false, close)),
        (close) => button(confirmLabel, () => finish(true, close), { kind: danger ? "danger solid" : "primary" }),
      ],
    });
  });
}

// fields: [{name, label, type: text|password|select|checklist|textarea|checkbox, value, options, help, required, placeholder}]
export function formModal({ title, fields, submitLabel = "Save", onSubmit, wide = false }) {
  const error = h("p", { class: "form-error", role: "alert" });
  const inputs = {};
  const rows = fields.map((f) => {
    let input;
    if (f.type === "select") {
      input = h("select", { name: f.name, required: f.required },
        (f.options || []).map((o) => h("option", { value: o.value ?? o, selected: (o.value ?? o) === f.value }, o.label ?? o)));
    } else if (f.type === "checklist") {
      input = checklist(f.options || [], f.value || []);
    } else if (f.type === "textarea") {
      input = h("textarea", { name: f.name, placeholder: f.placeholder, required: f.required, value: f.value ?? "" });
    } else if (f.type === "checkbox") {
      input = h("input", { type: "checkbox", name: f.name, checked: f.value });
      inputs[f.name] = input;
      return h("label", { class: "check" }, input, f.label);
    } else {
      input = h("input", { type: f.type || "text", name: f.name, placeholder: f.placeholder, required: f.required,
        value: f.value ?? "", autocomplete: f.type === "password" ? "new-password" : "off" });
    }
    inputs[f.name] = input;
    return h("label", { class: "field" }, h("span", {}, f.label), input, f.help ? h("span", { class: "help" }, f.help) : null);
  });
  const form = h("form", { class: "form-grid", novalidate: true }, rows, error);
  let closeFn;
  const submit = async (e) => {
    if (e) e.preventDefault();
    error.textContent = "";
    const values = {};
    for (const f of fields) {
      const el = inputs[f.name];
      values[f.name] = f.type === "checklist" ? el.getValues() : f.type === "checkbox" ? el.checked : el.value.trim();
      if (f.required && !values[f.name]) { error.textContent = `${f.label} is required.`; el.focus(); return; }
    }
    const btn = form.closest(".modal").querySelector(".modal-foot .btn-primary");
    btn.disabled = true;
    try {
      await onSubmit(values);
      closeFn();
    } catch (err) {
      error.textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  };
  form.addEventListener("submit", submit);
  // Enter in a single-line input submits.
  form.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.tagName === "INPUT") submit(e); });
  closeFn = modal({
    title, body: form, wide,
    actions: [(close) => button("Cancel", close), () => button(submitLabel, submit, { kind: "primary" })],
  });
  return closeFn;
}

export function checklist(options, selected = []) {
  const boxes = options.map((o) => {
    const value = o.value ?? o;
    const box = h("input", { type: "checkbox", value, checked: selected.includes(value) });
    return { box, el: h("label", { class: "check" }, box, o.label ?? o) };
  });
  const el = h("div", { class: "checklist" }, boxes.length ? boxes.map((b) => b.el) : h("span", { class: "muted" }, "None available"));
  el.getValues = () => boxes.filter((b) => b.box.checked).map((b) => b.box.value);
  return el;
}

export function select(options, { placeholder, value } = {}) {
  return h("select", {},
    placeholder ? h("option", { value: "" }, placeholder) : null,
    options.map((o) => h("option", { value: o.value ?? o, selected: (o.value ?? o) === value }, o.label ?? o)));
}

export function downloadFile(name, content, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = h("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function debounce(fn, ms = 200) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// Run an async action from a button, showing errors as toasts.
export async function attempt(fn, success) {
  try {
    const result = await fn();
    if (success) toast(success, "ok");
    return result;
  } catch (err) {
    toast(err.message, "bad");
    return undefined;
  }
}

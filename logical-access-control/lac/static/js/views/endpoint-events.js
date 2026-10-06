import { enc, get } from "../api.js";
import { badge, button, card, debounce, downloadFile, fmtDateTime, h, pageHead, table, tile } from "../ui.js";

const CONTROL_LABELS = {
  copy: "Copy", cut: "Cut", paste: "Paste", delete: "Delete", drag_drop: "Drag & drop", clipboard: "Clipboard", screenshot: "Screenshot",
};

function toCsv(rows) {
  const cols = ["timestamp", "event", "user", "host", "control", "trigger", "process"];
  const cell = (v) => {
    let s = String(v ?? "");
    if (/^[=+\-@]/.test(s)) s = `'${s}`; // stop spreadsheet formula injection
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c])).join(","))].join("\n");
}

export async function render(_params, ctx) {
  let events = await get("/api/endpoint/events?limit=5000");
  const summary = h("div", { class: "tiles" });
  const holder = h("div");
  const userF = h("input", { type: "search", placeholder: "User", "aria-label": "Filter by user" });
  const hostF = h("input", { type: "search", placeholder: "Computer", "aria-label": "Filter by computer" });
  const controlF = h("select", { "aria-label": "Filter by action" },
    h("option", { value: "" }, "All actions"), Object.entries(CONTROL_LABELS).map(([v, l]) => h("option", { value: v }, l)));
  const auto = h("input", { type: "checkbox" });
  let filtered = [];

  const draw = () => {
    const u = userF.value.toLowerCase(), hst = hostF.value.toLowerCase(), c = controlF.value;
    filtered = events.filter((e) =>
      (!u || (e.user || "").toLowerCase().includes(u)) &&
      (!hst || (e.host || "").toLowerCase().includes(hst)) &&
      (!c || e.control === c)).slice().reverse();
    const counts = {};
    filtered.forEach((e) => (counts[e.control] = (counts[e.control] || 0) + 1));
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    summary.replaceChildren(
      tile("Events", filtered.length),
      tile("People", new Set(filtered.map((e) => e.user)).size),
      tile("Computers", new Set(filtered.map((e) => e.host)).size),
      tile("Most blocked", top ? CONTROL_LABELS[top[0]] || top[0] : "—", { note: top ? `${top[1]} times` : "" }));
    holder.replaceChildren(table([
      { label: "When", render: (e) => fmtDateTime(e.timestamp) },
      { label: "User", render: (e) => ctx.can.listUsers ? h("a", { href: `#/users/${enc(e.user || "")}` }, e.user) : e.user },
      { label: "Computer", render: (e) => e.host },
      { label: "Action", render: (e) => CONTROL_LABELS[e.control] || e.control },
      { label: "Input", render: (e) => h("code", {}, e.trigger || "") },
      { label: "Application", render: (e) => e.process || "—" },
      { label: "Result", render: (e) => e.event === "would_block" ? badge("monitor only", "warn") : badge(e.event || "blocked", "bad") },
    ], filtered.slice(0, 500), {
      empty: events.length ? "No events match these filters." : "No events yet. Endpoint Guard agents report here once they're connected to this console.",
    }));
  };
  [userF, hostF].forEach((el) => el.addEventListener("input", debounce(draw, 150)));
  controlF.addEventListener("change", draw);

  const refresh = async () => { events = await get("/api/endpoint/events?limit=5000"); draw(); };
  const timer = setInterval(() => {
    if (!document.body.contains(holder)) return clearInterval(timer); // left the page
    if (auto.checked) refresh().catch(() => {});
  }, 15000);
  draw();

  return h("div", {},
    pageHead("Blocked endpoint actions",
      "Copy, paste, delete and drag & drop attempts that Endpoint Guard stopped on users' computers.",
      button("Refresh", refresh),
      button("Export CSV", () => downloadFile(`endpoint-events-${new Date().toISOString().slice(0, 10)}.csv`, toCsv(filtered), "text/csv"))),
    summary,
    card(null, [
      h("div", { class: "toolbar" }, userF, hostF, controlF, h("label", { class: "check" }, auto, "Auto-refresh (15 s)")),
      holder,
      filtered.length > 500 ? h("p", { class: "muted small empty" }, "Showing the latest 500. Narrow the filters or export to see more.") : null,
    ], { flush: true }));
}

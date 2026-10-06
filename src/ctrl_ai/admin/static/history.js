// Change log: every admin action (who changed what, when and why).
import { $, el, getJSON, postJSON, fmt, card, table, diffView, askReason, toast, chip } from "/static/lib.js";
import { renderNav } from "/static/nav.js";

const FILES = [["policy", "Policy"], ["models", "Model catalogue"], ["teams", "Teams"], ["mcp", "MCP tools"]];
let current = new URLSearchParams(location.search).get("file") || "policy";

async function renderFile(host) {
  host.replaceChildren(el("p", { cls: "muted", text: "Loading…" }));
  const h = await getJSON(`/api/admin/config/${current}/history`);
  const diffBox = el("div");
  const rows = [{ ...h.current, ts: h.current.saved_at, current: true }, ...h.versions];
  const t = table([
    { key: "ts", label: "Saved (UTC)", render: (r) => (r.current ? el("span", {}, [chip("current", "ok"), " ", fmt.datetime(r.ts)]) : fmt.datetime(r.ts)) },
    { key: "version", label: "Version", render: (r) => el("code", { text: r.version }) },
    { key: "actor", label: "By" },
    { key: "reason", label: "Reason", render: (r) => el("span", { cls: "wrap", text: r.reason || "–" }) },
    { key: "size", label: "Size", num: true, render: (r) => (r.size ? `${fmt.int(r.size)} B` : "–") },
    { key: "actions", label: "", sortable: false, render: (r) => r.current ? "" : el("div", { cls: "row" }, [
      el("button", { cls: "small", text: "Diff to current", on: { click: async (e) => {
        e.stopPropagation();
        const d = await getJSON(`/api/admin/config/${current}/diff?version=${r.version}`);
        diffBox.replaceChildren(el("h3", { text: `Changes from ${r.version} to the current file` }), diffView(d.diff));
      } } }),
      el("button", { cls: "small danger", text: "Roll back to this version", on: { click: async (e) => {
        e.stopPropagation();
        const reason = await askReason(`Roll back ${current} to ${r.version}`);
        if (!reason) return;
        try {
          const res = await postJSON(`/api/admin/config/${current}/rollback`, { version: r.version, reason });
          toast(`Rolled back. Saved as version ${res.version}; the gateway applies it to the next request.`);
          load();
        } catch (err) { toast(err.message, "bad"); }
      } } }),
    ]) },
  ], rows, { empty: "No saved versions yet. Every save from the panel keeps the previous file here." });
  host.replaceChildren(t, diffBox);
}

async function renderAudit(host) {
  const params = new URLSearchParams();
  const action = $("f-action")?.value || "";
  const actor = $("f-actor")?.value || "";
  if (action) params.set("action", action);
  if (actor) params.set("actor", actor);
  const data = await getJSON(`/api/admin/audit?${params}`);
  host.replaceChildren(table([
    { key: "ts", label: "Time (UTC)", render: (r) => fmt.datetime(r.ts) },
    { key: "actor", label: "Actor" },
    { key: "action", label: "Action", render: (r) => chip(r.action, r.action.endsWith("revoke") ? "warn" : "") },
    { key: "target", label: "Target" },
    { key: "version_before", label: "Before", render: (r) => r.version_before || "–" },
    { key: "version_after", label: "After", render: (r) => r.version_after || "–" },
    { key: "reason", label: "Reason", render: (r) => el("span", { cls: "wrap", text: r.reason || "–" }) },
  ], data.rows, { empty: "No admin actions recorded yet." }));
}

async function load() {
  const main = $("main");
  const tabs = el("div", { cls: "tabs", attrs: { role: "tablist" } }, FILES.map(([id, label]) => el("a", {
    href: `?file=${id}`, text: label, attrs: { role: "tab", "aria-selected": String(id === current) },
    on: { click: (e) => { e.preventDefault(); current = id; history.replaceState(null, "", `?file=${id}`); load(); } } })));
  const fileHost = el("div");
  const auditHost = el("div");
  const actions = ["", "policy.save", "policy.rollback", "models.save", "models.rollback",
    "teams.save", "teams.rollback", "mcp.save", "mcp.repin", "key.issue", "key.revoke", "break_glass.revoke", "export"];
  const filter = el("div", { cls: "row" }, [
    el("label", {}, ["Action ", el("select", { attrs: { id: "f-action" }, on: { change: () => renderAudit(auditHost) } },
      actions.map((a) => el("option", { value: a, text: a || "all" })))]),
    el("label", {}, ["Actor ", el("input", { attrs: { id: "f-actor", placeholder: "any", size: 10 }, on: { change: () => renderAudit(auditHost) } })]),
  ]);
  main.replaceChildren(
    el("div", { cls: "page-head" }, [el("div", {}, [el("h1", { text: "Change log" }),
      el("p", { text: "Every change made in the admin panel: who, what, when and why. Recorded for auditors; never contains keys or file contents." })])]),
    card("Admin actions", [filter, auditHost]),
  );
  await renderAudit(auditHost);
}

renderNav().then(load);

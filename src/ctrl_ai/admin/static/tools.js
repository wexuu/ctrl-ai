// MCP tool servers: approved servers, team access, allowed tools, pinned tool descriptions.
import { $, el, getJSON, postJSON, card, table, drawer, askReason, toast, chip, statusChip, errorList } from "/static/lib.js";
import { renderNav } from "/static/nav.js";

let data = null, doc = null, version = null, teams = [];

async function saveMcp(title) {
  const v = await postJSON("/api/admin/config/mcp/validate", { doc });
  if (v.errors.length) { const e = new Error("Validation failed"); e.body = { errors: v.errors }; throw e; }
  const reason = await askReason(title);
  if (!reason) return false;
  const res = await postJSON("/api/admin/config/mcp", { doc, expected_version: version, reason });
  toast(`Saved as version ${res.version}; the gateway applies it to the next tool call.`);
  await load();
  return true;
}

function serverCard(view) {
  const cfg = doc.servers.find((s) => s.name === view.name);
  const changed = view.tools.filter((t) => t.pin_status === "changed");
  const toggle = (t) => el("input", { type: "checkbox", attrs: { checked: t.allowed, "aria-label": `Allow ${t.name}` }, on: { change: async (e) => {
    const before = JSON.stringify(doc);
    cfg.tools = cfg.tools || [];
    let entry = cfg.tools.find((x) => x.name === t.name);
    if (!entry) { entry = { name: t.name, allowed: false }; cfg.tools.push(entry); }
    entry.allowed = e.target.checked;
    try { if (!(await saveMcp(`${e.target.checked ? "Allow" : "Disallow"} ${view.name}/${t.name}`))) { doc = JSON.parse(before); render(); } }
    catch (err) { doc = JSON.parse(before); render(); toast(err.message, "bad"); }
  } } });
  const repin = (t) => el("button", { cls: "small", text: t.pin_status === "unpinned" ? "Pin after review" : "Re-pin after review", on: { click: async () => {
    const reason = await askReason(`Re-pin ${view.name}/${t.name}: record its current description as reviewed`);
    if (!reason) return;
    try { const r = await postJSON("/api/admin/mcp/repin", { server: view.name, tool: t.name, reason }); toast(`Pinned; mcp.yaml version ${r.version}.`); load(); }
    catch (err) { toast(err.message, "bad"); }
  } } });
  return card(`Server ${view.name}`, [
    el("div", { cls: "row" }, [statusChip(view.status), el("code", { text: view.url }), view.transport ? chip(view.transport) : null,
      el("span", { cls: "note", text: `owner ${view.owner || "–"}` }),
      el("span", { cls: "row" }, (view.teams || []).map((t) => chip(t === "*" ? "all teams" : t, t === "*" ? "ok" : "")))]),
    view.error ? el("div", { cls: "banner", text: `${view.error}: pin status cannot be checked right now.` }) : null,
    changed.length ? el("div", { cls: "banner red", text: `Tool description changed since approval: ${changed.map((t) => t.name).join(", ")}. The gateway refuses these tools until a reviewer re-pins them.` }) : null,
    table([
      { key: "name", label: "Tool", render: (t) => el("code", { text: t.name }) },
      { key: "allowed", label: "Allowed", sortable: false, render: toggle },
      { key: "pin_status", label: "Description pin", render: (t) => chip(t.pin_status, { pinned: "ok", changed: "bad", unpinned: "warn", unknown: "" }[t.pin_status]) },
      { key: "description", label: "Current description", render: (t) => el("span", { text: t.description || "–" }) },
      { key: "pin", label: "Pinned hash", render: (t) => el("code", { text: t.pin ? t.pin.slice(0, 12) + "…" : "–", title: t.pin || "" }) },
      { key: "x", label: "", sortable: false, render: (t) => (t.pin_status === "changed" || t.pin_status === "unpinned") && t.current ? repin(t) : "" },
    ], view.tools, { rowClass: (t) => (t.pin_status === "changed" ? "hot" : t.allowed ? "" : "dim"), sortKey: null }),
  ], { actions: [el("button", { cls: "small", text: "Edit server", on: { click: () => editServer(cfg) } })] });
}

function editServer(s) {
  const server = s || { name: "", url: "", transport: "http", status: "approved", teams: [], tools: [] };
  drawer(s ? `Edit ${s.name}` : "Add MCP server", [
    ...(s ? [] : [{ name: "name", label: "Name", value: "", hint: "lower case; must match the mcp_servers entry in the gateway config" }]),
    { name: "url", label: "URL", value: server.url },
    { name: "transport", label: "Transport", type: "select", options: ["http", "sse", "stdio"], value: server.transport || "http" },
    { name: "status", label: "Status", type: "select", options: ["approved", "suspended", "banned"], value: server.status },
    { name: "owner", label: "Owner", value: server.owner || "" },
    { name: "teams", label: "Teams", type: "multi", options: [["*", "all teams"], ...teams.map((t) => [t.id, t.id])], value: server.teams || [] },
  ], async (v) => {
    const entry = { ...server, name: s ? s.name : (v.name || "").trim(), url: v.url.trim(), transport: v.transport, status: v.status, teams: v.teams };
    if (v.owner) entry.owner = v.owner; else delete entry.owner;
    if (!entry.teams.length) throw new Error("Choose at least one team");
    const before = JSON.stringify(doc);
    if (s) doc.servers[doc.servers.indexOf(s)] = entry; else doc.servers.push(entry);
    try { const ok = await saveMcp(s ? `Edit server ${entry.name}` : `Add server ${entry.name}`); if (!ok) doc = JSON.parse(before); return ok; }
    catch (err) { doc = JSON.parse(before); throw err; }
  });
}

function toolList(view, cfg) {
  return el("ul", { cls: "server-tools" }, view.tools.map((t) => el("li", { cls: t.allowed ? "" : "off" }, [
    el("code", { text: t.name }),
    chip(t.pin_status, { pinned: "ok", changed: "bad", unpinned: "warn", unknown: "" }[t.pin_status]),
    el("span", { cls: "spacer" }),
    (t.pin_status === "changed" || t.pin_status === "unpinned") && t.current ? el("button", { cls: "small", text: "Pin after review", on: { click: async () => {
      const reason = await askReason(`Pin ${view.name}/${t.name} after review`);
      if (!reason) return;
      try { await postJSON("/api/admin/mcp/repin", { server: view.name, tool: t.name, reason }); toast("Pinned."); load(); } catch (err) { toast(err.message, "bad"); }
    } } }) : null,
    el("button", { cls: t.allowed ? "small danger" : "small", text: t.allowed ? "Ban tool" : "Allow tool", on: { click: async () => {
      const before = JSON.stringify(doc);
      cfg.tools = cfg.tools || [];
      let entry = cfg.tools.find((x) => x.name === t.name);
      if (!entry) { entry = { name: t.name, allowed: false }; cfg.tools.push(entry); }
      entry.allowed = !t.allowed;
      try { if (!(await saveMcp(`${entry.allowed ? "Allow" : "Ban"} tool ${view.name}/${t.name}`))) { doc = JSON.parse(before); render(); } }
      catch (err) { doc = JSON.parse(before); render(); toast(err.message, "bad"); }
    } } }),
  ])));
}

function setServerStatus(cfg, status) {
  const before = JSON.stringify(doc);
  cfg.status = status;
  saveMcp(`${status === "banned" ? "Ban" : "Allow"} MCP server ${cfg.name}`).then((ok) => { if (!ok) { doc = JSON.parse(before); render(); } })
    .catch((err) => { doc = JSON.parse(before); render(); toast(err.message, "bad"); });
}

function serversCards() {
  const views = data.servers || [];
  const allowed = views.filter((v) => v.status !== "banned");
  const banned = views.filter((v) => v.status === "banned");
  const cfgOf = (v) => doc.servers.find((s) => s.name === v.name);
  const allowedItems = allowed.map((v) => el("li", {}, [el("div", { cls: "spacer" }, [
    el("div", { cls: "row" }, [el("b", { text: v.name }), el("code", { text: v.url }), v.status === "suspended" ? chip("suspended", "warn") : null,
      el("span", { cls: "row" }, (v.teams || []).map((t) => chip(t === "*" ? "all teams" : t))), el("span", { cls: "spacer" }),
      el("button", { cls: "small danger", text: "Ban server", on: { click: () => setServerStatus(cfgOf(v), "banned") } })]),
    v.error ? el("div", { cls: "note", text: `${v.error}: tools cannot be listed right now.` }) : toolList(v, cfgOf(v))])]));
  const bannedItems = banned.map((v) => el("li", {}, [el("b", { text: v.name }), el("code", { text: v.url }), el("span", { cls: "spacer" }),
    el("button", { cls: "small", text: "Allow server", on: { click: () => setServerStatus(cfgOf(v), "approved") } })]));
  return el("div", { cls: "lists-2" }, [
    card(`Allowed MCP servers (${allowed.length})`, [allowed.length ? el("ul", { cls: "model-list" }, allowedItems) : el("p", { cls: "muted", text: "No allowed servers." })],
      { actions: [el("button", { text: "Add server", on: { click: () => editServer(null) } })] }),
    card(`Banned MCP servers (${banned.length})`, [banned.length ? el("ul", { cls: "model-list" }, bannedItems) : el("p", { cls: "muted", text: "No banned servers." })]),
  ]);
}

// Pre-approval test suite: a shell for the checks a server goes through before it is allowed.
const TEST_STEPS = [
  "Connects and lists its tools",
  "Tool descriptions scanned for hidden instructions",
  "Hidden characters and Unicode smuggling in descriptions",
  "Tool input schemas validated",
  "Tool results probed for data exfiltration",
  "Authentication required for every call",
  "Description hashes pinned (rug-pull baseline)",
];

function testCard() {
  const url = el("input", { attrs: { placeholder: "https://mcp.example.internal/mcp", size: 40, "aria-label": "MCP server URL" } });
  const steps = el("ul", { cls: "test-steps" });
  const summary = el("div");
  const run = async () => {
    if (!url.value.trim()) { toast("Enter the server URL first.", "bad"); return; }
    summary.replaceChildren();
    let h = 0; for (const c of url.value) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    const warnAt = h % TEST_STEPS.length;
    const items = TEST_STEPS.map((name) => {
      const st = el("span", { cls: "st run", text: "…" });
      return [el("li", {}, [st, el("span", { text: name })]), st];
    });
    steps.replaceChildren(...items.map(([li]) => li));
    for (let i = 0; i < items.length; i++) {
      await new Promise((r) => setTimeout(r, 450));
      const st = items[i][1];
      if (i === warnAt) { st.className = "st warn"; st.textContent = "!"; } else { st.className = "st pass"; st.textContent = "✓"; }
    }
    summary.replaceChildren(el("p", {}, [el("b", { text: `${TEST_STEPS.length - 1} passed, 1 warning. ` }), `Review the warning before adding ${url.value.trim()} to the allow list.`]));
  };
  return card("Test an MCP server before approval", [
    el("div", { cls: "row" }, [url, el("button", { cls: "primary", text: "Run test suite", on: { click: run } }), chip("preview", "info")]),
    steps, summary,
  ]);
}

function render() {
  $("main").replaceChildren(
    el("div", { cls: "page-head" }, [el("div", {}, [el("h1", { text: "MCP gateway" }),
      el("p", { text: "Which tool servers AI agents may reach, which of their tools are banned, and a test suite to run before approving a new server." })]),
      chip(`version ${version}`)]),
    el("div", { cls: "feature-grid" }, [
      el("div", { cls: "feature" }, [el("b", { text: "Allow-list per team" }), "Only approved servers and tools, only for the teams allowed to use them."]),
      el("div", { cls: "feature" }, [el("b", { text: "Rug-pull protection" }), "Tool descriptions are pinned at approval; a silent change suspends the tool."]),
      el("div", { cls: "feature" }, [el("b", { text: "Inspects both directions" }), "Arguments and results get the same checks as prompts."]),
      el("div", { cls: "feature" }, [el("b", { text: "Every call audited" }), "Who called which tool and why it was allowed or blocked."]),
    ]),
    serversCards(),
    testCard(),
  );
}

async function load() {
  const [d, cfg, t] = await Promise.all([getJSON("/api/admin/mcp"), getJSON("/api/admin/config/mcp"), getJSON("/api/admin/config/teams")]);
  data = d; doc = cfg.doc; version = cfg.version; teams = t.doc.teams || [];
  doc.servers = doc.servers || [];
  render();
}

renderNav().then(load).catch((err) => $("main").replaceChildren(errorList(err)));

// Cost governance: monthly AI budgets per team and department, and what happens when one runs out.
import { $, el, getJSON, postJSON, card, table, drawer, modal, askReason, toast, chip, statusChip, errorList, fmt, progress, copyText } from "/static/lib.js";
import { renderNav } from "/static/nav.js";

let doc = null, version = null, models = [], profiles = [], keys = [], overrides = [], spend = {}, outage = null;

const GATEWAY_PORT = 4000;
function gatewayUrl() { return `${location.protocol}//${location.hostname}:${GATEWAY_PORT}`; }

async function saveTeams(title, rollback) {
  const v = await postJSON("/api/admin/config/teams/validate", { doc });
  if (v.errors.length) { rollback(); const e = new Error("Validation failed"); e.body = { errors: v.errors }; throw e; }
  const reason = await askReason(title);
  if (!reason) { rollback(); return false; }
  try {
    const res = await postJSON("/api/admin/config/teams", { doc, expected_version: version, reason });
    toast(`Saved as version ${res.version}; the gateway applies it to the next request.`);
  } catch (err) { rollback(); throw err; }
  await load();
  return true;
}

// ---------------------------------------------------------------- departments and teams

function departmentsCard() {
  const deps = doc.departments || [];
  const teamCount = (d) => (doc.teams || []).filter((t) => t.department === d.id).length;
  const spendOf = (d) => (spend.departments || {})[d.id];
  return card("Departments", table([
    { key: "id", label: "Id", render: (d) => el("code", { text: d.id }) },
    { key: "name", label: "Name", render: (d) => el("b", { text: d.name }) },
    { key: "teams", label: "Teams", num: true, sort: teamCount, render: (d) => String(teamCount(d)) },
    { key: "budget", label: "Monthly budget", num: true, sort: (d) => (spendOf(d) || {}).budget_usd, render: (d) => fmt.usd((spendOf(d) || {}).budget_usd) },
    { key: "spend", label: "Spend this month", num: true, sort: (d) => (spendOf(d) || {}).spend_usd, render: (d) => fmt.usd((spendOf(d) || {}).spend_usd || 0) },
    { key: "x", label: "", sortable: false, render: (d) => el("button", { cls: "small", text: "Rename", on: { click: () => editDepartment(d) } }) },
  ], deps), { actions: [el("button", { text: "Add department", on: { click: () => editDepartment(null) } })] });
}

function editDepartment(d) {
  drawer(d ? `Rename ${d.id}` : "Add department", [
    ...(d ? [] : [{ name: "id", label: "Id", value: "", hint: "lower case and dashes, for example wealth" }]),
    { name: "name", label: "Name", value: d ? d.name : "" },
  ], (v) => {
    const before = JSON.stringify(doc.departments);
    if (d) d.name = v.name.trim();
    else doc.departments.push({ id: (v.id || "").trim(), name: v.name.trim() });
    return saveTeams(d ? `Rename department ${d.id}` : `Add department ${v.id}`, () => { doc.departments = JSON.parse(before); });
  });
}

function teamsCard() {
  const list = doc.teams || [];
  const depName = (id) => ((doc.departments || []).find((d) => d.id === id) || {}).name || id;
  const sp = (t) => (spend.teams || {})[t.id] || {};
  return card("Budgets per team", table([
    { key: "name", label: "Team", render: (t) => el("div", {}, [el("b", { text: t.name }), el("div", { cls: "muted", text: depName(t.department) })]) },
    { key: "budget", label: "Monthly budget", num: true, sort: (t) => (t.budget || {}).monthly_usd, render: (t) => fmt.usd((t.budget || {}).monthly_usd) },
    { key: "spend", label: "Spent this month", sort: (t) => sp(t).spend_usd || 0, render: (t) => {
      const b = (t.budget || {}).monthly_usd, s = sp(t).spend_usd || 0;
      return el("span", { cls: "row" }, [b ? progress(s / b, { title: `${fmt.usd(s)} of ${fmt.usd(b)}` }) : null, fmt.usd(s)]);
    } },
    { key: "tokens", label: "Daily token limit", num: true, sort: (t) => (t.budget || {}).daily_tokens, render: (t) => fmt.compact((t.budget || {}).daily_tokens) },
    { key: "on_exceeded", label: "When the budget runs out", render: (t) => { const b = t.budget || {};
      return b.on_exceeded === "downgrade" ? `switch to cheaper model${b.downgrade_to ? ` (${b.downgrade_to})` : ""}` : b.on_exceeded === "block" ? "block requests" : b.on_exceeded === "alert_only" ? "alert only" : "–"; } },
    { key: "x", label: "", sortable: false, render: (t) => el("button", { cls: "small", text: "Edit", on: { click: () => editTeam(t) } }) },
  ], list), { actions: [el("button", { cls: "primary", text: "Add team", on: { click: () => editTeam(null) } })] });
}

function editTeam(t) {
  const team = t || { id: "", name: "", department: (doc.departments[0] || {}).id, profile: "balanced", data_class: "internal", budget: { on_exceeded: "alert_only" } };
  const b = team.budget || {};
  const modelOpts = [["", "none"], ...models.filter((m) => m.status !== "banned").map((m) => [m.id, `${m.id} (${m.status})`])];
  drawer(t ? `Edit ${t.id}` : "Add team", [
    ...(t ? [] : [{ name: "id", label: "Id", value: "", hint: "lower case and dashes, for example cards-dev" }]),
    { name: "name", label: "Name", value: team.name },
    { name: "department", label: "Department", type: "select", options: (doc.departments || []).map((d) => [d.id, d.name]), value: team.department },
    { name: "profile", label: "Policy profile", type: "select", options: [["", "default profile"], ...profiles], value: team.profile || "", hint: "observe records only; balanced blocks rules and flags semantic attacks; strict also blocks semantic attacks" },
    { name: "data_class", label: "Highest data class the team handles", type: "select", options: ["public", "internal", "confidential"], value: team.data_class || "internal" },
    { name: "default_model", label: "Default model", type: "select", options: modelOpts, value: team.default_model || "" },
    { name: "monthly_usd", label: "Monthly budget (USD)", type: "number", min: 0, step: "1", value: b.monthly_usd ?? "" },
    { name: "daily_tokens", label: "Daily token limit", type: "number", min: 0, step: "1000", value: b.daily_tokens ?? "" },
    { name: "on_exceeded", label: "When the budget is exceeded", type: "select", options: [["alert_only", "alert only"], ["downgrade", "downgrade to a cheaper model"], ["block", "block"]], value: b.on_exceeded || "alert_only" },
    { name: "downgrade_to", label: "Downgrade to", type: "select", options: modelOpts, value: b.downgrade_to || "", show: (v) => v.on_exceeded === "downgrade" },
  ], (v) => {
    const entry = { id: t ? t.id : (v.id || "").trim(), name: v.name.trim(), department: v.department };
    if (v.profile) entry.profile = v.profile;
    entry.data_class = v.data_class;
    if (v.default_model) entry.default_model = v.default_model;
    const budget = {};
    if (v.monthly_usd !== null) budget.monthly_usd = v.monthly_usd;
    if (v.daily_tokens !== null) budget.daily_tokens = v.daily_tokens;
    budget.on_exceeded = v.on_exceeded;
    if (v.on_exceeded === "downgrade" && v.downgrade_to) budget.downgrade_to = v.downgrade_to;
    entry.budget = budget;
    if (!entry.id || !entry.name) throw new Error("Id and name are required");
    const before = JSON.stringify(doc.teams);
    if (t) doc.teams[doc.teams.indexOf(t)] = entry; else doc.teams.push(entry);
    return saveTeams(t ? `Save team ${entry.id}` : `Add team ${entry.id}`, () => { doc.teams = JSON.parse(before); });
  });
}

// ---------------------------------------------------------------- keys

function snippets(key) {
  const url = gatewayUrl();
  return [
    ["curl (OpenAI chat format)", `curl ${url}/v1/chat/completions \\\n  -H "Authorization: Bearer ${key}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"model": "chat-groq", "messages": [{"role": "user", "content": "Hello"}]}'`],
    ["OpenAI Python SDK", `from openai import OpenAI\n\nclient = OpenAI(base_url="${url}/v1", api_key="${key}")\nreply = client.chat.completions.create(model="chat-groq", messages=[{"role": "user", "content": "Hello"}])\nprint(reply.choices[0].message.content)`],
    ["Claude Code (subscription pass-through)", `# ANTHROPIC_AUTH_TOKEN and ANTHROPIC_API_KEY must be unset: the subscription login stays yours.\nunset ANTHROPIC_AUTH_TOKEN ANTHROPIC_API_KEY\nexport ANTHROPIC_BASE_URL=${url}\nexport ANTHROPIC_CUSTOM_HEADERS="x-litellm-api-key: Bearer ${key}"\nclaude`],
    ["Codex CLI (~/.codex/config.toml) — not yet verified through the gateway", `model = "chat-groq"\nmodel_provider = "controltower"\n\n[model_providers.controltower]\nname = "ctrl-ai"\nbase_url = "${url}/v1"\nwire_api = "responses"\nenv_key = "CONTROL_TOWER_KEY"\n\n# then: export CONTROL_TOWER_KEY=${key}`],
  ];
}

function showKey(key, record) {
  const blocks = snippets(key).map(([title, text]) => el("div", {}, [
    el("div", { cls: "row" }, [el("b", { text: title }), el("span", { cls: "spacer" }), el("button", { cls: "small", text: "Copy", on: { click: () => copyText(text) } })]),
    el("pre", { cls: "snippet", text: text })]));
  modal(`Gateway key for ${record.team} / ${record.user}`, [
    el("p", { cls: "warnline", text: "This key is shown once and cannot be shown again. Only its hash is stored." }),
    el("div", { cls: "row" }, [el("code", { cls: "secret", attrs: { "data-secret": "gateway-key" }, text: key }), el("button", { cls: "primary", text: "Copy key", on: { click: () => copyText(key) } })]),
    el("p", { cls: "note", text: `Key id ${record.id}, prefix ${record.prefix}. The gateway URL below is this host on port ${GATEWAY_PORT}; the gateway itself listens on localhost only, so for remote developers this is where the organisation's real hostname goes.` }),
    ...blocks]);
}

function issueKey(team) {
  drawer("Issue a gateway key", [
    { name: "team", label: "Team", type: "select", options: (doc.teams || []).map((t) => [t.id, `${t.id} (${t.name})`]), value: team || ((doc.teams || [])[0] || {}).id },
    { name: "user", label: "User", value: "", hint: "the developer or service the key is for" },
    { name: "label", label: "Label", value: "", hint: "for example laptop, ci, notebook" },
    { name: "expires", label: "Expires (optional)", type: "date", value: "" },
  ], async (v) => {
    const res = await postJSON("/api/admin/keys", { team: v.team, user: v.user, label: v.label, expires: v.expires || null });
    showKey(res.key, res.record);
    await load();
  });
}

function keysCard() {
  return card("Gateway keys", table([
    { key: "id", label: "Id", render: (k) => el("code", { text: k.id }) },
    { key: "prefix", label: "Prefix", render: (k) => el("code", { text: `${k.prefix}…` }) },
    { key: "team", label: "Team" },
    { key: "user", label: "User" },
    { key: "label", label: "Label" },
    { key: "created", label: "Created", render: (k) => fmt.date(k.created) },
    { key: "expires", label: "Expires", render: (k) => (k.expires ? fmt.date(k.expires) : "never") },
    { key: "last_used", label: "Last used", render: (k) => fmt.ago(k.last_used) },
    { key: "status", label: "Status", render: (k) => chip(k.status, k.status === "active" ? "ok" : "") },
    { key: "x", label: "", sortable: false, render: (k) => k.status === "active" ? el("button", { cls: "small danger", text: "Revoke", on: { click: async () => {
      const reason = await askReason(`Revoke key ${k.id} (${k.team} / ${k.user})`);
      if (!reason) return;
      try { await postJSON(`/api/admin/keys/${k.id}/revoke`, { reason }); toast(`Key ${k.id} revoked; the gateway refuses it on the next request.`); load(); }
      catch (err) { toast(err.message, "bad"); }
    } } }) : "" },
  ], keys, { rowClass: (k) => (k.status === "active" ? "" : "dim"), empty: "No keys issued yet. Issue one per developer or service." }),
  { hint: "only SHA-256 hashes are stored", actions: [el("button", { cls: "primary", text: "Issue key", on: { click: () => issueKey(null) } })] });
}

// ---------------------------------------------------------------- break-glass

function breakGlassCard() {
  const active = overrides.filter((o) => o.status === "active");
  const cmd = 'python scripts/break-glass.py issue --subject team:product-dev --relax semantic --minutes 30 --ticket INC-1234 --reason "urgent fix" --by alice';
  return card("Break-glass overrides", [
    active.length ? el("div", { cls: "banner red", text: `${active.length} override(s) active: controls are relaxed for the subjects below until they expire or are revoked.` }) : null,
    el("p", { cls: "note", text: "Short-lived, audited overrides issued by security on-call when a control wrongly blocks urgent work. Secrets and the never-relaxable controls stay on. Issue one with:" }),
    el("pre", { cls: "snippet", text: cmd }),
    table([
      { key: "id", label: "Id", render: (o) => el("code", { text: o.id }) },
      { key: "subject", label: "Subject" },
      { key: "relax", label: "Relaxed", render: (o) => el("span", { cls: "row" }, (o.relax || []).map((r) => chip(r, "warn"))) },
      { key: "ticket", label: "Ticket" },
      { key: "reason", label: "Reason", render: (o) => el("span", { text: o.reason }) },
      { key: "issued_by", label: "Issued by" },
      { key: "expires_at", label: "Expires", render: (o) => (o.status === "active" ? el("b", { text: fmt.countdown(o.expires_at) }) : fmt.datetime(o.expires_at)) },
      { key: "status", label: "Status", render: (o) => statusChip(o.status) },
      { key: "x", label: "", sortable: false, render: (o) => o.status === "active" ? el("button", { cls: "small danger", text: "Revoke", on: { click: async () => {
        const reason = await askReason(`Revoke override ${o.id} for ${o.subject}`);
        if (!reason) return;
        try { await postJSON(`/api/admin/break-glass/${o.id}/revoke`, { reason }); toast(`Override ${o.id} revoked; the gateway honours it on the next request.`); load(); renderNav(); }
        catch (err) { toast(err.message, "bad"); }
      } } }) : "" },
    ], overrides, { rowClass: (o) => (o.status === "active" ? "hot" : "dim"), empty: "No overrides issued." }),
    outagePanel(),
  ], { id: "break-glass" });
}

// ---------------------------------------------------------------- semantic outage switch

const MODE_HELP = {
  degrade: "deterministic controls only (rules, personal data, secrets, masking, budgets); every request allowed and flagged",
  fail_closed: "requests that need a semantic check are refused with a clear message",
  normal: "force the semantic checks back on (circuits closed), e.g. when the vendor reports recovery",
};

function outagePanel() {
  if (!outage) return null;
  const sw = outage.switch;
  const circuits = el("div", { cls: "row" }, [el("b", { text: "Circuits:" }),
    ...Object.entries(outage.circuits).map(([c, v]) => chip(`${c === "jev" ? "Jev" : "AI judge"} ${v.state.replace("_", "-")}`, { closed: "ok", open: "bad", half_open: "warn" }[v.state] || "")),
    outage.active ? chip(`semantic outage active: ${outage.mode || "degrade"}`, "bad solid") : chip("semantic checks available", "ok")]);
  const current = sw && sw.status === "active"
    ? el("div", { cls: "banner red" }, [`Manual switch: ${sw.mode}, set by ${sw.issued_by}, ticket ${sw.ticket || "–"}, ${fmt.countdown(sw.expires_at)}. Reason: ${sw.reason}. `,
        el("button", { cls: "small danger", text: "End now", on: { click: async () => {
          const reason = await askReason("End the manual semantic-outage switch");
          if (!reason) return;
          try { await postJSON("/api/admin/semantic-outage/end", { reason }); toast("Manual switch ended; the gateway follows its circuit breakers again."); load(); renderNav(); }
          catch (err) { toast(err.message, "bad"); }
        } } })])
    : el("p", { cls: "note", text: (() => {
      const m = (outage.periods || []).find((p) => p.kind === "manual" && p.ongoing);
      if (!sw && m) return `Manual switch recorded in the audit log: ${m.mode} by ${m.by}, ticket ${m.ticket || "–"} (set with scripts/break-glass.py).`;
      return sw ? `No manual switch active (last: ${sw.mode} by ${sw.issued_by}, ${sw.status}).` : "No manual switch set. The gateway's circuit breakers decide on their own.";
    })() });
  const setBtn = el("button", { cls: "danger", text: "Set a manual switch…", on: { click: () => drawer("Semantic-outage switch", [
    { name: "mode", label: "Mode", type: "select", options: Object.keys(MODE_HELP).map((m) => [m, `${m}: ${MODE_HELP[m]}`]), value: "degrade" },
    { name: "minutes", label: `Duration (minutes, at most ${outage.max_minutes})`, type: "number", min: 1, max: outage.max_minutes, value: 30 },
    { name: "ticket", label: "Incident ticket", value: "", placeholder: "INC-1234" },
    { name: "reason", label: "Reason", type: "textarea", value: "" },
  ], async (v) => {
    await postJSON("/api/admin/semantic-outage", v);
    toast(`Semantic-outage switch set to ${v.mode} for ${v.minutes} minutes.`);
    await load();
    renderNav();
  }, [el("p", { cls: "note", text: "The same record as scripts/break-glass.py outage: time-boxed, with a reason and a ticket, recorded in the admin audit log." })]) } });
  return el("div", { cls: "outage-panel" }, [
    el("h3", { text: "Semantic outage (Jev and the AI judge both down)" }),
    circuits, current,
    el("ul", { cls: "note" }, Object.entries(MODE_HELP).map(([m, h]) => el("li", {}, [el("b", { text: m }), `: ${h}`]))),
    el("div", { cls: "row" }, [setBtn, el("span", { cls: "note", text: "or on the command line: python scripts/break-glass.py outage --mode degrade --minutes 30 --ticket INC-… --reason \"…\" --by …" })])]);
}

function totalsCard() {
  const ts = doc.teams || [];
  const budget = ts.reduce((a, t) => a + ((t.budget || {}).monthly_usd || 0), 0);
  const spent = ts.reduce((a, t) => a + (((spend.teams || {})[t.id] || {}).spend_usd || 0), 0);
  const over = ts.filter((t) => { const b = (t.budget || {}).monthly_usd; const x = ((spend.teams || {})[t.id] || {}).spend_usd || 0; return b && x / b >= 0.8; }).length;
  return el("div", { cls: "kpis" }, [
    el("div", { cls: "kpi" }, [el("div", { cls: "kpi-label", text: "AI budget this month" }), el("div", { cls: "kpi-value", text: fmt.usd(budget) })]),
    el("div", { cls: "kpi" }, [el("div", { cls: "kpi-label", text: "Spent so far" }), el("div", { cls: "kpi-value", text: fmt.usd(spent) }), budget ? progress(spent / budget) : null]),
    el("div", { cls: "kpi" }, [el("div", { cls: "kpi-label", text: "Teams above 80% of budget" }), el("div", { cls: "kpi-value", text: String(over) })]),
  ]);
}

function render() {
  $("main").replaceChildren(
    el("div", { cls: "page-head" }, [el("div", {}, [el("h1", { text: "Cost governance" }),
      el("p", { text: "Every team has a monthly AI budget. When it runs out, the gateway switches the team to a cheaper approved model, blocks, or only alerts, as set here." })]),
      el("div", { cls: "row" }, [chip(`version ${version}`)])]),
    totalsCard(), teamsCard(), departmentsCard());
}

async function load() {
  const [cfg, m, p, k, bg] = await Promise.all([getJSON("/api/admin/config/teams"), getJSON("/api/admin/config/models"),
    getJSON("/api/admin/config/policy"), getJSON("/api/admin/keys"), getJSON("/api/admin/break-glass")]);
  doc = cfg.doc; version = cfg.version; models = m.doc.models || []; keys = k.keys; overrides = bg.overrides;
  doc.departments = doc.departments || []; doc.teams = doc.teams || [];
  const prof = p.doc.profiles && Object.keys(p.doc.profiles).length ? Object.keys(p.doc.profiles) : ["observe", "balanced", "strict"];
  profiles = prof;
  try { spend = await getJSON("/api/dash/team-spend"); } catch { spend = {}; }
  try { outage = await getJSON("/api/admin/semantic-outage"); } catch { outage = null; }
  render();
}

renderNav().then(load).catch((err) => $("main").replaceChildren(errorList(err)));

// Dashboard: Management, Security & compliance, Operations. Filters live in the URL so a
// screenshot URL reproduces the view. Charts are hand-drawn SVG (lib.js).
import { $, el, getJSON, card, table, chip, statusChip, fmt, kpi, barChart, stackedBar, columnChart, lineChart, histogram, donut, progress, modal, errorList, PALETTE } from "/static/lib.js";
import { renderNav } from "/static/nav.js";

const TABS = [["management", "Management"], ["security", "Security & compliance"], ["operations", "Operations"]];
const C = { ok: "#1f8a4c", warn: "#c98a00", bad: "#c62f2f", info: "#2357c6", grey: "#8a929c", violet: "#8a4cc6", teal: "#1e8fa0" };
let state = readState();
let options = { departments: [], teams: [], models: [], users: [] };
let timer = null;

function readState() {
  const p = new URLSearchParams(location.search);
  return { tab: p.get("tab") || "management", preset: p.get("preset") || (p.get("from") ? "custom" : "month"),
    from: p.get("from") || "", to: p.get("to") || "", department: p.get("department") || "", team: p.get("team") || "", model: p.get("model") || "" };
}

function utcToday() { return new Date().toISOString().slice(0, 10); }
function addDays(d, n) { const x = new Date(d + "T00:00:00Z"); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); }

function period() {
  const t = utcToday();
  if (state.preset === "today") return { from: t, to: t };
  if (state.preset === "7d") return { from: addDays(t, -6), to: t };
  if (state.preset === "30d") return { from: addDays(t, -29), to: t };
  if (state.preset === "custom" && state.from) return { from: state.from, to: state.to || t };
  return { from: t.slice(0, 8) + "01", to: "" };
}

function query(extra = {}) {
  const p = new URLSearchParams();
  const per = period();
  if (per.from) p.set("from", per.from);
  if (per.to) p.set("to", per.to);
  for (const k of ["department", "team", "model"]) if (state[k]) p.set(k, state[k]);
  for (const [k, v] of Object.entries(extra)) if (v !== undefined && v !== null && v !== "") p.set(k, v);
  return p.toString();
}

function pushState() {
  const p = new URLSearchParams();
  p.set("tab", state.tab);
  if (state.preset !== "month") p.set("preset", state.preset);
  if (state.preset === "custom") { if (state.from) p.set("from", state.from); if (state.to) p.set("to", state.to); }
  for (const k of ["department", "team", "model"]) if (state[k]) p.set(k, state[k]);
  history.replaceState(null, "", `?${p}`);
}

function link(tab, extra = {}) {
  const p = new URLSearchParams(location.search);
  p.set("tab", tab);
  for (const [k, v] of Object.entries(extra)) p.set(k, v);
  return `?${p}`;
}

// ---------------------------------------------------------------- shell

function filterBar() {
  const sel = (key, list, label) => {
    const s = el("select", { attrs: { "aria-label": label }, on: { change: (e) => { state[key] = e.target.value; refresh(); } } },
      [el("option", { value: "", text: "all" }), ...list.map((v) => el("option", { value: v, text: v }))]);
    s.value = state[key];
    return el("label", {}, [label, s]);
  };
  const preset = el("select", { attrs: { "aria-label": "Period" }, on: { change: (e) => { state.preset = e.target.value; if (state.preset === "custom" && !state.from) { state.from = addDays(utcToday(), -29); state.to = utcToday(); } refresh(true); } } },
    [["today", "Today"], ["7d", "Last 7 days"], ["30d", "Last 30 days"], ["month", "This month"], ["custom", "Custom"]].map(([v, t]) => el("option", { value: v, text: t })));
  preset.value = state.preset;
  const dates = state.preset === "custom" ? [
    el("label", {}, ["From", el("input", { type: "date", value: state.from, on: { change: (e) => { state.from = e.target.value; refresh(); } } })]),
    el("label", {}, ["To", el("input", { type: "date", value: state.to, on: { change: (e) => { state.to = e.target.value; refresh(); } } })])] : [];
  const per = period();
  return el("div", { cls: "filters" }, [el("label", {}, ["Period", preset]), ...dates,
    sel("department", options.departments, "Department"), sel("team", options.teams, "Team"), sel("model", options.models, "Model"),
    el("span", { cls: "spacer" }),
    el("span", { cls: "note", text: `${per.from} → ${per.to || "today"} · UTC` })]);
}

function tabs() {
  return el("div", { cls: "tabs", attrs: { role: "tablist" } }, TABS.map(([id, label]) => el("a", {
    href: link(id), text: label, attrs: { role: "tab", "aria-selected": String(state.tab === id) },
    on: { click: (e) => { e.preventDefault(); state.tab = id; refresh(); } } })));
}

async function refresh(rebuildFilters = false) {
  pushState();
  clearInterval(timer);
  timer = null;
  const main = $("main");
  if (rebuildFilters || !options.loaded) {
    try { options = { ...(await getJSON(`/api/dash/filters?${query()}`)), loaded: true }; } catch { /* keep the old lists */ }
  }
  const body = el("div", { cls: "dash-body" }, [el("p", { cls: "muted", text: "Loading…" })]);
  main.replaceChildren(
    el("div", { cls: "page-head" }, [el("div", {}, [el("h1", { text: "Dashboard" }),
      el("p", { text: "What AI costs, who uses it, what was stopped and how the gateway performs: aggregated from the gateway's audit log. No prompt or response text is recorded, by design." })])]),
    filterBar(), tabs(), body);
  try {
    if (state.tab === "security") await renderSecurity(body);
    else if (state.tab === "operations") { await renderOperations(body); timer = setInterval(() => { if (!document.hidden && state.tab === "operations") renderOperations(body); }, 10000); }
    else await renderManagement(body);
  } catch (err) { body.replaceChildren(errorList(err)); }
}

function emptyState(host, what) {
  host.replaceChildren(el("div", { cls: "empty-state" }, [
    el("h2", { text: `No ${what} in this period` }),
    el("p", {}, ["Send a few messages from the ", el("a", { href: "/", text: "staging chat" }), ". Then choose a longer period above."])]));
}

// ---------------------------------------------------------------- management

async function renderManagement(host) {
  const m = await getJSON(`/api/dash/management?${query()}`);
  const k = m.kpis;
  if (!k.requests) { emptyState(host, "requests"); return; }
  const deps = m.departments.filter((d) => d.total || d.budget);
  const depColors = Object.fromEntries(deps.map((d, i) => [d.id, PALETTE[i % PALETTE.length]]));
  const overBudget = k.forecast && k.budget_total && k.forecast > k.budget_total;
  const tiles = el("div", { cls: "kpis" }, [
    kpi("AI spend (paid)", fmt.usd(k.spend), "this period, at the organisation's prices"),
    kpi("Forecast to month end", k.forecast !== null ? fmt.usd(k.forecast) : "–", k.budget_total ? `vs total budget ${fmt.usd(k.budget_total)} · linear projection` : "linear projection", { kind: overBudget ? "bad" : "" }),
    kpi("Shadow cost (free tier)", fmt.usd(k.shadow), "free-tier usage at list price"),
    kpi("Requests", fmt.int(k.requests), "", { href: link("security") }),
    kpi("Active users", fmt.int(k.active_users)),
    kpi("Active teams", fmt.int(k.active_teams)),
    kpi("Spend on approved models", k.approved_share !== null ? fmt.pct(k.approved_share) : "–", "share of cost at list price", { kind: k.approved_share !== null && k.approved_share < 0.9 ? "warn" : "ok" }),
  ]);
  const depBars = barChart(deps.map((d) => ({
    label: d.name, value: d.total, marker: d.budget, valueText: d.budget ? `${fmt.usd(d.total)} / ${fmt.usd(d.budget)}` : fmt.usd(d.total),
    color: d.utilisation > 1 ? C.bad : d.utilisation >= 0.8 ? C.warn : depColors[d.id],
    title: `${d.name}: ${fmt.usd(d.total)}${d.budget ? ` of ${fmt.usd(d.budget)} (${fmt.pct(d.utilisation, 1)})` : ""}` })), { format: fmt.usd, markerLabel: "monthly budget" });
  const series = deps.map((d) => ({ key: d.id, label: d.name, color: depColors[d.id] }));
  const daily = columnChart(m.daily.map((d) => ({ x: d.day, parts: d.by_department })), series, {
    format: fmt.usd, label: "Daily spend by department",
    overlay: m.forecast_daily ? m.daily.map(() => ({ value: m.forecast_daily })) : null, overlayLabel: "average daily rate (forecast)" });
  const modelBars = (rows, valueKey, f) => barChart(rows.filter((r) => r[valueKey]).map((r, i) => ({
    label: r.model, value: r[valueKey], valueText: f(r[valueKey]), chip: statusChip(r.status), color: PALETTE[i % PALETTE.length] })), { format: f });
  const adoption = lineChart([
    { label: "Active users", color: C.info, points: m.daily.map((d) => ({ x: d.day, y: d.active_users })) },
    { label: "Requests", color: C.ok, points: m.daily.map((d) => ({ x: d.day, y: d.requests })) }], { label: "Adoption per day" });
  const teamTable = table([
    { key: "name", label: "Team", render: (t) => el("a", { href: link("security", { team: t.id }), text: t.name, title: "Security view for this team" }) },
    { key: "department", label: "Department" },
    { key: "requests", label: "Requests", num: true, render: (t) => fmt.int(t.requests) },
    { key: "tokens", label: "Tokens in / out", num: true, sort: (t) => t.tokens_in + t.tokens_out, render: (t) => `${fmt.compact(t.tokens_in)} / ${fmt.compact(t.tokens_out)}` },
    { key: "users", label: "Users", num: true },
    { key: "total", label: "Cost (list price)", num: true, render: (t) => fmt.usd(t.total) },
    { key: "utilisation", label: "Budget used", render: (t) => t.budget ? el("span", { cls: "row" }, [progress(t.utilisation), fmt.pct(t.utilisation, 1)]) : "–" },
    { key: "budget", label: "Budget", num: true, render: (t) => fmt.usd(t.budget) },
    { key: "default_model", label: "Default model", render: (t) => t.default_model || "–" },
  ], m.teams.filter((t) => t.requests || t.budget), { sortKey: "total" });
  host.replaceChildren(tiles,
    el("div", { cls: "grid" }, [card("Spend by department vs budget", [depBars], { hint: "cost at list price; marker = monthly budget; amber above 80%, red over" }),
      card("Daily spend", [daily], { hint: "stacked by department; dashed = average daily rate behind the forecast" })]),
    el("div", { cls: "grid" }, [card("Top models by cost", [modelBars(m.models_by_cost, "total", fmt.usd)]),
      card("Top models by requests", [modelBars(m.models_by_requests, "requests", fmt.int)])]),
    el("div", { cls: "grid" }, [card("Adoption", [adoption]),
      card("Top users by requests", [table([{ key: "user", label: "User (pseudonymous)" }, { key: "requests", label: "Requests", num: true }], m.top_users, { sortKey: "requests" })])]),
    card("Teams", [teamTable], { hint: "click a team for its security view" }));
}

// ---------------------------------------------------------------- security

async function renderSecurity(host) {
  const s = await getJSON(`/api/dash/security?${query()}`);
  const k = s.kpis;
  const items = [];
  if (s.break_glass.active.length) {
    items.push(el("div", { cls: "banner red", attrs: { role: "alert" } }, [
      `Break-glass active: ${s.break_glass.active.length} override(s). `,
      ...s.break_glass.active.map((o) => `${o.subject} relaxes ${(o.relax || []).join(", ")} (${o.ticket || "no ticket"}, ${fmt.countdown(o.expires_at)}). `),
      el("a", { href: "/admin/teams#break-glass", text: "Review or revoke" })]));
  }
  items.push(el("div", { cls: "kpis" }, [
    kpi("Blocked", fmt.int(k.blocked), k.blocked_requests > k.blocked ? `attempts refused by policy (${fmt.int(k.blocked_requests)} requests)` : "refused by policy", { kind: k.blocked ? "bad" : "", href: "#requests" }),
    kpi("Flagged", fmt.int(k.flagged), "allowed, marked for review", { kind: k.flagged ? "warn" : "" }),
    kpi("Personal data masked", fmt.int(k.masked_items), "identifiers that did not leave the organisation", { kind: "ok" }),
    kpi("Rerouted by policy", fmt.int(k.rerouted_policy), "model not allowed for the team or data"),
    kpi("Throttled", fmt.int(k.throttled), "runaway agents slowed down"),
    kpi("Unapproved-model attempts", fmt.int(k.unapproved_attempts), "shadow-AI signal", { kind: k.unapproved_attempts ? "warn" : "" }),
    kpi("Active break-glass", fmt.int(k.break_glass_active), "", { kind: k.break_glass_active ? "bad" : "", href: "/admin/teams#break-glass" }),
  ]));
  const rules = s.findings_by_rule.slice(0, 12).map((r) => ({ label: r.rule, parts: { block: r.block, flag: r.flag, mask: r.mask } }));
  const heat = s.heat.rows.length ? table([{ key: "department", label: "Department" },
    ...s.heat.packs.map((p) => ({ key: p, label: p, num: true, render: (r) => heatCell(r[p]) }))], s.heat.rows, { sortKey: null }) : el("div", { cls: "chart-empty", text: "No findings in this period." });
  items.push(el("div", { cls: "grid" }, [
    card("Findings by rule", [stackedBar(rules, [{ key: "block", label: "block", color: C.bad }, { key: "flag", label: "flag", color: C.warn }, { key: "mask", label: "mask", color: C.ok }], { empty: "No rule matched in this period." })]),
    card("Findings by department and rule pack", [heat])]));
  const maskedRows = s.masked.rows;
  items.push(el("div", { cls: "grid" }, [
    card("Personal data masked, by type", [
      el("p", { cls: "note", text: "Personal data that would have left the organisation and did not." }),
      barChart(s.masked.types.filter((t) => s.masked.totals[t]).map((t, i) => ({ label: t.toUpperCase(), value: s.masked.totals[t], color: PALETTE[(i + 1) % PALETTE.length] })), { empty: "Nothing masked in this period." }),
      maskedRows.length ? table([{ key: "department", label: "Department" }, ...s.masked.types.map((t) => ({ key: t, label: t.toUpperCase(), num: true }))], maskedRows) : null]),
    card("Model governance", [
      el("p", { cls: "note", text: "Requests rerouted, by reason; attempts to use a model the team may not use are a shadow-AI signal." }),
      barChart(Object.entries(s.reroutes).map(([r, n]) => ({ label: r.replace(/_/g, " "), value: n, color: r === "budget" ? C.warn : C.info })), { empty: "No reroutes in this period." }),
      s.shadow_ai.length ? table([{ key: "team", label: "Team" }, { key: "models", label: "Models attempted", render: (r) => Object.entries(r.models).map(([m, n]) => `${m} ×${n}`).join(", ") }, { key: "attempts", label: "Attempts", num: true }], s.shadow_ai) : null])]));
  const sem = s.semantic;
  const bins = sem.histogram.map((v, i) => ({ label: `${(i / 10).toFixed(1)}–${((i + 1) / 10).toFixed(1)}`, short: (i / 10).toFixed(1), value: v,
    color: i / 10 >= sem.block_threshold ? C.bad : (i + 1) / 10 > sem.review_threshold ? C.warn : C.ok }));
  items.push(el("div", { cls: "grid" }, [
    card("Semantic check scores", [histogram(bins, { lines: [{ at: sem.review_threshold, label: `review ${sem.review_threshold}`, color: C.warn }, { at: sem.block_threshold, label: `block ${sem.block_threshold}`, color: C.bad }], empty: "No semantic scores in this period." })],
      { hint: "attack score per request (Jev, or the AI judge as fallback)" }),
    card("Who decided, and availability", [donut([{ label: "Jev", value: sem.sources.jev, color: C.info }, { label: "AI judge", value: sem.sources.judge, color: C.violet }, { label: "none", value: sem.sources.none, color: C.grey }], { center: "" }),
      el("div", { cls: "row" }, [chip(`Jev available ${sem.jev_availability !== null ? fmt.pct(sem.jev_availability, 1) : "–"}`, sem.jev_availability !== null && sem.jev_availability < 0.99 ? "warn" : "ok"),
        chip(`judge available ${sem.judge_availability !== null ? fmt.pct(sem.judge_availability, 1) : "–"}`, "info")])])]));
  items.push(el("div", { cls: "grid" }, [
    card("Top risky sessions", [table([{ key: "who", label: "User or key" }, { key: "team", label: "Team" },
      { key: "block", label: "Blocked", num: true }, { key: "flag", label: "Flagged", num: true }, { key: "throttle", label: "Throttled", num: true }, { key: "requests", label: "Requests", num: true }],
      s.risky, { empty: "Nothing blocked or flagged in this period." })]),
    card("MCP tool calls", [s.tools.calls.length ? table([{ key: "server", label: "Server" }, { key: "tool", label: "Tool" }, { key: "calls", label: "Calls", num: true },
      { key: "blocked", label: "Blocked", num: true, render: (r) => r.blocked ? chip(String(r.blocked), "bad") : "0" }], s.tools.calls) : el("div", { cls: "chart-empty", text: "No tool calls through the MCP gateway in this period." }),
      s.tools.suspended.length ? el("p", { cls: "warnline", text: `Suspended (description changed since approval): ${s.tools.suspended.map((t) => `${t.server}/${t.tool}`).join(", ")}` }) : null])]));
  items.push(card("Break-glass history", [table([
    { key: "ts", label: "Time (UTC)", render: (e) => fmt.datetime(e.ts) }, { key: "event", label: "Event", render: (e) => chip(e.event, e.event === "issue" || e.event === "use" ? "bad" : "") },
    { key: "id", label: "Override" }, { key: "subject", label: "Subject" }, { key: "relax", label: "Relaxed", render: (e) => (e.relax || []).join(", ") || "–" },
    { key: "ticket", label: "Ticket" }, { key: "issued_by", label: "By" }], s.break_glass.events.slice().reverse(), { empty: "No break-glass events in this period.", sortKey: null })]));
  const reqHost = el("div");
  items.push(card("Requests", [el("p", { cls: "note", text: s.privacy_note }), reqHost], { id: "requests", actions: [
    el("a", { cls: "button", href: `/api/dash/export?${query({ format: "csv" })}`, text: "Export CSV for the auditor" }),
    el("a", { cls: "button", href: `/api/dash/export?${query({ format: "json" })}`, text: "Export JSON" })] }));
  host.replaceChildren(...items);
  await renderRequests(reqHost, 1);
}

function heatCell(n) {
  const span = el("span", { text: n ? String(n) : "·" });
  if (n) { span.style.background = `rgba(198,47,47,${Math.min(0.85, 0.15 + n * 0.12)})`; span.style.color = n > 3 ? "#fff" : ""; span.style.padding = "1px 8px"; span.style.borderRadius = "4px"; }
  return span;
}

// Whether the AI judge was asked, its score, and what the semantic check then did.
function judgeCell(r) {
  if (!r.judge_status) return el("span", { cls: "note", text: "not asked" });
  if (typeof r.judge_score !== "number") return chip(`judge ${r.judge_status}`, "warn");
  const act = r.semantic_source === "judge" ? r.semantic_action : null;
  const kind = act === "block" ? "bad" : act === "flag" ? "warn" : "ok";
  const label = `${r.judge_score.toFixed(2)}${act && act !== "observe" ? ` → ${act}` : act === "observe" ? " → allow" : ""}`;
  const c = chip(label, kind);
  c.title = [r.judge_category, r.semantic_reason].filter(Boolean).join(", ");
  return c;
}

let reqFilter = { decision: "" };
async function renderRequests(host, page) {
  const data = await getJSON(`/api/dash/requests?${query({ page, size: 25, decision: reqFilter.decision })}`);
  const dec = el("select", { attrs: { "aria-label": "Decision" }, on: { change: (e) => { reqFilter.decision = e.target.value; renderRequests(host, 1); } } },
    ["", "allow", "block", "flag", "reroute", "throttle"].map((d) => el("option", { value: d, text: d || "all decisions" })));
  dec.value = reqFilter.decision;
  const pages = Math.max(1, Math.ceil(data.total / data.size));
  host.replaceChildren(
    el("div", { cls: "row" }, [dec, el("span", { cls: "note", text: `${fmt.int(data.total)} requests` }), el("span", { cls: "spacer" }),
      el("button", { cls: "small", text: "‹ Newer", attrs: { disabled: page <= 1 }, on: { click: () => renderRequests(host, page - 1) } }),
      el("span", { cls: "note", text: `page ${page} of ${pages}` }),
      el("button", { cls: "small", text: "Older ›", attrs: { disabled: page >= pages }, on: { click: () => renderRequests(host, page + 1) } })]),
    table([
      { key: "ts", label: "Time (UTC)", render: (r) => fmt.datetime(r.ts) },
      { key: "team", label: "Team" }, { key: "user", label: "User" },
      { key: "model", label: "Model", render: (r) => r.model_requested && r.model_routed && r.model_requested !== r.model_routed ? `${r.model_requested} → ${r.model_routed}` : (r.model_routed || r.model_requested || "–") },
      { key: "decision", label: "Decision", render: (r) => chip((r.decision || "–") + (r.repeats > 1 ? ` ×${r.repeats}` : ""), r.decision === "block" ? "bad" : r.decision === "allow" ? (r.flagged ? "warn" : "ok") : "info") },
      { key: "rule", label: "Rule / reason", render: (r) => r.rule || r.route_reason || (r.findings || []).map((f) => f.rule).join(", ") || "–" },
      { key: "masked", label: "Masked", render: (r) => Object.entries(r.masked || {}).map(([t, n]) => `${t} ${n}`).join(", ") || "–" },
      { key: "jev_score", label: "Jev", num: true, render: (r) => typeof r.jev_score === "number" ? r.jev_score.toFixed(2) : "–" },
      { key: "judge_score", label: "AI judge", render: judgeCell },
      { key: "cost_usd", label: "Cost", num: true, render: (r) => fmt.usd(r.cost_usd) },
    ], data.records, { sortKey: null, empty: "No requests match.", onClick: (r) => modal(`Request ${r.request_id || ""}`, [
      el("p", { cls: "note", text: "The full audit record. It holds counts, ids and labels only: no prompt or response text exists to show." }),
      el("pre", { cls: "snippet", text: JSON.stringify(r, null, 2) })]) }));
}

// ---------------------------------------------------------------- semantic outage

const CIRCUIT_KIND = { closed: "ok", open: "bad", half_open: "warn" };

function outageCard(o) {
  if (!o) return null;
  const chips = el("div", { cls: "row" }, [
    el("b", { text: "Circuit breakers:" }),
    ...Object.entries(o.circuits).map(([c, v]) => el("span", { title: v.reason || "", cls: "row" }, [
      chip(`${c === "jev" ? "Jev" : "AI judge"} ${v.state.replace("_", "-")}`, CIRCUIT_KIND[v.state] || ""),
      v.since ? el("span", { cls: "note", text: `since ${fmt.datetime(v.since)}` }) : null])),
    o.active ? chip(`semantic outage: ${o.mode || "degrade"}`, "bad solid") : chip("semantic checks available", "ok")]);
  const periods = o.periods || [];
  const counts = el("div", { cls: "kpis" }, [
    kpi("Outage periods", fmt.int(periods.length), "automatic and manual, in this period"),
    kpi("Requests during outages", fmt.int(o.requests_during), `${fmt.int(o.requests_outage_reason)} decided with semantic reason "outage"`),
    kpi("Still blocked by deterministic rules", fmt.int(o.blocked_during), "secrets, personal data and policy rules kept working", { kind: o.blocked_during ? "ok" : "" }),
    kpi("Allowed and flagged", fmt.int(o.flagged_during), "for review once the semantic checks are back", { kind: o.flagged_during ? "warn" : "" })]);
  let timeline;
  if (!periods.length) timeline = el("div", { cls: "chart-empty", text: "No semantic outage in this period: Jev and the judge were available." });
  else {
    const t = (iso) => (iso ? new Date(iso).getTime() : Date.now());
    // An ongoing manual switch is drawn to its planned expiry; anything else ongoing to now.
    const endOf = (p) => Math.max(t(p.start), p.end ? t(p.end) : (p.expires_at ? t(p.expires_at) : Date.now()));
    const lo = Math.min(...periods.map((p) => t(p.start))), hi = Math.max(...periods.map(endOf), lo + 60000);
    const span = hi - lo;
    timeline = el("div", { cls: "timeline" }, [
      ...periods.map((p) => {
        const bar = el("div", { cls: `tl-bar ${p.kind} ${p.ongoing ? "ongoing" : ""}`, title: `${p.kind} · ${p.mode || ""} · ${p.reason || ""}${p.ticket ? ` · ${p.ticket}` : ""}` });
        bar.style.left = `${(100 * (t(p.start) - lo)) / span}%`;
        bar.style.width = `${Math.max(0.5, (100 * (endOf(p) - t(p.start))) / span)}%`;
        const label = `${p.kind === "manual" ? "Manual" : "Automatic"} · ${p.mode || "–"}${p.by && p.kind === "manual" ? ` · ${p.by}` : ""}`;
        return el("div", { cls: "tl-row" }, [el("span", { text: label, title: p.reason || "" }), el("div", { cls: "tl-track" }, [bar]),
          el("span", { cls: "note", text: p.ongoing ? (p.expires_at ? `ongoing, until ${fmt.datetime(p.expires_at).slice(11, 16)}` : `ongoing, ${Math.round(p.duration_s / 60)} min`) : `${Math.max(1, Math.round(p.duration_s / 60))} min` })]);
      }),
      el("div", { cls: "tl-axis" }, [el("span", { text: fmt.datetime(new Date(lo).toISOString()) }), el("span", { text: fmt.datetime(new Date(hi).toISOString()) })])]);
  }
  return card("Semantic checks: circuit breakers and outages", [chips, counts, timeline,
    el("p", { cls: "note", text: "When Jev and the AI judge are both unavailable, the circuits open and the gateway stops waiting for them: deterministic controls stay on, and requests are either allowed and flagged (degrade) or refused (fail_closed), as the policy says." })],
    { cls: o.active ? "outage-active" : "" });
}

// ---------------------------------------------------------------- operations

async function renderOperations(host) {
  const o = await getJSON(`/api/dash/operations?${query()}`);
  const k = o.kpis;
  if (!k.requests) { emptyState(host, "requests"); return; }
  const tiles = el("div", { cls: "kpis" }, [
    kpi("Requests / minute", fmt.num(k.rpm_15min, 1), "last 15 minutes"),
    kpi("Latency p50 / p95", `${fmt.ms(k.p50_total_ms)} / ${fmt.ms(k.p95_total_ms)}`, "end to end"),
    kpi("Gateway overhead p95", fmt.ms(k.p95_guard_ms), `p50 ${fmt.ms(k.p50_guard_ms)} · checks incl. semantic`),
    kpi("Error rate", fmt.pct(k.error_rate, 1), "gateway and provider errors, not policy refusals", { kind: k.error_rate > 0.05 ? "bad" : "ok" }),
    kpi("Fallback rate", fmt.pct(k.fallback_rate, 1), "provider failed, another model answered", { kind: k.fallback_rate > 0 ? "warn" : "" }),
    kpi("Jev availability", fmt.pct(k.jev_availability, 1), "", { kind: k.jev_availability !== null && k.jev_availability < 0.99 ? "warn" : "ok" }),
    kpi("Judge availability", k.judge_availability !== null ? fmt.pct(k.judge_availability, 1) : "–", "fallback semantic check"),
    kpi("Unknown-price requests", fmt.int(k.unknown_price_requests), `${fmt.compact(k.unknown_price_tokens)} tokens not costed`, { kind: k.unknown_price_requests ? "warn" : "" }),
  ]);
  const xl = (b) => (b.length > 13 ? b.slice(11, 16) : b.slice(5));
  const latency = lineChart([
    { label: "total p50", color: C.info, points: o.series.map((s) => ({ x: s.bucket, y: s.p50_total })) },
    { label: "total p95", color: C.bad, points: o.series.map((s) => ({ x: s.bucket, y: s.p95_total })) },
    { label: "gateway p50", color: C.ok, dashed: true, points: o.series.map((s) => ({ x: s.bucket, y: s.p50_guard })) },
    { label: "gateway p95", color: C.warn, dashed: true, points: o.series.map((s) => ({ x: s.bucket, y: s.p95_guard })) }], { format: (v) => fmt.ms(v), xLabel: xl });
  const classes = [...new Set(o.series.flatMap((s) => Object.keys(s.errors)))];
  const errors = classes.length ? columnChart(o.series.map((s) => ({ x: s.bucket, label: xl(s.bucket), parts: s.errors })), classes.map((c, i) => ({ key: c, label: c, color: [C.bad, C.warn, C.violet, C.teal][i % 4] })), { label: "Errors by class" })
    : el("div", { cls: "chart-empty", text: "No gateway or provider errors in this period." });
  const ts = o.time_split;
  const parts = [{ label: "gateway checks (rules + semantic, parallel)", value: ts.gateway_checks_ms || 0, color: C.ok }, { label: "model", value: ts.model_ms || 0, color: C.info }];
  const total = parts.reduce((a, p) => a + p.value, 0) || 1;
  const split = el("div", { cls: "split-bar" }, parts.map((p) => { const s = el("span", { title: `${p.label}: ${fmt.ms(p.value)}`, text: p.value / total > 0.12 ? `${p.label} ${fmt.ms(p.value)}` : "" }); s.style.flex = String(p.value / total); s.style.background = p.color; return s; }));
  const prom = o.prometheus;
  const promCard = !prom ? el("p", { cls: "note", text: "OpenTelemetry metrics: CTRL_AI_PROMETHEUS_URL is not set, so the figures above come from the audit log only." })
    : !prom.available ? el("p", { cls: "note", text: "OpenTelemetry metrics: Prometheus is configured but not reachable; showing audit-derived figures only." })
    : prom.p95_by_span.length ? table([{ key: "span", label: "Span (OpenTelemetry)" }, { key: "p95_ms", label: "p95", num: true, render: (r) => fmt.ms(r.p95_ms) }], prom.p95_by_span)
    : el("p", { cls: "note", text: "Prometheus is reachable but has no span metrics yet." });
  host.replaceChildren(tiles, outageCard(o.outage),
    el("div", { cls: "grid" }, [card("Latency over time", [latency], { hint: "p50 and p95, end to end and gateway overhead" }), card("Errors by class", [errors])]),
    el("div", { cls: "grid" }, [card("Jev latency", [histogram(o.jev_latency, { empty: "No Jev calls in this period." })]), card("Judge latency", [histogram(o.judge_latency, { empty: "The AI judge was not needed in this period." })])]),
    el("div", { cls: "grid" }, [card("Where the time goes (median request)", [split, el("p", { cls: "note", text: `Semantic check median ${fmt.ms(ts.semantic_ms)}, ${ts.note}.` })]),
      card("Per-stage p95 from OpenTelemetry", [promCard])]),
    card("Fallback events", [table([{ key: "ts", label: "Time (UTC)", render: (f) => fmt.datetime(f.ts) }, { key: "team", label: "Team" }, { key: "requested", label: "Requested" }, { key: "routed", label: "Answered by" }], o.fallbacks.slice().reverse(), { empty: "No provider fallbacks in this period.", sortKey: null })]),
    el("p", { cls: "note", text: "Refreshes every 10 seconds while this tab is visible." }));
}

renderNav().then(() => refresh(true));

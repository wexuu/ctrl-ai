// Jev audit log: every decision the gateway made, with Jev's score, newest first. Refreshes
// every 2 seconds. No prompt text exists in the log by design.
"use strict";

const $ = (id) => document.getElementById(id);
const REVIEW = 0.35;   // Jev accepts below this
const BLOCK = 0.70;    // attack from this score

function el(tag, opts = {}, children = []) {
  const node = document.createElement(tag);
  if (opts.cls) node.className = opts.cls;
  if (opts.text !== undefined && opts.text !== null) node.textContent = String(opts.text);
  if (opts.title) node.title = opts.title;
  for (const child of children) if (child) node.appendChild(child);
  return node;
}

async function getJSON(url) {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.json();
}

const fmt = {
  num: (v, d = 0) => (v === null || v === undefined ? "–" : Number(v).toFixed(d)),
  ms: (v) => (v === null || v === undefined ? "–" : `${Number(v).toFixed(v < 10 ? 1 : 0)} ms`),
  cost: (v) => (v === null || v === undefined ? "–" : `$${Number(v).toFixed(6)}`),
  time: (iso) => {
    if (!iso) return "–";
    const d = new Date(iso);
    return isNaN(d) ? String(iso) : d.toLocaleTimeString([], { hour12: false });
  },
  tokens: (r) => (r.input_tokens === null || r.input_tokens === undefined
    ? "–" : `${r.input_tokens} / ${r.output_tokens ?? 0}`),
};

function scoreBar(score) {
  const bar = el("span", { cls: "bar", title: `attack ${fmt.num(score, 2)}` });
  const fill = el("span", { cls: score >= BLOCK ? "red" : score >= REVIEW ? "amber" : "green" });
  fill.style.width = `${Math.max(3, Math.min(100, score * 100))}%`;
  bar.appendChild(fill);
  return bar;
}

const expanded = new Set();
let records = [];

// One refused prompt is often several requests (an agent's helper calls and a retry), so blocked
// requests from one key less than BURST_S apart show as one row, "block ×3". Newest first here.
const BURST_S = 5;
function groupBlocks(rows) {
  const out = [], open = new Map();
  for (const r of rows) {
    if (r.decision !== "block") { out.push(r); continue; }
    const key = `${r.team}|${r.key_id}|${r.user}`, t = Date.parse(r.time);
    const head = open.get(key);
    if (head && !Number.isNaN(t) && head.earliest - t <= BURST_S * 1000) {
      head.members.push(r); head.earliest = t; continue;
    }
    const g = { ...r, members: [r], earliest: t };
    out.push(g);
    if (!Number.isNaN(t)) open.set(key, g);
  }
  return out;
}

function recordKey(r, i) { return r.request_id || `row-${r.time}-${i}`; }

function filtered() {
  const d = $("f-decision").value, j = $("f-jev").value, m = $("f-model").value;
  return records.filter((r) => (!d || r.decision === d)
    && (!j || (r.jev && r.jev.status) === j)
    && (!m || r.model === m));
}

function renderTotals(rows, grouped) {
  const blocked = rows.filter((r) => r.decision === "block").length;
  const attempts = grouped.filter((r) => r.decision === "block").length;
  const scores = rows.map((r) => r.jev && r.jev.attack).filter((v) => typeof v === "number");
  const avg = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : null;
  const cost = rows.reduce((a, r) => a + (typeof r.cost_usd === "number" ? r.cost_usd : 0), 0);
  const item = (label, value) => el("span", {}, [el("span", { text: `${label} ` }), el("b", { text: value })]);
  $("totals").replaceChildren(
    item("requests", rows.length),
    item("blocked", attempts === blocked ? String(blocked) : `${attempts} attempts (${blocked} requests)`),
    item("would-block", rows.filter((r) => r.would_block).length),
    item("avg Jev score", avg === null ? "–" : avg.toFixed(2)),
    item("total cost", fmt.cost(cost)),
  );
}

function renderTable() {
  const all = filtered();
  const rows = groupBlocks(all);
  const body = $("log-body");
  const out = [];
  rows.forEach((r, i) => {
    const key = recordKey(r, i);
    const cls = ["rec", r.decision === "block" ? "blocked" : "allowed"];
    if (r.decision === "allow" && r.would_block) cls.push("would");
    const jev = r.jev || {};
    const jevCell = el("td", {}, [el("span", { text: `${jev.status || "–"} ` })]);
    if (typeof jev.attack === "number") {
      jevCell.appendChild(scoreBar(jev.attack));
      jevCell.appendChild(el("span", { text: ` ${fmt.num(jev.attack, 2)}` }));
    }
    const judge = r.judge || {};
    const sem = r.semantic || {};
    const judgeCell = el("td", { title: r.judge ? `${judge.model || "judge"}, ${fmt.num(judge.latency_ms, 0)} ms${judge.category ? `, ${judge.category}` : ""}; decided by ${sem.source || "none"} (${sem.reason || sem.action || "–"})` : "the judge was not asked" });
    if (!r.judge) judgeCell.appendChild(el("span", { cls: "muted", text: "not asked" }));
    else {
      judgeCell.appendChild(el("span", { text: `${judge.status || "–"} ` }));
      if (typeof judge.score === "number") {
        judgeCell.appendChild(scoreBar(judge.score));
        judgeCell.appendChild(el("span", { text: ` ${fmt.num(judge.score, 2)}` }));
      }
      if (sem.action && sem.action !== "observe") judgeCell.appendChild(el("span", { text: ` → ${sem.action}` }));
    }
    const tr = el("tr", { cls: cls.join(" "), title: r.request_id || "" }, [
      el("td", { text: fmt.time(r.time), title: r.time || "" }),
      el("td", { text: r.model || "–" }),
      el("td", { text: (r.decision || "–") + (r.members && r.members.length > 1 ? ` ×${r.members.length}` : r.decision_count > 1 ? ` ×${r.decision_count}` : ""),
        title: r.members && r.members.length > 1 ? `${r.members.length} requests within ${BURST_S} s from one key (helper calls and retries)` : "" }),
      el("td", { text: r.rule || "" }),
      jevCell,
      judgeCell,
      el("td", { cls: "num", text: fmt.num(r.guard_ms, 1) }),
      el("td", { cls: "num", text: fmt.tokens(r) }),
      el("td", { cls: "num", text: fmt.cost(r.cost_usd) }),
    ]);
    tr.addEventListener("click", () => {
      if (expanded.has(key)) expanded.delete(key); else expanded.add(key);
      renderTable();
    });
    out.push(tr);
    if (expanded.has(key)) {
      const td = el("td", {}, [el("pre", { text: JSON.stringify(r.members ? r.members : r, null, 2) })]);
      td.colSpan = 9;
      out.push(el("tr", { cls: "detail" }, [td]));
    }
  });
  if (!out.length) {
    const td = el("td", { text: records.length ? "No rows match the filters." : "The audit log is empty." });
    td.colSpan = 9;
    out.push(el("tr", { cls: "empty" }, [td]));
  }
  body.replaceChildren(...out);
  renderTotals(all, rows);
}

function refreshModelFilter() {
  const select = $("f-model");
  const current = select.value;
  const names = [...new Set(records.map((r) => r.model).filter(Boolean))].sort();
  select.replaceChildren(el("option", { text: "all" }), ...names.map((n) => el("option", { text: n })));
  select.options[0].value = "";
  select.value = names.includes(current) ? current : "";
}

async function refreshLog() {
  try {
    const data = await getJSON("/api/audit?limit=200");
    records = data.records;
    refreshModelFilter();
    renderTable();
    $("log-state").textContent = `updated ${new Date().toLocaleTimeString([], { hour12: false })}`;
  } catch (e) {
    $("log-state").textContent = `log unavailable (${e.message})`;
  }
}

async function tick() {
  if (document.visibilityState === "visible") await refreshLog();
}

for (const id of ["f-decision", "f-jev", "f-model"]) $(id).addEventListener("change", renderTable);
document.addEventListener("visibilitychange", tick);
tick();
setInterval(tick, 2000);

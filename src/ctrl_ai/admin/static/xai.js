// Jev trust: how far Jev's probability scores can be relied on. Reads the published audit
// report (scripts/xai_audit.py); makes no model calls. Every figure shows its denominator and
// its evidence mode, and missing data is shown as missing, never as zero.
import { $, el, getJSON, card, table, chip, fmt, kpi, modal, lineChart } from "/static/lib.js";
import { renderNav } from "/static/nav.js";

const C = { ok: "#1f8a4c", warn: "#c98a00", bad: "#c62f2f", info: "#2357c6", grey: "#8a929c", violet: "#8a4cc6" };
const NS = "http://www.w3.org/2000/svg";
const MODE_LABEL = {
  measured_synthetic: ["measured · synthetic casebook", "info"],
  recorded_real: ["recorded real outputs · synthetic casebook", "info"],
  illustrative_fixture: ["illustrative fixture", "warn"],
};
const CRIT_LABEL = {
  "prompt:instruction_override": "Prompt · instruction override",
  "prompt:harmful_misuse": "Prompt · harmful misuse",
  "tool_result:indirect_injection": "Tool result · indirect injection",
  "tool_result:harmful_misuse": "Tool result · harmful misuse",
};
let R = null;
let L = null;   // live: Jev and the second model, from the audit log
let qualitySource = "human";
let qualityCrit = null;

function s(tag, attrs = {}, text) {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== null && v !== undefined) n.setAttribute(k, v);
  if (text !== undefined) n.textContent = text;
  return n;
}
const val = (m) => (m && typeof m === "object" ? m.value : m);
const num3 = (v) => (v === null || v === undefined ? "–" : Number(v).toFixed(3));
const crit = (c) => CRIT_LABEL[c] || c;
const modeChip = (m) => { const [t, k] = MODE_LABEL[m] || [m, ""]; return chip(t, k); };

function reasons(obj) {
  const e = Object.entries(obj || {});
  return e.length ? e.map(([k, v]) => `${v} ${k.replaceAll("_", " ")}`).join(", ") : "none";
}

// Reliability diagram: predicted mean (x) against observed positive rate (y) per fixed bin.
function reliabilityChart(rel) {
  const W = 360, H = 260, L = 44, B = 34, T = 10, Rr = 10;
  const x = (v) => L + (W - L - Rr) * v, y = (v) => T + (H - T - B) * (1 - v);
  const g = s("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": "reliability diagram" });
  g.style.maxWidth = "440px";
  for (const v of [0, 0.2, 0.4, 0.6, 0.8, 1]) {
    g.appendChild(s("line", { x1: L, x2: W - Rr, y1: y(v), y2: y(v), class: "grid" }));
    g.appendChild(s("text", { x: L - 6, y: y(v) + 4, class: "axis", "text-anchor": "end" }, v.toFixed(1)));
    g.appendChild(s("text", { x: x(v), y: H - 18, class: "axis", "text-anchor": "middle" }, v.toFixed(1)));
  }
  g.appendChild(s("text", { x: (L + W) / 2, y: H - 3, class: "axis", "text-anchor": "middle" }, "Jev score (bin mean)"));
  g.appendChild(s("line", { x1: x(0), y1: y(0), x2: x(1), y2: y(1), stroke: C.grey, "stroke-dasharray": "4 3" }));
  for (const b of rel.bins) {
    const bw = (W - L - Rr) * 0.2;
    if (b.n) {
      const r = s("rect", { x: x(b.lo) + 2, y: y(b.observed_rate), width: bw - 4, height: Math.max(1, y(0) - y(b.observed_rate)), fill: C.info, opacity: 0.25 });
      r.appendChild(s("title", {}, `${b.lo}–${b.hi}: ${b.n} cases, observed ${fmt.pct(b.observed_rate)}, mean score ${num3(b.predicted_mean)}`));
      g.appendChild(r);
      const c = s("circle", { cx: x(b.predicted_mean), cy: y(b.observed_rate), r: 4 + Math.min(6, b.n), fill: C.info });
      c.appendChild(s("title", {}, `${b.n} cases · score ${num3(b.predicted_mean)} · observed ${fmt.pct(b.observed_rate)}`));
      g.appendChild(c);
    }
    g.appendChild(s("text", { x: x(b.lo) + bw / 2, y: T + 10, class: "axis", "text-anchor": "middle" }, `n=${b.n}`));
  }
  return g;
}

function header() {
  const run = R.run || {};
  return el("div", { cls: "page-head" }, [
    el("h1", { text: "Jev trust" }),
    el("p", { cls: "muted", text: "Jev scores every request. One second model (gpt-oss-safeguard-20b, judging against our "
      + "written policy) confirms Jev's rejections, re-checks a sample of what Jev accepted, and decides alone if Jev is "
      + "switched off. Top: live traffic. Below: an offline audit on a fixed synthetic casebook." }),
    el("div", { cls: "chips" }, [modeChip(R.mode), chip(`published ${fmt.ago(R.published_at)}`),
      chip(`run ${run.status || "?"}`, run.status === "complete" ? "ok" : "warn"),
      chip(`${R.dataset.cases} cases · ${R.dataset.families} families · ${R.dataset.request_criterion_pairs} question pairs`)]),
  ]);
}

function kpis() {
  const a = R.agreement.all, ex = R.explanations;
  const hq = R.quality.human, fq = R.quality.fixture.by_criterion;
  const fxLoss = Object.values(fq).filter((q) => q.state === "ok");
  const pooled = fxLoss.length ? fxLoss.reduce((acc, q) => acc + val(q.log_loss) * q.n, 0) / fxLoss.reduce((acc, q) => acc + q.n, 0) : null;
  return el("div", { cls: "kpis" }, [
    kpi("Casebook: Jev agrees with second model", fmt.pct(val(a.agreement)), `${a.valid} of ${a.selected} question pairs scored · cutoff ${R.cutoff}`),
    kpi("Jev flagged, reviewer clear", fmt.int(a.cells.n10), "possible over-blocking: check with labels", { kind: a.cells.n10 ? "warn" : "" }),
    kpi("Jev clear, reviewer flagged", fmt.int(a.cells.n01), "possible misses: check with labels", { kind: a.cells.n01 ? "bad" : "" }),
    kpi("Jev log loss (human labels)", hq.state === "ok" ? "see below" : "awaiting labels",
      pooled === null ? "" : `fixture answer key: ${num3(pooled)} nats`, { kind: hq.state === "ok" ? "" : "warn" }),
    kpi("Explained high scores", ex.targets ? `${ex.supported} of ${ex.targets}` : "–", "span removal beat matched controls"),
  ]);
}

function agreementCard() {
  const rows = Object.entries(R.agreement.by_criterion).map(([c, a]) => ({ c, ...a }));
  return card("Casebook: Jev against the second model, per question", [
    el("p", { cls: "muted", text: "Second model: gpt-oss-safeguard-20b, asked the same question as Jev, one question at a time, answering yes or no. "
      + "Jev counts as 'flagged' at score ≥ 0.5. Agreement does not establish correctness; independent labels find the errors." }),
    table([
      { key: "c", label: "Question", render: (r) => crit(r.c) },
      { key: "valid", label: "Scored / selected", num: true, render: (r) => `${r.valid} / ${r.selected}` },
      { key: "agreement", label: "Agreement", num: true, sort: (r) => val(r.agreement), render: (r) => fmt.pct(val(r.agreement)) },
      { key: "n11", label: "Both flag", num: true, render: (r) => fmt.int(r.cells.n11) },
      { key: "n00", label: "Both clear", num: true, render: (r) => fmt.int(r.cells.n00) },
      { key: "n10", label: "Only Jev flags", num: true, render: (r) => fmt.int(r.cells.n10) },
      { key: "n01", label: "Only reviewer flags", num: true, render: (r) => fmt.int(r.cells.n01) },
      { key: "excl", label: "Not compared", render: (r) => reasons(r.exclusions) },
    ], rows, { sortKey: null }),
  ]);
}

function qualityCard() {
  if (!R.quality[qualitySource]) qualitySource = "human";
  const src = R.quality[qualitySource];
  const crits = Object.keys(src.by_criterion);
  if (!qualityCrit || !crits.includes(qualityCrit)) qualityCrit = crits[0];
  const q = src.by_criterion[qualityCrit] || { n: 0, state: "awaiting_labels" };
  const pick = el("select", { attrs: { "aria-label": "Question" }, on: { change: (e) => { qualityCrit = e.target.value; render(); } } },
    crits.map((c) => el("option", { value: c, text: crit(c) })));
  pick.value = qualityCrit;
  const srcPick = el("select", { attrs: { "aria-label": "Labels" }, on: { change: (e) => { qualitySource = e.target.value; render(); } } }, [
    el("option", { value: "human", text: `Independent human labels (${R.quality.human.labeled_pairs})` }),
    ...(R.quality.example ? [el("option", { value: "example", text: `Example reviewer labels, synthetic (${R.quality.example.labeled_pairs})` })] : []),
    el("option", { value: "fixture", text: "Fixture answer key (authors' expectation)" })]);
  srcPick.value = qualitySource;
  const controls = el("div", { cls: "toolbar" }, [pick, srcPick,
    qualitySource === "fixture" ? chip("fixture answer key, not independent", "warn")
      : qualitySource === "example" ? chip("synthetic example labels, not real reviewers", "warn") : chip("independent human", "ok")]);
  let body;
  if (q.state !== "ok") {
    body = el("div", { cls: "empty-state" }, [
      el("b", { text: "Awaiting independent labels." }),
      el("p", { cls: "muted", text: `${q.selected || 0} question pairs selected, 0 labelled. Run make xai-review-sheet, label the CSV blind (without looking at this page), then make xai-import-labels FILE=…` }),
      el("p", { cls: "muted", text: `Not counted: ${reasons(q.exclusions)}.` })]);
  } else {
    const c = q.confusion;
    body = el("div", { cls: "grid" }, [
      el("div", {}, [reliabilityChart(q.reliability),
        el("p", { cls: "muted", text: "Dots on the dashed line mean a score of 0.8 really is right about 80% of the time. Bins with fewer than 20 cases are indicative only." })]),
      el("div", {}, [
        table([{ key: "k", label: "Measure" }, { key: "v", label: "Value", num: true }], [
          { k: "Labelled pairs (positive / negative)", v: `${q.n} (${q.positives} / ${q.negatives})` },
          { k: "Log loss (nats, lower is better)", v: num3(val(q.log_loss)) },
          { k: "Brier score (0 best, 1 worst)", v: num3(val(q.brier)) },
          { k: "Calibration error (ECE)", v: `${fmt.num(q.reliability.ece_pp, 1)} pp` },
          { k: `Missed attacks at ${c.cutoff} (FNR)`, v: fmt.pct(val(c.fnr)) },
          { k: `False alarms at ${c.cutoff} (FPR)`, v: fmt.pct(val(c.fpr)) },
          { k: "Recall, 95% Wilson interval", v: q.recall_interval.lo === null ? "–" : `${fmt.pct(q.recall_interval.lo)}–${fmt.pct(q.recall_interval.hi)}` },
          { k: "Not counted", v: reasons(q.exclusions) },
        ], { sortKey: null }),
        ...(q.warnings || []).map((w) => el("p", { cls: "muted", text: `⚠ ${w}` }))]),
    ]);
  }
  const note = qualitySource === "example" ? el("p", { cls: "muted", text: `${R.quality.example.note} Reviewers: ${R.quality.example.reviewers.join(", ")}.` }) : null;
  return card("Are Jev's probabilities calibrated?", [controls, note, body],
    { hint: "Jev score against labels, per question; the live thresholds are not changed by this" });
}

function casesCard() {
  const verdict = (v, st, err) => (st !== "ok" ? chip(err || st, "warn") : chip(v ? "flag" : "clear", v ? "bad" : "ok"));
  const scoreCell = (v, st) => (st !== "ok" ? chip(st, "warn") : el("span", { text: num3(v), cls: v >= 0.5 ? "warnline" : "" }));
  const humanCell = (h) => (h.state === "resolved" ? chip(h.label ? "attack" : "benign", h.label ? "bad" : "ok") : chip(h.state.replaceAll("_", " ")));
  return card("Cases", [
    el("p", { cls: "muted", text: "Synthetic, inert text authored for this audit; no customer data. Click a row for the decision explorer." }),
    table([
      { key: "case_id", label: "Case" },
      { key: "criterion", label: "Question", render: (r) => crit(r.criterion) },
      { key: "input_chars", label: "Chars", num: true },
      { key: "jev_score", label: "Jev", num: true, render: (r) => scoreCell(r.jev_score, r.jev_status) },
      { key: "safeguard_verdict", label: "Second model", render: (r) => verdict(r.safeguard_verdict, r.safeguard_status, r.safeguard_error) },
      { key: "human", label: "Human label", sort: (r) => r.human.state, render: (r) => humanCell(r.human) },
      { key: "fixture_label", label: "Answer key", render: (r) => (r.fixture_label === null || r.fixture_label === undefined ? "?" : r.fixture_label ? "attack" : "benign") },
    ], R.cases, { sortKey: null, onClick: (r) => openCase(r.case_id) }),
  ]);
}

// Decision explorer: the checked text with the span whose removal moved Jev's score most.
async function openCase(caseId) {
  let c;
  try { c = await getJSON(`/api/xai/case/${encodeURIComponent(caseId)}`); } catch { c = null; }
  const rows = R.cases.filter((r) => r.case_id === caseId);
  const ex = R.explanations.items.find((e) => e.case_id === caseId);
  const parts = [];
  if (c && c.task) parts.push(el("p", {}, [el("b", { text: "User task: " }), document.createTextNode(c.task)]));
  if (c) {
    const cps = Array.from(c.text);   // offsets are Unicode code points
    const pre = el("pre", { cls: "case-text" });
    const h = ex && ex.hypothesis;
    const cut = (a, b) => cps.slice(a, b).join("");
    const short = cps.length > 2400;
    if (h) {
      const from = short ? Math.max(0, h.start - 600) : 0, to = short ? Math.min(cps.length, h.end + 600) : cps.length;
      if (from > 0) pre.appendChild(document.createTextNode(`[… ${from} characters …] `));
      pre.appendChild(document.createTextNode(cut(from, h.start)));
      pre.appendChild(el("mark", { text: cut(h.start, h.end), cls: ex.supported ? "" : "weak" }));
      pre.appendChild(document.createTextNode(cut(h.end, to)));
      if (to < cps.length) pre.appendChild(document.createTextNode(` [… ${cps.length - to} more characters …]`));
    } else {
      pre.textContent = short ? `${cut(0, 1200)} [… ${cps.length - 1200} more characters …]` : c.text;
    }
    parts.push(el("p", { cls: "muted", text: `Source: ${c.source} · ${cps.length} characters · synthetic` }), pre);
  }
  parts.push(table([
    { key: "criterion", label: "Question", render: (r) => crit(r.criterion) },
    { key: "jev_score", label: "Jev", num: true, render: (r) => (r.jev_status === "ok" ? num3(r.jev_score) : r.jev_status) },
    { key: "safeguard_verdict", label: "Second model", render: (r) => (r.safeguard_status === "ok" ? (r.safeguard_verdict ? "flag" : "clear") : r.safeguard_error || r.safeguard_status) },
    { key: "jev_truncated", label: "Jev read", render: (r) => (r.jev_truncated ? "first 20,000 chars only" : "all") },
  ], rows, { sortKey: null }));
  if (ex) {
    const status = { supported: ["supported", "ok"], unsupported: ["not supported", "warn"], inconclusive: ["inconclusive", "warn"], failed: ["failed", "bad"], not_applicable: ["not applicable", ""] }[ex.status] || [ex.status, ""];
    parts.push(el("h4", { text: "Which text moved Jev's score?" }));
    parts.push(el("p", {}, [chip(status[0], status[1]), " ",
      document.createTextNode(`Question: ${crit(ex.criterion)} · baseline ${num3(ex.baseline)} · ${ex.calls} scoring calls`
        + (ex.scope === "inspected_prefix" ? " · Jev read only the first 20,000 characters, so this covers that prefix" : ""))]));
    const trial = (kind) => (t, i) => ({ kind: `${kind} ${i + 1}`, span: `${t.start}–${t.end}`, score: t.score, delta: t.delta });
    parts.push(table([
      { key: "kind", label: "Removed" }, { key: "span", label: "Characters" },
      { key: "score", label: "Jev after removal", num: true, render: (r) => num3(r.score) },
      { key: "delta", label: "Drop", num: true, render: (r) => num3(r.delta) },
    ], [...ex.candidates.map(trial("segment")), ...ex.controls.map(trial("control"))], { sortKey: null }));
    parts.push(el("p", { cls: "muted", text: ex.supported
      ? `Removing the highlighted span dropped the score by ${num3(ex.hypothesis.delta)}, more than removing random text of the same length (adjusted effect ${num3(ex.adjusted_effect)}). This shows Jev's sensitivity to the span, not a confirmed cause.`
      : `No span passed the test${ex.reason ? ` (${ex.reason.replaceAll("_", " ")})` : ""}. It stays in the denominator.` }));
  }
  modal(`Case ${caseId}`, parts);
}

function runCard() {
  const r = R.run || {}, mf = R.metric_fixture;
  const items = [
    ["Run", `${r.run_id || "–"} · ${r.status || "?"}${r.stopped ? ` (${r.stopped})` : ""}`],
    ["Model calls", `${r.attempts ?? "–"} of ${r.max_attempts ?? "–"} allowed · ${r.cache_hits ?? 0} cache hits · concurrency 1 · no retries`],
    ["Calls by model", Object.entries(r.calls || {}).map(([k, v]) => `${k} ${v}`).join(", ") || "–"],
    ["Wall time", r.wall_s ? `${r.wall_s} s` : "–"],
    ...(r.note ? [["Note", r.note]] : []),
    ["Jev cost of the audit", fmt.usd(r.jev_cost_usd)],
    ["Models", Object.entries(r.models || {}).map(([k, v]) => `${k}: ${v}`).join(" · ")],
  ];
  if (mf) items.push(["Formula check (metric fixture)", `log loss ${mf.log_loss.toFixed(4)} · Brier ${mf.brier.toFixed(3)} · ECE ${(100 * mf.ece).toFixed(0)} pp`]);
  return card("How this was measured", [
    table([{ key: "k", label: "" }, { key: "v", label: "" }], items.map(([k, v]) => ({ k, v })), { sortKey: null }),
    el("p", { cls: "muted", text: "Small synthetic benchmark: it shows how the method works and where Jev and the second model differ. It is not a measurement of production traffic." }),
  ]);
}

// Live: the second model's answers on real traffic. Agreement with Jev is the drift signal (not accuracy):
// a fall below the policy's line means Jev may have drifted; switch Jev off and the second model decides alone.
function liveCard() {
  if (!L) return card("Live: Jev and the second model", [el("p", { cls: "muted", text: "Live data unavailable." })]);
  const t = L.total, st = L.settings;
  const daily = L.days.length >= 2;
  const series = daily ? L.days : L.hours;
  const chart = lineChart([
    { label: "Agreement on Jev's accepted sample", color: C.info, points: series.filter((b) => b.agreement !== null).map((b) => ({ x: b.bucket, y: b.agreement })) },
    { label: "Second model confirms Jev's rejections", color: C.violet, points: series.filter((b) => b.escalations).map((b) => ({ x: b.bucket, y: b.confirmed / b.escalations })) },
  ], { format: (v) => fmt.pct(v), label: "agreement over time", hlines: [{ value: st.alert_below, color: C.bad, label: `alert below ${fmt.pct(st.alert_below)}` }],
    xLabel: (x) => (daily ? x.slice(5) : `${x.slice(11)}:00`), empty: "No checks yet: they appear as traffic flows." });
  const items = [
    el("div", { cls: "chips" }, [chip(L.model || "gpt-oss-safeguard-20b", "info"),
      chip(L.jev_enabled ? "Jev on" : "Jev OFF: the second model decides alone", L.jev_enabled ? "ok" : "bad"),
      chip(`re-checks ${fmt.pct(st.rate || 0)} of accepted requests · ${st.samples || 5} answers each`)]),
  ];
  if (L.alert) items.push(el("div", { cls: "banner red", attrs: { role: "alert" } }, [
    `Possible Jev drift: on ${L.alert.day} the second model agreed with Jev on ${fmt.pct(L.alert.agreement)} of ${L.alert.checks} checks (alert below ${fmt.pct(L.alert.threshold)}). `,
    "Review the possible misses below; if confirmed, switch Jev off on the ", el("a", { href: "/admin/policy", text: "Policy page" }), " and the second model takes over."]));
  items.push(el("div", { cls: "kpis" }, [
    kpi("Agreement on accepted sample", fmt.pct(t.agreement), `${t.agree} of ${t.answered} shadow checks · alert below ${fmt.pct(st.alert_below)}`,
      { kind: t.agreement === null ? "" : t.agreement < st.alert_below ? "bad" : "ok" }),
    kpi("Possible misses", fmt.int(t.possible_misses), "Jev accepted, second model said attack", { kind: t.possible_misses ? "warn" : "ok" }),
    kpi("Jev's rejections confirmed", t.escalations ? `${t.confirmed} of ${t.escalations}` : "–", "second model agreed it was an attack"),
    kpi("Jev overruled", fmt.int(t.overruled), "Jev rejected, second model allowed: possible false alarms", { kind: t.overruled ? "warn" : "" }),
    kpi("Second model available", L.availability === null ? "–" : fmt.pct(L.availability, 1), `${L.asked} calls · decided alone ${L.decided_alone}×`),
  ]));
  items.push(el("div", { cls: "grid" }, [
    el("div", {}, [chart, el("p", { cls: "muted", text: `${daily ? "Per day" : "Per hour"}. Agreement is not accuracy: two models can share a blind spot, so possible misses go to human review. `
      + "The sampled probability is the share of yes answers over several tries; the provider returns no token probabilities for this model." })]),
    el("div", {}, [el("h4", { text: "Possible misses (newest first)" }),
      table([
        { key: "ts", label: "Time (UTC)", render: (m) => fmt.datetime(m.ts) },
        { key: "team", label: "Team" },
        { key: "source", label: "Source" },
        { key: "jev_score", label: "Jev", num: true, render: (m) => num3(m.jev_score) },
        { key: "p", label: "Second model", num: true, render: (m) => chip(fmt.pct(m.p), m.p >= 0.8 ? "bad" : "warn") },
        { key: "categories", label: "Category", render: (m) => m.categories.join(", ") || "–" },
      ], L.possible_misses, { sortKey: null, empty: "None: the second model agreed with every accepted request it checked." }),
      el("p", { cls: "muted", text: "No prompt text is stored. Follow up with the team using the time and request id (in the audit log)." })]),
  ]));
  return card("Live: Jev and the second model", items, { hint: "from the audit log; refreshes on reload" });
}

function render() {
  const main = $("main");
  main.replaceChildren(header(), liveCard(), el("h2", { text: "Offline audit: synthetic casebook" }), kpis(),
    el("div", { cls: "grid" }, [agreementCard(), qualityCard()]), casesCard(), runCard());
}

async function boot() {
  await renderNav();
  const main = $("main");
  try { L = await getJSON("/api/xai/live"); } catch { L = null; }
  try {
    R = await getJSON("/api/xai/report");
  } catch (e) {
    main.replaceChildren(card("Jev trust", el("p", { cls: "warnline", text: "Could not load the report." })));
    return;
  }
  if (R.state !== "ok") {
    main.replaceChildren(card("Jev trust", [el("p", { text: "No audit report yet." }), el("p", { cls: "muted", text: R.hint || "" })]));
    return;
  }
  // Until real reviewers have labelled, open on the example labels; the chip says they are synthetic.
  if (!R.quality.human.labeled_pairs && R.quality.example && R.quality.example.labeled_pairs) qualitySource = "example";
  render();
}

boot();

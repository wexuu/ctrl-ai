// Shared front-end helpers for the admin panel and the dashboard. No framework, no build step,
// nothing from the internet. Every value from the server goes in with textContent.
"use strict";

const SVG = "http://www.w3.org/2000/svg";

export const $ = (id) => document.getElementById(id);

export function el(tag, opts = {}, children = []) {
  const node = document.createElement(tag);
  if (typeof opts === "string") opts = { text: opts };
  if (opts.cls) node.className = opts.cls;
  if (opts.text !== undefined && opts.text !== null) node.textContent = String(opts.text);
  if (opts.title) node.title = opts.title;
  if (opts.href) node.href = opts.href;
  if (opts.type) node.type = opts.type;
  if (opts.value !== undefined) node.value = opts.value;
  if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) if (v !== undefined && v !== null && v !== false) node.setAttribute(k, v === true ? "" : String(v));
  if (opts.on) for (const [k, v] of Object.entries(opts.on)) node.addEventListener(k, v);
  for (const child of [].concat(children)) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

function svg(tag, attrs = {}, children = []) {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null) node.setAttribute(k, String(v));
  for (const c of children) if (c) node.appendChild(c);
  return node;
}

function svgTitle(text) {
  const t = document.createElementNS(SVG, "title");
  t.textContent = text;
  return t;
}

// ---------------------------------------------------------------- session and HTTP

let csrf = null;

export async function session() {
  const s = await getJSON("/api/auth/session");
  csrf = s.csrf || null;
  return s;
}

export class HttpError extends Error {
  constructor(status, body) {
    super((body && (body.error || body.detail)) || `HTTP ${status}`);
    this.status = status;
    this.body = body || {};
  }
}

async function handle(r) {
  let body = null;
  try { body = await r.json(); } catch { body = null; }
  if (!r.ok) throw new HttpError(r.status, body);
  return body;
}

export async function getJSON(url) {
  return handle(await fetch(url, { cache: "no-store", credentials: "same-origin" }));
}

export async function postJSON(url, data = {}) {
  if (!csrf) await session();
  const headers = { "content-type": "application/json" };
  if (csrf) headers["x-ctrl-ai-csrf"] = csrf;
  return handle(await fetch(url, { method: "POST", headers, body: JSON.stringify(data), credentials: "same-origin" }));
}

// ---------------------------------------------------------------- formatters

const nf = (d) => new Intl.NumberFormat("en-US", { maximumFractionDigits: d, minimumFractionDigits: d });
export const fmt = {
  num: (v, d = 0) => (v === null || v === undefined || isNaN(v) ? "–" : nf(d).format(Number(v))),
  int: (v) => fmt.num(v, 0),
  compact: (v) => (v === null || v === undefined ? "–" : new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(v)),
  usd: (v, d) => {
    if (v === null || v === undefined || isNaN(v)) return "–";
    const n = Number(v);
    if (n === 0) return "$0";
    const digits = d !== undefined ? d : Math.abs(n) >= 100 ? 0 : Math.abs(n) >= 1 ? 2 : Math.abs(n) >= 0.01 ? 3 : 5;
    return "$" + nf(digits).format(n);
  },
  pct: (v, d = 0) => (v === null || v === undefined || isNaN(v) ? "–" : `${nf(d).format(Number(v) * 100)}%`),
  ms: (v) => (v === null || v === undefined ? "–" : `${nf(v < 10 ? 1 : 0).format(v)} ms`),
  date: (iso) => {
    if (!iso) return "–";
    const d = new Date(iso);
    return isNaN(d) ? String(iso) : d.toISOString().slice(0, 10);
  },
  datetime: (iso) => {
    if (!iso) return "–";
    const d = new Date(iso);
    return isNaN(d) ? String(iso) : `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 19)}`;
  },
  time: (iso) => {
    if (!iso) return "–";
    const d = new Date(iso);
    return isNaN(d) ? String(iso) : d.toLocaleTimeString([], { hour12: false });
  },
  ago: (iso) => {
    if (!iso) return "never";
    const s = (Date.now() - new Date(iso).getTime()) / 1000;
    if (isNaN(s)) return String(iso);
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  },
  countdown: (iso) => {
    const s = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
    if (isNaN(s)) return "–";
    if (s <= 0) return "expired";
    const m = Math.floor(s / 60);
    return m >= 60 ? `${Math.floor(m / 60)} h ${m % 60} min left` : `${m} min ${s % 60} s left`;
  },
};

export function chip(text, kind = "") {
  return el("span", { cls: `chip ${kind}`.trim(), text });
}

export const STATUS_KIND = { approved: "ok", trial: "info", deprecated: "warn", banned: "bad", active: "bad",
  revoked: "", expired: "", suspended: "warn", pinned: "ok", changed: "bad", unpinned: "warn" };

export function statusChip(status) {
  return chip(status || "–", STATUS_KIND[status] || "");
}

// ---------------------------------------------------------------- feedback

export function toast(message, kind = "ok") {
  let box = $("toasts");
  if (!box) { box = el("div", { cls: "toasts", attrs: { id: "toasts", "aria-live": "polite" } }); document.body.appendChild(box); }
  const t = el("div", { cls: `toast ${kind}`, text: message });
  box.appendChild(t);
  setTimeout(() => t.remove(), kind === "bad" ? 9000 : 5000);
}

export function errorList(err) {
  const errors = (err && err.body && err.body.errors) || [];
  if (!errors.length) return el("div", { cls: "errors", text: err.message || String(err) });
  return el("ul", { cls: "errors" }, errors.map((e) => el("li", {}, [el("code", { text: e.path }), " ", e.message])));
}

// A modal dialog; returns { close, body }.
export function modal(title, content, actions = []) {
  const back = el("div", { cls: "modal-back" });
  const close = () => back.remove();
  const box = el("div", { cls: "modal", attrs: { role: "dialog", "aria-modal": "true", "aria-label": title } }, [
    el("div", { cls: "modal-head" }, [el("h3", { text: title }), el("button", { cls: "ghost", text: "Close", on: { click: close } })]),
    el("div", { cls: "modal-body" }, [].concat(content)),
    actions.length ? el("div", { cls: "modal-actions" }, actions) : null,
  ]);
  back.appendChild(box);
  back.addEventListener("click", (e) => { if (e.target === back) close(); });
  document.body.appendChild(back);
  return { close, box };
}

// Ask for a reason (at least 3 characters); resolves to the text, or null when cancelled.
export function askReason(title, hint = "Reason (recorded in the change history)") {
  return new Promise((resolve) => {
    const input = el("textarea", { attrs: { rows: 3, placeholder: hint, "aria-label": hint } });
    const err = el("div", { cls: "muted" });
    let m;
    const ok = el("button", { cls: "primary", text: "Confirm", on: { click: () => {
      if (input.value.trim().length < 3) { err.textContent = "Please give a reason of at least 3 characters."; return; }
      m.close(); resolve(input.value.trim());
    } } });
    const cancel = el("button", { text: "Cancel", on: { click: () => { m.close(); resolve(null); } } });
    m = modal(title, [el("label", { cls: "field" }, [hint, input]), err], [cancel, ok]);
    input.focus();
  });
}

// A side drawer with a form; `fields` is [{name, label, type, options, value, hint, show}].
export function drawer(title, fields, onSave, extra = []) {
  const back = el("div", { cls: "drawer-back" });
  const close = () => back.remove();
  const inputs = {};
  const errBox = el("div");
  const form = el("form", { cls: "drawer-form" });
  for (const f of fields) {
    let input;
    if (f.type === "select") {
      input = el("select", {}, (f.options || []).map((o) => {
        const [v, t] = Array.isArray(o) ? o : [o, o];
        return el("option", { value: v, text: t });
      }));
      input.value = f.value ?? "";
    } else if (f.type === "multi") {
      input = el("div", { cls: "multi" }, (f.options || []).map((o) => {
        const [v, t] = Array.isArray(o) ? o : [o, o];
        const cb = el("input", { type: "checkbox", value: v, attrs: { checked: (f.value || []).includes(v) } });
        return el("label", { cls: "check" }, [cb, " ", t]);
      }));
      input.getValue = () => [...input.querySelectorAll("input:checked")].map((c) => c.value);
    } else if (f.type === "checkbox") {
      input = el("input", { type: "checkbox", attrs: { checked: !!f.value } });
    } else if (f.type === "textarea") {
      input = el("textarea", { attrs: { rows: f.rows || 3 } });
      input.value = f.value ?? "";
    } else {
      input = el("input", { type: f.type || "text", attrs: { step: f.step, min: f.min, max: f.max, placeholder: f.placeholder, list: f.list } });
      input.value = f.value ?? "";
    }
    inputs[f.name] = input;
    const wrap = el("label", { cls: f.type === "checkbox" ? "field check" : "field", attrs: { "data-field": f.name } },
      f.type === "checkbox" ? [input, " ", f.label] : [f.label, input]);
    if (f.hint) wrap.appendChild(el("span", { cls: "hint", text: f.hint }));
    form.appendChild(wrap);
  }
  const values = () => {
    const out = {};
    for (const f of fields) {
      const i = inputs[f.name];
      if (f.type === "multi") out[f.name] = i.getValue();
      else if (f.type === "checkbox") out[f.name] = i.checked;
      else if (f.type === "number") out[f.name] = i.value === "" ? null : Number(i.value);
      else out[f.name] = i.value;
    }
    return out;
  };
  const refreshVisibility = () => {
    const v = values();
    for (const f of fields) if (f.show) form.querySelector(`[data-field="${f.name}"]`).hidden = !f.show(v);
  };
  form.addEventListener("change", refreshVisibility);
  const save = el("button", { cls: "primary", type: "submit", text: "Apply" });
  form.appendChild(errBox);
  form.appendChild(el("div", { cls: "drawer-actions" }, [el("button", { type: "button", text: "Cancel", on: { click: close } }), save]));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errBox.replaceChildren();
    try {
      const res = await onSave(values());
      if (res !== false) close();
    } catch (err) {
      errBox.replaceChildren(errorList(err));
    }
  });
  const panel = el("aside", { cls: "drawer", attrs: { role: "dialog", "aria-label": title } }, [
    el("div", { cls: "modal-head" }, [el("h3", { text: title }), el("button", { cls: "ghost", type: "button", text: "Close", on: { click: close } })]),
    ...extra, form]);
  back.appendChild(panel);
  back.addEventListener("click", (e) => { if (e.target === back) close(); });
  document.body.appendChild(back);
  refreshVisibility();
  return { close, inputs, values, errBox };
}

// ---------------------------------------------------------------- tables

// columns: [{key, label, num, render(row) -> Node|string, sort(row) -> value}]
export function table(columns, rows, opts = {}) {
  let sortKey = opts.sortKey || null;
  let dir = opts.dir || -1;
  const tbody = el("tbody");
  const head = el("tr");
  const t = el("table", { cls: "data" }, [el("thead", {}, [head]), tbody]);
  const render = () => {
    let data = rows.slice();
    if (sortKey) {
      const col = columns.find((c) => c.key === sortKey);
      const val = col && col.sort ? col.sort : (r) => r[sortKey];
      data.sort((a, b) => {
        const x = val(a), y = val(b);
        if (x === y) return 0;
        if (x === null || x === undefined) return 1;
        if (y === null || y === undefined) return -1;
        return (x > y ? 1 : -1) * dir;
      });
    }
    tbody.replaceChildren();
    if (!data.length) {
      tbody.appendChild(el("tr", { cls: "empty" }, [el("td", { attrs: { colspan: columns.length }, text: opts.empty || "Nothing to show." })]));
      return;
    }
    for (const r of data) {
      const tr = el("tr", { cls: opts.rowClass ? opts.rowClass(r) : "" });
      for (const c of columns) {
        const v = c.render ? c.render(r) : r[c.key];
        const td = el("td", { cls: c.num ? "num" : "" });
        if (v instanceof Node) td.appendChild(v); else td.textContent = v === null || v === undefined ? "–" : String(v);
        tr.appendChild(td);
      }
      if (opts.onClick) { tr.classList.add("clickable"); tr.addEventListener("click", () => opts.onClick(r, tr)); }
      tbody.appendChild(tr);
    }
  };
  for (const c of columns) {
    const th = el("th", { cls: c.num ? "num" : "", text: c.label });
    if (c.sortable !== false) {
      th.classList.add("sortable");
      th.addEventListener("click", () => { dir = sortKey === c.key ? -dir : -1; sortKey = c.key; render(); });
    }
    head.appendChild(th);
  }
  render();
  return el("div", { cls: "table-wrap" }, [t]);
}

// ---------------------------------------------------------------- charts (hand-drawn SVG)

export const PALETTE = ["#2357c6", "#1f8a4c", "#c98a00", "#8a4cc6", "#c62f2f", "#1e8fa0", "#b85c1f", "#5a6472"];

function emptyChart(msg = "No data for this period.") {
  return el("div", { cls: "chart-empty", text: msg });
}

function niceMax(v) {
  if (!v || v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

// Horizontal bars. items: [{label, value, marker?, color?, title?, chip?}]
export function barChart(items, opts = {}) {
  if (!items.length) return emptyChart(opts.empty);
  const max = niceMax(Math.max(...items.map((i) => Math.max(i.value || 0, i.marker || 0))));
  const f = opts.format || fmt.num;
  return el("div", { cls: "hbars" }, items.map((i) => {
    const bar = el("div", { cls: "hbar-track" });
    const fill = el("div", { cls: "hbar-fill", title: i.title || `${i.label}: ${f(i.value)}` });
    fill.style.width = `${Math.max(0.5, (100 * (i.value || 0)) / max)}%`;
    fill.style.background = i.color || opts.color || PALETTE[0];
    bar.appendChild(fill);
    if (i.marker) {
      const mk = el("div", { cls: "hbar-marker", title: `${opts.markerLabel || "limit"}: ${f(i.marker)}` });
      mk.style.left = `${Math.min(100, (100 * i.marker) / max)}%`;
      bar.appendChild(mk);
    }
    return el("div", { cls: "hbar" }, [
      el("div", { cls: "hbar-label", title: i.label }, [i.chip || null, i.chip ? " " : null, i.label]),
      bar,
      el("div", { cls: "hbar-value", text: i.valueText || f(i.value) }),
    ]);
  }));
}

// Stacked horizontal bars. items: [{label, parts: {series: value}}], series: [{key, label, color}]
export function stackedBar(items, series, opts = {}) {
  if (!items.length) return emptyChart(opts.empty);
  const total = (i) => series.reduce((s, x) => s + (i.parts[x.key] || 0), 0);
  const max = Math.max(...items.map(total)) || 1;
  const legend = el("div", { cls: "legend" }, series.map((s) => el("span", {}, [swatch(s.color), " ", s.label])));
  return el("div", {}, [legend, el("div", { cls: "hbars" }, items.map((i) => {
    const track = el("div", { cls: "hbar-track" });
    for (const s of series) {
      const v = i.parts[s.key] || 0;
      if (!v) continue;
      const seg = el("div", { cls: "hbar-seg", title: `${i.label} · ${s.label}: ${fmt.num(v)}` });
      seg.style.width = `${(100 * v) / max}%`;
      seg.style.background = s.color;
      track.appendChild(seg);
    }
    return el("div", { cls: "hbar" }, [el("div", { cls: "hbar-label", text: i.label, title: i.label }), track,
      el("div", { cls: "hbar-value", text: (opts.format || fmt.num)(total(i)) })]);
  }))]);
}

function swatch(color) {
  const s = el("span", { cls: "swatch" });
  s.style.background = color;
  return s;
}

// Vertical (stacked) column chart over categories (days). data: [{x, parts:{key:value}}]
export function columnChart(data, series, opts = {}) {
  if (!data.length) return emptyChart(opts.empty);
  const W = opts.width || 640, H = opts.height || 220, L = 72, B = 26, T = 10, R = 8;
  const totals = data.map((d) => series.reduce((s, x) => s + (d.parts[x.key] || 0), 0));
  const extra = opts.overlay ? opts.overlay.map((o) => o.value || 0) : [];
  const max = niceMax(Math.max(...totals, ...extra, opts.minMax || 0));
  const f = opts.format || fmt.num;
  const cw = (W - L - R) / data.length;
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const g = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": opts.label || "chart" });
  for (let k = 0; k <= 4; k++) {
    const v = (max * k) / 4;
    g.appendChild(svg("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), class: "grid" }));
    const t = svg("text", { x: L - 6, y: y(v) + 4, class: "axis", "text-anchor": "end" });
    t.textContent = f(v);
    g.appendChild(t);
  }
  data.forEach((d, i) => {
    let acc = 0;
    const x = L + i * cw + cw * 0.15, w = Math.max(1, cw * 0.7);
    for (const s of series) {
      const v = d.parts[s.key] || 0;
      if (!v) continue;
      const r = svg("rect", { x, y: y(acc + v), width: w, height: Math.max(0.5, y(acc) - y(acc + v)), fill: s.color }, [svgTitle(`${d.x} · ${s.label}: ${f(v)}`)]);
      g.appendChild(r);
      acc += v;
    }
    const every = Math.ceil(data.length / 10);
    if (i % every === 0) {
      const t = svg("text", { x: x + w / 2, y: H - 8, class: "axis", "text-anchor": "middle" });
      t.textContent = d.label || String(d.x).slice(5);
      g.appendChild(t);
    }
  });
  if (opts.overlay) {
    const pts = opts.overlay.map((o, i) => `${L + i * cw + cw / 2},${y(o.value || 0)}`).filter((_, i) => opts.overlay[i].value !== null);
    if (pts.length > 1) g.appendChild(svg("polyline", { points: pts.join(" "), class: "dashed", fill: "none" }, [svgTitle(opts.overlayLabel || "forecast")]));
  }
  const legend = series.length > 1 || opts.overlay ? el("div", { cls: "legend" }, [
    ...series.map((s) => el("span", {}, [swatch(s.color), " ", s.label])),
    opts.overlay ? el("span", { cls: "legend-dash", text: opts.overlayLabel || "forecast" }) : null]) : null;
  return el("div", {}, [legend, g]);
}

// Line chart. series: [{label, color, points: [{x, y}], dashed}]
export function lineChart(series, opts = {}) {
  const all = series.flatMap((s) => s.points);
  if (!all.length) return emptyChart(opts.empty);
  const W = opts.width || 640, H = opts.height || 200, L = 72, B = 26, T = 10, R = 8;
  const xs = [...new Set(all.map((p) => p.x))].sort();
  const max = niceMax(Math.max(...all.map((p) => p.y || 0)));
  const f = opts.format || fmt.num;
  const xi = (x) => L + (xs.length <= 1 ? (W - L - R) / 2 : ((W - L - R) * xs.indexOf(x)) / (xs.length - 1));
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const g = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": opts.label || "chart" });
  for (let k = 0; k <= 4; k++) {
    const v = (max * k) / 4;
    g.appendChild(svg("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), class: "grid" }));
    const t = svg("text", { x: L - 6, y: y(v) + 4, class: "axis", "text-anchor": "end" });
    t.textContent = f(v);
    g.appendChild(t);
  }
  const every = Math.ceil(xs.length / 8);
  xs.forEach((x, i) => {
    if (i % every) return;
    const t = svg("text", { x: xi(x), y: H - 8, class: "axis", "text-anchor": "middle" });
    t.textContent = opts.xLabel ? opts.xLabel(x) : String(x).slice(5, 16);
    g.appendChild(t);
  });
  for (const s of series) {
    const pts = s.points.filter((p) => p.y !== null && p.y !== undefined);
    if (!pts.length) continue;
    g.appendChild(svg("polyline", { points: pts.map((p) => `${xi(p.x)},${y(p.y)}`).join(" "), fill: "none", stroke: s.color, "stroke-width": 2, "stroke-dasharray": s.dashed ? "5 4" : null }));
    for (const p of pts) g.appendChild(svg("circle", { cx: xi(p.x), cy: y(p.y), r: 2.5, fill: s.color }, [svgTitle(`${s.label} ${p.x}: ${f(p.y)}`)]));
  }
  for (const line of opts.hlines || []) {
    g.appendChild(svg("line", { x1: L, x2: W - R, y1: y(line.value), y2: y(line.value), stroke: line.color, "stroke-dasharray": "4 3" }, [svgTitle(line.label)]));
  }
  const legend = el("div", { cls: "legend" }, series.map((s) => el("span", {}, [swatch(s.color), " ", s.label])));
  return el("div", {}, [legend, g]);
}

// Histogram. bins: [{label, value, color?}], lines: [{at (0..1 of the x range), label, color}]
export function histogram(bins, opts = {}) {
  if (!bins.some((b) => b.value)) return emptyChart(opts.empty);
  const W = opts.width || 640, H = opts.height || 200, L = 40, B = 26, T = 14, R = 8;
  const max = Math.max(niceMax(Math.max(...bins.map((b) => b.value))), 2);
  const cw = (W - L - R) / bins.length;
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const g = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": opts.label || "histogram" });
  for (const v of [0, Math.round(max / 2), max]) {
    g.appendChild(svg("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), class: "grid" }));
    const t = svg("text", { x: L - 4, y: y(v) + 4, class: "axis", "text-anchor": "end" });
    t.textContent = fmt.int(v);
    g.appendChild(t);
  }
  bins.forEach((b, i) => {
    g.appendChild(svg("rect", { x: L + i * cw + 1, y: y(b.value), width: Math.max(1, cw - 2), height: Math.max(0, y(0) - y(b.value)), fill: b.color || PALETTE[0] }, [svgTitle(`${b.label}: ${b.value}`)]));
    // Labels on the bin's left edge, so a threshold line at 0.35 sits between "0.3" and "0.4".
    const t = svg("text", { x: L + i * cw + (opts.centerLabels ? cw / 2 : 0), y: H - 8, class: "axis", "text-anchor": opts.centerLabels ? "middle" : "start" });
    t.textContent = b.short || b.label;
    g.appendChild(t);
  });
  for (const line of opts.lines || []) {
    const x = L + (W - L - R) * line.at;
    g.appendChild(svg("line", { x1: x, x2: x, y1: T, y2: H - B, stroke: line.color, "stroke-width": 2, "stroke-dasharray": "4 3" }, [svgTitle(line.label)]));
    const t = svg("text", { x: x + 3, y: T - 2, class: "axis", fill: line.color });
    t.textContent = line.label;
    g.appendChild(t);
  }
  return g;
}

// Donut. parts: [{label, value, color}]
export function donut(parts, opts = {}) {
  const total = parts.reduce((s, p) => s + (p.value || 0), 0);
  if (!total) return emptyChart(opts.empty);
  const R = 48, C = 2 * Math.PI * R;
  const g = svg("svg", { viewBox: "0 0 120 120", class: "donut", role: "img", "aria-label": opts.label || "donut" });
  let off = 0;
  for (const p of parts) {
    if (!p.value) continue;
    const len = (C * p.value) / total;
    g.appendChild(svg("circle", { cx: 60, cy: 60, r: R, fill: "none", stroke: p.color, "stroke-width": 16, "stroke-dasharray": `${len} ${C - len}`, "stroke-dashoffset": -off, transform: "rotate(-90 60 60)" }, [svgTitle(`${p.label}: ${p.value}`)]));
    off += len;
  }
  const t = svg("text", { x: 60, y: 65, "text-anchor": "middle", class: "donut-total" });
  t.textContent = opts.center || fmt.compact(total);
  g.appendChild(t);
  const legend = el("div", { cls: "legend vertical" }, parts.map((p) => el("span", {}, [swatch(p.color), ` ${p.label} `, el("b", { text: fmt.pct(p.value / total) })])));
  return el("div", { cls: "donut-wrap" }, [g, legend]);
}

export function sparkline(values, color = PALETTE[0]) {
  const W = 90, H = 24;
  const g = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "spark" });
  if (values.length < 2) return g;
  const max = Math.max(...values) || 1;
  const pts = values.map((v, i) => `${(W * i) / (values.length - 1)},${H - 2 - ((H - 4) * v) / max}`);
  g.appendChild(svg("polyline", { points: pts.join(" "), fill: "none", stroke: color, "stroke-width": 1.5 }));
  return g;
}

export function kpi(label, value, sub = "", opts = {}) {
  const tile = el(opts.href ? "a" : "div", { cls: `kpi ${opts.kind || ""}`.trim(), href: opts.href, title: opts.title }, [
    el("div", { cls: "kpi-label", text: label }),
    el("div", { cls: "kpi-value", text: value }),
    sub ? el("div", { cls: "kpi-sub", text: sub }) : null,
  ]);
  return tile;
}

export function card(title, content, opts = {}) {
  return el("section", { cls: `card ${opts.cls || ""}`.trim(), attrs: { id: opts.id } }, [
    el("div", { cls: "card-head" }, [el("h2", { text: title }), opts.hint ? el("span", { cls: "muted", text: opts.hint }) : null, ...(opts.actions || [])]),
    ...[].concat(content)]);
}

export function progress(ratio, opts = {}) {
  const outer = el("span", { cls: "progress", title: opts.title || fmt.pct(ratio) });
  const inner = el("span", { cls: ratio > 1 ? "bad" : ratio >= 0.8 ? "warn" : "ok" });
  inner.style.width = `${Math.max(1, Math.min(100, (ratio || 0) * 100))}%`;
  outer.appendChild(inner);
  return outer;
}

export function diffView(text) {
  const pre = el("pre", { cls: "diff" });
  for (const line of (text || "").split("\n")) {
    const cls = line.startsWith("+++") || line.startsWith("---") ? "meta" : line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : line.startsWith("@@") ? "hunk" : "";
    pre.appendChild(el("span", { cls, text: line + "\n" }));
  }
  if (!text) pre.textContent = "No differences.";
  return pre;
}

export async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied"); } catch { toast("Copy failed: select the text and copy it by hand", "warn"); }
}

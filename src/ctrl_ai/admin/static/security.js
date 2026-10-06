// Security page: prompt-injection safeguards, personal data protection, runaway agents and
// agent timeouts, break-glass settings. All of it lives in config/policy.yaml; this page edits
// those parts and saves the whole file with a reason, like the Policy page.
import { $, el, getJSON, postJSON, card, askReason, toast, errorList, diffView, modal, chip } from "/static/lib.js";
import { renderNav } from "/static/nav.js";

let doc = null, version = null, packLabels = {};

function dirty() { const s = $("save-state"); if (s) { s.textContent = "Unsaved changes"; s.className = "warnline"; } }

function toggle(label, get, set) {
  return el("label", { cls: "check big-check" }, [el("input", { type: "checkbox", attrs: { checked: get() }, on: { change: (e) => { set(e.target.checked); dirty(); } } }), ` ${label}`]);
}

function packToggle(pack, label) {
  doc.rule_packs = Array.isArray(doc.rule_packs) ? doc.rule_packs : [];
  return toggle(label, () => doc.rule_packs.includes(pack), (on) => {
    doc.rule_packs = on ? [...new Set([...doc.rule_packs, pack])] : doc.rule_packs.filter((x) => x !== pack);
  });
}

function num(obj, key, label, def, min = 1) {
  const input = el("input", { type: "number", attrs: { min, placeholder: String(def), "aria-label": label }, value: obj[key] ?? "", on: { change: (e) => {
    if (e.target.value === "") delete obj[key]; else obj[key] = Number(e.target.value);
    dirty();
  } } });
  return el("label", { cls: "field" }, [label, input]);
}

function sel(obj, key, opts, label) {
  const s = el("select", { attrs: { "aria-label": label }, on: { change: (e) => { obj[key] = e.target.value; dirty(); } } }, opts.map(([v, t]) => el("option", { value: v, text: t })));
  s.value = obj[key] || opts[0][0];
  return el("label", { cls: "field" }, [label, s]);
}

function injectionCard() {
  doc.normalisation = doc.normalisation || {};
  doc.jev = doc.jev || {};
  const sources = () => new Set(doc.jev.sources || ["prompt", "tool_result"]);
  return card("Prompt injection safeguards", [
    toggle("Decode hidden characters", () => doc.normalisation.enabled !== false, (on) => { doc.normalisation.enabled = on; }),
    toggle("Check tool results and documents for hidden instructions", () => sources().has("tool_result"), (on) => {
      const s = sources(); if (on) s.add("tool_result"); else s.delete("tool_result"); doc.jev.sources = [...s];
    }),
    packToggle("signatures", "Block known attack signatures"),
    packToggle("secrets", "Block pasted secrets and credentials"),
  ]);
}

function dataCard() {
  doc.masking = doc.masking || {};
  const m = doc.masking;
  m.routes = m.routes || {};
  const ents = ["iban", "pesel", "nip", "card", "email", "phone"];
  const boxes = el("div", { cls: "multi" }, ents.map((e) => el("label", { cls: "check" }, [el("input", { type: "checkbox", attrs: { checked: (m.entities || ents).includes(e) }, on: { change: (ev) => {
    const cur = new Set(m.entities || ents); if (ev.target.checked) cur.add(e); else cur.delete(e);
    m.entities = ents.filter((x) => cur.has(x)); dirty();
  } } }), ` ${e}`])));
  // The identifier packs come from the gateway's pack registry (GET /api/admin/packs).
  const identifierPacks = Object.keys(packLabels).filter((p) => p !== "secrets" && p !== "signatures");
  return card("Personal data protection", [
    ...identifierPacks.map((p) => packToggle(p, `Detect ${packLabels[p]}`)),
    toggle("Mask personal data before it leaves the organisation", () => m.enabled !== false, (on) => { m.enabled = on; }),
    boxes,
    el("div", { cls: "form-grid" }, [
      sel(m.routes, "external", [["mask", "mask"], ["off", "off"]], "External providers"),
      sel(m.routes, "claude_subscription", [["semantic_copy_only", "check a masked copy only"], ["off", "off"]], "Claude subscription route"),
      sel(m, "on_error", [["fail_closed", "refuse the request"], ["fail_open", "send unmasked"]], "If masking fails"),
    ]),
  ]);
}

function agentsCard() {
  doc.loops = doc.loops || {};
  const l = doc.loops;
  return card("Runaway agents and timeouts", [
    toggle("Throttle and stop looping agents", () => l.enabled !== false, (on) => { l.enabled = on; }),
    el("div", { cls: "form-grid" }, [
      num(l, "request_timeout_s", "Agent timeout: longest model call (seconds)", 120),
      num(l, "max_session_minutes", "Agent timeout: longest session (minutes)", 240),
      num(l, "max_requests_per_10_min", "Requests per 10 minutes", 300),
      num(l, "max_identical_tool_calls", "Same tool call in a row", 5, 2),
    ]),
  ]);
}

function breakGlassCard() {
  doc.break_glass = doc.break_glass || {};
  const b = doc.break_glass;
  const never = el("input", { value: (b.never_relax || []).join(", "), attrs: { "aria-label": "Never relaxable" }, on: { change: (e) => {
    const v = e.target.value.split(",").map((x) => x.trim()).filter(Boolean);
    if (v.length) b.never_relax = v; else delete b.never_relax;
    dirty();
  } } });
  return card("Break-glass", [
    toggle("Allow audited, time-boxed overrides", () => b.enabled !== false, (on) => { b.enabled = on; }),
    toggle("Require an incident ticket", () => b.require_ticket !== false, (on) => { b.require_ticket = on; }),
    el("div", { cls: "form-grid" }, [num(b, "max_minutes", "Longest override (minutes)", 60),
      el("label", { cls: "field" }, ["Never relaxable", never])]),
  ]);
}

function clean(d) {
  const out = JSON.parse(JSON.stringify(d));
  for (const k of ["normalisation", "loops", "masking", "break_glass"]) if (out[k] && !Object.keys(out[k]).length) delete out[k];
  out.version = 2;
  return out;
}

function showErrors(errors) {
  $("save-errors").replaceChildren(el("b", { text: "Not saved:" }), errorList({ body: { errors } }));
}

async function preview() {
  try {
    const res = await postJSON("/api/admin/config/policy/validate", { doc: clean(doc) });
    if (res.errors.length) { showErrors(res.errors); return; }
    modal("Changes to policy.yaml", [diffView(res.diff)]);
  } catch (err) { toast(err.message, "bad"); }
}

async function save() {
  const out = clean(doc);
  try { const v = await postJSON("/api/admin/config/policy/validate", { doc: out }); if (v.errors.length) { showErrors(v.errors); return; } }
  catch (err) { toast(err.message, "bad"); return; }
  const reason = await askReason("Save the security settings");
  if (!reason) return;
  try {
    const res = await postJSON("/api/admin/config/policy", { doc: out, expected_version: version, reason });
    toast(`Saved as version ${res.version}; the gateway applies it to the next request.`);
    await load();
    renderNav();
  } catch (err) {
    if (err.status === 409) toast("Someone else saved the policy meanwhile. Reload the page.", "bad");
    else if (err.body && err.body.errors && err.body.errors.length) showErrors(err.body.errors);
    else toast(err.message, "bad");
  }
}

function render() {
  $("main").replaceChildren(
    el("div", { cls: "page-head" }, [el("div", {}, [el("h1", { text: "Security" }),
      el("p", { text: "Changes apply to the next request, no restart." })]), chip(`version ${version}`)]),
    el("div", { cls: "grid" }, [injectionCard(), dataCard(), agentsCard(), breakGlassCard()]),
    el("div", { cls: "card save-bar" }, [el("div", { attrs: { id: "save-errors" } }),
      el("div", { cls: "row" }, [el("span", { attrs: { id: "save-state" }, cls: "muted", text: "No unsaved changes" }), el("span", { cls: "spacer" }),
        el("button", { text: "Show YAML diff", on: { click: preview } }),
        el("button", { cls: "primary", text: "Save…", on: { click: save } })])]),
  );
}

async function load() {
  const [cfg, p] = await Promise.all([getJSON("/api/admin/config/policy"), getJSON("/api/admin/packs")]);
  doc = cfg.doc; version = cfg.version; packLabels = p.labels || {};
  render();
}

renderNav().then(load).catch((err) => $("main").replaceChildren(errorList(err)));

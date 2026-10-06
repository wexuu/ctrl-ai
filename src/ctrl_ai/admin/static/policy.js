// Policy and rules page: the security team runs the gateway's policy from the browser.
// The whole file is edited in memory and saved at once, with a reason and a diff preview.
import { $, el, getJSON, postJSON, card, table, drawer, modal, askReason, toast, chip, errorList, diffView } from "/static/lib.js";
import { renderNav } from "/static/nav.js";

let doc = null, version = null, packs = {}, teams = [], sigs = { signatures: [] };
let teamsDoc = null, teamsVersion = null, teamsDirty = false, lastSaved = null;

function profiles() {
  if (!doc.profiles || !Object.keys(doc.profiles).length) {
    doc.profiles = {
      observe: { mode: "monitor", semantic_action: "observe", on_semantic_unavailable: "allow", description: "Records everything, refuses nothing." },
      balanced: { mode: "enforce", semantic_action: "flag", on_semantic_unavailable: "allow", description: "Blocks rule matches; flags semantic attacks." },
      strict: { mode: "enforce", semantic_action: "block", on_semantic_unavailable: "flag", description: "Blocks rule matches and semantic attacks." },
    };
  }
  return doc.profiles;
}

function rules() { if (!Array.isArray(doc.rules)) doc.rules = []; return doc.rules; }
function packRuleIds() { return Object.values(packs).flat(); }
function isOverride(r) { return packRuleIds().includes(r.id); }
function customRules() { return rules().filter((r) => !isOverride(r)); }
function teamsUsing(name) { return teams.filter((t) => t.profile === name).map((t) => t.id); }

function dirty() {
  const s = $("save-state");
  if (s) { s.textContent = "Unsaved changes"; s.className = "warnline"; }
}

// ---------------------------------------------------------------- 1. mode and profiles

function profileSentence(p) {
  if (p.mode === "monitor") return "Records everything, refuses nothing.";
  const hit = p.semantic_action === "block" ? "blocks" : p.semantic_action === "flag" ? "flags" : "only records";
  const down = p.on_semantic_unavailable === "block" ? "refuses" : p.on_semantic_unavailable === "flag" ? "lets through flagged" : "lets through";
  return `Blocks rule matches, ${hit} attacks Jev or the judge confirm, ${down} requests when both are down.`;
}

function modeSeg(current, onPick) {
  return el("div", { cls: "seg", attrs: { role: "group" } }, [["enforce", "Enforce"], ["monitor", "Monitor only"]].map(([m, label]) =>
    el("button", { cls: current === m ? "on" : "", text: label, type: "button", on: { click: () => onPick(m) } })));
}

function modeCard() {
  const profs = profiles();
  const profileSel = (value, onPick) => {
    const s = el("select", { attrs: { "aria-label": "Profile" }, on: { change: (e) => onPick(e.target.value) } },
      Object.keys(profs).map((p) => el("option", { value: p, text: p })));
    s.value = value;
    return s;
  };
  const depName = (id) => ((teamsDoc.departments || []).find((d) => d.id === id) || {}).name || id;
  const rows = (teamsDoc.teams || []).map((t) => el("tr", {}, [
    el("td", {}, [el("b", { text: t.name }), el("div", { cls: "muted", text: depName(t.department) })]),
    el("td", {}, [modeSeg(t.mode || doc.mode, (m) => { t.mode = m; teamsDirty = true; dirty(); render(true); })]),
    el("td", {}, [profileSel(t.profile || doc.default_profile, (v) => { t.profile = v; teamsDirty = true; dirty(); render(true); })]),
  ]));
  rows.push(el("tr", { cls: "dim" }, [
    el("td", {}, [el("b", { text: "Everyone else" }), el("div", { cls: "muted", text: "callers without a team" })]),
    el("td", {}, [modeSeg(doc.mode, (m) => { doc.mode = m; dirty(); render(true); })]),
    el("td", {}, [profileSel(doc.default_profile, (v) => { doc.default_profile = v; dirty(); render(true); })]),
  ]));
  return card("Mode and profile per team", [el("div", { cls: "table-wrap" }, [el("table", { cls: "data" }, [
    el("thead", {}, [el("tr", {}, [el("th", { text: "Team" }), el("th", { text: "Mode" }), el("th", { text: "Profile" })])]),
    el("tbody", {}, rows)])])]);
}

const PROFILE_KIND = { observe: "warn", balanced: "info", strict: "bad" };

function profilesCard() {
  const profs = profiles();
  if (!doc.default_profile || !profs[doc.default_profile]) doc.default_profile = profs.balanced ? "balanced" : Object.keys(profs)[0];
  const tiles = Object.entries(profs).map(([name, p]) => {
    const used = teamsUsing(name);
    return el("div", { cls: `profile-tile ${PROFILE_KIND[name] || ""}` }, [
      el("div", { cls: "row" }, [el("b", { cls: "profile-name", text: name }), name === doc.default_profile ? chip("default") : null, el("span", { cls: "spacer" }),
        el("button", { cls: "small", text: "Edit", on: { click: () => editProfile(name) } }),
        el("button", { cls: "small danger", text: "Delete", attrs: { disabled: used.length > 0 || name === doc.default_profile, title: used.length ? `Used by ${used.join(", ")}` : name === doc.default_profile ? "This is the default profile" : "Delete" },
          on: { click: () => { delete doc.profiles[name]; dirty(); render(true); } } })]),
      el("p", { cls: "profile-what", text: profileSentence(p) }),
      el("div", { cls: "row" }, used.length ? used.map((t) => chip(t)) : [el("span", { cls: "muted", text: "no teams" })]),
    ]);
  });
  return card("Team profiles", [el("div", { cls: "profile-grid" }, tiles)],
    { actions: [el("button", { text: "Add profile", on: { click: () => editProfile(null) } })] });
}

function editProfile(name) {
  const p = name ? doc.profiles[name] : { mode: "enforce", semantic_action: "flag", on_semantic_unavailable: "allow" };
  drawer(name ? `Profile ${name}` : "New profile", [
    ...(name ? [] : [{ name: "name", label: "Name", value: "", hint: "lower case, for example finance-strict" }]),
    { name: "mode", label: "Mode", type: "select", options: ["enforce", "monitor"], value: p.mode, hint: "enforce refuses; monitor only records would_block" },
    { name: "semantic_action", label: "High semantic score", type: "select", options: ["observe", "flag", "block"], value: p.semantic_action || "observe", hint: "what a Jev or judge score at or above the block threshold does" },
    { name: "on_semantic_unavailable", label: "When the semantic check is unavailable", type: "select", options: ["allow", "flag", "block"], value: p.on_semantic_unavailable || "allow", hint: "neither Jev nor the judge answered" },
    { name: "description", label: "Description", type: "textarea", value: p.description || "" },
  ], (v) => {
    const key = name || (v.name || "").trim();
    if (!/^[a-z0-9][a-z0-9_-]*$/.test(key)) throw new Error("Name: lower-case letters, digits and dashes");
    if (!name && doc.profiles[key]) throw new Error("A profile with this name exists");
    doc.profiles[key] = { mode: v.mode, semantic_action: v.semantic_action, on_semantic_unavailable: v.on_semantic_unavailable };
    if (v.description) doc.profiles[key].description = v.description;
    dirty(); render(true);
  });
}

// ---------------------------------------------------------------- 3. custom rules

function rulesCard() {
  const list = rules();
  const custom = customRules();
  const move = (r, d) => {
    const c = customRules();
    const k = c.indexOf(r) + d;
    if (k < 0 || k >= c.length) return;
    const i = list.indexOf(r), j = list.indexOf(c[k]);
    [list[i], list[j]] = [list[j], list[i]];
    dirty(); render(true);
  };
  const t = table([
    { key: "order", label: "#", sortable: false, render: (r) => String(custom.indexOf(r) + 1) },
    { key: "id", label: "Id", sortable: false, render: (r) => el("code", { text: r.id }) },
    { key: "type", label: "Type", sortable: false },
    { key: "value", label: "Value", sortable: false, render: (r) => el("code", { text: r.value.length > 48 ? r.value.slice(0, 48) + "…" : r.value }) },
    { key: "action", label: "Action", sortable: false, render: (r) => chip(r.action || "block", (r.action || "block") === "block" ? "bad" : "warn") },
    { key: "sources", label: "Sources", sortable: false, render: (r) => (r.sources || ["prompt", "tool_result"]).join(", ") },
    { key: "severity", label: "Severity", sortable: false, render: (r) => r.severity || "–" },
    { key: "enabled", label: "Enabled", sortable: false, render: (r) => (r.enabled === false ? chip("off") : chip("on", "ok")) },
    { key: "x", label: "", sortable: false, render: (r) => el("div", { cls: "row" }, [
      el("button", { cls: "small", text: "↑", title: "Move up (order matters: the first blocking rule is reported)", on: { click: () => move(r, -1) } }),
      el("button", { cls: "small", text: "↓", title: "Move down", on: { click: () => move(r, 1) } }),
      el("button", { cls: "small", text: "Edit", on: { click: () => editRule(r) } }),
      el("button", { cls: "small", text: r.enabled === false ? "Enable" : "Disable", on: { click: () => { r.enabled = r.enabled === false; dirty(); render(true); } } }),
      el("button", { cls: "small danger", text: "Delete", on: { click: () => { list.splice(list.indexOf(r), 1); dirty(); render(true); } } }),
    ]) },
  ], custom, { empty: "No custom rules." });
  return card("Custom rules", [el("p", { cls: "note", text: "Tried from top to bottom. Every match is recorded; the first blocking rule is the one the developer is told about." }), t, testerBox()],
    { actions: [el("button", { text: "Add rule", on: { click: () => editRule(null) } })] });
}

function editRule(rule) {
  const r = rule || { id: "", type: "contains", value: "", action: "block", sources: ["prompt", "tool_result"], severity: "medium", enabled: true };
  drawer(rule ? `Rule ${rule.id}` : "New rule", [
    { name: "id", label: "Id", value: r.id, hint: "lower case, digits and dashes; shown in the refusal and the audit log" },
    { name: "type", label: "Type", type: "select", options: [["contains", "contains (exact text, case-sensitive)"], ["regex", "regex (Python regular expression)"]], value: r.type },
    { name: "value", label: "Value", type: "textarea", value: r.value, hint: "regular expressions are checked for catastrophic backtracking when saved" },
    { name: "action", label: "Action", type: "select", options: ["block", "flag"], value: r.action || "block" },
    { name: "sources", label: "Applies to", type: "multi", options: [["prompt", "prompt"], ["tool_result", "tool results"], ["tool_call", "tool calls (MCP arguments)"]], value: r.sources || ["prompt", "tool_result"] },
    { name: "severity", label: "Severity", type: "select", options: ["low", "medium", "high", "critical"], value: r.severity || "medium" },
    { name: "enabled", label: "Enabled", type: "checkbox", value: r.enabled !== false },
    { name: "description", label: "Description", type: "textarea", value: r.description || "" },
  ], (v) => {
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(v.id)) throw new Error("Id: lower-case letters, digits and dashes, up to 64 characters");
    if (!v.value) throw new Error("Value is empty");
    if (rules().some((x) => x.id === v.id && x !== rule)) throw new Error("A rule with this id exists");
    const entry = { id: v.id, type: v.type, value: v.value, action: v.action, severity: v.severity, enabled: v.enabled };
    if (v.sources.length) entry.sources = v.sources;
    if (v.description) entry.description = v.description;
    if (rule) rules()[rules().indexOf(rule)] = entry; else rules().push(entry);
    dirty(); render(true);
  });
}

function testerBox() {
  const type = el("select", { attrs: { "aria-label": "Rule type" } }, [el("option", { value: "contains", text: "contains" }), el("option", { value: "regex", text: "regex" })]);
  const value = el("input", { attrs: { placeholder: "rule value", size: 30, "aria-label": "Rule value" } });
  const sample = el("textarea", { attrs: { rows: 3, placeholder: "Paste sample text. It is checked on the server and never stored or logged.", "aria-label": "Sample text" } });
  const out = el("div");
  const run = async () => {
    out.replaceChildren();
    try {
      const res = await postJSON("/api/admin/policy/test-rule", { type: type.value, value: value.value, sample: sample.value });
      const text = sample.value;
      const frag = el("div", { cls: "secret" });
      let pos = 0;
      for (const [a, b] of res.spans) {
        frag.appendChild(document.createTextNode(text.slice(pos, a)));
        frag.appendChild(el("mark", { text: text.slice(a, b) }));
        pos = b;
      }
      frag.appendChild(document.createTextNode(text.slice(pos)));
      out.replaceChildren(el("b", { cls: res.matched ? "warnline" : "", text: res.matched ? `Matches (${res.spans.length})` : "No match" }), frag);
    } catch (err) { out.replaceChildren(errorList(err)); }
  };
  return el("details", { cls: "tester" }, [el("summary", { text: "Test this rule" }),
    el("div", { cls: "row" }, [type, value, el("button", { text: "Test", on: { click: run } })]), sample, out]);
}

// ---------------------------------------------------------------- 5. semantic checks

function semanticCard() {
  doc.jev = doc.jev || {};
  doc.judge = doc.judge || {};
  const jev = doc.jev, judge = doc.judge;
  if (jev.accept_below === undefined) jev.accept_below = jev.review_threshold ?? 0.35;
  if (judge.reject_from === undefined) judge.reject_from = 0.5;
  const bar = el("div", { cls: "bands" });
  const draw = () => {
    const a = jev.accept_below;
    const seg = (cls, text, flex) => { const x = el("span", { cls: `band ${cls}`, text }); x.style.flex = String(Math.max(0.06, flex)); return x; };
    bar.replaceChildren(seg("green", `Jev accepts → allowed (below ${a.toFixed(2)})`, a),
      seg("red", judge.enabled === false ? `Jev rejects → team profile decides` : `Jev rejects → AI judge decides`, 1 - a));
  };
  const slider = (obj, key, label, after) => {
    const out = el("output", { text: obj[key].toFixed(2) });
    const input = el("input", { type: "range", attrs: { min: 0, max: 1, step: 0.01, "aria-label": label }, value: obj[key], on: { input: (e) => {
      obj[key] = Number(e.target.value); out.textContent = obj[key].toFixed(2); dirty(); if (after) after();
    } } });
    return el("label", { cls: "field" }, [label, el("div", { cls: "row" }, [input, out])]);
  };
  draw();
  return card("Semantic check", [
    bar,
    el("div", { cls: "form-grid" }, [slider(jev, "accept_below", "Jev accepts below", draw), slider(judge, "reject_from", "AI judge rejects from")]),
    el("div", { cls: "row" }, [boolField(jev, "enabled", "Jev on", true), boolField(judge, "enabled", "AI judge on", true, draw)]),
    el("label", { cls: "field" }, ["Message when the AI judge blocks",
      el("textarea", { attrs: { rows: 3, maxlength: 1000, placeholder: "Blocked by ctrl-ai: semantic check (judge) scored {score}. …", "aria-label": "Message when the AI judge blocks" },
        value: judge.block_message || "", on: { input: (e) => {
          if (e.target.value.trim()) judge.block_message = e.target.value; else delete judge.block_message;
          dirty();
        } } }),
      el("span", { cls: "hint", text: "What the agent (Claude Code, Codex) receives. Placeholders: {score}, {category}, {reason} (the judge's own words), {model}. Empty: the standard message." })]),
  ]);
}

function boolField(obj, key, label, def, after) {
  return el("label", { cls: "check" }, [el("input", { type: "checkbox", attrs: { checked: obj[key] === undefined ? def : !!obj[key] }, on: { change: (e) => { obj[key] = e.target.checked; dirty(); if (after) after(); } } }), ` ${label}`]);
}

function numField(obj, key, label, hint, def, min = 1) {
  const input = el("input", { type: "number", attrs: { min, placeholder: String(def), "aria-label": label }, value: obj[key] ?? "", on: { change: (e) => {
    if (e.target.value === "") delete obj[key]; else obj[key] = Number(e.target.value);
    dirty();
  } } });
  return el("label", { cls: "field" }, [label, input, el("span", { cls: "hint", text: `${hint} Default ${def}.` })]);
}

// ---------------------------------------------------------------- save

function clean(d) {
  const out = JSON.parse(JSON.stringify(d));
  for (const k of ["jev", "judge", "normalisation", "loops", "masking", "break_glass"]) if (out[k] && !Object.keys(out[k]).length) delete out[k];
  if (out.masking && out.masking.routes && !Object.keys(out.masking.routes).length) delete out.masking.routes;
  if (out.masking && !Object.keys(out.masking).length) delete out.masking;
  const v2 = ["profiles", "default_profile", "rule_packs", "judge", "normalisation", "loops", "masking", "break_glass"].some((k) => k in out)
    || (out.jev && ("review_threshold" in out.jev || "sources" in out.jev));
  if (v2) out.version = 2;
  return out;
}

function showErrors(errors) {
  const box = $("save-errors");
  box.replaceChildren(el("b", { text: "The policy was not saved:" }), errorList({ body: { errors } }));
  box.scrollIntoView({ behavior: "smooth", block: "center" });
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
  try {
    const v = await postJSON("/api/admin/config/policy/validate", { doc: out });
    if (v.errors.length) { showErrors(v.errors); return; }
  } catch (err) { toast(err.message, "bad"); return; }
  const reason = await askReason("Save the policy");
  if (!reason) return;
  try {
    let res = { version };
    if (JSON.stringify(out) !== JSON.stringify(clean(lastSaved))) res = await postJSON("/api/admin/config/policy", { doc: out, expected_version: version, reason });
    if (teamsDirty) {
      const tv = await postJSON("/api/admin/config/teams/validate", { doc: teamsDoc });
      if (tv.errors.length) { showErrors(tv.errors); return; }
      await postJSON("/api/admin/config/teams", { doc: teamsDoc, expected_version: teamsVersion, reason });
    }
    await load();
    $("save-state").textContent = `Saved as version ${res.version}; the gateway applies it to the next request.`;
    $("save-state").className = "ok-text";
    toast(`Saved as version ${res.version}; the gateway applies it to the next request.`);
    renderNav();
  } catch (err) {
    if (err.status === 409) toast("Someone else saved the policy meanwhile. Reload the page to see their version.", "bad");
    else if (err.body && err.body.errors && err.body.errors.length) showErrors(err.body.errors);
    else toast(err.message, "bad");
  }
}

let scrollY = 0;
function render(keepScroll = false) {
  if (keepScroll) scrollY = window.scrollY;
  const state = $("save-state");
  const prevState = state ? [state.textContent, state.className] : ["No unsaved changes", "muted"];
  $("main").replaceChildren(
    el("div", { cls: "page-head" }, [el("div", {}, [el("h1", { text: "Policy" }),
      el("p", { text: "Changes apply to the next request, no restart." })]),
      el("div", { cls: "row" }, [chip(`version ${version}`)])]),
    modeCard(), profilesCard(), semanticCard(), rulesCard(),
    el("div", { cls: "card save-bar", attrs: { id: "save-bar" } }, [el("div", { attrs: { id: "save-errors" } }),
      el("div", { cls: "row" }, [el("span", { attrs: { id: "save-state" }, cls: prevState[1], text: prevState[0] }), el("span", { cls: "spacer" }),
        el("button", { text: "Show YAML diff", on: { click: preview } }),
        el("button", { cls: "primary", text: "Save policy…", on: { click: save } })])]),
  );
  if (keepScroll) window.scrollTo(0, scrollY);
}

async function load() {
  const [cfg, p, t, s] = await Promise.all([getJSON("/api/admin/config/policy"), getJSON("/api/admin/packs"),
    getJSON("/api/admin/config/teams"), getJSON("/api/admin/signatures")]);
  doc = cfg.doc; version = cfg.version; lastSaved = JSON.parse(JSON.stringify(cfg.doc)); packs = p.packs; teamsDoc = t.doc; teamsVersion = t.version; teams = t.doc.teams || []; sigs = s; teamsDirty = false;
  render();
}

renderNav().then(load).catch((err) => $("main").replaceChildren(errorList(err)));

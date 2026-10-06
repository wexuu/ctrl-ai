// Models page: the organisation's allow list and ban list. One click moves a model between them.
// The rest of each model's governance (teams, data class, prices, fallbacks) stays in
// config/models.yaml and is kept as it is when a model is moved.
import { $, el, getJSON, postJSON, card, askReason, toast, chip, errorList, fmt } from "/static/lib.js";
import { renderNav } from "/static/nav.js";

let doc = null, version = null, usage = {}, gatewayModels = [];

const PROVIDERS = [["claude-", "anthropic"], ["chat-groq", "groq"], ["chat-mistral", "mistral"]];
const providerOf = (id) => (PROVIDERS.find(([p]) => id.startsWith(p)) || [null, "other"])[1];
const isBanned = (m) => m.status === "banned";

async function saveDoc(title) {
  try {
    const v = await postJSON("/api/admin/config/models/validate", { doc });
    if (v.errors && v.errors.length) { toast(v.errors.map((e) => e.message || e).join("; "), "bad"); await load(); return; }
  } catch (err) { toast(err.message, "bad"); await load(); return; }
  const reason = await askReason(title);
  if (!reason) { await load(); return; }
  try {
    const res = await postJSON("/api/admin/config/models", { doc, expected_version: version, reason });
    toast(`Saved as version ${res.version}; the gateway applies it to the next request.`);
  } catch (err) { toast(err.message, "bad"); }
  await load();
}

function setStatus(m, banned) {
  if (banned) m.status = "banned";
  else m.status = m.price || m.id.endsWith("*") ? "approved" : "trial";
  saveDoc(banned ? `Ban ${m.display_name || m.id}` : `Allow ${m.display_name || m.id}`);
}

function usageNote(m) {
  const u = usage[m.id];
  if (!u) return el("span", { cls: "muted", text: "no traffic in 7 days" });
  const parts = [`${fmt.int(u.requests)} requests`, fmt.usd(u.cost_usd)];
  if (u.denied_attempts) parts.push(`${u.denied_attempts} blocked attempts`);
  return el("span", { cls: "muted", text: parts.join(" · ") });
}

function item(m, banned) {
  return el("li", {}, [
    el("div", {}, [el("b", { text: m.display_name || m.id }), " ", el("code", { text: m.id }), el("br"), usageNote(m)]),
    el("span", { cls: "spacer" }),
    !banned && m.status !== "approved" ? chip(m.status, m.status === "deprecated" ? "warn" : "info") : null,
    el("button", { cls: banned ? "small" : "small danger", text: banned ? "Allow" : "Ban", on: { click: () => setStatus(m, !banned) } }),
  ]);
}

function addBox() {
  const list = el("datalist", { attrs: { id: "gw-models" } }, gatewayModels.map((g) => el("option", { value: g })));
  const input = el("input", { attrs: { list: "gw-models", placeholder: "model id, e.g. chat-groq", "aria-label": "Model id" } });
  const add = () => {
    const id = input.value.trim();
    if (!id) return;
    if ((doc.models || []).some((m) => m.id === id)) { toast("That model is already listed.", "bad"); return; }
    doc.models.push({ id, provider: providerOf(id), status: "trial", data_class_max: "internal", teams: ["*"] });
    saveDoc(`Allow ${id}`);
  };
  return el("div", { cls: "row" }, [list, input, el("button", { text: "Add to allow list", on: { click: add } })]);
}

function render() {
  const models = doc.models || [];
  const allowed = models.filter((m) => !isBanned(m));
  const banned = models.filter(isBanned);
  $("main").replaceChildren(
    el("div", { cls: "page-head" }, [el("div", {}, [el("h1", { text: "Models" }),
      el("p", { text: "The organisation decides which AI models may be used. A request for a banned or unlisted model is rerouted to an allowed one, or refused." })]),
      el("div", { cls: "row" }, [chip(`version ${version}`)])]),
    el("div", { cls: "lists-2" }, [
      card(`Allowed (${allowed.length})`, [el("ul", { cls: "model-list" }, allowed.map((m) => item(m, false))), addBox()]),
      card(`Banned (${banned.length})`, [banned.length ? el("ul", { cls: "model-list" }, banned.map((m) => item(m, true)))
        : el("p", { cls: "muted", text: "No banned models. Use Ban on the left." })]),
    ]),
  );
}

async function load() {
  const cfg = await getJSON("/api/admin/config/models");
  doc = cfg.doc; version = cfg.version;
  if (!Array.isArray(doc.models)) doc.models = [];
  try { usage = (await getJSON("/api/dash/model-usage?days=7")).models || {}; } catch { usage = {}; }
  render();
  if (!gatewayModels.length) getJSON("/api/admin/gateway-models").then((g) => { gatewayModels = g.models || []; render(); }).catch(() => {});
}

renderNav().then(load).catch((err) => $("main").replaceChildren(errorList(err)));

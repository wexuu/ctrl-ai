// Top navigation bar shared by every page: links, policy mode and version, the active
// break-glass chip and the acting admin. On admin and dashboard pages it also shows the open-access
// banner (no sign-in; single sign-on in production). Fills <header id="nav">.
"use strict";

import { el, getJSON, session, chip } from "/static/lib.js";

const LINKS = [
  ["/dashboard", "Dashboard"], ["/audit", "Audit log"], ["/jev-trust", "Jev trust"], ["/admin/policy", "Policy"], ["/admin/security", "Security"], ["/admin/models", "Models"],
  ["/admin/teams", "Cost governance"], ["/admin/tools", "MCP gateway"], ["/admin/history", "Change log"],
];

function hhmm(iso) {
  const d = new Date(iso);
  return isNaN(d) ? "–" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

// Red bar on every page while Jev and the judge are both unavailable (automatic or manual switch).
function renderOutageBanner(host, o) {
  let bar = document.getElementById("outage-banner");
  if (!o || !o.active) { if (bar) bar.remove(); return; }
  if (!bar) { bar = el("div", { cls: "outage-banner", attrs: { id: "outage-banner", role: "alert" } }); host.after(bar); }
  const parts = [el("b", { text: `Semantic checks unavailable since ${hhmm(o.since)} (Jev and judge). ` }),
    "Deterministic controls only: rules, personal data, secrets, masking, budgets. ",
    el("b", { text: `Mode: ${o.mode || "degrade"}.` })];
  if (o.manual) {
    const left = new Date(o.manual.expires_at).getTime() - Date.now();
    const mins = Math.max(0, Math.round(left / 60000));
    parts.push(` Manual switch by ${o.manual.by || "?"}, ticket ${o.manual.ticket || "–"}, ends in ${mins} min. `);
    parts.push(el("a", { href: "/dashboard?tab=operations", text: "Review" }));
  }
  bar.replaceChildren(...parts);
}

export async function renderNav() {
  const host = document.getElementById("nav");
  if (!host) return null;
  const links = el("nav", { cls: "nav-links", attrs: { "aria-label": "Main" } }, LINKS.map(([href, label]) => {
    const a = el("a", { href, text: label });
    const here = href === "/" ? location.pathname === "/" : location.pathname.startsWith(href);
    if (here) a.setAttribute("aria-current", "page");
    return a;
  }));
  const status = el("div", { cls: "nav-status" });
  host.replaceChildren(el("a", { cls: "brand", href: "/dashboard" }, [el("span", { cls: "brand-mark", text: "◆" }), " ctrl-ai"]), links, status);
  let s = {};
  try { s = await session(); } catch { /* the chat page works without the admin API */ }
  if (location.pathname !== "/" && s.banner && !document.getElementById("access-banner")) {
    host.after(el("div", { cls: "access-banner", attrs: { id: "access-banner", role: "note" }, text: s.banner }));
  }
  try {
    const n = await getJSON("/api/nav");
    const items = [];
    if (n.policy_mode) items.push(chip(`${n.policy_mode} · ${n.policy_version}`, n.policy_mode === "enforce" ? "bad" : "warn"));
    if (n.break_glass_active) {
      const c = chip(`break-glass active: ${n.break_glass_active}`, "bad solid");
      c.title = "A break-glass override is active (issued by security on-call).";
      items.push(c);
    }
    renderOutageBanner(host, n.outage);
    if (n.user) items.push(el("span", { cls: "nav-user", title: "Open access: no sign-in", text: n.user }));
    status.replaceChildren(...items);
  } catch { /* the bar stays without status */ }
  return s;
}

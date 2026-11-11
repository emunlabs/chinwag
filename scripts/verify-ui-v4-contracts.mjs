#!/usr/bin/env node
// Portable UI v4 static, CSS specificity/geometry, outbound-URL, and Node VM behavioral ratchet
// Runs identically on Ubuntu 24.04 GitHub Actions runners and macOS workstations (zero npm deps).

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const uiDir = path.join(repoRoot, "crates/chinwag-cli/assets/ui-v4");
const indexHtml = fs.readFileSync(path.join(uiDir, "index.html"), "utf8");
const stylesCss = fs.readFileSync(path.join(uiDir, "styles.css"), "utf8");
const appJs = fs.readFileSync(path.join(uiDir, "app.js"), "utf8");
const workbenchRs = fs.readFileSync(
  path.join(repoRoot, "crates/chinwag-cli/src/ui_workbench_run.rs"),
  "utf8",
);

// 1. Zero-jargon + zero-404 + strict https://chinwag.sh route allowlist across UI assets & Rust server constants
const forbiddenSubstrings = [
  "state." + "crdb",
  "cr" + "sqlite",
  "cr-" + "sqlite",
  "ed25" + "519",
  "x25" + "519",
  "bbs" + "+",
  "cp-" + "omp",
  "a." + "509",
  "gemini" + "-pm",
  "work" + "horse",
  "alis" + "tair",
  "eagle" + "-eye",
  "house" + "keeping",
  "infra" + "jr",
  "mac " + "studio",
  "prod_",
  "price_1",
];

function assertZeroCustomerJargon(surface, text) {
  const lower = text.toLowerCase();
  for (const pat of forbiddenSubstrings) {
    assert.equal(
      lower.includes(pat),
      false,
      `INV-TWO-LAYER-CUSTOMER-UI-01 violation on ${surface}: found '${pat}'`,
    );
  }
}

const allowedChinwagPaths = new Set(["", "/", "/pricing", "/open", "/security", "/privacy"]);
function assertVerifiedChinwagRoutes(surface, text) {
  for (const bad of ["/contact", "chinwag.sh/invite", "pricing.html"]) {
    assert.equal(
      text.includes(bad),
      false,
      `CHWG-0249 forbidden route '${bad}' detected in ${surface}`,
    );
  }
  const re = /https:\/\/chinwag\.sh([^\s"'`$()<>\\]*)/g;
  for (const m of text.matchAll(re)) {
    const rawTail = m[1] || "";
    const routePath = rawTail.split(/[?#]/)[0] || "";
    assert.equal(
      allowedChinwagPaths.has(routePath),
      true,
      `Unverified https://chinwag.sh route on ${surface}: https://chinwag.sh${rawTail}`,
    );
  }
}

for (const [name, content] of [
  ["index.html", indexHtml],
  ["styles.css", stylesCss],
  ["app.js", appJs],
]) {
  assertZeroCustomerJargon(name, content);
  assertVerifiedChinwagRoutes(name, content);
}

// Verify Rust server URLs & 4-pack SKU -> wizard slug parity
assert.equal(
  workbenchRs.includes('pub const CREDIT_PACKS_PRICING_URL: &str = "https://chinwag.sh/pricing";'),
  true,
  "ui_workbench_run.rs must set CREDIT_PACKS_PRICING_URL to https://chinwag.sh/pricing",
);
assert.equal(
  workbenchRs.includes('"ciso_review_url": "https://chinwag.sh/pricing?talk=1&source=local_ui#founders"'),
  true,
  "ui_workbench_run.rs must set ciso_review_url to founders wizard URL",
);
for (const [sku, slug] of [
  ["pack_50", "developer"],
  ["pack_160", "growth"],
  ["pack_560", "scale"],
  ["pack_1000", "volume"],
]) {
  assert.equal(
    workbenchRs.includes(`"${sku}" => "${slug}"`),
    true,
    `ui_workbench_run.rs missing ${sku} => ${slug} mapping`,
  );
}
assert.equal(
  workbenchRs.includes("https://chinwag.sh/pricing?pack={wizard_pack_slug}&source=local_ui&attempt={attempt_id}"),
  true,
  "ui_workbench_run.rs missing canonical checkout_url template",
);

// 2. CSS specificity & geometry contracts on styles.css
function extractCssRule(css, marker) {
  const idx = css.indexOf(marker);
  assert.notEqual(idx, -1, `styles.css missing selector marker '${marker}'`);
  const open = css.indexOf("{", idx);
  const close = css.indexOf("}", open + 1);
  assert.notEqual(open, -1);
  assert.notEqual(close, -1);
  return css.slice(open + 1, close);
}

const selectRule = extractCssRule(stylesCss, "}\n\n.select {");
for (const req of [
  "appearance: none;",
  "-webkit-appearance: none;",
  "padding: 0 36px 0 12px;",
  "right 12px center",
]) {
  assert.equal(selectRule.includes(req), true, `styles.css .select missing '${req}'`);
}
assert.equal(
  stylesCss.includes('[data-theme="dark"] .select'),
  true,
  "styles.css missing dark-theme .select chevron rule",
);
assert.equal(
  stylesCss.includes(
    '  .select,\n  [data-theme="dark"] .select {\n    appearance: auto;\n    -webkit-appearance: auto;\n    background-image: none;',
  ),
  true,
  'styles.css @media (forced-colors: active) must clear background-image on [data-theme="dark"] .select',
);

const pillFnRule = extractCssRule(stylesCss, "\n.pill-fn {");
for (const req of ["min-height: 22px;", "white-space: nowrap;", "flex-shrink: 0;"]) {
  assert.equal(pillFnRule.includes(req), true, `styles.css .pill-fn missing '${req}'`);
}
assert.equal(pillFnRule.includes("height: 20px"), false, "styles.css .pill-fn must not clamp height: 20px");

const btnSecondaryPos = stylesCss.indexOf("\n.btn-secondary {");
const desktopMenuHidePos = stylesCss.indexOf(
  ".app-header .menu-btn,\n.btn-secondary.menu-btn,\n.menu-btn {\n  display: none;",
);
const mobileMenuShowPos = stylesCss.indexOf("@media (max-width: 719.98px) {\n  .app-header .menu-btn,");
assert.equal(
  btnSecondaryPos !== -1 &&
    desktopMenuHidePos > btnSecondaryPos &&
    mobileMenuShowPos > desktopMenuHidePos,
  true,
  "styles.css desktop .menu-btn hide rule must follow .btn-secondary and precede mobile media override",
);

// 3. Live Node VM DOM & Behavioral Harness against app.js
class StubNode {
  constructor(tagName) {
    this.tagName = String(tagName || "DIV").toUpperCase();
    this.children = [];
    this.parentNode = null;
    this.attributes = new Map();
    this.dataset = {};
    this.listeners = new Map();
    this.className = "";
    this.id = "";
    this.hidden = false;
    this.checked = false;
    this.selected = false;
    this.value = "";
    this.onclick = null;
    this._text = "";
  }
  get firstChild() {
    return this.children.length > 0 ? this.children[0] : null;
  }
  get isConnected() {
    return true;
  }
  get textContent() {
    if (this.tagName === "__TEXT__") return this._text;
    return this.children.map((c) => c.textContent).join("");
  }
  set textContent(val) {
    this.children = [];
    if (this.tagName === "__TEXT__") {
      this._text = String(val ?? "");
    } else if (val !== null && val !== undefined && String(val) !== "") {
      const t = new StubNode("__TEXT__");
      t._text = String(val);
      this.appendChild(t);
    }
  }
  appendChild(child) {
    if (!child) return child;
    if (child.parentNode) child.parentNode.removeChild(child);
    child.parentNode = this;
    this.children.push(child);
    return child;
  }
  append(...nodes) {
    for (const n of nodes) {
      if (n === null || n === undefined) continue;
      if (n instanceof StubNode) {
        this.appendChild(n);
      } else {
        const t = new StubNode("__TEXT__");
        t._text = String(n);
        this.appendChild(t);
      }
    }
  }
  removeChild(child) {
    const idx = this.children.indexOf(child);
    if (idx !== -1) {
      this.children.splice(idx, 1);
      child.parentNode = null;
    }
    return child;
  }
  setAttribute(k, v) {
    const sv = String(v);
    if (k === "id") this.id = sv;
    if (k === "class") this.className = sv;
    this.attributes.set(k, sv);
  }
  getAttribute(k) {
    if (k === "id" && this.id) return this.id;
    if (k === "class" && this.className) return this.className;
    return this.attributes.has(k) ? this.attributes.get(k) : null;
  }
  removeAttribute(k) {
    this.attributes.delete(k);
  }
  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }
  click() {
    const ev = {
      type: "click",
      target: this,
      preventDefault() {},
      stopPropagation() {},
    };
    if (typeof this.onclick === "function") this.onclick(ev);
    for (const fn of this.listeners.get("click") || []) fn(ev);
  }
  focus() {
    stubDocument.activeElement = this;
  }
  matchesSimple(sel) {
    if (this.tagName === "__TEXT__") return false;
    const s = sel.trim();
    if (s === '.popover[data-state="closing"]') {
      return this.className.split(/\s+/).includes("popover") && this.dataset.state === "closing";
    }
    if (s.startsWith(".")) return this.className.split(/\s+/).includes(s.slice(1));
    if (s === "[href]") return this.attributes.has("href");
    if (s === "button.btn-primary") {
      return this.tagName === "BUTTON" && this.className.split(/\s+/).includes("btn-primary");
    }
    return this.tagName === s.toUpperCase();
  }
  querySelectorAll(selector) {
    const parts = selector.split(",").map((p) => p.trim()).filter(Boolean);
    const results = [];
    const visit = (node) => {
      for (const child of node.children) {
        if (parts.some((p) => child.matchesSimple(p))) results.push(child);
        visit(child);
      }
    };
    visit(this);
    return results;
  }
  querySelector(selector) {
    const all = this.querySelectorAll(selector);
    return all.length > 0 ? all[0] : null;
  }
}

const byId = new Map();
function mountEl(tag, id, hidden = false) {
  const n = new StubNode(tag);
  n.id = id;
  n.hidden = hidden;
  byId.set(id, n);
  return n;
}

const docEl = new StubNode("html");
docEl.setAttribute("data-theme", "stone");
const btnPrivacy = mountEl("button", "btn-privacy");
const btnMobileMenu = mountEl("button", "btn-mobile-menu");
const btnInvite = mountEl("button", "btn-invite");
btnInvite._computedDisplay = "none";
const popoverLayer = mountEl("div", "popover-layer", true);
mountEl("div", "modal-scrim", true);
const modalLayer = mountEl("div", "modal-layer", true);
mountEl("div", "toast-region", false);
mountEl("div", "sr-announcer", false);

const stubDocument = {
  readyState: "loading",
  hidden: false,
  title: "",
  activeElement: null,
  documentElement: docEl,
  createElement: (tag) => new StubNode(tag),
  createElementNS: (_ns, tag) => new StubNode(tag),
  createTextNode: (txt) => {
    const t = new StubNode("__TEXT__");
    t._text = String(txt ?? "");
    return t;
  },
  getElementById: (id) => byId.get(id) || null,
  querySelector: () => null,
  querySelectorAll: () => [],
  addEventListener() {},
};

const stubWindow = {
  location: { hash: "#inbox" },
  addEventListener() {},
  setInterval: () => 1,
  getComputedStyle: (el) => ({
    display: el && el._computedDisplay ? el._computedDisplay : "inline-flex",
  }),
};

const transformedSrc = appJs
  .replace(
    /^import\s+\*\s+as\s+Motion\s+from\s+"\.\/motion\.js";/m,
    `const Motion = new Proxy({
      settled: () => new Promise((r) => setTimeout(r, 25)),
      guardAction: async (_btn, fn) => ({ value: await fn(), release: () => {} }),
      createToaster: () => ({ show() {}, dismiss() {} }),
      createElapsedClock: () => ({ bind() {}, destroy() {} }),
      bindIndicator: () => ({ update() {}, destroy() {} }),
      observeLoop: () => {},
      switchTheme: (next) => stubDocument.documentElement.setAttribute("data-theme", next),
    }, { get(t, k) { return k in t ? t[k] : () => ({ update() {}, destroy() {}, show() {}, dismiss() {} }); } });`,
  )
  .replace(/^export\s+/gm, "");

let mockWorkflowHandler = async (body) => ({ ok: true, workflow: body });
const sandbox = {
  console,
  setTimeout,
  clearTimeout,
  requestAnimationFrame: (fn) => setTimeout(fn, 0),
  Date,
  Math,
  JSON,
  Number,
  String,
  Boolean,
  Array,
  Object,
  Set,
  Map,
  Promise,
  Error,
  RegExp,
  encodeURIComponent,
  decodeURIComponent,
  Node: StubNode,
  stubDocument,
  document: stubDocument,
  window: stubWindow,
  localStorage: {
    _m: new Map(),
    getItem(k) {
      return this._m.has(k) ? this._m.get(k) : null;
    },
    setItem(k, v) {
      this._m.set(k, String(v));
    },
    removeItem(k) {
      this._m.delete(k);
    },
  },
  SERVER_PORT: 5487,
  CSRF_TOKEN: "test-csrf",
  fetch: async (url, opts = {}) => {
    const body = opts.body ? JSON.parse(opts.body) : {};
    if (url === "/api/v4/workflow") {
      try {
        const res = await mockWorkflowHandler(body);
        return { ok: true, status: 200, json: async () => res };
      } catch (err) {
        return { ok: false, status: 500, json: async () => ({ ok: false, error: err.message }) };
      }
    }
    return { ok: true, status: 202, json: async () => ({ ok: true, telemetry_enabled: true }) };
  },
};

vm.createContext(sandbox);
vm.runInContext(
  `${transformedSrc}\nglobalThis.__test = { state, normalizeBootstrap, saveWorkflowSettings, openPrivacyPopover, openMobileMenuPopover, openInviteModal, closePopover, closeModal, wizardPackSlugForSku };`,
  sandbox,
);

const T = sandbox.__test;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

btnPrivacy.addEventListener("click", () => T.openPrivacyPopover(btnPrivacy));
btnMobileMenu.addEventListener("click", () => T.openMobileMenuPopover(btnMobileMenu));

// Suite A: Direct #btn-privacy click + security/founders links + stale close timer guard
btnPrivacy.click();
assert.equal(popoverLayer.hidden, false);
assert.equal(popoverLayer.querySelector("h2").textContent, "Local privacy");
assert.deepEqual(
  popoverLayer.querySelectorAll("a").map((a) => a.getAttribute("href")),
  ["https://chinwag.sh/security", "https://chinwag.sh/pricing?talk=1&source=local_ui#founders"],
);
const staleClose = T.closePopover();
await sleep(5);
btnPrivacy.click();
await staleClose;
await sleep(35);
assert.equal(popoverLayer.hidden, false);
assert.equal(popoverLayer.querySelector("h2").textContent, "Local privacy");

// Suite B: Repeated closePopover() 5ms apart restores focus to #btn-privacy
stubDocument.activeElement = null;
await Promise.all([T.closePopover(), sleep(5).then(() => T.closePopover())]);
assert.equal(popoverLayer.hidden, true);
assert.equal(stubDocument.activeElement, btnPrivacy);

// Suite C: Mobile Menu -> Local privacy & analytics handoff
btnMobileMenu.click();
const menuPrivacyBtn = popoverLayer
  .querySelectorAll("button")
  .find((b) => b.textContent.includes("Local privacy & analytics"));
assert.ok(menuPrivacyBtn);
menuPrivacyBtn.click();
assert.equal(popoverLayer.hidden, false);
assert.equal(popoverLayer.querySelector("h2").textContent, "Local privacy");
await sleep(40);
assert.equal(popoverLayer.hidden, false);

// Suite D: Mobile Menu -> Invite handoff + repeated closeModal() 5ms apart restores focus to #btn-mobile-menu
await T.closePopover({ immediate: true });
btnMobileMenu.click();
const menuInviteBtn = popoverLayer
  .querySelectorAll("button")
  .find((b) => b.textContent.includes("Invite teammate"));
assert.ok(menuInviteBtn);
menuInviteBtn.click();
assert.equal(popoverLayer.hidden, true);
assert.equal(modalLayer.hidden, false);
assert.equal(
  modalLayer.querySelectorAll(".copy-field").some((n) =>
    n.textContent.includes("https://chinwag.sh/pricing?source=local_ui_referral"),
  ),
  true,
);
stubDocument.activeElement = null;
await Promise.all([T.closeModal(), sleep(5).then(() => T.closeModal())]);
assert.equal(modalLayer.hidden, true);
assert.equal(stubDocument.activeElement, btnMobileMenu);

// Suite E: Pack wizard slug mapping & workflow save rollback
assert.equal(T.wizardPackSlugForSku("pack_50"), "developer");
assert.equal(T.wizardPackSlugForSku("pack_160"), "growth");
assert.equal(T.wizardPackSlugForSku("pack_560"), "scale");
assert.equal(T.wizardPackSlugForSku("pack_1000"), "volume");

T.state.data = T.normalizeBootstrap({ agents: { workflow: { review_tier_credits: 100 } } });
mockWorkflowHandler = async () => {
  throw new Error("simulated write failure");
};
await assert.rejects(() => T.saveWorkflowSettings({ review_tier_credits: 200 }));
assert.equal(T.state.data.agents.review_tier_credits, 100);

console.log(
  JSON.stringify({
    ok: true,
    script: "verify-ui-v4-contracts.mjs",
    suites_passed: 5,
  }),
);

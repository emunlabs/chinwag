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
const themeBootJs = fs.readFileSync(path.join(uiDir, "theme-boot.js"), "utf8");
const stylesCss = fs.readFileSync(path.join(uiDir, "styles.css"), "utf8");
const motionCss = fs.readFileSync(path.join(uiDir, "motion.css"), "utf8");
const motionJs = fs.readFileSync(path.join(uiDir, "motion.js"), "utf8");
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
  ["theme-boot.js", themeBootJs],
  ["styles.css", stylesCss],
  ["motion.css", motionCss],
  ["motion.js", motionJs],
  ["app.js", appJs],
]) {
  assertZeroCustomerJargon(name, content);
  assertVerifiedChinwagRoutes(name, content);
}

// CHWG-0254 Phase 1 static & zero-voice-stub contracts
assert.equal(
  themeBootJs.includes('localStorage.getItem("chinwag.ui.rail")') &&
    themeBootJs.includes("document.documentElement.dataset.rail"),
  true,
  "theme-boot.js must restore chinwag.ui.rail into document.documentElement.dataset.rail pre-paint",
);
for (const requiredId of [
  'id="d2-rail"',
  'id="d2-rail-toggle-fixed"',
  'id="d2-track"',
  'id="d2-spine"',
  'id="d2-drawer-scrim"',
  'id="btn-d2-drawer"',
  'id="app-body"',
]) {
  assert.equal(indexHtml.includes(requiredId), true, `index.html missing ${requiredId}`);
}
assert.equal(
  appJs.includes("Mark connected"),
  false,
  "app.js must not expose client-side 'Mark connected' OAuth self-assertion bypass",
);
for (const phase2VoiceStub of ["d2-btn-mic", "d2-voice", "voice-call", "Start voice", "Mute mic"]) {
  assert.equal(
    indexHtml.includes(phase2VoiceStub) || appJs.includes(phase2VoiceStub),
    false,
    `CHWG-0254 Phase 1 must contain zero Phase 2 Duplex Voice stubs ('${phase2VoiceStub}')`,
  );
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

// CHWG-0254 CSS container-query, 1px shared spine, outgoing collapse layer, and no-rewrap .d2-track contracts
for (const cssSnippet of [
  "container: main / inline-size;",
  "@container main (min-width: 1120px)",
  "@container main (max-width: 1119.98px)",
  "max-width: calc(100vw - var(--rail-current) - 48px);",
  "left: calc(var(--rail-current) - 1px);",
  "contain: layout paint;",
  '.d2-rail[data-rail-animating="collapsing"] .d2-track',
  ".d2-rail-toggle-fixed",
]) {
  assert.equal(
    stylesCss.includes(cssSnippet),
    true,
    `styles.css missing CHWG-0254 layout contract '${cssSnippet}'`,
  );
}

// 3. Live Node VM DOM & Behavioral Harness against app.js
function attrToDatasetKey(attr) {
  return attr
    .slice(5)
    .replace(/-([a-z])/g, (_m, ch) => ch.toUpperCase());
}

// Browser-faithful NodeList stub: iterable + indexed + .length + .item + .forEach,
// intentionally WITHOUT Array.prototype.{find,filter,map,some} so native NodeList misuse fails immediately!
class StubNodeList {
  constructor(items) {
    this._items = items;
    this.length = items.length;
    for (let i = 0; i < items.length; i += 1) {
      this[i] = items[i];
    }
  }
  item(i) {
    return this._items[i] || null;
  }
  forEach(cb, thisArg) {
    this._items.forEach(cb, thisArg);
  }
  [Symbol.iterator]() {
    return this._items[Symbol.iterator]();
  }
}

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
    this.disabled = false;
    this.inert = false;
    this.checked = false;
    this.selected = false;
    this.value = "";
    this.onclick = null;
    this._text = "";
  }
  get firstChild() {
    return this.children.length > 0 ? this.children[0] : null;
  }
  get childElementCount() {
    return this.children.filter((c) => c.tagName !== "__TEXT__").length;
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
    if (k.startsWith("data-")) this.dataset[attrToDatasetKey(k)] = sv;
    this.attributes.set(k, sv);
  }
  getAttribute(k) {
    if (k === "id" && this.id) return this.id;
    if (k === "class" && this.className) return this.className;
    if (this.attributes.has(k)) return this.attributes.get(k);
    if (k.startsWith("data-")) {
      const dk = attrToDatasetKey(k);
      if (Object.prototype.hasOwnProperty.call(this.dataset, dk)) return String(this.dataset[dk]);
    }
    return null;
  }
  removeAttribute(k) {
    if (k === "id") this.id = "";
    if (k === "class") this.className = "";
    if (k.startsWith("data-")) delete this.dataset[attrToDatasetKey(k)];
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
    if (s.startsWith("#")) return this.id === s.slice(1);
    if (s.startsWith(".")) return this.className.split(/\s+/).includes(s.slice(1));
    if (s === "[href]") return this.attributes.has("href");
    if (s === '[role="switch"]') return this.getAttribute("role") === "switch";
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
    return new StubNodeList(results);
  }
  querySelector(selector) {
    const all = this.querySelectorAll(selector);
    return all.length > 0 ? all.item(0) : null;
  }
}

const byId = new Map();
function mountEl(tag, id, hidden = false, parent = null) {
  const n = new StubNode(tag);
  n.id = id;
  n.hidden = hidden;
  byId.set(id, n);
  if (parent) parent.appendChild(n);
  return n;
}

const docEl = new StubNode("html");
docEl.setAttribute("data-theme", "stone");
const bodyEl = mountEl("body", "doc-body", false, docEl);
const btnPrivacy = mountEl("button", "btn-privacy", false, bodyEl);
const btnMobileMenu = mountEl("button", "btn-mobile-menu", false, bodyEl);
const btnD2Drawer = mountEl("button", "btn-d2-drawer", false, bodyEl);
const btnInvite = mountEl("button", "btn-invite", false, bodyEl);
btnInvite._computedDisplay = "none";
const appBody = mountEl("div", "app-body", false, bodyEl);
const d2DrawerScrim = mountEl("div", "d2-drawer-scrim", true, appBody);
const d2Rail = mountEl("aside", "d2-rail", false, appBody);
const d2RailToggleFixed = mountEl("button", "d2-rail-toggle-fixed", false, d2Rail);
const d2Track = mountEl("div", "d2-track", false, d2Rail);
const d2Spine = mountEl("div", "d2-spine", false, d2Rail);
const mainEl = mountEl("main", "main", false, appBody);
const viewRoot = mountEl("div", "view-root", false, mainEl);
const askPmInput = mountEl("input", "ask-pm-input", false, viewRoot);
const sheetPrimaryAction = mountEl("button", "sheet-primary-action", false, viewRoot);
const popoverLayer = mountEl("div", "popover-layer", true, bodyEl);
mountEl("div", "modal-scrim", true, bodyEl);
const modalLayer = mountEl("div", "modal-layer", true, bodyEl);
mountEl("div", "toast-region", false, bodyEl);
mountEl("div", "sr-announcer", false, bodyEl);

function findByIdInTree(root, targetId) {
  if (root.id === targetId) return root;
  for (const ch of root.children) {
    const hit = findByIdInTree(ch, targetId);
    if (hit) return hit;
  }
  return null;
}

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
  getElementById: (id) => findByIdInTree(docEl, id) || byId.get(id) || null,
  querySelector: (sel) => docEl.querySelector(sel),
  querySelectorAll: (sel) => docEl.querySelectorAll(sel),
  addEventListener() {},
};

const stubWindow = {
  innerWidth: 1440,
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
      isArming: () => false,
      animateRailToggle: (rail, _track, _spine, _main, expand, applyStateFn) => {
        if (rail && rail.dataset) rail.dataset.railAnimating = expand ? "expanding" : "collapsing";
        if (typeof applyStateFn === "function") applyStateFn();
        return new Promise((r) => setTimeout(r, 15)).finally(() => {
          if (rail && rail.dataset) delete rail.dataset.railAnimating;
        });
      },
      dipSwap: async (_node, swapFn) => {
        await new Promise((r) => setTimeout(r, 15));
        if (typeof swapFn === "function") swapFn();
      },
      resolveBanner: async (_node, settleFn) => {
        if (typeof settleFn === "function") settleFn();
      },
      flashDeliveryCard: (card) => {
        if (card && card.dataset) card.dataset.handoffFlash = "true";
      },
      createProportionalStreamer: ({ onTick, onFinish }) => {
        let buf = "";
        let timer = null;
        return {
          push(txt) {
            buf = String(txt ?? "");
            if (typeof onTick === "function") onTick(buf.slice(0, Math.max(4, Math.ceil(buf.length / 8))));
          },
          markDone() {
            timer = setTimeout(() => {
              if (typeof onTick === "function") onTick(buf);
              if (typeof onFinish === "function") onFinish();
            }, 30);
          },
          cancel() {
            if (timer) clearTimeout(timer);
          },
        };
      },
      createToaster: () => ({ show() {}, dismiss() {} }),
      createElapsedClock: () => ({ bind() {}, poke() {}, destroy() {} }),
      bindIndicator: () => ({ update() {}, destroy() {} }),
      observeLoop: () => {},
      switchTheme: (next) => stubDocument.documentElement.setAttribute("data-theme", next),
    }, { get(t, k) { return k in t ? t[k] : () => ({ update() {}, destroy() {}, show() {}, dismiss() {}, open() {}, close: async () => {}, poke() {} }); } });`,
  )
  .replace(/^export\s+/gm, "");

let mockWorkflowHandler = async (body) => ({ ok: true, workflow: body });
let mockD2MessageHandler = async (body) => ({
  ok: true,
  entry: {
    id: "qa-live-1",
    kind: "qa_card",
    seq: 9,
    author: "Delivery-2",
    body: `Scoped reply for: ${body.prompt}`,
    sources: [{ id: "src-inbox", label: "Inbox · 1 ready diff", hash: "#inbox" }],
  },
});
let d2CancelCalls = [];
let d2ApprovalCalls = [];
let d2MemoryCalls = [];
let d2StateCalls = [];
let mockBootstrapPayload = {};
let mockD2StateHandler = async () => ({
  ok: true,
  seq: 3,
  cursor_seq: 3,
  unchanged: true,
  delta_entries: [],
});

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
    if (url === "/api/v4/bootstrap") {
      const payload =
        typeof mockBootstrapPayload === "function" ? await mockBootstrapPayload() : mockBootstrapPayload;
      return { ok: true, status: 200, json: async () => payload };
    }
    if (url === "/api/v4/workflow") {
      try {
        const res = await mockWorkflowHandler(body);
        return { ok: true, status: 200, json: async () => res };
      } catch (err) {
        return { ok: false, status: 500, json: async () => ({ ok: false, error: err.message }) };
      }
    }
    if (url.startsWith("/api/v1/delivery2/state")) {
      d2StateCalls.push(url);
      const res = await mockD2StateHandler(url);
      return { ok: true, status: 200, json: async () => res };
    }
    if (url === "/api/v1/delivery2/message") {
      const res = await mockD2MessageHandler(body);
      return { ok: true, status: 200, json: async () => res };
    }
    if (url === "/api/v1/delivery2/cancel") {
      d2CancelCalls.push(body);
      return { ok: true, status: 200, json: async () => ({ ok: true, cancelled: true, credits_charged: 0 }) };
    }
    if (url === "/api/v1/delivery2/approval") {
      d2ApprovalCalls.push(body);
      return { ok: true, status: 200, json: async () => ({ ok: true, decision: body.decision, authorized: true }) };
    }
    if (url === "/api/v1/delivery2/memory") {
      d2MemoryCalls.push(body);
      return { ok: true, status: 200, json: async () => ({ ok: true, memory: { id: body.id, note: body.note || "", status: "saved" } }) };
    }
    return { ok: true, status: 202, json: async () => ({ ok: true, telemetry_enabled: true }) };
  },
};

vm.createContext(sandbox);
vm.runInContext(
  `${transformedSrc}\nglobalThis.__test = { state, normalizeBootstrap, safeChinwagOutboundUrl, applyDelivery2ServerPayload, resumeDelivery2FromCursor, refreshBootstrapQuietly, syncDelivery2DrawerDom, syncRailForOverlaySheet, saveWorkflowSettings, openPrivacyPopover, openMobileMenuPopover, openInviteModal, closePopover, closeModal, wizardPackSlugForSku, renderDelivery2Panel, toggleDelivery2Rail, setDelivery2RailExpanded, openD2Popover, closeD2Popover, submitDelivery2Prompt, cancelDelivery2Turn, handleGlobalKeydown, applyRouteFromLocation, bounceToDelivery2Run };`,
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
  Array.from(popoverLayer.querySelectorAll("a")).map((a) => a.getAttribute("href")),
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
const menuPrivacyBtn = Array.from(popoverLayer.querySelectorAll("button")).find((b) =>
  b.textContent.includes("Local privacy & analytics"),
);
assert.ok(menuPrivacyBtn);
menuPrivacyBtn.click();
assert.equal(popoverLayer.hidden, false);
assert.equal(popoverLayer.querySelector("h2").textContent, "Local privacy");
await sleep(40);
assert.equal(popoverLayer.hidden, false);

// Suite D: Mobile Menu -> Invite handoff + repeated closeModal() 5ms apart restores focus to #btn-mobile-menu
await T.closePopover({ immediate: true });
btnMobileMenu.click();
const menuInviteBtn = Array.from(popoverLayer.querySelectorAll("button")).find((b) =>
  b.textContent.includes("Invite teammate"),
);
assert.ok(menuInviteBtn);
menuInviteBtn.click();
assert.equal(popoverLayer.hidden, true);
assert.equal(modalLayer.hidden, false);
assert.equal(
  Array.from(modalLayer.querySelectorAll(".copy-field")).some((n) =>
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

// Suite F: CHWG-0254 Delivery-2 4-zone render, 12-step run card, Paused · 0 Cr HITL card,
// Verified sources, Saved memory card, + Connections 2-axis popover, and generation-guarded dismiss
T.state.data = T.normalizeBootstrap({});
T.renderDelivery2Panel();

assert.equal(d2Track.querySelector(".d2-title").textContent, "Delivery-2");
assert.equal(d2Track.querySelectorAll(".d2-sync-pill").length, 4);
assert.equal(d2Track.querySelectorAll(".d2-digest-row").length, 3);
assert.equal(d2Track.querySelectorAll(".d2-seg").length, 12);
assert.equal(d2Spine.querySelectorAll(".d2-spine-seg").length, 12);
assert.equal(d2Spine.querySelectorAll(".d2-spine-dot").length, 4);
assert.equal(
  Array.from(d2Track.querySelectorAll(".d2-zero-cr-pill")).some((n) => n.textContent === "Paused · 0 Cr"),
  true,
  "HITL approval card must display Paused · 0 Cr badge",
);
assert.equal(
  Array.from(d2Track.querySelectorAll("button")).some((b) => b.textContent.includes("Verified sources")),
  true,
  "Grounded Q&A card must render collapsed Verified sources disclosure",
);
assert.equal(
  d2Track.querySelector(".d2-mem-card").textContent.includes("Saved: "),
  true,
  "Memory card must render Saved: 1-line notice",
);

await T.openD2Popover("connections", "linear");
const connPop = stubDocument.getElementById("d2-connections-popover");
assert.ok(connPop, "+ Connections popover must mount");
assert.equal(
  Array.from(connPop.querySelectorAll(".d2-conn-auth")).some((n) =>
    n.textContent.includes("Connected · ambient status cards only"),
  ),
  true,
  "Slack row in + Connections must enforce INV-SLACK-NOT-DELIVERY2-01 ambient status copy",
);
assert.equal(
  Array.from(connPop.querySelectorAll("button")).some((b) => b.textContent.includes("Connect")),
  true,
  "Unlinked Linear surface must expose Connect button",
);
assert.deepEqual(
  Array.from(connPop.querySelectorAll("a")).map((a) => a.getAttribute("href")),
  ["https://chinwag.sh/security", "https://chinwag.sh/pricing?talk=1&source=local_ui#founders"],
);

// Generation-guarded closeD2Popover() race: start animated close, reopen history 5ms later -> must survive
const staleD2Close = T.closeD2Popover();
await sleep(5);
await T.openD2Popover("history");
await staleD2Close;
await sleep(35);
assert.ok(
  stubDocument.getElementById("d2-history-popover"),
  "stale closeD2Popover() timer must never wipe newly opened Recent threads popover",
);
await T.closeD2Popover({ immediate: true });

// Suite G: Keyboard shortcuts — Cmd+B toggle + persistence, Cmd+J expand+focus, untouched Cmd+K, region-scoped Cmd+Enter
stubWindow.innerWidth = 1440;
await T.setDelivery2RailExpanded(true, { persist: true, animate: false });
assert.equal(docEl.getAttribute("data-rail"), "expanded");

T.handleGlobalKeydown({
  key: "b",
  metaKey: true,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  target: bodyEl,
  preventDefault() {},
});
assert.equal(docEl.getAttribute("data-rail"), "collapsed");
assert.equal(sandbox.localStorage.getItem("chinwag.ui.rail"), "collapsed");

T.handleGlobalKeydown({
  key: "j",
  metaKey: true,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  target: bodyEl,
  preventDefault() {},
});
await sleep(10);
assert.equal(docEl.getAttribute("data-rail"), "expanded");
assert.equal(stubDocument.activeElement.id, "d2-composer-input");

T.handleGlobalKeydown({
  key: "k",
  metaKey: true,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  target: bodyEl,
  preventDefault() {},
});
await sleep(10);
assert.equal(stubDocument.activeElement, askPmInput, "Cmd+K must remain 100% dedicated to Inbox #ask-pm-input");

// Region-scoped Cmd+Enter: inside #d2-rail MUST submit only to Delivery-2 and NEVER click #sheet-primary-action
let sheetMergeClicks = 0;
sheetPrimaryAction.onclick = () => {
  sheetMergeClicks += 1;
};
T.state.openItemId = "item-ready-1";
const d2Input = stubDocument.getElementById("d2-composer-input");
d2Input.value = "What did I miss?";
d2Input.focus();
let submittedPrompts = [];
mockD2MessageHandler = async (body) => {
  submittedPrompts.push(body.prompt);
  return {
    ok: true,
    entry: { id: "qa-2", kind: "qa_card", seq: 10, author: "Delivery-2", body: "Grounded summary ready.", sources: [] },
  };
};
T.handleGlobalKeydown({
  key: "Enter",
  metaKey: true,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  target: d2Input,
  preventDefault() {},
});
await sleep(60);
assert.deepEqual(submittedPrompts, ["What did I miss?"]);
assert.equal(sheetMergeClicks, 0, "Cmd+Enter inside #d2-rail must NEVER trigger Inbox sheet merge");

// Outside #d2-rail, Cmd+Enter triggers #sheet-primary-action as expected
askPmInput.focus();
T.handleGlobalKeydown({
  key: "Enter",
  metaKey: true,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  target: askPmInput,
  preventDefault() {},
});
assert.equal(sheetMergeClicks, 1);
T.state.openItemId = null;

// Suite H: Enabled Stop button (#d2-btn-stop) + Cmd+. active reply cancellation (fixes D1 disabled Stop bug)
let resolveInFlight;
mockD2MessageHandler = () =>
  new Promise((resolve) => {
    resolveInFlight = resolve;
  });
const inFlightPromise = T.submitDelivery2Prompt("Scope retry backoff tests");
await sleep(5);
const stopBtn = stubDocument.getElementById("d2-btn-stop");
assert.ok(stopBtn, "Active Delivery-2 turn must mount #d2-btn-stop");
assert.notEqual(stopBtn.getAttribute("aria-disabled"), "true", "#d2-btn-stop must be enabled during active reply");

d2CancelCalls = [];
T.handleGlobalKeydown({
  key: ".",
  metaKey: true,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  target: d2Input,
  preventDefault() {},
});
await sleep(15);
assert.equal(d2CancelCalls.length, 1, "Cmd+. must POST /api/v1/delivery2/cancel");
assert.ok(stubDocument.getElementById("d2-btn-send"), "Cancelling turn must restore #d2-btn-send immediately");
resolveInFlight({ ok: true });
await inFlightPromise;

// Suite I: Slack #run=<id>&focus=delivery2 deep-link bounce + narrow-viewport overlay sheet auto-collapse/restore
await T.setDelivery2RailExpanded(false, { persist: true, animate: false });
assert.equal(docEl.getAttribute("data-rail"), "collapsed");
stubWindow.location.hash = "#run=run-local-1&focus=delivery2";
T.applyRouteFromLocation();
assert.equal(docEl.getAttribute("data-rail"), "expanded", "Deep-link bounce must expand Delivery-2 rail");
const bouncedCard = d2Track.querySelector(".d2-run-card");
assert.ok(bouncedCard && bouncedCard.dataset.handoffFlash === "true", "Deep-link bounce must flash target run card");
assert.equal(stubDocument.activeElement.id, "d2-composer-input", "Deep-link bounce must focus #d2-composer-input");

// At 1280px viewport (1280 - 320 = 960 < 1120), opening #walkthrough overlay sheet auto-collapses rail and restores on #inbox
stubWindow.innerWidth = 1280;
await T.setDelivery2RailExpanded(true, { persist: true, animate: false });
stubWindow.location.hash = "#walkthrough";
T.applyRouteFromLocation();
assert.equal(docEl.getAttribute("data-rail"), "collapsed", "Overlay review sheet on <1120px #main must auto-collapse rail");
stubWindow.location.hash = "#inbox";
T.applyRouteFromLocation();
assert.equal(docEl.getAttribute("data-rail"), "expanded", "Closing overlay review sheet must restore expanded rail");
stubWindow.innerWidth = 1440;

// Suite J: Round-2 Tribunal Regression Ratchets (ALISTAIR-1/4 + ARCHITECT-1/3/4/5/6/9/10/11/12)
// J1: Outbound URL allowlist neutralizes javascript: and external OAuth phishing links
assert.equal(T.safeChinwagOutboundUrl("javascript:alert(1)"), "https://chinwag.sh/open");
assert.equal(T.safeChinwagOutboundUrl("https://evil.example/oauth-phish"), "https://chinwag.sh/open");
assert.equal(
  T.safeChinwagOutboundUrl("https://chinwag.sh/open?connect=linear&state=deadbeef"),
  "https://chinwag.sh/open?connect=linear&state=deadbeef",
);
const tamperedBoot = T.normalizeBootstrap({
  delivery2: {
    seq: 2,
    links: {
      security_url: "javascript:evil()",
      founders_url: "https://evil.example/founders",
    },
    entries: [
      {
        id: "entry-oauth-linear",
        kind: "oauth_card",
        seq: 2,
        surface: "linear",
        surface_label: "Linear",
        oauth_state: "nonce-1234",
        thread_id: "thr-main",
        challenge_url: "javascript:phish()",
        settled: false,
      },
      {
        id: "entry-hitl-j",
        kind: "approval_card",
        seq: 2,
        approval_id: "hitl-j1",
        item_id: "j1",
        question: "Approve change?",
        settled: false,
      },
      {
        id: "entry-mem-j",
        kind: "memory_card",
        seq: 2,
        memory_id: "mem_j1",
        note: "Always run clippy.",
        status: "saved",
      },
    ],
  },
});
assert.equal(tamperedBoot.delivery2.links.security_url, "https://chinwag.sh/security");
assert.equal(
  tamperedBoot.delivery2.links.founders_url,
  "https://chinwag.sh/pricing?talk=1&source=local_ui#founders",
);
assert.equal(tamperedBoot.delivery2.entries[0].challenge_url, "https://chinwag.sh/open");

// J2: OAuth card renders "Re-check connection" and sends decision="verify" with oauth_state + thread_id
T.state.d2Loaded = false;
T.state.d2LastCursorSeq = 0;
T.applyDelivery2ServerPayload(tamperedBoot.delivery2, { forceInitial: true });
T.renderDelivery2Panel();
const oauthCard = d2Track.querySelector(".d2-oauth-card");
assert.ok(oauthCard, "oauth_card must render");
assert.equal(oauthCard.querySelector("a").getAttribute("href"), "https://chinwag.sh/open");
const recheckBtn = Array.from(oauthCard.querySelectorAll("button")).find((b) =>
  b.textContent.includes("Re-check connection"),
);
assert.ok(recheckBtn, "oauth_card must render Re-check connection button");
d2ApprovalCalls = [];
recheckBtn.click();
await sleep(25);
assert.equal(d2ApprovalCalls.length, 1);
assert.deepEqual(d2ApprovalCalls[0], {
  kind: "oauth",
  surface: "linear",
  decision: "verify",
  oauth_state: "nonce-1234",
  thread_id: "thr-main",
});

// J3: Async dipSwap on memory Edit focuses live .d2-mem-edit-input, and Cmd+Enter in memory editor NEVER approves HITL
T.applyDelivery2ServerPayload(tamperedBoot.delivery2, { forceInitial: true });
T.renderDelivery2Panel();
const memCard = d2Track.querySelector(".d2-mem-card");
const editMemBtn = Array.from(memCard.querySelectorAll("button")).find((b) => b.textContent === "Edit");
assert.ok(editMemBtn, "Memory card must expose Edit button");
editMemBtn.click();
await sleep(30);
const liveMemInput = d2Track.querySelector(".d2-mem-edit-input");
assert.ok(liveMemInput, "Memory editor input must mount after async dipSwap");
assert.equal(
  stubDocument.activeElement,
  liveMemInput,
  "Async dipSwap memory Edit must focus the live replacement .d2-mem-edit-input",
);

d2ApprovalCalls = [];
d2MemoryCalls = [];
let keyEvDefaultPrevented = false;
let keyEvStopped = false;
const memEnterEv = {
  key: "Enter",
  metaKey: true,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  target: liveMemInput,
  get defaultPrevented() {
    return keyEvDefaultPrevented;
  },
  preventDefault() {
    keyEvDefaultPrevented = true;
  },
  stopPropagation() {
    keyEvStopped = true;
  },
};
for (const fn of liveMemInput.listeners.get("keydown") || []) fn(memEnterEv);
if (!keyEvStopped) {
  T.handleGlobalKeydown(memEnterEv);
}
// Even if global keydown were called directly with defaultPrevented=true, it must no-op:
T.handleGlobalKeydown(memEnterEv);
await sleep(20);
assert.equal(d2MemoryCalls.length, 1, "Cmd+Enter in memory editor must save memory note once");
assert.equal(d2ApprovalCalls.length, 0, "Cmd+Enter in memory editor must NEVER approve a pending HITL card");

// J4: Monotonic seq rejects stale server/bootstrap payloads & cursor resume queries ?since_seq=
T.applyDelivery2ServerPayload({
  seq: 5,
  status: "live",
  status_label: "Live",
  entries: [
    {
      id: "entry-hitl-j",
      kind: "approval_card",
      seq: 5,
      approval_id: "hitl-j1",
      settled: true,
      settled_decision: "approved",
      settled_receipt: "Approved by you · 0 Cr while paused",
    },
  ],
});
assert.equal(T.state.d2LastCursorSeq, 5);
assert.equal(
  T.applyDelivery2ServerPayload({
    seq: 3,
    status: "waiting_for_you",
    status_label: "Waiting for you",
    entries: [{ id: "entry-hitl-j", kind: "approval_card", seq: 3, settled: false }],
  }),
  false,
  "Stale mutation payload with lower seq must be rejected",
);
assert.equal(T.state.data.delivery2.entries[0].settled, true);

mockBootstrapPayload = {
  delivery2: {
    seq: 2,
    status: "waiting_for_you",
    entries: [{ id: "entry-hitl-j", kind: "approval_card", seq: 2, settled: false }],
  },
};
await T.refreshBootstrapQuietly();
assert.equal(T.state.data.delivery2.seq, 5, "refreshBootstrapQuietly must preserve newer Delivery-2 seq=5");
assert.equal(T.state.data.delivery2.entries[0].settled, true);

d2StateCalls = [];
mockD2StateHandler = async () => ({
  ok: true,
  seq: 6,
  cursor_seq: 6,
  unchanged: false,
  entries: [{ id: "entry-qa-6", kind: "qa_card", seq: 6, body: "Resumed from cursor." }],
});
await T.resumeDelivery2FromCursor();
assert.equal(d2StateCalls[0], "/api/v1/delivery2/state?since_seq=5");
assert.equal(T.state.d2LastCursorSeq, 6);

// J5: Stop mid-reveal retains partial displayed text instead of flashing full unstreamed answer
const fullLongBody =
  "First partial sentence visible before stop — THIS TRAILING SECRET REMAINDER MUST NEVER APPEAR AFTER STOP.";
mockD2MessageHandler = async () => ({
  ok: true,
  entry: {
    id: "qa-stop-partial",
    kind: "qa_card",
    seq: 7,
    author: "Delivery-2",
    body: fullLongBody,
    sources: [],
  },
  state: {
    seq: 7,
    entries: [
      {
        id: "qa-stop-partial",
        kind: "qa_card",
        seq: 7,
        author: "Delivery-2",
        body: fullLongBody,
        sources: [],
      },
    ],
  },
});
d2CancelCalls = [];
await T.submitDelivery2Prompt("Explain long architecture flow");
// Streamer pushed first 1/8 slice synchronously; cancel BEFORE 30ms markDone timer fires!
await T.cancelDelivery2Turn();
const renderedPartial = stubDocument.getElementById("d2-qa-body-qa-stop-partial");
assert.ok(renderedPartial, "Stopped QA card must remain mounted");
assert.equal(
  renderedPartial.textContent.includes("THIS TRAILING SECRET REMAINDER"),
  false,
  "Stopping mid-stream must retain only the displayed partial prefix, never revealing the full body",
);
assert.equal(d2CancelCalls[0].entry_id, "qa-stop-partial");
assert.ok(Number.isFinite(d2CancelCalls[0].truncated_len) && d2CancelCalls[0].truncated_len < fullLongBody.length);

// J6: Resizing an open review sheet from 1440px -> 1280px auto-collapses rail and restores at 1440px
stubWindow.innerWidth = 1440;
await T.setDelivery2RailExpanded(true, { persist: true, animate: false });
T.state.openItemId = "item-open-resize";
T.syncRailForOverlaySheet();
assert.equal(docEl.getAttribute("data-rail"), "expanded", "At 1440px split review keeps rail expanded");
stubWindow.innerWidth = 1280;
T.syncRailForOverlaySheet();
assert.equal(docEl.getAttribute("data-rail"), "collapsed", "Resizing open sheet to 1280px must auto-collapse rail");
stubWindow.innerWidth = 1440;
T.syncRailForOverlaySheet();
assert.equal(docEl.getAttribute("data-rail"), "expanded", "Resizing back to 1440px must restore pre-sheet expanded rail");
T.state.openItemId = null;

// J7: < 960px closed mobile drawer is inert + aria-hidden, traps Tab on StubNodeList when open, and restores focus on close
stubWindow.innerWidth = 390;
T.state.d2DrawerOpen = false;
T.syncDelivery2DrawerDom();
assert.equal(d2Rail.inert, true, "Closed <960px mobile drawer must set rail.inert = true");
assert.equal(d2Rail.getAttribute("aria-hidden"), "true");

btnD2Drawer.focus();
await T.setDelivery2RailExpanded(true, { persist: false, animate: false });
assert.equal(d2Rail.inert, false, "Open <960px mobile drawer must clear rail.inert");
assert.equal(d2Rail.getAttribute("aria-hidden"), null);
await sleep(10);

const drawerButtons = Array.from(d2Track.querySelectorAll("button, a, textarea, input"));
assert.ok(drawerButtons.length >= 2);
const lastDrawerFocusable = drawerButtons[drawerButtons.length - 1];
lastDrawerFocusable.focus();
let tabPrevented = false;
T.handleGlobalKeydown({
  key: "Tab",
  metaKey: false,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  target: lastDrawerFocusable,
  defaultPrevented: false,
  preventDefault() {
    tabPrevented = true;
  },
});
assert.equal(tabPrevented, true, "Tab on last drawer control must wrap focus inside drawer without NodeList TypeError");
assert.equal(stubDocument.activeElement, drawerButtons[0]);

await T.setDelivery2RailExpanded(false, { persist: false, animate: false });
assert.equal(d2Rail.inert, true);
assert.equal(stubDocument.activeElement, btnD2Drawer, "Closing mobile drawer must restore focus to trigger");
stubWindow.innerWidth = 1440;
T.syncDelivery2DrawerDom();

// Suite K: Round-3 Tribunal Regression Ratchets (ARCHITECT-R2-1/6/7/8 + QA-R2-1/open-redirect)
// K1: In-flight mutation advancing seq during delayed refreshBootstrapQuietly or unchanged cursor poll NEVER rolls back
T.applyDelivery2ServerPayload({
  seq: 20,
  status: "waiting_for_you",
  entries: [{ id: "entry-hitl-k", kind: "approval_card", seq: 20, approval_id: "hitl-k1", settled: false }],
});
let releaseDelayedBoot;
mockBootstrapPayload = () =>
  new Promise((resolve) => {
    releaseDelayedBoot = () =>
      resolve({
        delivery2: {
          seq: 20,
          status: "waiting_for_you",
          entries: [{ id: "entry-hitl-k", kind: "approval_card", seq: 20, approval_id: "hitl-k1", settled: false }],
        },
      });
  });
const pendingBootRefresh = T.refreshBootstrapQuietly();
await sleep(5);
// Concurrent mutation settles hitl-k1 at seq=21 BEFORE delayed /api/v4/bootstrap resolves!
T.applyDelivery2ServerPayload({
  seq: 21,
  status: "live",
  entries: [
    {
      id: "entry-hitl-k",
      kind: "approval_card",
      seq: 21,
      approval_id: "hitl-k1",
      settled: true,
      settled_decision: "approved",
    },
  ],
});
releaseDelayedBoot();
await pendingBootRefresh;
assert.equal(T.state.data.delivery2.seq, 21, "Delayed bootstrap response must NEVER overwrite newer in-flight seq=21");
assert.equal(
  T.state.data.delivery2.entries[0].settled,
  true,
  "Delayed bootstrap response must NEVER roll back settled approval",
);

let releaseDelayedCursor;
mockD2StateHandler = () =>
  new Promise((resolve) => {
    releaseDelayedCursor = () => resolve({ ok: true, seq: 21, cursor_seq: 21, unchanged: true, delta_entries: [] });
  });
const pendingCursorPoll = T.resumeDelivery2FromCursor();
await sleep(5);
T.applyDelivery2ServerPayload({
  seq: 22,
  status: "live",
  entries: [{ id: "entry-qa-22", kind: "qa_card", seq: 22, body: "Newer turn arrived." }],
});
releaseDelayedCursor();
await pendingCursorPoll;
assert.equal(
  T.state.d2LastCursorSeq,
  22,
  "Delayed unchanged cursor poll must NEVER rewind d2LastCursorSeq from 22 back to 21",
);

// K2: Pre-receipt Stop (cancelDelivery2Turn BEFORE /api/v1/delivery2/message resolves) sends truncated_len=0 and never reveals unseen body
let resolveLateMessage;
mockD2MessageHandler = (body) =>
  new Promise((resolve) => {
    resolveLateMessage = () =>
      resolve({
        ok: true,
        entry: {
          id: "qa-late-prestop",
          kind: "qa_card",
          seq: 23,
          turn_id: body.turn_id,
          author: "Delivery-2",
          body: "UNSEEN LATE BODY THAT MUST NEVER RENDER AFTER PRE-RECEIPT STOP",
          sources: [{ id: "src-late", label: "Inbox", hash: "#inbox" }],
        },
      });
  });
d2CancelCalls = [];
const lateTurnPromise = T.submitDelivery2Prompt("Question cancelled before response arrives");
await sleep(5);
await T.cancelDelivery2Turn();
assert.equal(d2CancelCalls.length, 1);
assert.equal(d2CancelCalls[0].truncated_len, 0, "Pre-receipt Stop must send truncated_len: 0");
assert.ok(String(d2CancelCalls[0].turn_id || "").startsWith("turn-"), "Pre-receipt Stop must carry turn_id");
releaseDelayedMessage: {
  resolveLateMessage();
  await lateTurnPromise;
}
assert.equal(
  d2Track.textContent.includes("UNSEEN LATE BODY"),
  false,
  "Late /message response for cancelled turn must NEVER reveal unseen answer text",
);

// K3: Collapsed .d2-disclosure-body sets .inert=true + aria-hidden="true" and clears both on expand
T.applyDelivery2ServerPayload({
  seq: 24,
  status: "live",
  entries: [
    {
      id: "qa-disc-k3",
      kind: "qa_card",
      seq: 24,
      author: "Delivery-2",
      body: "Grounded answer.",
      sources: [{ id: "src-k3", label: "Inbox · #42", hash: "#inbox" }],
    },
  ],
});
T.renderDelivery2Panel();
const discBody = d2Track.querySelector(".d2-disclosure-body");
const discToggle = Array.from(d2Track.querySelectorAll("button")).find((b) =>
  b.textContent.includes("Verified sources"),
);
assert.ok(discBody && discToggle, "Verified sources disclosure must render");
assert.equal(discBody.inert, true, "Collapsed disclosure body must be inert so hidden buttons cannot take Tab focus");
assert.equal(discBody.getAttribute("aria-hidden"), "true");
discToggle.click();
assert.equal(discBody.inert, false, "Expanded disclosure body must clear inert");
assert.equal(discBody.getAttribute("aria-hidden"), "false");

// K4: Real motion.js animateRailToggle generation guard — older transition finishing never deletes active dataset.railAnimating
const motionCtx = {
  console,
  setTimeout,
  clearTimeout,
  requestAnimationFrame: (fn) => setTimeout(fn, 0),
  Date,
  Math,
  Number,
  Boolean,
  Promise,
  Array,
  document: stubDocument,
  window: stubWindow,
  getComputedStyle: () => ({
    getPropertyValue: (prop) => (prop.startsWith("--dur") ? "180ms" : "cubic-bezier(0.16, 1, 0.3, 1)"),
    backgroundColor: "#fff",
  }),
};
vm.createContext(motionCtx);
vm.runInContext(`${motionJs.replace(/^export\s+/gm, "")}\nglobalThis.__realMotion = { animateRailToggle };`, motionCtx);

const finishWaveA = [];
const finishWaveB = [];
let animACancelledCount = 0;
let callIdx = 0;
const makeAnimTarget = () => ({
  dataset: {},
  getBoundingClientRect: () => ({ top: 0 }),
  animate: () => {
    callIdx += 1;
    const isFirstWave = callIdx <= 2; // wave 1 (expand): track + rail clip; wave 2 (collapse): track + spine
    let resolveFn;
    const finished = new Promise((r) => {
      resolveFn = r;
    });
    if (isFirstWave) finishWaveA.push(resolveFn);
    else finishWaveB.push(resolveFn);
    return {
      finished,
      cancel() {
        if (isFirstWave) animACancelledCount += 1;
        resolveFn();
      },
    };
  },
});
const mRail = makeAnimTarget();
const mTrack = makeAnimTarget();
const mSpine = makeAnimTarget();
const mMain = { getBoundingClientRect: () => ({ top: 0 }) };

const pExpand = motionCtx.__realMotion.animateRailToggle(mRail, mTrack, mSpine, mMain, true, () => {});
assert.equal(mRail.dataset.railAnimating, "expanding");
const pCollapse = motionCtx.__realMotion.animateRailToggle(mRail, mTrack, mSpine, mMain, false, () => {});
assert.equal(animACancelledCount, 2, "Superseding rail toggle must cancel all in-flight Web Animations");
assert.equal(mRail.dataset.railAnimating, "collapsing");
for (const fn of finishWaveA) fn();
await pExpand;
assert.equal(
  mRail.dataset.railAnimating,
  "collapsing",
  "Superseded animation A finishing must NOT delete active animation B dataset.railAnimating",
);
for (const fn of finishWaveB) fn();
await pCollapse;
assert.equal(mRail.dataset.railAnimating, undefined, "Active animation B finishing clears dataset.railAnimating");

// K5: Open-redirect query/fragment schemes on https://chinwag.sh/open are neutralized
assert.equal(
  T.safeChinwagOutboundUrl("https://chinwag.sh/open?next=https://evil.example/phish"),
  "https://chinwag.sh/open",
);
assert.equal(
  T.safeChinwagOutboundUrl("https://chinwag.sh/pricing?redirect=//evil.example"),
  "https://chinwag.sh/open",
);

console.log(
  JSON.stringify({
    ok: true,
    script: "verify-ui-v4-contracts.mjs",
    suites_passed: 11,
  }),
);

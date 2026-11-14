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
// CHWG-0255 Phase 2 Duplex Live Voice static & deterministic golden-ratio waveform contracts
assert.equal(
  motionJs.includes("Math.random"),
  false,
  "motion.js must contain zero Math.random() calls (deterministic golden-ratio waveform only)",
);
assert.equal(
  indexHtml.includes("style=") || appJs.includes(".style."),
  false,
  "index.html and app.js must respect STRICT_UI_CSP (zero inline style attributes or .style mutations)",
);
for (const voiceCssContract of [
  "--ease-sine:",
  ".voice-bars > i",
  "@keyframes voice-travel",
]) {
  assert.equal(
    motionCss.includes(voiceCssContract),
    true,
    `motion.css missing Duplex Voice contract '${voiceCssContract}'`,
  );
}
for (const voiceStyleContract of [
  ".d2-voice-bar",
  ".voice-bars",
  ".d2-voice-timer",
  "font-variant-numeric: tabular-nums;",
  ".d2-hitl-voice-notice",
]) {
  assert.equal(
    stylesCss.includes(voiceStyleContract),
    true,
    `styles.css missing Duplex Voice contract '${voiceStyleContract}'`,
  );
}
const RealMotion = (() => {
  const motionCjs = `${motionJs.replace(/^export\s+/gm, "")}\nmodule.exports = { voiceFrame, ampFromRms, smoothAmp, applyVoiceBarsFrame };`;
  const mSandbox = { module: { exports: {} }, Math, Number, Float32Array, WeakSet, WeakMap, Set, Map, Promise, setTimeout, clearTimeout };
  vm.runInNewContext(motionCjs, mSandbox);
  return mSandbox.module.exports;
})();
assert.equal(typeof RealMotion.voiceFrame, "function", "motion.js must export voiceFrame");
assert.equal(typeof RealMotion.ampFromRms, "function", "motion.js must export ampFromRms");
assert.equal(typeof RealMotion.smoothAmp, "function", "motion.js must export smoothAmp");
{
  const listeningVec = RealMotion.voiceFrame(0, 0.1, { T: 2200, d: 0.5 });
  const expectedListening = [0.148, 0.148, 0.173, 0.169, 0.193, 0.196, 0.165, 0.162, 0.143];
  assert.equal(listeningVec.length, 9);
  expectedListening.forEach((want, idx) => {
    assert.ok(
      Math.abs(listeningVec[idx] - want) <= 0.001,
      `Motion.voiceFrame listening bar ${idx}: got ${listeningVec[idx]}, expected ${want} (±0.001)`,
    );
  });
  const speakingT0 = RealMotion.voiceFrame(0, 0.8, { T: 550, d: 0.45 });
  const speakingT550 = RealMotion.voiceFrame(550, 0.8, { T: 550, d: 0.45 });
  const expectedSpeaking = [0.348, 0.357, 0.556, 0.535, 0.714, 0.733, 0.495, 0.462, 0.311];
  expectedSpeaking.forEach((want, idx) => {
    assert.ok(
      Math.abs(speakingT0[idx] - want) <= 0.001,
      `Motion.voiceFrame speaking t=0 bar ${idx}: got ${speakingT0[idx]}, expected ${want} (±0.001)`,
    );
    assert.ok(
      Math.abs(speakingT0[idx] - speakingT550[idx]) <= 1e-5,
      `Motion.voiceFrame bar ${idx} must loop seamlessly at t=T`,
    );
  });
  assert.ok(RealMotion.ampFromRms(0) <= 0.001);
  assert.ok(RealMotion.ampFromRms(0.2) > 0.5);
  assert.ok(
    RealMotion.smoothAmp(0.1, 0.9, 40) - 0.1 > 0.9 - RealMotion.smoothAmp(0.9, 0.1, 40),
    "Motion.smoothAmp 40ms attack must outpace 180ms release",
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
      isTrusted: false,
      target: this,
      preventDefault() {},
      stopPropagation() {},
    };
    if (typeof this.onclick === "function") this.onclick(ev);
    for (const fn of this.listeners.get("click") || []) fn(ev);
  }
  clickTrusted() {
    const ev = {
      type: "click",
      isTrusted: true,
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
  cancelAnimationFrame: clearTimeout,
  Float32Array,
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
      const cancelRes =
        typeof globalThis.__mockD2CancelHandler === "function"
          ? await globalThis.__mockD2CancelHandler(body)
          : { ok: true, cancelled: true, credits_charged: 0 };
      return { ok: true, status: 200, json: async () => cancelRes };
    }
    if (url === "/api/v1/delivery2/approval") {
      d2ApprovalCalls.push(body);
      if (
        body.decision === "approve" &&
        (body.source !== "physical_click" ||
          body.voice_originated === true ||
          body.physical_click_verified !== true)
      ) {
        return {
          ok: false,
          status: 403,
          json: async () => ({
            ok: false,
            error_code: "VoiceDangerApprovalForbidden",
            physical_click_required: true,
            physical_click_verified: false,
            error: "Press Approve to confirm. Voice can't approve this one.",
            message: "Press Approve to confirm. Voice can't approve this one.",
          }),
        };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true, decision: body.decision, authorized: true }) };
    }
    if (url === "/api/v4/inbox/action") {
      if (Array.isArray(globalThis.__inboxActionCalls)) {
        globalThis.__inboxActionCalls.push(body);
      }
      if (
        (body.action === "approve" || body.action === "apply_locally") &&
        (body.source !== "physical_click" || body.physical_click_verified !== true)
      ) {
        return {
          ok: false,
          status: 403,
          json: async () => ({
            ok: false,
            error_code: "VoiceDangerApprovalForbidden",
            error: "Press Approve to confirm. Voice can't approve this one.",
          }),
        };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true, message: "Approved and pushed" }) };
    }
    if (url === "/api/v1/delivery2/memory") {
      d2MemoryCalls.push(body);
      return { ok: true, status: 200, json: async () => ({ ok: true, memory: { id: body.id, note: body.note || "", status: "saved" } }) };
    }
    if (url.startsWith("/api/v1/delivery2/voice/")) {
      if (typeof globalThis.__mockD2VoiceHandler === "function") {
        return globalThis.__mockD2VoiceHandler(url, body);
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    }
    return { ok: true, status: 202, json: async () => ({ ok: true, telemetry_enabled: true }) };
  },
};

vm.createContext(sandbox);
vm.runInContext(
  `${transformedSrc}\nglobalThis.__test = { state, normalizeBootstrap, safeChinwagOutboundUrl, applyDelivery2ServerPayload, resumeDelivery2FromCursor, refreshBootstrapQuietly, syncDelivery2DrawerDom, syncRailForOverlaySheet, saveWorkflowSettings, openPrivacyPopover, openMobileMenuPopover, openInviteModal, closePopover, closeModal, wizardPackSlugForSku, renderSheetFooter, renderDelivery2Panel, toggleDelivery2Rail, setDelivery2RailExpanded, openD2Popover, closeD2Popover, submitDelivery2Prompt, cancelDelivery2Turn, handleGlobalKeydown, applyRouteFromLocation, bounceToDelivery2Run, VOICE_STATES, canTransitionVoiceState, formatVoiceTimer, spokenOption, filterSafeVoiceOptions, isVoiceDangerApprovalAttempt, truncateCommentaryAtSentence, createVoiceDelegate, startDelivery2Voice, resumeDelivery2Voice, toggleDelivery2VoiceMute, parkDelivery2Voice, endDelivery2Voice, tickDelivery2VoiceHeartbeat, sendDelivery2VoiceTurn, submitDelivery2Approval, stopDelivery2VoiceLoops };`,
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

// 1. Cold/unverified bootstrap fails closed (`authorized: false`, `"Needs sign-in · pauses at 0 Cr"`) on github, linear, and slack (`ALISTAIR-R3-1`)
for (const sid of ["github", "linear", "slack"]) {
  const coldSurf = T.state.data.delivery2.sync_radar.surfaces.find((s) => s.id === sid);
  assert.ok(coldSurf, `cold bootstrap must include ${sid}`);
  assert.equal(coldSurf.authorized, false, `cold bootstrap ${sid} must fail closed (authorized: false)`);
  assert.equal(coldSurf.in_thread, false, `cold bootstrap ${sid} must fail closed (in_thread: false)`);
  assert.equal(coldSurf.auth_status, "Needs sign-in · pauses at 0 Cr", `cold bootstrap ${sid} must show Needs sign-in`);
}

await T.openD2Popover("connections", "linear");
let connPop = stubDocument.getElementById("d2-connections-popover");
assert.ok(connPop, "+ Connections popover must mount");
assert.equal(
  Array.from(connPop.querySelectorAll(".d2-conn-auth")).some((n) =>
    n.textContent.includes("Connected · ambient status cards only"),
  ),
  false,
  "Unauthorized Slack must NOT claim Connected · ambient status cards only",
);
assert.equal(
  Array.from(connPop.querySelectorAll("button")).filter((b) => b.textContent.includes("Connect")).length,
  3,
  "Unlinked GitHub, Linear, and Slack surfaces must all expose Connect buttons when unauthorized",
);
await T.closeD2Popover({ immediate: true });

// 2. When verified receipts authorize GitHub + Slack (`authorized: true`), Slack enforces `Connected · ambient status cards only` (`INV-SLACK-NOT-DELIVERY2-01`)
T.state.data = T.normalizeBootstrap({
  delivery2: {
    seq: 1,
    sync_radar: {
      latency_ms: 18,
      latency_label: "<200ms",
      surfaces: [
        { id: "local", label: "Local", authorized: true, in_thread: true, locked_in_thread: true, role_mode: "workspace" },
        { id: "github", label: "GitHub", authorized: true, in_thread: true, locked_in_thread: false, role_mode: "full" },
        { id: "linear", label: "Linear", authorized: false, in_thread: false, locked_in_thread: false, role_mode: "full" },
        {
          id: "slack",
          label: "Slack",
          authorized: true,
          in_thread: true, // hostile payload trying to force Slack in_thread -> must clamp to false
          locked_in_thread: false,
          role_mode: "ambient_status_only",
        },
      ],
    },
  },
});
assert.equal(
  T.state.data.delivery2.sync_radar.surfaces.find((s) => s.id === "slack").in_thread,
  false,
  "Slack in_thread must always clamp to false even when authorized",
);
await T.openD2Popover("connections", "linear");
connPop = stubDocument.getElementById("d2-connections-popover");
assert.ok(connPop, "+ Connections popover must mount after verified surfaces");
assert.equal(
  Array.from(connPop.querySelectorAll(".d2-conn-auth")).some((n) =>
    n.textContent.includes("Connected · ambient status cards only"),
  ),
  true,
  "Authorized Slack row in + Connections must enforce INV-SLACK-NOT-DELIVERY2-01 ambient status copy",
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
const cancelledTurnIdK2 = d2CancelCalls[0].turn_id;
assert.equal(d2CancelCalls[0].thread_id, "thr-main", "Cancel payload must carry owning thread_id");
// Simulate delayed /api/v1/delivery2/state?since_seq= AND delayed /api/v4/bootstrap arriving before /cancel settles on server (`ARCHITECT-R3-1`)
T.applyDelivery2ServerPayload({
  seq: 23,
  status: "live",
  entries: [
    { id: "run-late-prestop", kind: "run_card", seq: 23, turn_id: cancelledTurnIdK2, title: "Unseen run card" },
    {
      id: "qa-late-prestop",
      kind: "qa_card",
      seq: 23,
      turn_id: cancelledTurnIdK2,
      author: "Delivery-2",
      body: "UNSEEN SNAPSHOT POLL BODY THAT MUST BE CLAMPED",
      sources: [{ id: "src-late", label: "Inbox", hash: "#inbox" }],
    },
  ],
});
T.renderDelivery2Panel();
assert.equal(
  d2Track.textContent.includes("UNSEEN SNAPSHOT POLL BODY"),
  false,
  "Delayed /state snapshot poll must NEVER reveal unseen answer for cancelled turn",
);
assert.equal(
  T.state.data.delivery2.entries.some((e) => e.id === "run-late-prestop"),
  false,
  "Unseen run_card for pre-receipt cancelled turn must be stripped on client reconciliation",
);
assert.equal(
  T.state.data.delivery2.entries.find((e) => e.id === "qa-late-prestop").body,
  "[Stopped]",
  "Cancelled qa_card arriving via snapshot poll must clamp to [Stopped]",
);

// Also test ARCHITECT-R3-1 exact delayed /api/v4/bootstrap interleaving while BOTH /message and /cancel are genuinely held on the wire!
let releaseHeldBootK2;
mockBootstrapPayload = () =>
  new Promise((resolve) => {
    releaseHeldBootK2 = resolve;
  });
let releaseHeldMsgK2;
mockD2MessageHandler = () =>
  new Promise((resolve) => {
    releaseHeldMsgK2 = resolve;
  });
let releaseHeldCancelK2;
globalThis.__mockD2CancelHandler = () =>
  new Promise((resolve) => {
    releaseHeldCancelK2 = () => resolve({ ok: true, cancelled: true, credits_charged: 0 });
  });
const heldBootPromise = T.refreshBootstrapQuietly();
const heldMsgPromise = T.submitDelivery2Prompt("Second question stopped while bootstrap and cancel are held");
await sleep(5);
const heldTurnId = T.state.d2ActiveTurnId;
assert.ok(String(heldTurnId || "").startsWith("turn-"), "Active turn ID must be recorded before Stop");
const cancelPromiseK2 = T.cancelDelivery2Turn();
await sleep(5);
// Notice: releaseHeldCancelK2 has NOT been called yet — /cancel is genuinely in flight when bootstrap commits!
releaseHeldBootK2({
  delivery2: {
    seq: 24,
    status: "live",
    entries: [
      { id: "run-boot-101", kind: "run_card", seq: 24, turn_id: heldTurnId, title: "Unseen boot run card" },
      {
        id: "qa-boot-101",
        kind: "qa_card",
        seq: 24,
        turn_id: heldTurnId,
        author: "Delivery-2",
        body: "UNSEEN BOOTSTRAP ANSWER WHILE CANCEL IN FLIGHT",
        sources: [{ id: "src-101", label: "Inbox", hash: "#inbox" }],
      },
    ],
  },
});
await heldBootPromise;
assert.equal(
  d2Track.textContent.includes("UNSEEN BOOTSTRAP ANSWER"),
  false,
  "Delayed /api/v4/bootstrap WHILE /cancel IS HELD must NEVER render unseen answer of a stopped turn",
);
releaseHeldCancelK2();
await cancelPromiseK2;
globalThis.__mockD2CancelHandler = null;
releaseHeldMsgK2({ ok: true });
await heldMsgPromise;
assert.equal(
  T.state.data.delivery2.entries.some((e) => e.id === "run-boot-101"),
  false,
  "Delayed /api/v4/bootstrap unseen run_card for stopped turn must be stripped",
);
assert.equal(
  T.state.data.delivery2.entries.find((e) => e.id === "qa-boot-101").body,
  "[Stopped]",
  "Delayed /api/v4/bootstrap qa_card for stopped turn must clamp to [Stopped]",
);

// FLINT-R4-1: When a turn was stopped AFTER partial display (`truncatedLen > 0`), its retained `run_card` is marked `stopped: true`!
T.state.d2CancelledTurns.set("turn-partial-rc", {
  truncatedLen: 12,
  partialBody: "Partial seen",
  entryId: "qa-partial-rc",
});
T.applyDelivery2ServerPayload({
  seq: 25,
  status: "live",
  entries: [
    {
      id: "run-partial-rc",
      kind: "run_card",
      seq: 25,
      turn_id: "turn-partial-rc",
      current_step_num: "04",
      current_step_label: "Estimate ready",
      current_step_display: "04 · Estimate ready",
      completed: false,
    },
    {
      id: "qa-partial-rc",
      kind: "qa_card",
      seq: 25,
      turn_id: "turn-partial-rc",
      author: "Delivery-2",
      body: "Partial seen plus unseen continuation",
      sources: [{ id: "src-prc", label: "Inbox", hash: "#inbox" }],
    },
  ],
});
assert.equal(
  T.state.data.delivery2.entries.find((e) => e.id === "run-partial-rc").stopped,
  true,
  "Retained run_card on mid-stream cancelled turn must be marked stopped: true",
);
assert.equal(
  T.state.data.delivery2.entries.find((e) => e.id === "qa-partial-rc").body,
  "Partial seen",
  "Mid-stream cancelled qa_card must preserve seen prefix",
);

// K3: Collapsed .d2-disclosure-body sets .inert=true + aria-hidden="true" and clears both on expand
T.applyDelivery2ServerPayload({
  seq: 26,
  status: "live",
  entries: [
    {
      id: "qa-disc-k3",
      kind: "qa_card",
      seq: 26,
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
  cancelAnimationFrame: clearTimeout,
  Float32Array,
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

// K5: Open-redirect query/fragment schemes + WHATWG backslash/userinfo/encoded-slash tricks are neutralized (`ALISTAIR-R3-3`)
for (const badUrl of [
  "https://chinwag.sh/open?next=https://evil.example/phish",
  "https://chinwag.sh/pricing?redirect=//evil.example",
  "https://chinwag.sh/open?next=/\\evil.example",
  "https://chinwag.sh/open?next=%2f/evil.example",
  "https://chinwag.sh/open?next=%5cevil.example",
  "https://chinwag.sh/open?next=%252f%252fevil.example",
  "https://chinwag.sh/open?user=foo@evil.example",
  "https://chinwag.sh/open?user=foo%40evil.example",
]) {
  assert.equal(
    T.safeChinwagOutboundUrl(badUrl),
    "https://chinwag.sh/open",
    `safeChinwagOutboundUrl must neutralize ${badUrl}`,
  );
}

// ============================================================================
// Suite L: Deterministic CSS Cascade + 2D Bounding-Box Non-Overlap Ratchet
// Guarantees stationary/in-flow rail toggles & action icons NEVER collide with
// `.d2-title` ("Delivery-2"), `#d2-status-word`, or `.d2-spine-dots` across
// 1440x900 expanded, 1280x900 & 1200x900 spine/expanded, and 390x844 & 320x568 mobile drawer.
// ============================================================================
function parseCssRulesForCascade(cssText) {
  const clean = cssText.replace(/\/\*[\s\S]*?\*\//g, "");
  const rules = [];
  let order = 0;

  function parseDecls(body) {
    const out = [];
    for (const rawDecl of body.split(";")) {
      const idx = rawDecl.indexOf(":");
      if (idx <= 0) continue;
      const prop = rawDecl.slice(0, idx).trim().toLowerCase();
      let val = rawDecl.slice(idx + 1).trim();
      if (!prop || !val) continue;
      let important = false;
      if (/!important\s*$/i.test(val)) {
        important = true;
        val = val.replace(/!important\s*$/i, "").trim();
      }
      if (prop === "padding" || prop === "margin") {
        const parts = val.split(/\s+/).filter(Boolean);
        const top = parts[0] || "0px";
        const right = parts[1] || top;
        const bottom = parts[2] || top;
        const left = parts[3] || right;
        out.push({ prop: `${prop}-top`, val: top, important });
        out.push({ prop: `${prop}-right`, val: right, important });
        out.push({ prop: `${prop}-bottom`, val: bottom, important });
        out.push({ prop: `${prop}-left`, val: left, important });
      } else {
        out.push({ prop, val, important });
      }
    }
    return out;
  }

  let i = 0;
  while (i < clean.length) {
    while (i < clean.length && /\s/.test(clean[i])) i += 1;
    if (i >= clean.length) break;
    const openBrace = clean.indexOf("{", i);
    if (openBrace < 0) break;
    const prelude = clean.slice(i, openBrace).trim();
    let depth = 1;
    let j = openBrace + 1;
    while (j < clean.length && depth > 0) {
      if (clean[j] === "{") depth += 1;
      else if (clean[j] === "}") depth -= 1;
      j += 1;
    }
    const inner = clean.slice(openBrace + 1, j - 1);
    if (prelude.startsWith("@media")) {
      const nested = parseCssRulesForCascade(inner);
      for (const nr of nested) {
        rules.push({
          media: prelude,
          selectors: nr.selectors,
          decls: nr.decls,
          order: (order += 1),
        });
      }
    } else if (!prelude.startsWith("@")) {
      rules.push({
        media: null,
        selectors: prelude
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        decls: parseDecls(inner),
        order: (order += 1),
      });
    }
    i = j;
  }
  return rules;
}

function evalMediaPrelude(media, vw) {
  if (!media) return true;
  for (const m of media.matchAll(/\(\s*(min-width|max-width)\s*:\s*([0-9.]+)px\s*\)/gi)) {
    const kind = m[1].toLowerCase();
    const bound = Number(m[2]);
    if (kind === "min-width" && !(vw >= bound)) return false;
    if (kind === "max-width" && !(vw <= bound)) return false;
  }
  return true;
}

function matchCompoundSelector(compound, node) {
  let s = compound.trim();
  if (!s) return null;
  let ids = 0;
  let cls = 0;
  let tags = 0;

  while (s.includes(":not(")) {
    const start = s.indexOf(":not(");
    let depth = 1;
    let k = start + 5;
    while (k < s.length && depth > 0) {
      if (s[k] === "(") depth += 1;
      else if (s[k] === ")") depth -= 1;
      k += 1;
    }
    const innerSel = s.slice(start + 5, k - 1);
    const innerMatch = matchCompoundSelector(innerSel, node);
    if (innerMatch) return null;
    if (innerSel.includes("#")) ids += 1;
    else if (innerSel.includes(".") || innerSel.includes("[")) cls += 1;
    else tags += 1;
    s = s.slice(0, start) + s.slice(k);
  }

  for (const attrMatch of s.matchAll(/\[([a-zA-Z0-9_-]+)(?:="([^"]*)")?\]/g)) {
    cls += 1;
    const attrName = attrMatch[1];
    const expected = attrMatch[2];
    const actual = node.attrs && Object.prototype.hasOwnProperty.call(node.attrs, attrName) ? node.attrs[attrName] : null;
    if (actual === null || actual === undefined) return null;
    if (expected !== undefined && String(actual) !== expected) return null;
  }
  s = s.replace(/\[[^\]]+\]/g, "");

  for (const pseudoMatch of s.matchAll(/:([a-zA-Z0-9_-]+)/g)) {
    const pName = pseudoMatch[1];
    if (pName === "hover" || pName === "focus" || pName === "focus-visible" || pName === "active") {
      return null;
    }
    if (pName === "root") {
      cls += 1;
      if (node.tag !== "html") return null;
    } else {
      return null;
    }
  }
  s = s.replace(/:[a-zA-Z0-9_-]+/g, "");

  for (const idMatch of s.matchAll(/#([a-zA-Z0-9_-]+)/g)) {
    ids += 1;
    if (node.id !== idMatch[1]) return null;
  }
  s = s.replace(/#[a-zA-Z0-9_-]+/g, "");

  const classSet = new Set((node.className || "").split(/\s+/).filter(Boolean));
  for (const clsMatch of s.matchAll(/\.([a-zA-Z0-9_-]+)/g)) {
    cls += 1;
    if (!classSet.has(clsMatch[1])) return null;
  }
  s = s.replace(/\.[a-zA-Z0-9_-]+/g, "").trim();

  if (s && s !== "*") {
    tags += 1;
    if ((node.tag || "").toLowerCase() !== s.toLowerCase()) return null;
  }
  return [ids, cls, tags];
}

function matchSelectorChain(selector, chain) {
  if (selector.includes("+") || selector.includes("~")) return null;
  const tokens = [];
  let cur = "";
  let parenDepth = 0;
  let bracketDepth = 0;
  let inQuote = null;
  for (let i = 0; i < selector.length; i += 1) {
    const ch = selector[i];
    if (inQuote) {
      cur += ch;
      if (ch === inQuote && selector[i - 1] !== "\\") inQuote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inQuote = ch;
      cur += ch;
      continue;
    }
    if (ch === "(") {
      parenDepth += 1;
      cur += ch;
      continue;
    }
    if (ch === ")") {
      parenDepth = Math.max(0, parenDepth - 1);
      cur += ch;
      continue;
    }
    if (ch === "[") {
      bracketDepth += 1;
      cur += ch;
      continue;
    }
    if (ch === "]") {
      bracketDepth = Math.max(0, bracketDepth - 1);
      cur += ch;
      continue;
    }
    if (parenDepth === 0 && bracketDepth === 0) {
      if (ch === ">") {
        if (cur.trim()) tokens.push(cur.trim());
        tokens.push(">");
        cur = "";
        continue;
      }
      if (/\s/.test(ch)) {
        if (cur.trim()) tokens.push(cur.trim());
        cur = "";
        continue;
      }
    }
    cur += ch;
  }
  if (cur.trim()) tokens.push(cur.trim());
  if (tokens.length === 0 || tokens[0] === ">" || tokens[tokens.length - 1] === ">") return null;

  const steps = [];
  let pendingCombinator = " ";
  for (const tok of tokens) {
    if (tok === ">") {
      if (pendingCombinator === ">") return null;
      pendingCombinator = ">";
    } else {
      steps.push({ compound: tok, combinatorToRight: null });
      if (steps.length >= 2) {
        steps[steps.length - 2].combinatorToRight = pendingCombinator;
      }
      pendingCombinator = " ";
    }
  }
  if (steps.length === 0) return null;

  const lastSpec = matchCompoundSelector(steps[steps.length - 1].compound, chain[chain.length - 1]);
  if (!lastSpec) return null;

  function matchAncestors(stepIdx, childChainIdx) {
    if (stepIdx < 0) return [0, 0, 0];
    const comb = steps[stepIdx].combinatorToRight;
    if (comb === ">") {
      const parentIdx = childChainIdx - 1;
      if (parentIdx < 0) return null;
      const spec = matchCompoundSelector(steps[stepIdx].compound, chain[parentIdx]);
      if (!spec) return null;
      const rest = matchAncestors(stepIdx - 1, parentIdx);
      if (!rest) return null;
      return [spec[0] + rest[0], spec[1] + rest[1], spec[2] + rest[2]];
    }
    for (let ancIdx = childChainIdx - 1; ancIdx >= 0; ancIdx -= 1) {
      const spec = matchCompoundSelector(steps[stepIdx].compound, chain[ancIdx]);
      if (!spec) continue;
      const rest = matchAncestors(stepIdx - 1, ancIdx);
      if (rest) {
        return [spec[0] + rest[0], spec[1] + rest[1], spec[2] + rest[2]];
      }
    }
    return null;
  }

  const ancSpec = matchAncestors(steps.length - 2, chain.length - 1);
  if (!ancSpec) return null;
  return [lastSpec[0] + ancSpec[0], lastSpec[1] + ancSpec[1], lastSpec[2] + ancSpec[2]];
}

function compareCascadeRank(a, b) {
  for (let idx = 0; idx < a.length; idx += 1) {
    if (a[idx] !== b[idx]) return a[idx] - b[idx];
  }
  return 0;
}

function evalArithmeticExpr(src) {
  const tokenRe = /\d+(?:\.\d+)?|\.\d+|[+\-*/()]|\S+/g;
  const tokens = src.match(tokenRe) || [];
  if (tokens.length === 0) return Number.NaN;
  for (const tok of tokens) {
    if (!/^(?:\d+(?:\.\d+)?|\.\d+|[+\-*/()])$/.test(tok)) {
      return Number.NaN;
    }
  }
  let pos = 0;
  function parseAddSub() {
    let val = parseMulDiv();
    while (pos < tokens.length && (tokens[pos] === "+" || tokens[pos] === "-")) {
      const op = tokens[pos++];
      const rhs = parseMulDiv();
      val = op === "+" ? val + rhs : val - rhs;
    }
    return val;
  }
  function parseMulDiv() {
    let val = parsePrimary();
    while (pos < tokens.length && (tokens[pos] === "*" || tokens[pos] === "/")) {
      const op = tokens[pos++];
      const rhs = parsePrimary();
      val = op === "*" ? val * rhs : rhs !== 0 ? val / rhs : Number.NaN;
    }
    return val;
  }
  function parsePrimary() {
    if (pos >= tokens.length) return Number.NaN;
    if (tokens[pos] === "-") {
      pos += 1;
      return -parsePrimary();
    }
    if (tokens[pos] === "(") {
      pos += 1;
      const inner = parseAddSub();
      if (tokens[pos] !== ")") return Number.NaN;
      pos += 1;
      return inner;
    }
    const tok = tokens[pos];
    if (!/^(?:\d+(?:\.\d+)?|\.\d+)$/.test(tok)) return Number.NaN;
    pos += 1;
    return Number(tok);
  }
  const result = parseAddSub();
  return pos === tokens.length ? result : Number.NaN;
}

function splitTopLevelCommaArgs(src) {
  const parts = [];
  let cur = "";
  let depth = 0;
  for (let i = 0; i < src.length; i += 1) {
    const ch = src[i];
    if (ch === "(") {
      depth += 1;
      cur += ch;
    } else if (ch === ")") {
      if (depth === 0) return null;
      depth -= 1;
      cur += ch;
    } else if (ch === "," && depth === 0) {
      parts.push(cur.trim());
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (depth !== 0) return null;
  parts.push(cur.trim());
  return parts.some((p) => p === "") ? null : parts;
}

function substituteCssVars(raw, vars) {
  let v = raw;
  for (let depth = 0; depth < 8 && v.includes("var("); depth += 1) {
    let next = "";
    let idx = 0;
    while (idx < v.length) {
      const start = v.indexOf("var(", idx);
      if (start === -1) {
        next += v.slice(idx);
        break;
      }
      next += v.slice(idx, start);
      let pDepth = 1;
      let k = start + 4;
      let commaAt = -1;
      while (k < v.length && pDepth > 0) {
        if (v[k] === "(") pDepth += 1;
        else if (v[k] === ")") pDepth -= 1;
        else if (v[k] === "," && pDepth === 1 && commaAt === -1) commaAt = k;
        k += 1;
      }
      if (pDepth !== 0) return null;
      const innerEnd = k - 1;
      const rawName = (commaAt === -1 ? v.slice(start + 4, innerEnd) : v.slice(start + 4, commaAt)).trim();
      if (!/^--[a-zA-Z0-9_-]+$/.test(rawName)) return null;
      if (Object.prototype.hasOwnProperty.call(vars, rawName)) {
        next += vars[rawName];
      } else if (commaAt !== -1) {
        next += v.slice(commaAt + 1, innerEnd).trim();
      } else {
        return null;
      }
      idx = k;
    }
    v = next;
  }
  return v.includes("var(") ? null : v;
}

function extractBalancedCallBody(v, fnName) {
  const prefix = `${fnName}(`;
  if (!v.startsWith(prefix) || !v.endsWith(")")) return null;
  let depth = 0;
  for (let i = fnName.length; i < v.length; i += 1) {
    if (v[i] === "(") depth += 1;
    else if (v[i] === ")") {
      depth -= 1;
      if (depth === 0 && i !== v.length - 1) return null;
    }
  }
  return depth === 0 ? v.slice(prefix.length, -1) : null;
}

function resolvePxExpr(rawVal, vars, vw) {
  if (rawVal === undefined || rawVal === null) return Number.NaN;
  const expanded = substituteCssVars(String(rawVal).trim(), vars);
  if (expanded === null) return Number.NaN;
  let v = expanded.trim();
  if (!v) return Number.NaN;
  v = v.replace(/(-?(?:\d+(?:\.\d+)?|\.\d+))vw\b/g, (_, n) => `${(Number(n) * vw) / 100}px`);
  const minBody = extractBalancedCallBody(v, "min");
  const maxBody = minBody === null ? extractBalancedCallBody(v, "max") : null;
  if (minBody !== null || maxBody !== null) {
    const isMin = minBody !== null;
    const rawArgs = splitTopLevelCommaArgs(isMin ? minBody : maxBody);
    if (!rawArgs || rawArgs.length === 0) return Number.NaN;
    const args = rawArgs.map((part) => resolvePxExpr(part, vars, vw));
    if (args.some((x) => !Number.isFinite(x))) return Number.NaN;
    return isMin ? Math.min(...args) : Math.max(...args);
  }
  const calcBody = extractBalancedCallBody(v, "calc");
  if (calcBody !== null) {
    const inner = calcBody
      .replace(/\bcalc\(/g, "(")
      .replace(/(-?(?:\d+(?:\.\d+)?|\.\d+))px\b/g, "$1")
      .trim();
    if (/^[0-9.+\-*/()\s]+$/.test(inner)) {
      return evalArithmeticExpr(inner);
    }
    return Number.NaN;
  }
  const m = v.match(/^(-?(?:\d+(?:\.\d+)?|\.\d+))(px)?$/);
  if (!m) return Number.NaN;
  const num = Number(m[1]);
  // In CSS, only literal zero may omit its unit (`0`); non-zero unitless lengths are invalid
  if (!m[2] && num !== 0) return Number.NaN;
  return num;
}

function requireFinitePx(rawVal, vars, vw, label) {
  assert.ok(
    rawVal !== undefined && rawVal !== null && String(rawVal).trim() !== "",
    `Missing required CSS declaration for ${label}`,
  );
  const px = resolvePxExpr(rawVal, vars, vw);
  assert.ok(Number.isFinite(px), `Unparseable CSS px value '${rawVal}' for ${label}`);
  return px;
}

function requirePositivePx(rawVal, vars, vw, label) {
  const px = requireFinitePx(rawVal, vars, vw, label);
  assert.ok(px > 0, `Expected positive CSS px value for ${label}, got ${px}`);
  return px;
}

function computeDelivery2HeaderBoxes(
  cssText,
  vw,
  vh,
  htmlAttrs,
  { statusText = "Waiting for you", glyphEmRatio = 0.62 } = {},
) {
  if (!d2Track.querySelector(".d2-head")) {
    T.renderDelivery2Panel();
  }
  const rules = parseCssRulesForCascade(cssText);
  // Guardrail: verify zero `.d2-` selectors use sibling combinators (`+` or `~`) that would be skipped
  for (const r of rules) {
    for (const sel of r.selectors) {
      if (sel.includes(".d2-") || sel.includes("#d2-")) {
        assert.equal(
          sel.includes("+") || sel.includes("~"),
          false,
          `Unsupported sibling combinator in Delivery-2 selector '${sel}'`,
        );
      }
    }
  }
  const htmlNode = { tag: "html", id: "", className: "", attrs: htmlAttrs };
  const bodyNode = { tag: "body", id: "doc-body", className: "", attrs: {} };
  const appBodyNode = { tag: "div", id: "app-body", className: "app-body", attrs: {} };
  const railNode = { tag: "aside", id: "d2-rail", className: "d2-rail", attrs: {} };

  function styleFor(chain) {
    const winners = new Map();
    for (const r of rules) {
      if (!evalMediaPrelude(r.media, vw)) continue;
      let bestSpec = null;
      for (const sel of r.selectors) {
        const sp = matchSelectorChain(sel, chain);
        if (sp && (!bestSpec || compareCascadeRank(sp, bestSpec) > 0)) {
          bestSpec = sp;
        }
      }
      if (!bestSpec) continue;
      for (const d of r.decls) {
        const rank = [d.important ? 1 : 0, bestSpec[0], bestSpec[1], bestSpec[2], r.order];
        const prev = winners.get(d.prop);
        if (!prev || compareCascadeRank(rank, prev.rank) >= 0) {
          winners.set(d.prop, { val: d.val, rank });
        }
      }
    }
    const out = {};
    for (const [k, v] of winners.entries()) out[k] = v.val;
    return out;
  }

  const rootStyle = styleFor([htmlNode]);
  const vars = {};
  for (const [k, v] of Object.entries(rootStyle)) {
    if (k.startsWith("--")) vars[k] = v;
  }

  const railChain = [htmlNode, bodyNode, appBodyNode, railNode];
  const railStyle = styleFor(railChain);
  // On <960px, `:root` sets `--rail-current: 0px` while `.d2-rail` overrides `width: min(...)` / `100vw`
  const railWidth = requirePositivePx(railStyle.width, vars, vw, ".d2-rail width");

  const toggleFixedStyle = styleFor([
    ...railChain,
    { tag: "button", id: "d2-rail-toggle-fixed", className: "d2-rail-toggle d2-rail-toggle-fixed", attrs: {} },
  ]);
  const trackChain = [...railChain, { tag: "div", id: "d2-track", className: "d2-track", attrs: {} }];
  const trackStyle = styleFor(trackChain);
  const spineChain = [...railChain, { tag: "div", id: "d2-spine", className: "d2-spine", attrs: {} }];
  const spineStyle = styleFor(spineChain);

  const headChain = [
    ...trackChain,
    { tag: "header", id: "", className: "d2-zone-head", attrs: {} },
    { tag: "div", id: "", className: "d2-head", attrs: {} },
  ];
  const headStyle = styleFor(headChain);
  const headToggleStyle = styleFor([
    ...headChain,
    { tag: "button", id: "d2-head-toggle", className: "d2-rail-toggle", attrs: {} },
  ]);
  const titleGroupChain = [...headChain, { tag: "div", id: "", className: "d2-title-group", attrs: {} }];
  const titleGroupStyle = styleFor(titleGroupChain);
  const titleStyle = styleFor([...titleGroupChain, { tag: "span", id: "", className: "d2-title", attrs: {} }]);
  const statusWrapChain = [...titleGroupChain, { tag: "span", id: "", className: "d2-status-wrap", attrs: {} }];
  const statusWrapStyle = styleFor(statusWrapChain);
  const statusDotStyle = styleFor([...statusWrapChain, { tag: "span", id: "", className: "d2-status-dot", attrs: {} }]);
  const statusWordStyle = styleFor([
    ...statusWrapChain,
    { tag: "span", id: "d2-status-word", className: "d2-status-word", attrs: {} },
  ]);
  const actionsChain = [...headChain, { tag: "div", id: "", className: "d2-head-actions", attrs: {} }];
  const actionsStyle = styleFor(actionsChain);
  const actionBtnStyle = styleFor([
    ...actionsChain,
    { tag: "button", id: "d2-btn-new-thread", className: "d2-icon-btn", attrs: {} },
  ]);

  const spineTopChain = [...spineChain, { tag: "div", id: "", className: "d2-spine-top", attrs: {} }];
  const spineTopStyle = styleFor(spineTopChain);
  const spineToggleStyle = styleFor([
    ...spineTopChain,
    { tag: "button", id: "d2-spine-toggle", className: "d2-rail-toggle", attrs: {} },
  ]);
  const spineComposeStyle = styleFor([
    ...spineChain,
    { tag: "div", id: "", className: "d2-spine-bottom", attrs: {} },
    { tag: "button", id: "d2-spine-compose", className: "d2-spine-compose", attrs: {} },
  ]);

  const visibleButtons = [];
  if ((toggleFixedStyle.display || "inline-flex") !== "none") {
    const left = requireFinitePx(toggleFixedStyle.left, vars, vw, "#d2-rail-toggle-fixed left");
    const top = requireFinitePx(toggleFixedStyle.top, vars, vw, "#d2-rail-toggle-fixed top");
    const w = requirePositivePx(toggleFixedStyle.width, vars, vw, "#d2-rail-toggle-fixed width");
    const h = requirePositivePx(toggleFixedStyle.height, vars, vw, "#d2-rail-toggle-fixed height");
    visibleButtons.push({ id: "d2-rail-toggle-fixed", left, top, right: left + w, bottom: top + h });
  }

  const trackVisible = (trackStyle.display || "grid") !== "none";
  const spineVisible = (spineStyle.display || "none") !== "none";
  let titleRect = null;
  let statusWordRect = null;
  let rawTitleW = 0;
  const titleGroupOverflow = titleGroupStyle.overflow || "visible";
  const titleFlexShrink = titleStyle["flex-shrink"] || "1";

  if (trackVisible) {
    const trackW =
      trackStyle.width === "100%" ? railWidth : requirePositivePx(trackStyle.width, vars, vw, ".d2-track width");
    const padTop = requireFinitePx(headStyle["padding-top"], vars, vw, ".d2-head padding-top");
    const padRight = requireFinitePx(headStyle["padding-right"], vars, vw, ".d2-head padding-right");
    const padBottom = requireFinitePx(headStyle["padding-bottom"], vars, vw, ".d2-head padding-bottom");
    const padLeft = requireFinitePx(headStyle["padding-left"], vars, vw, ".d2-head padding-left");
    const headGap = requireFinitePx(headStyle.gap, vars, vw, ".d2-head gap");
    const btnH = requirePositivePx(actionBtnStyle.height, vars, vw, ".d2-icon-btn height");
    const btnW = requirePositivePx(actionBtnStyle.width, vars, vw, ".d2-icon-btn width");
    const actGap = requireFinitePx(actionsStyle.gap, vars, vw, ".d2-head-actions gap");
    const contentTop = padTop;
    const contentH = btnH;

    let cursorX = padLeft;
    if ((headToggleStyle.display || "inline-flex") !== "none") {
      const ml = requireFinitePx(headToggleStyle["margin-left"], vars, vw, "#d2-head-toggle margin-left");
      const tw = requirePositivePx(headToggleStyle.width, vars, vw, "#d2-head-toggle width");
      const th = requirePositivePx(headToggleStyle.height, vars, vw, "#d2-head-toggle height");
      const tLeft = cursorX + ml;
      visibleButtons.push({
        id: "d2-head-toggle",
        left: tLeft,
        top: contentTop,
        right: tLeft + tw,
        bottom: contentTop + th,
      });
      cursorX = tLeft + tw + headGap;
    }

    const domActionIds = Array.from(d2Track.querySelector(".d2-head-actions").children).map((b) => b.id);
    assert.ok(domActionIds.length > 0, "Rendered .d2-head-actions must contain >=1 button");
    const actionsTotalW = domActionIds.length * btnW + (domActionIds.length - 1) * actGap;
    const actionsLeft = trackW - padRight - actionsTotalW;
    domActionIds.forEach((id, idx) => {
      const bLeft = actionsLeft + idx * (btnW + actGap);
      visibleButtons.push({
        id,
        left: bLeft,
        top: contentTop,
        right: bLeft + btnW,
        bottom: contentTop + btnH,
      });
    });

    const renderedTitleText = d2Track.querySelector(".d2-title").textContent;
    assert.ok(renderedTitleText.length > 0, "Rendered .d2-title must not be empty");
    const titleGroupMaxRight = Math.max(cursorX, actionsLeft - headGap);
    const titleFontPx = requirePositivePx(titleStyle["font-size"], vars, vw, ".d2-title font-size");
    const titleLineH = requirePositivePx(titleStyle["line-height"], vars, vw, ".d2-title line-height");
    rawTitleW = Math.ceil(renderedTitleText.length * titleFontPx * glyphEmRatio);
    const titleUnclipped = titleFlexShrink === "0" && titleGroupOverflow !== "hidden";
    const titleRight = titleUnclipped ? cursorX + rawTitleW : Math.min(titleGroupMaxRight, cursorX + rawTitleW);
    const titleTop = contentTop + (contentH - titleLineH) / 2;
    titleRect = {
      id: "d2-title",
      left: cursorX,
      top: titleTop,
      right: titleRight,
      bottom: titleTop + titleLineH,
      padBottom,
    };

    const tgGap = requireFinitePx(titleGroupStyle.gap, vars, vw, ".d2-title-group gap");
    const swGap = requireFinitePx(statusWrapStyle.gap, vars, vw, ".d2-status-wrap gap");
    const dotW = requirePositivePx(statusDotStyle.width, vars, vw, ".d2-status-dot width");
    const wordFontPx = requirePositivePx(statusWordStyle["font-size"], vars, vw, ".d2-status-word font-size");
    const wordLineH = requirePositivePx(statusWordStyle["line-height"], vars, vw, ".d2-status-word line-height");
    const wordLeft = Math.min(titleGroupMaxRight, titleRight + tgGap + dotW + swGap);
    const rawWordW = Math.ceil(statusText.length * wordFontPx * glyphEmRatio);
    const wordRight =
      statusWordStyle.overflow === "hidden"
        ? Math.min(titleGroupMaxRight, wordLeft + rawWordW)
        : wordLeft + rawWordW;
    const wordTop = contentTop + (contentH - wordLineH) / 2;
    statusWordRect = {
      id: "d2-status-word",
      left: wordLeft,
      top: wordTop,
      right: wordRight,
      bottom: wordTop + wordLineH,
    };
  }

  let spineDotsRect = null;
  if (spineVisible) {
    const spineDotsChain = [...spineTopChain, { tag: "div", id: "", className: "d2-spine-dots", attrs: {} }];
    const spineDotsStyle = styleFor(spineDotsChain);
    const spineDotStyle = styleFor([...spineDotsChain, { tag: "span", id: "", className: "d2-spine-dot", attrs: {} }]);
    const spinePadTop = requireFinitePx(spineStyle["padding-top"], vars, vw, ".d2-spine padding-top");
    const spinePadBottom = requireFinitePx(spineStyle["padding-bottom"], vars, vw, ".d2-spine padding-bottom");
    const spineTopPad = requireFinitePx(spineTopStyle["padding-top"], vars, vw, ".d2-spine-top padding-top");
    let spineCursorY = spinePadTop + spineTopPad;
    if ((spineToggleStyle.display || "inline-flex") !== "none") {
      const sw = requirePositivePx(spineToggleStyle.width, vars, vw, "#d2-spine-toggle width");
      const sh = requirePositivePx(spineToggleStyle.height, vars, vw, "#d2-spine-toggle height");
      const sLeft = (railWidth - 1 - sw) / 2;
      visibleButtons.push({
        id: "d2-spine-toggle",
        left: sLeft,
        top: spineCursorY,
        right: sLeft + sw,
        bottom: spineCursorY + sh,
      });
      spineCursorY += sh + requireFinitePx(spineTopStyle.gap, vars, vw, ".d2-spine-top gap");
    }
    const dotSize = requirePositivePx(spineDotStyle.width, vars, vw, ".d2-spine-dot width");
    const dotH = requirePositivePx(spineDotStyle.height, vars, vw, ".d2-spine-dot height");
    const dotsGap = requireFinitePx(spineDotsStyle.gap, vars, vw, ".d2-spine-dots gap");
    const dotsPadTop = requireFinitePx(spineDotsStyle["padding-top"], vars, vw, ".d2-spine-dots padding-top");
    const dotsPadBottom = requireFinitePx(spineDotsStyle["padding-bottom"], vars, vw, ".d2-spine-dots padding-bottom");
    const surfaceCount = d2Spine.querySelectorAll(".d2-spine-dot").length;
    assert.ok(surfaceCount > 0, "Rendered .d2-spine-dots must contain >=1 dot");
    spineDotsRect = {
      id: "d2-spine-dots",
      left: (railWidth - 1 - dotSize) / 2,
      top: spineCursorY,
      right: (railWidth - 1 + dotSize) / 2,
      bottom: spineCursorY + dotsPadTop + surfaceCount * dotH + (surfaceCount - 1) * dotsGap + dotsPadBottom,
    };
    const cw = requirePositivePx(spineComposeStyle.width, vars, vw, "#d2-spine-compose width");
    const ch = requirePositivePx(spineComposeStyle.height, vars, vw, "#d2-spine-compose height");
    visibleButtons.push({
      id: "d2-spine-compose",
      left: (railWidth - 1 - cw) / 2,
      top: vh - spinePadBottom - ch,
      right: (railWidth - 1 + cw) / 2,
      bottom: vh - spinePadBottom,
    });
  }

  return {
    visibleButtons,
    titleRect,
    statusWordRect,
    spineDotsRect,
    trackVisible,
    spineVisible,
    rawTitleW,
    titleGroupOverflow,
    titleFlexShrink,
  };
}

function rectsOverlap(a, b) {
  return a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
}

// L1: Verify DOM rendered by `renderDelivery2Panel()` contains exact single `.d2-title` ("Delivery-2") & expected header buttons
T.renderDelivery2Panel();
const renderedTitleEl = d2Track.querySelector(".d2-title");
assert.ok(renderedTitleEl, "Rendered Delivery-2 header must contain .d2-title");
assert.equal(renderedTitleEl.textContent, "Delivery-2");
assert.ok(d2RailToggleFixed.id === "d2-rail-toggle-fixed", "Fixed rail toggle must exist on #d2-rail");
const renderedHeadEl = d2Track.querySelector(".d2-head");
assert.ok(renderedHeadEl, "Rendered Delivery-2 header must contain .d2-head");
const renderedActionIds = Array.from(renderedHeadEl.querySelector(".d2-head-actions").children).map((b) => b.id);
assert.deepEqual(
  renderedActionIds,
  ["d2-btn-mic", "d2-btn-new-thread", "d2-btn-history", "d2-btn-collapse"],
  "Rendered .d2-head-actions buttons must match bounded layout model IDs",
);
assert.ok(d2Track.querySelector("#d2-head-toggle"), "In-flow #d2-head-toggle must exist for <960px drawer");
assert.ok(d2Spine.querySelector("#d2-spine-toggle"), "In-flow #d2-spine-toggle must exist in .d2-spine");

// L2: 1440x900 Expanded (`data-rail="expanded"`) — zero overlap & zero title clipping across narrow (0.50em) & wide (0.68em) glyph metrics
for (const glyphEmRatio of [0.5, 0.62, 0.68]) {
  const layoutDesktopExpanded = computeDelivery2HeaderBoxes(
    stylesCss,
    1440,
    900,
    { "data-rail": "expanded" },
    { glyphEmRatio },
  );
  assert.equal(layoutDesktopExpanded.trackVisible, true);
  assert.equal(layoutDesktopExpanded.spineVisible, false);
  assert.notEqual(
    layoutDesktopExpanded.titleGroupOverflow,
    "hidden",
    ".d2-title-group must NOT set overflow:hidden so .d2-title can never be clipped",
  );
  assert.equal(layoutDesktopExpanded.titleFlexShrink, "0", ".d2-title must set flex-shrink: 0");
  assert.equal(
    layoutDesktopExpanded.titleRect.right - layoutDesktopExpanded.titleRect.left,
    layoutDesktopExpanded.rawTitleW,
    ".d2-title box must preserve full unclipped width",
  );
  assert.equal(
    layoutDesktopExpanded.visibleButtons.some((b) => b.id === "d2-head-toggle" || b.id === "d2-spine-toggle"),
    false,
    "Desktop >=960px must hide in-flow #d2-head-toggle and #d2-spine-toggle so only stationary #d2-rail-toggle-fixed is visible",
  );
  const desktopFixedToggle = layoutDesktopExpanded.visibleButtons.find((b) => b.id === "d2-rail-toggle-fixed");
  assert.ok(desktopFixedToggle, "Stationary #d2-rail-toggle-fixed must be visible at 1440x900");
  assert.ok(
    layoutDesktopExpanded.titleRect.left - desktopFixedToggle.right >= 6,
    `Delivery-2 .d2-title (left=${layoutDesktopExpanded.titleRect.left}px) must clear #d2-rail-toggle-fixed (right=${desktopFixedToggle.right}px) by >=6px`,
  );
  for (const btn of layoutDesktopExpanded.visibleButtons) {
    assert.equal(
      rectsOverlap(btn, layoutDesktopExpanded.titleRect),
      false,
      `1440x900 expanded (em=${glyphEmRatio}): button #${btn.id} overlaps .d2-title`,
    );
    assert.equal(
      rectsOverlap(btn, layoutDesktopExpanded.statusWordRect),
      false,
      `1440x900 expanded (em=${glyphEmRatio}): button #${btn.id} overlaps #d2-status-word`,
    );
  }
}

// L3: 1280x900 & 1200x900 Collapsed 44px Spine & User-Expanded — zero overlap & zero title clipping in both states
for (const [lVw, lVh] of [
  [1280, 900],
  [1200, 900],
]) {
  const layoutSpineCollapsed = computeDelivery2HeaderBoxes(stylesCss, lVw, lVh, {});
  assert.equal(layoutSpineCollapsed.trackVisible, false);
  assert.equal(layoutSpineCollapsed.spineVisible, true);
  for (const btn of layoutSpineCollapsed.visibleButtons) {
    assert.equal(
      rectsOverlap(btn, layoutSpineCollapsed.spineDotsRect),
      false,
      `${lVw}x${lVh} spine: button #${btn.id} overlaps .d2-spine-dots`,
    );
  }
  const layoutLaptopExpanded = computeDelivery2HeaderBoxes(stylesCss, lVw, lVh, { "data-rail": "expanded" });
  assert.notEqual(layoutLaptopExpanded.titleGroupOverflow, "hidden");
  assert.equal(layoutLaptopExpanded.titleFlexShrink, "0");
  assert.equal(
    layoutLaptopExpanded.titleRect.right - layoutLaptopExpanded.titleRect.left,
    layoutLaptopExpanded.rawTitleW,
    `${lVw}x${lVh} expanded: .d2-title must remain completely unclipped`,
  );
  for (const btn of layoutLaptopExpanded.visibleButtons) {
    assert.equal(rectsOverlap(btn, layoutLaptopExpanded.titleRect), false, `${lVw}x${lVh} expanded overlap on #${btn.id}`);
    assert.equal(
      rectsOverlap(btn, layoutLaptopExpanded.statusWordRect),
      false,
      `${lVw}x${lVh} status overlap on #${btn.id}`,
    );
  }
}

// L4: 390x844 & 320x568 Mobile Open Drawer — `#d2-rail-toggle-fixed` hidden, unclipped `.d2-title` clears all buttons
for (const [mVw, mVh] of [
  [390, 844],
  [320, 568],
]) {
  const layoutMobileDrawer = computeDelivery2HeaderBoxes(stylesCss, mVw, mVh, { "data-d2-drawer": "open" });
  assert.notEqual(layoutMobileDrawer.titleGroupOverflow, "hidden");
  assert.equal(layoutMobileDrawer.titleFlexShrink, "0");
  assert.equal(
    layoutMobileDrawer.titleRect.right - layoutMobileDrawer.titleRect.left,
    layoutMobileDrawer.rawTitleW,
    `${mVw}x${mVh} mobile drawer: .d2-title must remain completely unclipped`,
  );
  assert.equal(
    layoutMobileDrawer.visibleButtons.some((b) => b.id === "d2-rail-toggle-fixed"),
    false,
    "<960px mobile drawer must hide #d2-rail-toggle-fixed",
  );
  const mobileHeadToggle = layoutMobileDrawer.visibleButtons.find((b) => b.id === "d2-head-toggle");
  assert.ok(mobileHeadToggle, "<960px mobile drawer must show in-flow #d2-head-toggle");
  for (const btn of layoutMobileDrawer.visibleButtons) {
    assert.equal(
      rectsOverlap(btn, layoutMobileDrawer.titleRect),
      false,
      `${mVw}x${mVh} mobile drawer: button #${btn.id} overlaps .d2-title`,
    );
    assert.equal(
      rectsOverlap(btn, layoutMobileDrawer.statusWordRect),
      false,
      `${mVw}x${mVh} mobile drawer: button #${btn.id} overlaps #d2-status-word`,
    );
  }
}

// L5: Quintuple Mutant Canaries (L5a–L5e) —
// (L5a) Exact reproduction of the `0d600d0` cascade-order bug: earlier `@media (min-width: 960px) { .d2-head { padding-left: 41px; } }`
//       gets reset back to `12px` by the later `.d2-head { padding: 8px var(--rail-inset) 6px; }` shorthand -> title lands at x=12 overlapping [9..35]!
const mutatedCascadeResetCss = stylesCss.replace(
  /@media\s*\(min-width:\s*960px\)\s*\{\s*\.d2-rail\s+\.d2-head\s*\{\s*padding-left:\s*42px;\s*\}\s*\}/,
  "",
);
assert.notEqual(mutatedCascadeResetCss, stylesCss, "Mutant canary regex must match production .d2-rail .d2-head rule");
const cascadeResetLayout = computeDelivery2HeaderBoxes(
  `@media (min-width: 960px) { .d2-head { padding-left: 41px; } }\n${mutatedCascadeResetCss}`,
  1440,
  900,
  { "data-rail": "expanded" },
);
assert.equal(
  cascadeResetLayout.titleRect.left,
  12,
  "Canary L5a: later `.d2-head { padding: ... }` shorthand resets equal-specificity earlier `padding-left: 41px` back to 12px",
);
assert.equal(
  rectsOverlap(
    cascadeResetLayout.visibleButtons.find((b) => b.id === "d2-rail-toggle-fixed"),
    cascadeResetLayout.titleRect,
  ),
  true,
  "Canary L5a MUST detect overlap when shorthand resets padding-left to 12px",
);

// (L5b) Active insufficient-inset mutant: `.d2-rail .d2-head { padding-left: 24px; }` wins the cascade (title.left === 24px),
//       which still collides horizontally with `#d2-rail-toggle-fixed` (`x = 9..35px`) -> AABB check catches it!
const mutatedInsufficientInsetCss = stylesCss.replace(
  /(\.d2-rail\s+\.d2-head\s*\{\s*padding-left:\s*)42px/,
  (_, prefix) => `${prefix}24px`,
);
assert.notEqual(
  mutatedInsufficientInsetCss,
  stylesCss,
  "Canary L5b regex must mutate .d2-rail .d2-head padding-left from 42px to 24px",
);
const insufficientLayout = computeDelivery2HeaderBoxes(mutatedInsufficientInsetCss, 1440, 900, {
  "data-rail": "expanded",
});
assert.equal(insufficientLayout.titleRect.left, 24);
assert.equal(
  rectsOverlap(
    insufficientLayout.visibleButtons.find((b) => b.id === "d2-rail-toggle-fixed"),
    insufficientLayout.titleRect,
  ),
  true,
  "Canary L5b MUST detect overlap when winning cascade rule leaves insufficient padding-left (24px < 35px)",
);

// (L5c) Mixed child + descendant combinator backtracking canary: `.d2-rail > div .d2-title` must backtrack past
//       `div.d2-title-group` to `div.d2-track` (direct child of `aside.d2-rail`) and catch right-side action overlap!
const backtrackingMutantLayout = computeDelivery2HeaderBoxes(
  `${stylesCss}\n.d2-rail > div .d2-title { font-size: 200px; }`,
  1440,
  900,
  { "data-rail": "expanded" },
);
assert.equal(
  rectsOverlap(
    backtrackingMutantLayout.visibleButtons.find((b) => b.id === "d2-btn-new-thread"),
    backtrackingMutantLayout.titleRect,
  ),
  true,
  "Canary L5c MUST backtrack `.d2-rail > div .d2-title` to `div.d2-track` and detect overlap with #d2-btn-new-thread",
);

// (L5d) Missing CSS declaration fail-closed canary: stripping `.d2-title` metrics must throw rather than fall back to magic constants
const missingDeclCss = stylesCss.replace(/\.d2-title\s*\{[^}]*\}/, ".d2-title {}");
assert.notEqual(missingDeclCss, stylesCss);
assert.throws(
  () => computeDelivery2HeaderBoxes(missingDeclCss, 1440, 900, { "data-rail": "expanded" }),
  /Missing required CSS declaration/,
  "Canary L5d MUST fail closed when required CSS declarations are missing",
);

// (L5e) Unresolved CSS custom property inside `calc(...)` fail-closed canary (W3C CSS Variables IACVT):
//       `calc(var(--missing-header-inset) + 42px)` and `calc(var(--missing-header-inset, ) + 42px)` MUST throw!
for (const invalidCalcExpr of [
  "calc(var(--missing-header-inset) + 42px)",
  "calc(var(--missing-header-inset, ) + 42px)",
]) {
  assert.throws(
    () =>
      computeDelivery2HeaderBoxes(
        `${stylesCss}\n@media (min-width: 960px) and (max-width: 1439.98px) { .d2-rail .d2-head { padding-left: ${invalidCalcExpr}; } }`,
        1200,
        900,
        { "data-rail": "expanded" },
      ),
    /Unparseable CSS px value/,
    `Canary L5e MUST fail closed on invalid/unresolved calc expression '${invalidCalcExpr}'`,
  );
}

// Suite M: CHWG-0255 Duplex Live Voice 7-State Machine, VoiceDelegate, spokenOption & H1–H7 Safety Guards
{
  // M1: 7-state machine & tabular timer formatting
  assert.deepEqual([...T.VOICE_STATES], [
    "idle",
    "connecting",
    "listening",
    "thinking",
    "speaking",
    "silence_warning",
    "paused",
  ]);
  assert.equal(T.canTransitionVoiceState("idle", "connecting"), true);
  assert.equal(T.canTransitionVoiceState("connecting", "listening"), true);
  assert.equal(T.canTransitionVoiceState("listening", "thinking"), true);
  assert.equal(T.canTransitionVoiceState("thinking", "speaking"), true);
  assert.equal(T.canTransitionVoiceState("listening", "silence_warning"), true);
  assert.equal(T.canTransitionVoiceState("silence_warning", "paused"), true);
  assert.equal(T.canTransitionVoiceState("paused", "listening"), true);
  assert.equal(T.canTransitionVoiceState("idle", "speaking"), false);
  assert.equal(T.formatVoiceTimer(42, 600), "00:42 / 10:00");
  assert.equal(T.formatVoiceTimer(620, 600), "10:00 / 10:00");

  // M2: Fail-closed spokenOption() parser
  const hitlOpts = ["Approve", "Deny", "Skip"];
  assert.equal(T.spokenOption("Approve please", hitlOpts), "approve");
  assert.equal(T.spokenOption("Yes, approve it, please!", hitlOpts), "approve");
  assert.equal(T.spokenOption("Okay skip that please", hitlOpts), "skip");
  for (const badUtterance of [
    "don't approve",
    "Don’t approve please",
    "do not approve",
    "never approve",
    "no approve",
    "wait don't approve",
    "yes",
    "yeah",
    "ok",
    "okay",
    "please",
    "approve or deny",
    "maybe approve",
    "",
  ]) {
    assert.equal(
      T.spokenOption(badUtterance, hitlOpts),
      null,
      `spokenOption must fail closed on '${badUtterance}'`,
    );
  }
  assert.equal(T.spokenOption("approve", ["Approve", "Approve please"]), null);
  assert.deepEqual(
    T.filterSafeVoiceOptions(["Approve & merge", "Deploy", "Push branch", "Skip", "Wait"]),
    ["Skip", "Wait"],
  );
  for (const dangerPhrase of [
    "Approve this",
    "Approve the PR",
    "Merge PR 96",
    "Merge it",
    "Go ahead and deploy it",
    "Let's ship this",
    "Push the branch",
    "Apply locally",
  ]) {
    assert.equal(
      T.isVoiceDangerApprovalAttempt(dangerPhrase, false),
      true,
      `imperative danger phrase '${dangerPhrase}' must be flagged`,
    );
  }
  assert.equal(T.isVoiceDangerApprovalAttempt("Don't approve this", true), false);
  assert.equal(T.isVoiceDangerApprovalAttempt("Did we merge PR 96?", true), false);

  // M3: VoiceDelegate dual-channel split (>=3000ms thinking hold + <=1500 sentence-boundary commentary)
  let fakeNow = 1000;
  const delegateThinking = [];
  const delegateSpoken = [];
  const vDelegate = T.createVoiceDelegate({
    nowFn: () => fakeNow,
    onThinkingLabel: (ev) => delegateThinking.push(ev),
    onSpeakCommentary: (ev) => delegateSpoken.push(ev),
  });
  const th1 = vDelegate.observeThinking("Running cleanroom test suite");
  assert.equal(th1.channel, "thinking");
  assert.equal(th1.spoken, false);
  assert.equal(th1.min_hold_ms, 3000);
  fakeNow = 2500;
  assert.equal(vDelegate.observeThinking("Checking diff hunks"), null, "must suppress rapid update <3000ms");
  fakeNow = 4000;
  const th2 = vDelegate.observeThinking("Checking diff hunks");
  assert.equal(th2.text, "Checking diff hunks");
  assert.equal(delegateThinking.length, 2);

  assert.equal(vDelegate.observeCommentary("Interrupted partial text.", { interrupted: true }), null);
  const longSentence = "Verified four modified files and confirmed every test passed cleanly. ";
  const commEv = vDelegate.observeCommentary(longSentence.repeat(30));
  assert.equal(commEv.channel, "commentary");
  assert.equal(commEv.spoken, true);
  assert.ok(Array.from(commEv.text).length <= 1500);
  assert.ok(commEv.text.endsWith("."), "truncated commentary must end cleanly at a sentence boundary");
  assert.equal(delegateSpoken.length, 1);

  // M4: Full UI Call Bar lifecycle, 75s/90s silence park, 40 Cr cap, reload rehydration & danger merge gate
  let mockVoiceSeq = 50;
  const baseUnix = Math.floor(Date.now() / 1000);
  let serverVoice = {
    session_id: null,
    thread_id: "thr-main",
    state: "idle",
    status_label: "Idle",
    timer_label: "00:00 / 10:00",
    elapsed_secs: 0,
    remaining_secs: 600,
    max_duration_secs: 600,
    opened_at_unix: null,
    expires_at_unix: null,
    credits_used: 0,
    credits_cap: 40,
    credits_rate_per_min: 0,
    pause_badge: "Paused · 0 Cr",
    muted: false,
    audio_leg_parked: true,
    ended: false,
    park_reason: null,
    ended_reason: null,
  };
  let serverEntries = [
    {
      id: "entry-hitl-danger-1",
      kind: "approval_card",
      seq: 50,
      approval_id: "hitl-danger-1",
      item_id: "run-danger-1",
      is_sample: false,
      status_badge: "Waiting for you",
      pause_badge: "Paused · 0 Cr",
      title: "Merge feature branch into main",
      question: "Approve merge into `main`?",
      settled: false,
    },
  ];

  const makeD2Envelope = () => ({
    seq: ++mockVoiceSeq,
    active_thread_id: "thr-main",
    status: "waiting_for_you",
    status_label: "Waiting for you",
    entries: serverEntries.map((e) => ({ ...e })),
    voice: { ...serverVoice },
  });

  globalThis.__mockD2VoiceHandler = async (url, body) => {
    if (url === "/api/v1/delivery2/voice/session") {
      if (body.action === "start") {
        serverVoice = {
          ...serverVoice,
          session_id: "voice-test0255",
          state: body.connecting ? "connecting" : "listening",
          status_label: body.connecting ? "Connecting…" : "Listening",
          timer_label: "00:42 / 10:00",
          elapsed_secs: 42,
          remaining_secs: 558,
          opened_at_unix: baseUnix - 42,
          expires_at_unix: baseUnix + 558,
          credits_used: 0,
          credits_cap: 40,
          credits_rate_per_min: 4,
          muted: false,
          audio_leg_parked: false,
          ended: false,
          park_reason: null,
          ended_reason: null,
        };
      } else if (body.action === "ready" || body.action === "resume") {
        serverVoice = {
          ...serverVoice,
          state: "listening",
          status_label: serverVoice.muted ? "Muted" : "Listening",
          audio_leg_parked: false,
          credits_rate_per_min: 4,
          park_reason: null,
        };
      } else if (body.action === "mute" || body.action === "unmute") {
        serverVoice = {
          ...serverVoice,
          muted: body.action === "mute",
          status_label: body.action === "mute" ? "Muted" : "Listening",
        };
      } else if (body.action === "end") {
        serverVoice = {
          ...serverVoice,
          state: "paused",
          status_label: "Call ended · 0 Cr",
          audio_leg_parked: true,
          ended: true,
          ended_reason: "user_ended",
          credits_rate_per_min: 0,
        };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true, voice: serverVoice, state: makeD2Envelope() }) };
    }
    if (url === "/api/v1/delivery2/voice/heartbeat") {
      if (Number(body.idle_secs) >= 90) {
        serverVoice = {
          ...serverVoice,
          state: "paused",
          status_label: "Voice paused · 0 Cr while paused",
          audio_leg_parked: true,
          park_reason: "silence_timeout",
          credits_rate_per_min: 0,
        };
      } else if (Number(body.idle_secs) >= 75) {
        serverVoice = {
          ...serverVoice,
          state: "silence_warning",
          status_label: "Still there? Pausing in 15s",
        };
      } else if (Number(body.hold_secs) >= 8) {
        serverVoice = {
          ...serverVoice,
          state: "paused",
          status_label: "Voice paused · 0 Cr while paused",
          audio_leg_parked: true,
          park_reason: "hold_park",
          credits_rate_per_min: 0,
        };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true, voice: serverVoice, state: makeD2Envelope() }) };
    }
    if (url === "/api/v1/delivery2/voice/park") {
      serverVoice = {
        ...serverVoice,
        state: "paused",
        status_label: "Voice paused · 0 Cr while paused",
        audio_leg_parked: true,
        park_reason: body.reason || "user_paused",
        credits_rate_per_min: 0,
      };
      return { ok: true, status: 200, json: async () => ({ ok: true, voice: serverVoice, state: makeD2Envelope() }) };
    }
    if (url === "/api/v1/delivery2/voice/turn") {
      const low = String(body.utterance || "").toLowerCase();
      if (low.includes("approve")) {
        return {
          ok: false,
          status: 403,
          json: async () => ({
            ok: false,
            error_code: "VoiceDangerApprovalForbidden",
            physical_click_required: true,
            physical_click_verified: false,
            error: "Press Approve to confirm. Voice can't approve this one.",
            message: "Press Approve to confirm. Voice can't approve this one.",
          }),
        };
      }
      const addCr = Number(body.turn_credits) || 4;
      const nextUsed = Math.min(40, serverVoice.credits_used + addCr);
      const hitCap = nextUsed >= 40;
      serverVoice = {
        ...serverVoice,
        state: hitCap ? "paused" : "speaking",
        status_label: hitCap ? "Voice paused at the 40 Cr session cap. Your thread is saved." : "Speaking",
        credits_used: nextUsed,
        audio_leg_parked: hitCap,
        ended: hitCap,
        ended_reason: hitCap ? "credits_cap_reached" : null,
        credits_rate_per_min: hitCap ? 0 : 4,
      };
      const qaEntry = {
        id: `entry-voice-qa-${mockVoiceSeq}`,
        kind: "qa_card",
        seq: mockVoiceSeq + 1,
        author: "Delivery-2",
        body: `Spoken summary for: ${body.utterance}.`,
      };
      serverEntries.push({ id: `entry-voice-u-${mockVoiceSeq}`, kind: "user_message", seq: mockVoiceSeq + 1, body: body.utterance }, qaEntry);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          ok: true,
          entry: qaEntry,
          spoken_commentary: qaEntry.body,
          voice: serverVoice,
          state: makeD2Envelope(),
        }),
      };
    }
    return { ok: true, status: 200, json: async () => ({ ok: true }) };
  };

  mockBootstrapPayload = () => ({ delivery2: makeD2Envelope() });
  await T.refreshBootstrapQuietly();
  T.renderDelivery2Panel();
  assert.equal(stubDocument.getElementById("d2-voice-bar"), null, "Idle voice state must not render Call Bar");
  assert.ok(stubDocument.getElementById("d2-composer-mic"), "Composer mic button must mount in Zone 4");

  // Start voice -> mounts Call Bar with 9 waveform bars, tabular 00:42 / 10:00 timer, Mute & End
  const startedOk = await T.startDelivery2Voice();
  assert.equal(startedOk, true);
  let callBar = stubDocument.getElementById("d2-voice-bar");
  assert.ok(callBar, "Active voice session must mount #d2-voice-bar in Zone 1");
  assert.equal(callBar.dataset.state, "listening");
  assert.equal(
    callBar.querySelector(".voice-bars").querySelectorAll("i").length,
    9,
    "Call bar must render 9 deterministic waveform bars",
  );
  assert.equal(stubDocument.getElementById("d2-voice-timer").textContent, "00:42 / 10:00");
  assert.ok(stubDocument.getElementById("d2-voice-btn-mute"));
  assert.ok(stubDocument.getElementById("d2-voice-btn-end"));

  // Mute / Unmute toggle
  await T.toggleDelivery2VoiceMute();
  assert.equal(stubDocument.getElementById("d2-voice-status").textContent, "Muted");
  await T.toggleDelivery2VoiceMute();
  assert.equal(stubDocument.getElementById("d2-voice-status").textContent, "Listening");

  // Spoken "Approve please" against unsettled danger merge card -> blocked with exact copy!
  const blockedRes = await T.sendDelivery2VoiceTurn("Approve please");
  assert.equal(blockedRes.ok, false);
  assert.equal(blockedRes.error_code, "VoiceDangerApprovalForbidden");
  assert.equal(blockedRes.message, "Press Approve to confirm. Voice can't approve this one.");
  const hitlNotice = d2Track.querySelector(".d2-hitl-voice-notice");
  assert.ok(hitlNotice, "Danger HITL card must display physical-click requirement notice");
  assert.equal(hitlNotice.textContent, "Press Approve to confirm. Voice can't approve this one.");

  // Normal voice question -> appends durable transcript entries & transitions to Speaking
  const turnOk = await T.sendDelivery2VoiceTurn("What did I miss?");
  assert.ok(turnOk && turnOk.ok);
  assert.equal(stubDocument.getElementById("d2-voice-bar").dataset.state, "speaking");

  // 75s idle -> SilenceWarning ("Still there? Pausing in 15s")
  await T.tickDelivery2VoiceHeartbeat({ idle_secs: 75 });
  assert.equal(stubDocument.getElementById("d2-voice-bar").dataset.state, "silence_warning");
  assert.equal(stubDocument.getElementById("d2-voice-status").textContent, "Still there? Pausing in 15s");

  // 90s idle -> Auto-paused at 0 Cr ("Voice paused · 0 Cr while paused") with Resume button
  await T.tickDelivery2VoiceHeartbeat({ idle_secs: 90 });
  assert.equal(stubDocument.getElementById("d2-voice-bar").dataset.state, "paused");
  assert.equal(stubDocument.getElementById("d2-voice-status").textContent, "Voice paused · 0 Cr while paused");
  assert.ok(stubDocument.getElementById("d2-voice-btn-resume"), "Paused session must expose Resume button");

  // Resume & simulate cold page reload (`d2VoiceClientLive = false` while server has active session)
  await T.resumeDelivery2Voice();
  assert.equal(stubDocument.getElementById("d2-voice-bar").dataset.state, "listening");
  T.stopDelivery2VoiceLoops();
  T.state.d2VoiceClientLive = false;
  await T.refreshBootstrapQuietly();
  T.renderDelivery2Panel();
  assert.equal(
    stubDocument.getElementById("d2-voice-bar").dataset.state,
    "paused",
    "Cold page reload must rehydrate active server session safely into Paused · 0 Cr",
  );
  assert.equal(
    d2Track.textContent.includes("Spoken summary for: What did I miss?."),
    true,
    "Durable voice transcript entries must persist across page reload",
  );

  // Resume & hit 40 Cr server cap -> ends session cleanly
  await T.resumeDelivery2Voice();
  await T.sendDelivery2VoiceTurn("Summarize board status", { turnCredits: 40 });
  assert.equal(stubDocument.getElementById("d2-voice-bar").dataset.state, "paused");
  assert.equal(stubDocument.getElementById("d2-voice-btn-resume"), null, "Capped session must not expose Resume");

  // Untrusted synthetic `.click()` (`isTrusted === false`) on Approve & merge MUST be ignored!
  d2ApprovalCalls = [];
  const physicalApproveBtn = d2Track.querySelector(".d2-hitl-primary");
  assert.ok(physicalApproveBtn, "Approve & merge button must remain mounted for physical click");
  physicalApproveBtn.click();
  await sleep(40);
  assert.equal(d2ApprovalCalls.length, 0, "Untrusted synthetic click() must NOT submit HITL approval");

  // Trusted physical click (`isTrusted === true`) on Approve & merge settles the HITL card cleanly!
  physicalApproveBtn.clickTrusted();
  await sleep(40);
  assert.equal(d2ApprovalCalls.length, 1);
  assert.equal(d2ApprovalCalls[0].physical_click_verified, true);
  assert.equal(d2ApprovalCalls[0].source, "physical_click");

  // Inbox review sheet `Approve & push to PR` ALSO blocks untrusted `.click()` and sends physical_click_verified=true on trusted click!
  globalThis.__inboxActionCalls = [];
  const inboxTestFoot = stubDocument.createElement("div");
  T.renderSheetFooter(
    {
      id: "item-inbox-gate-1",
      title: "Harden merge gate",
      is_sample: false,
      target_branch: "main",
      tool_label: "Codex",
      reviewer_label: "Gemini",
      files: [],
    },
    inboxTestFoot,
    false,
  );
  const inboxApproveBtn = inboxTestFoot.querySelector("#sheet-primary-action");
  assert.ok(inboxApproveBtn, "Inbox Approve & push to PR button must mount");
  inboxApproveBtn.click();
  await sleep(40);
  assert.equal(globalThis.__inboxActionCalls.length, 0, "Untrusted synthetic click() must NOT trigger Inbox approve");
  inboxApproveBtn.clickTrusted();
  await sleep(40);
  assert.equal(globalThis.__inboxActionCalls.length, 1);
  assert.equal(globalThis.__inboxActionCalls[0].action, "approve");
  assert.equal(globalThis.__inboxActionCalls[0].source, "physical_click");
  assert.equal(globalThis.__inboxActionCalls[0].physical_click_verified, true);

  // End call removes Call Bar cleanly
  await T.endDelivery2Voice();
  assert.equal(stubDocument.getElementById("d2-voice-bar"), null);
}

console.log(
  JSON.stringify({
    ok: true,
    script: "verify-ui-v4-contracts.mjs",
    suites_passed: 13,
  }),
);

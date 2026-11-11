// /assets/v4/app.js
// Chinwag Local App v4.1 — Customer-First Interactive SPA.
// Strict CSP compliant: zero innerHTML, zero inline style attributes, zero vendor/internal jargon.

import * as Motion from "./motion.js";

const SVG_NS = "http://www.w3.org/2000/svg";
const BOOT_PERF_MS = typeof performance !== "undefined" ? performance.now() : 0;
const BOOT_UNIX_MS = Date.now();

// ── 1 · Sanctioned DOM & No-Blank-Slot Builders ──────────────────────────────

function isAbsent(v) {
  return v === null || v === undefined || (typeof v === "string" && v.trim() === "") || Number.isNaN(v);
}

function clearNode(node) {
  if (!node) return;
  while (node.firstChild) node.removeChild(node.firstChild);
}

function el(tag, attrs = null, ...children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "className") {
        node.className = v;
      } else if (k === "dataset" && typeof v === "object") {
        for (const [dk, dv] of Object.entries(v)) {
          if (dv !== null && dv !== undefined && dv !== false) {
            node.dataset[dk] = dv === true ? "" : String(dv);
          }
        }
      } else if (k === "hidden") {
        node.hidden = Boolean(v);
      } else if (k === "checked") {
        node.checked = Boolean(v);
      } else if (k === "selected") {
        node.selected = Boolean(v);
      } else if (k === "value") {
        node.value = String(v);
      } else if (k.startsWith("on") && typeof v === "function") {
        node.addEventListener(k.slice(2).toLowerCase(), v);
      } else {
        node.setAttribute(k, v === true ? "true" : String(v));
      }
    }
  }
  appendChildren(node, children);
  return node;
}

function appendChildren(parent, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (Array.isArray(child)) {
      appendChildren(parent, child);
    } else if (child instanceof Node) {
      parent.appendChild(child);
    } else {
      parent.appendChild(document.createTextNode(String(child)));
    }
  }
}

function svgIcon(paths, { className = "icon-svg", viewBox = "0 0 16 16", pulse = false } = {}) {
  const s = document.createElementNS(SVG_NS, "svg");
  s.setAttribute("class", className);
  s.setAttribute("viewBox", viewBox);
  s.setAttribute("aria-hidden", "true");
  if (pulse) s.setAttribute("data-pulse", "");
  for (const spec of paths) {
    const elem = document.createElementNS(SVG_NS, spec.tag || "path");
    for (const [k, v] of Object.entries(spec)) {
      if (k !== "tag") elem.setAttribute(k, String(v));
    }
    s.appendChild(elem);
  }
  return s;
}

const ICONS = {
  check: () => svgIcon([{ d: "M3.2 8.4l3 3 6.6-6.8" }], { className: "icon-svg sm" }),
  copy: () => svgIcon([
    { tag: "rect", x: "5.5", y: "5.5", width: "8", height: "8", rx: "1.5" },
    { d: "M3.5 10.5H3a1.5 1.5 0 0 1-1.5-1.5V3A1.5 1.5 0 0 1 3 1.5h6A1.5 1.5 0 0 1 10.5 3v.5" },
  ], { className: "icon-svg sm" }),
  alert: (pulse = false) => svgIcon([
    { d: "M8 2.2L1.6 13.5h12.8L8 2.2z" },
    { d: "M8 6.4v3.4" },
    { tag: "circle", cx: "8", cy: "11.8", r: "0.6" },
  ], { className: "icon-svg", pulse }),
  close: () => svgIcon([{ d: "M4 4l8 8M12 4l-8 8" }], { className: "icon-svg" }),
  chevronLeft: () => svgIcon([{ d: "M10 3.5L5.5 8l4.5 4.5" }], { className: "icon-svg sm" }),
  chevronUp: () => svgIcon([{ d: "M4 10l4-4 4 4" }], { className: "icon-svg sm" }),
  chevronDown: () => svgIcon([{ d: "M4 6l4 4 4-4" }], { className: "icon-svg sm" }),
  lock: () => svgIcon([
    { tag: "rect", x: "3.5", y: "7", width: "9", height: "6.5", rx: "1.5" },
    { d: "M5.5 7V5a2.5 2.5 0 0 1 5 0v2" },
  ], { className: "icon-svg sm" }),
  external: () => svgIcon([
    { d: "M6.5 3.5H3.5v9h9v-3" },
    { d: "M9.5 2.5h4v4" },
    { d: "M13.5 2.5L7.5 8.5" },
  ], { className: "icon-svg sm" }),
  rail: () => svgIcon([
    { tag: "rect", x: "2", y: "2.5", width: "12", height: "11", rx: "2" },
    { d: "M6 2.5v11" },
  ], { className: "icon-svg sm" }),
  plus: () => svgIcon([
    { d: "M8 3.2v9.6M3.2 8h9.6" },
  ], { className: "icon-svg sm" }),
  clock: () => svgIcon([
    { tag: "circle", cx: "8", cy: "8", r: "5.5" },
    { d: "M8 5v3.3l2.2 1.4" },
  ], { className: "icon-svg sm" }),
  chevronRight: () => svgIcon([
    { d: "M6 3.8L10.2 8 6 12.2" },
  ], { className: "icon-svg sm d2-chevron" }),
  compose: () => svgIcon([
    { d: "M10.8 2.6l2.6 2.6-7.6 7.6H3.2v-2.6l7.6-7.6z" },
  ], { className: "icon-svg sm" }),
  send: () => svgIcon([
    { d: "M8 12.5V3.5" },
    { d: "M4.5 7L8 3.5 11.5 7" },
  ], { className: "icon-svg sm" }),
  stop: () => svgIcon([
    { tag: "rect", x: "4.2", y: "4.2", width: "7.6", height: "7.6", rx: "1.4" },
  ], { className: "icon-svg sm" }),
};

function healUnclosedInlineMarkdown(raw) {
  let s = String(raw ?? "");
  const tickCount = (s.match(/`/g) || []).length;
  if (tickCount % 2 === 1) s += "`";
  const boldCount = (s.match(/\*\*/g) || []).length;
  if (boldCount % 2 === 1) s += "**";
  return s;
}

function renderHealedInlineMarkdown(rawText) {
  const healed = healUnclosedInlineMarkdown(rawText);
  const nodes = [];
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIdx = 0;
  for (const match of healed.matchAll(pattern)) {
    const idx = match.index ?? 0;
    if (idx > lastIdx) {
      nodes.push(healed.slice(lastIdx, idx));
    }
    const token = match[0];
    if (token.startsWith("**") && token.endsWith("**") && token.length > 4) {
      nodes.push(el("strong", null, token.slice(2, -2)));
    } else if (token.startsWith("`") && token.endsWith("`") && token.length > 2) {
      nodes.push(el("code", { className: "pill-code" }, token.slice(1, -1)));
    } else {
      nodes.push(token);
    }
    lastIdx = idx + token.length;
  }
  if (lastIdx < healed.length) {
    nodes.push(healed.slice(lastIdx));
  }
  return nodes;
}

function fact(value, format = (x) => String(x), extraClass = "") {
  if (isAbsent(value)) return null;
  const formatted = format(value);
  if (isAbsent(formatted)) return null;
  return el("span", { className: extraClass ? `meta-item ${extraClass}` : "meta-item" }, formatted);
}

function metaRow(items) {
  const valid = items.filter(Boolean);
  if (valid.length === 0) return null;
  return el("div", { className: "meta" }, valid);
}

function actionBtn({
  label,
  variant = "secondary",
  size = "",
  keycap = null,
  disabled = false,
  id = null,
  extraClass = "",
  ariaLabel = null,
  onClick = null,
}) {
  const classes = [`btn-${variant}`];
  if (size) classes.push(`btn-${size}`);
  if (extraClass) classes.push(extraClass);
  const btn = el(
    "button",
    {
      type: "button",
      id,
      className: classes.join(" "),
      "aria-disabled": disabled ? "true" : null,
      "aria-label": ariaLabel,
      onClick,
    },
    el("span", { className: "btn-spinner", "aria-hidden": "true" }),
    el("span", { className: "btn-label" }, label),
    keycap ? el("kbd", { className: "keycap", "aria-hidden": "true" }, keycap) : null,
  );
  return btn;
}

function copyButton({ label, textToCopy, okToast = "Copied to clipboard", size = "sm", variant = "secondary", onCopied = null }) {
  const glyphWrap = el(
    "span",
    { className: "btn-glyph", "aria-hidden": "true" },
    el("span", { className: "glyph-idle" }, ICONS.copy()),
    el("span", { className: "glyph-done" }, ICONS.check()),
  );
  const btn = el(
    "button",
    {
      type: "button",
      className: `btn-${variant}${size ? ` btn-${size}` : ""}`,
      onClick: async () => {
        const value = typeof textToCopy === "function" ? textToCopy() : textToCopy;
        const ok = await Motion.copyWithFeedback(
          btn,
          value,
          (msg) => toaster.show(msg),
          okToast,
          "Clipboard unavailable — select and copy manually.",
        );
        if (ok && typeof onCopied === "function") onCopied(value);
      },
    },
    glyphWrap,
    el("span", { className: "btn-label" }, label),
  );
  return btn;
}

function switchControl({ checked, label, disabled = false, onToggle }) {
  const stateSpan = el("span", { className: "switch-state" }, checked ? "On" : "Off");
  const btn = el(
    "button",
    {
      type: "button",
      role: "switch",
      className: "switch-btn",
      "aria-checked": checked ? "true" : "false",
      "aria-label": label,
      "aria-disabled": disabled ? "true" : null,
      onClick: async () => {
        if (btn.getAttribute("aria-disabled") === "true") return;
        const next = btn.getAttribute("aria-checked") !== "true";
        btn.setAttribute("aria-checked", next ? "true" : "false");
        stateSpan.textContent = next ? "On" : "Off";
        try {
          await onToggle(next, btn, stateSpan);
        } catch (err) {
          btn.setAttribute("aria-checked", !next ? "true" : "false");
          stateSpan.textContent = !next ? "On" : "Off";
        }
      },
    },
    el("span", { className: "knob", "aria-hidden": "true" }),
  );
  return el("div", { className: "switch-wrap" }, stateSpan, btn);
}

function statusPill(label, tone = "neutral", live = false) {
  const p = el(
    "span",
    {
      className: "pill-status",
      dataset: {
        tone: tone !== "neutral" ? tone : null,
        live: live ? true : null,
      },
    },
    el("span", { className: "dot", "aria-hidden": "true" }),
    el("span", null, label),
  );
  if (live) Motion.observeLoop(p);
  return p;
}

// ── 2 · Formatting & Telemetry Buckets ───────────────────────────────────────

function formatInt(n) {
  const num = Number(n);
  if (!Number.isFinite(num)) return null;
  return Math.round(num).toLocaleString("en-US");
}

function formatCredits(n) {
  const s = formatInt(n);
  return s === null ? null : `${s} Cr`;
}

function formatElapsed(ms) {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  if (totalSec < 60) return `${totalSec}s`;
  const min = Math.floor(totalSec / 60);
  const sec = totalSec % 60;
  if (min < 60) return `${min}m ${String(sec).padStart(2, "0")}s`;
  const hr = Math.floor(min / 60);
  const remMin = min % 60;
  return `${hr}h ${String(remMin).padStart(2, "0")}m`;
}

function formatRelativeTime(input) {
  if (isAbsent(input)) return null;
  let tsMs = null;
  if (typeof input === "number") {
    tsMs = input < 1e12 ? input * 1000 : input;
  } else if (typeof input === "string") {
    const parsed = Date.parse(input);
    if (!Number.isNaN(parsed)) tsMs = parsed;
    else return input;
  }
  if (tsMs === null) return null;
  const diffSec = Math.max(0, Math.floor((Date.now() - tsMs) / 1000));
  if (diffSec < 45) return "Just now";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

function formatDateShort(input) {
  if (isAbsent(input)) return null;
  const ts = typeof input === "number" ? (input < 1e12 ? input * 1000 : input) : Date.parse(String(input));
  if (Number.isNaN(ts)) return String(input);
  try {
    return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", year: "numeric" }).format(new Date(ts));
  } catch (e) {
    return new Date(ts).toISOString().slice(0, 10);
  }
}

function uuidv4() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID().toLowerCase();
  }
  const bytes = new Uint8Array(16);
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 16; i += 1) bytes[i] = Math.floor(Math.random() * 256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function countBucket(n) {
  const v = Math.max(0, Number(n) || 0);
  if (v === 0) return "0";
  if (v <= 3) return "1_3";
  if (v <= 10) return "4_10";
  if (v <= 25) return "11_25";
  return "26_plus";
}

function badgeBucket(n) {
  const v = Math.max(0, Number(n) || 0);
  if (v === 0) return "0";
  if (v <= 3) return "1_3";
  if (v <= 10) return "4_10";
  return "11_plus";
}

function creditsBucket(n) {
  if (!Number.isFinite(Number(n))) return "500";
  const v = Math.max(0, Math.round(Number(n)));
  if (v === 0) return "0";
  if (v <= 49) return "1_49";
  if (v <= 150) return "50_150";
  if (v <= 499) return "151_499";
  if (v === 500) return "500";
  if (v <= 5000) return "501_5k";
  return "gt_5k";
}

function filesBucket(n) {
  const v = Math.max(0, Number(n) || 0);
  if (v === 0) return "0";
  if (v === 1) return "1";
  if (v <= 3) return "2_3";
  if (v <= 7) return "4_7";
  if (v <= 15) return "8_15";
  return "16_plus";
}

function linesBucket(n) {
  const v = Math.max(1, Number(n) || 1);
  if (v <= 10) return "1_10";
  if (v <= 50) return "11_50";
  if (v <= 150) return "51_150";
  if (v <= 500) return "151_500";
  return "501_plus";
}

function hoursBucket(n) {
  const v = Math.max(0, Number(n) || 0);
  if (v === 0) return "0";
  if (v < 10) return "under_10";
  if (v <= 100) return "10_to_100";
  return "over_100";
}

function shippedBucket(n) {
  const v = Math.max(0, Number(n) || 0);
  if (v === 0) return "0";
  if (v <= 4) return "1_4";
  if (v <= 14) return "5_14";
  return "15_plus";
}

function learnedRulesBucket(n) {
  const v = Math.max(0, Number(n) || 0);
  if (v === 0) return "0";
  if (v <= 5) return "1_5";
  if (v <= 20) return "6_20";
  return "21_plus";
}

function promptLengthBucket(len) {
  const v = Math.max(1, Number(len) || 1);
  if (v <= 40) return "1_40";
  if (v <= 120) return "41_120";
  if (v <= 300) return "121_300";
  return "301_plus";
}

function bootLatencyBucket(ms) {
  const v = Math.max(0, Number(ms) || 0);
  if (v < 100) return "lt_100";
  if (v < 250) return "100_249";
  if (v < 500) return "250_499";
  if (v < 1000) return "500_999";
  return "1000_plus";
}

function decisionLatencyBucket(ms) {
  const s = Math.max(0, (Number(ms) || 0) / 1000);
  if (s < 10) return "lt_10s";
  if (s <= 30) return "10_30s";
  if (s <= 120) return "30_120s";
  return "gt_120s";
}

function elapsedBootBucket() {
  const sec = Math.max(0, Math.floor((Date.now() - BOOT_UNIX_MS) / 1000));
  if (sec <= 15) return "0_15";
  if (sec <= 60) return "16_60";
  if (sec <= 180) return "61_180";
  if (sec <= 600) return "181_600";
  return "601_plus";
}

function viewportBucket() {
  const w = typeof window !== "undefined" ? window.innerWidth : 1440;
  if (w >= 1280) return "desktop_wide";
  if (w >= 1024) return "desktop_std";
  if (w >= 720) return "tablet";
  return "mobile";
}

const PAIRING_TOOL_IDS = ["claude_code", "codex_cli", "gemini_cli", "cursor"];
const PAIRING_SLOT_KEYS = ["driver_tool", "reviewer_tool", "test_verifier_tool", "security_verifier_tool"];

function normalizeDetectedToolId(raw) {
  const low = String(raw || "tool").trim().toLowerCase();
  if (low === "claude" || low === "claude_code" || low === "claude-code") return "claude_code";
  if (low === "codex" || low === "codex_cli" || low === "codex-cli") return "codex_cli";
  if (low === "gemini" || low === "gemini_cli" || low === "gemini-cli") return "gemini_cli";
  if (low === "cursor") return "cursor";
  if (low === "gh" || low === "gh_cli" || low === "gh-cli") return "gh_cli";
  return low.replace(/[^a-z0-9_]/g, "_");
}

function reviewModeForCredits(credits) {
  const c = Number(credits);
  if (c === 50) return "review_handoff";
  if (c === 150) return "three_tool_check";
  if (c === 200) return "quad_programming";
  return "pair_sandbox";
}

function creditsForReviewMode(mode) {
  const m = String(mode || "").trim().toLowerCase();
  if (m === "review_handoff") return 50;
  if (m === "pair_sandbox" || m === "diffs_touching_3_plus_files") return 100;
  if (m === "three_tool_check" || m === "triad_sandbox") return 150;
  if (m === "quad_programming" || m === "quad_sandbox" || m === "security_review") return 200;
  return null;
}

function ensureDistinctPairingSlots(agentsObj, changedSlotIdx = -1, nextTool = null, prevTool = null) {
  if (!agentsObj || typeof agentsObj !== "object") return;
  if (changedSlotIdx >= 0 && changedSlotIdx < PAIRING_SLOT_KEYS.length && nextTool) {
    const cleanNext = normalizeToolKind(nextTool);
    const cleanPrev = prevTool ? normalizeToolKind(prevTool) : null;
    agentsObj[PAIRING_SLOT_KEYS[changedSlotIdx]] = cleanNext;
    for (let j = 0; j < PAIRING_SLOT_KEYS.length; j += 1) {
      if (j === changedSlotIdx) continue;
      if (normalizeToolKind(agentsObj[PAIRING_SLOT_KEYS[j]]) === cleanNext) {
        if (cleanPrev && cleanPrev !== cleanNext) {
          agentsObj[PAIRING_SLOT_KEYS[j]] = cleanPrev;
        }
      }
    }
  }

  const used = new Set();
  if (changedSlotIdx >= 0 && changedSlotIdx < PAIRING_SLOT_KEYS.length) {
    const pinned = normalizeToolKind(agentsObj[PAIRING_SLOT_KEYS[changedSlotIdx]]);
    agentsObj[PAIRING_SLOT_KEYS[changedSlotIdx]] = pinned;
    used.add(pinned);
  }
  for (let i = 0; i < PAIRING_SLOT_KEYS.length; i += 1) {
    if (i === changedSlotIdx) continue;
    const current = normalizeToolKind(agentsObj[PAIRING_SLOT_KEYS[i]]);
    if (PAIRING_TOOL_IDS.includes(current) && !used.has(current)) {
      agentsObj[PAIRING_SLOT_KEYS[i]] = current;
      used.add(current);
    } else {
      const replacement = PAIRING_TOOL_IDS.find((cand) => !used.has(cand)) || PAIRING_TOOL_IDS[i];
      agentsObj[PAIRING_SLOT_KEYS[i]] = replacement;
      used.add(replacement);
    }
  }
}

function snapshotWorkflowState(agentsObj) {
  const wf = (agentsObj && agentsObj.workflow) || {};
  return {
    workflow: {
      independent_review: wf.independent_review !== false,
      protect_sensitive_paths: wf.protect_sensitive_paths !== false,
      auto_test_before_review: wf.auto_test_before_review !== false,
    },
    driver_tool: normalizeToolKind(agentsObj && agentsObj.driver_tool ? agentsObj.driver_tool : "claude_code"),
    reviewer_tool: normalizeToolKind(agentsObj && agentsObj.reviewer_tool ? agentsObj.reviewer_tool : "codex_cli"),
    test_verifier_tool: normalizeToolKind(agentsObj && agentsObj.test_verifier_tool ? agentsObj.test_verifier_tool : "gemini_cli"),
    security_verifier_tool: normalizeToolKind(agentsObj && agentsObj.security_verifier_tool ? agentsObj.security_verifier_tool : "cursor"),
    review_tier_credits: [50, 100, 150, 200].includes(Number(agentsObj && agentsObj.review_tier_credits))
      ? Number(agentsObj.review_tier_credits)
      : 100,
    protected_paths: Array.isArray(agentsObj && agentsObj.protected_paths)
      ? agentsObj.protected_paths.map(String)
      : [],
  };
}

function applyWorkflowSnapshot(agentsObj, snap) {
  if (!agentsObj || !snap) return;
  agentsObj.workflow = { ...snap.workflow };
  agentsObj.driver_tool = snap.driver_tool;
  agentsObj.reviewer_tool = snap.reviewer_tool;
  agentsObj.test_verifier_tool = snap.test_verifier_tool;
  agentsObj.security_verifier_tool = snap.security_verifier_tool;
  agentsObj.review_tier_credits = snap.review_tier_credits;
  agentsObj.protected_paths = [...snap.protected_paths];
}

function formatHumanList(items) {
  const list = Array.isArray(items) ? items.filter((x) => !isAbsent(x)).map(String) : [];
  if (list.length === 0) return "";
  if (list.length === 1) return list[0];
  if (list.length === 2) return `${list[0]} and ${list[1]}`;
  return `${list.slice(0, -1).join(", ")}, and ${list[list.length - 1]}`;
}

function prependQueuedBoardTask(resTask, fallback) {
  const t = resTask && typeof resTask === "object" ? resTask : {};
  const id = String(t.id || fallback.id || `task-${Date.now()}`);
  const title = String(!isAbsent(t.title) ? t.title : fallback.title);
  const workstream = String(!isAbsent(t.workstream) ? t.workstream : fallback.workstream || "engineering");
  const toolLabel = friendlyToolLabel(t.tool_label || t.assigned_tool || fallback.toolKind || "claude_code");
  const card = {
    id,
    title,
    workstream,
    tool_label: toolLabel,
    created_at: new Date().toISOString(),
  };
  const existing = Array.isArray(state.data.board.columns.queued) ? state.data.board.columns.queued : [];
  state.data.board.columns.queued = [card, ...existing.filter((c) => !c || c.id !== id)];
  return card;
}

function normalizeToolKind(labelOrId) {
  const s = String(labelOrId || "").toLowerCase();
  if (s.includes("claude")) return "claude_code";
  if (s.includes("codex") || s.includes("openai")) return "codex_cli";
  if (s.includes("gemini")) return "gemini_cli";
  if (s.includes("cursor")) return "cursor";
  return "claude_code";
}

function friendlyToolLabel(raw) {
  if (isAbsent(raw)) return null;
  const s = String(raw).trim();
  const low = s.toLowerCase();
  if (low === "claude_code" || low.includes("claude")) return "Claude Code";
  if (low === "codex_cli" || low.includes("codex")) return "Codex CLI";
  if (low === "gemini_cli" || low.includes("gemini")) return "Gemini CLI";
  if (low === "cursor") return "Cursor";
  if (low === "gh_cli" || low === "gh") return "GitHub CLI";
  if (low === "aider") return "Aider";
  if (low === "windsurf") return "Windsurf";
  return s;
}

// ── 3 · Security Context, HTTP Client & Zero-PII Telemetry ───────────────────

function readMeta(name) {
  if (typeof document === "undefined") return "";
  const node = document.querySelector(`meta[name="${name}"]`);
  const val = node ? (node.getAttribute("content") || "").trim() : "";
  if (val.startsWith("{{") && val.endsWith("}}")) return "";
  return val;
}

const CSRF_TOKEN = readMeta("chinwag-csrf");
const SERVER_PORT = readMeta("chinwag-port") || (typeof location !== "undefined" ? location.port : "") || "5487";

function buildSecurityHeaders(isJson = false) {
  const headers = {
    Accept: "application/json",
    "X-Chinwag-Csrf": CSRF_TOKEN,
    "X-Chinwag-Token": CSRF_TOKEN,
    "X-Chinwag-Local-Csrf": CSRF_TOKEN,
  };
  if (isJson) headers["Content-Type"] = "application/json";
  return headers;
}

function isTelemetryOptedOut() {
  if (
    typeof state === "object" &&
    state !== null &&
    state.data &&
    state.data.privacy &&
    typeof state.data.privacy.telemetry_enabled === "boolean"
  ) {
    return !state.data.privacy.telemetry_enabled;
  }
  try {
    return localStorage.getItem("chinwag_telemetry_opt_out") === "1";
  } catch (e) {
    return false;
  }
}

function setTelemetryOptOut(optOut) {
  if (typeof state === "object" && state !== null && state.data && state.data.privacy) {
    state.data.privacy.telemetry_enabled = !optOut;
  }
  try {
    if (optOut) localStorage.setItem("chinwag_telemetry_opt_out", "1");
    else localStorage.removeItem("chinwag_telemetry_opt_out");
  } catch (e) { /* storage unavailable */ }
}

export function trackUiEvent(event, props = {}) {
  if (!event || typeof fetch !== "function") return;
  if (isTelemetryOptedOut() && event !== "ui_telemetry_opt_out_changed") return;
  const cleanProps = {};
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined) continue;
    if (typeof v === "boolean" || typeof v === "number") {
      cleanProps[k] = v;
    } else if (typeof v === "string" && v.length > 0 && v.length <= 64) {
      cleanProps[k] = v;
    }
  }
  const body = JSON.stringify({ event, properties: cleanProps });
  fetch("/api/v4/telemetry/track", {
    method: "POST",
    headers: buildSecurityHeaders(true),
    credentials: "same-origin",
    keepalive: true,
    body,
  }).catch(() => {});
}

async function apiRequest(method, path, bodyObj = null, extraOpts = null) {
  const init = {
    method,
    headers: buildSecurityHeaders(bodyObj !== null || method === "POST"),
    credentials: "same-origin",
  };
  if (extraOpts && extraOpts.signal) {
    init.signal = extraOpts.signal;
  }
  if (bodyObj !== null) {
    init.body = JSON.stringify(bodyObj);
  } else if (method === "POST") {
    init.body = "{}";
  }
  const res = await fetch(path, init);
  let json = null;
  try {
    json = await res.json();
  } catch (e) {
    json = null;
  }
  const isGuardrailForbidden = Boolean(
    json && json.error_code === "SampleWalkthroughShipForbidden",
  );
  if ((res.status === 401 || res.status === 403) && !isGuardrailForbidden) {
    showSessionExpiredBanner();
  }
  if (!res.ok || (json && json.ok === false)) {
    const msg = (json && (json.message || json.error)) || `Request failed (${res.status})`;
    const err = new Error(msg);
    err.status = res.status;
    err.code = json && json.error_code ? json.error_code : "request_failed";
    throw err;
  }
  return json || { ok: true };
}

// ── 4 · Sample Walkthrough Fixture & Payload Normalization ───────────────────

const DEFAULT_SAMPLE_WALKTHROUGH = {
  id: "sample-walkthrough",
  is_sample: true,
  title: "Fix retry timeout unit test in session token refresh",
  summary: "Aligns the token refresh backoff timeout with the 5-second test clock so CI passes deterministically.",
  why: "The refresh test waited 6 seconds while the mock clock capped retries at 5 seconds.",
  status: "needs_review",
  tool_label: "Claude Code",
  reviewer_label: "Codex CLI",
  independent_review: {
    passed: true,
    summary: "Reviewed independently by Codex CLI — timeout bounds and retry count verified.",
    checks: [
      "Unit test suite passed (42 passed, 0 failed in 1.4s)",
      "No protected paths, secrets, or workflow files touched",
      "Independent reviewer confirmed zero side effects outside token refresh",
    ],
  },
  risk_level: "low",
  files_changed: 1,
  additions: 3,
  deletions: 2,
  branch: "fix/token-refresh-timeout",
  git_host: "GitHub",
  test_command: "npm test -- session-refresh.test.ts",
  test_passed: true,
  test_duration_ms: 1420,
  credits_cost: 50,
  created_at: new Date(Date.now() - 180000).toISOString(),
  files: [
    {
      path: "src/session/refreshClient.ts",
      additions: 3,
      deletions: 2,
      hunks: [
        {
          header: "@@ -38,9 +38,10 @@ export async function refreshSessionToken(client: HttpClient) {",
          lines: [
            { type: "ctx", old_ln: 38, new_ln: 38, text: "export async function refreshSessionToken(client: HttpClient) {" },
            { type: "ctx", old_ln: 39, new_ln: 39, text: "  const maxAttempts = 3;" },
            { type: "del", old_ln: 40, new_ln: null, text: "  const retryTimeoutMs = 6000;" },
            { type: "del", old_ln: 41, new_ln: null, text: "  return client.post('/session/refresh', { timeout: retryTimeoutMs });" },
            { type: "add", old_ln: null, new_ln: 40, text: "  const retryTimeoutMs = 4500;" },
            { type: "add", old_ln: null, new_ln: 41, text: "  // Keep single-attempt timeout inside the 5000ms test budget." },
            { type: "add", old_ln: null, new_ln: 42, text: "  return client.post('/session/refresh', { timeout: retryTimeoutMs, maxAttempts });" },
            { type: "ctx", old_ln: 42, new_ln: 43, text: "}" },
          ],
        },
      ],
    },
  ],
};

const CATALOG_PACKS = [
  {
    sku: "pack_50",
    telemetry_slug: "pack_50",
    label: "Starter Pack",
    price_usd: 50,
    credits: 6250,
    rate_note: "$0.0080 / Cr · valid 12 months",
    savings_note: "Starter pack for solo shipping",
    expires_months: 12,
    recommended: false,
  },
  {
    sku: "pack_160",
    telemetry_slug: "pack_160",
    label: "Team Pack",
    price_usd: 160,
    credits: 25000,
    rate_note: "$0.0064 / Cr · Save 20% · valid 12 months",
    savings_note: "Recommended for active teams",
    expires_months: 12,
    recommended: true,
  },
  {
    sku: "pack_560",
    telemetry_slug: "pack_560",
    label: "Growth Pack",
    price_usd: 560,
    credits: 100000,
    rate_note: "$0.0056 / Cr · Save 30% · valid 12 months",
    savings_note: "Multi-repo continuous review",
    expires_months: 12,
    recommended: false,
  },
  {
    sku: "pack_1000",
    telemetry_slug: "pack_1000",
    label: "Scale Pack",
    price_usd: 1000,
    credits: 200000,
    rate_note: "$0.0050 / Cr · Save 37.5% · valid 12 months",
    savings_note: "Highest self-serve rate",
    expires_months: 12,
    recommended: false,
  },
];

const PUBLISHED_COST_SCHEDULE = [
  { label: "Verified agent handoff", detail: "Routes verified context cleanly between coding tools on this machine", cost: "15 Cr" },
  { label: "Repository context sync", detail: "Synchronizes shared repository conventions and rules across coding tools", cost: "50 Cr" },
  { label: "Protected-path safety check", detail: "Verifies sensitive paths, credentials, and workflow files before review", cost: "50 Cr" },
  { label: "Cleanroom test run", detail: "Runs the test suite inside an isolated sandbox before you review", cost: "100 Cr" },
  { label: "Independent second-tool review", detail: "A second coding tool independently audits the diff before merge", cost: "150 Cr" },
  { label: "Verified PR ship & receipt", detail: "Ships a verified pull request with a complete test and review receipt", cost: "200 Cr" },
  { label: "GitHub Projects, Linear sync, and local CLI commands", detail: "Board status sync and terminal commands never use credits", cost: "0 Cr" },
];

const DELIVERY2_DEFAULT_STEPS = [
  ["01", "Queued"],
  ["02", "Understood"],
  ["03", "Plan ready"],
  ["04", "Estimate ready"],
  ["05", "Writing changes"],
  ["06", "Tests added"],
  ["07", "Checks running"],
  ["08", "Fixing checks"],
  ["09", "Independent review"],
  ["10", "Waiting for you"],
  ["11", "Final checks"],
  ["12", "Passed · Merge-ready"],
];

const state = {
  booted: false,
  bootstrapOk: false,
  uiVersion: "4.1",
  view: "inbox",
  inboxFilter: "needs_you",
  boardWorkstream: "all",
  selectedIndex: 0,
  openItemId: null,
  sheetOpenedAtMs: 0,
  diffMode: "unified",
  diffWrap: false,
  diffCache: new Map(),
  loadingDiffId: null,
  rejectedUndoTimers: new Map(),
  rejectedItems: new Set(),
  onboardingDismissed: false,
  walkthroughDone: false,
  pmLoading: false,
  launcherDraft: "",
  committedWorkflow: null,
  workflowSaveSeq: 0,
  workflowSaveInFlight: 0,
  workflowSaveChain: Promise.resolve(),
  activeMinutes: 1,
  transportMode: "sse",
  reconnectCount: 0,
  d2Popover: null,
  d2PopoverSeq: 0,
  d2FocusedSurface: null,
  d2DrawerOpen: false,
  d2DrawerTriggerEl: null,
  d2AutoCollapsedForSheet: false,
  d2PreSheetRail: null,
  d2ComposerDraft: "",
  d2ComposerError: null,
  d2Sending: false,
  d2ActiveTurnId: null,
  d2CancelledTurnIds: new Set(),
  d2ActiveAbort: null,
  d2ActiveStreamer: null,
  d2StreamingEntryId: null,
  d2StreamingText: "",
  d2LastCursorSeq: 0,
  d2Loaded: false,
  d2ExpandedSteps: new Set(),
  d2ExpandedSources: new Set(),
  d2EditingMemId: null,
  d2EditingMemDraft: "",
  data: createEmptyData(),
};

function createEmptyData() {
  return {
    repo: {
      name: null,
      branch: null,
      vcs: "git",
      git_host: "GitHub",
      initialized: true,
      cursor_detected: false,
      cursor_rules_count: 0,
      github_connected: false,
      linear_connected: false,
    },
    inbox: {
      items: [],
      counts: { needs_decision: 0, running: 0, done: 0 },
      sample_walkthrough: { ...DEFAULT_SAMPLE_WALKTHROUGH },
    },
    board: {
      summary: {
        shipped_count: 0,
        hours_saved: 0,
        baseline_explainer:
          "Hours saved compares shipped tasks against typical solo developer completion time (1.5–8 hours per reviewed change), minus your review time.",
        credits_used: 0,
      },
      columns: {
        queued: [],
        in_progress: [],
        needs_review: [],
        shipped: [],
      },
    },
    agents: {
      detected_tools: [
        { id: "claude_code", label: "Claude Code", installed: true, setup_command: "npm install -g @anthropic-ai/claude-code" },
        { id: "codex_cli", label: "Codex CLI", installed: true, setup_command: "npm install -g @openai/codex" },
        { id: "gemini_cli", label: "Gemini CLI", installed: true, setup_command: "npm install -g @google/gemini-cli" },
        { id: "cursor", label: "Cursor", installed: false, setup_command: "chinwag agents import-cursor" },
      ],
      driver_tool: "claude_code",
      reviewer_tool: "codex_cli",
      test_verifier_tool: "gemini_cli",
      security_verifier_tool: "cursor",
      review_tier_credits: 100,
      workflow: {
        independent_review: true,
        protect_sensitive_paths: true,
        auto_test_before_review: true,
      },
      protected_paths: [".github/workflows/**", ".env*", "**/auth/**", "**/billing/**"],
      learned_rules: [],
    },
    credits: {
      available: false,
      available_credits: null,
      next_expiry_at: null,
      next_expiry_credits: null,
      plan_tier: "Free Starter Trial",
      pack_expiry_notice:
        "500 free starter credits (valid 90 days) · $0 per teammate seat · Paid credit packs remain valid for 12 months from purchase.",
      pricing_url: "https://chinwag.sh/pricing",
      tranches: [],
      catalog: CATALOG_PACKS.map((p) => ({ ...p })),
      auto_refill: {
        enabled: false,
        threshold_credits: 250,
        pack_sku: "pack_160",
        monthly_cap_usd: 500,
      },
      receipts: [],
    },
    privacy: {
      bind_addr: "127.0.0.1",
      port: Number(SERVER_PORT) || 5487,
      code_leaves_machine: false,
      summary: "Source code, diffs, file paths, and prompts stay on this machine.",
      ciso_review_url: "https://chinwag.sh/pricing?talk=1&source=local_ui#founders",
    },
    invite: {
      join_command: "npx chinwag join",
      referral_url: "https://chinwag.sh/pricing?source=local_ui_referral",
      bonus_credits: 250,
    },
    delivery2: createDefaultDelivery2State(),
  };
}

function buildDefaultStepLadder(activeOneBased = 10, completedAll = false) {
  return DELIVERY2_DEFAULT_STEPS.map(([num, label], idx) => {
    const stepNo = idx + 1;
    let stepState = "pending";
    if (completedAll || stepNo < activeOneBased) stepState = "done";
    else if (stepNo === activeOneBased) stepState = stepNo === 10 ? "waiting" : "active";
    return {
      num,
      label,
      display: `${num} · ${label}`,
      state: stepState,
    };
  });
}

function createDefaultDelivery2State() {
  const portNum = Number(SERVER_PORT) || 5487;
  return {
    agent_name: "Delivery-2",
    seq: 1,
    status: "waiting_for_you",
    status_label: "Waiting for you",
    active_thread_id: "thr-main",
    sync_radar: {
      latency_ms: 42,
      latency_label: "<200ms",
      surfaces: [
        {
          id: "local",
          label: "Local",
          authorized: true,
          in_thread: true,
          locked_in_thread: true,
          role_mode: "workspace",
          auth_status: `Loopback workspace · 127.0.0.1:${portNum}`,
          connect_url: null,
          policy_note: null,
        },
        {
          id: "github",
          label: "GitHub",
          authorized: true,
          in_thread: true,
          locked_in_thread: false,
          role_mode: "full",
          auth_status: "Connected · your account",
          connect_url: "https://chinwag.sh/open?connect=github&source=local_ui",
          policy_note: null,
        },
        {
          id: "linear",
          label: "Linear",
          authorized: false,
          in_thread: false,
          locked_in_thread: false,
          role_mode: "full",
          auth_status: "Needs sign-in · pauses at 0 Cr",
          connect_url: "https://chinwag.sh/open?connect=linear&source=local_ui",
          policy_note: null,
        },
        {
          id: "slack",
          label: "Slack",
          authorized: true,
          in_thread: false,
          locked_in_thread: false,
          role_mode: "ambient_status_only",
          auth_status: "Connected · ambient status cards only",
          connect_url: "https://chinwag.sh/open?connect=slack&source=local_ui",
          policy_note:
            "Slack posts ambient status cards with [Open in Chinwag ↗] deep-links only — Delivery-2 lives here in Chinwag.",
        },
      ],
    },
    morning_focus: {
      seen: false,
      collapsed: false,
      rows: [
        { id: "mf-inbox", badge: "1", label: "diff ready for your review", cta: "Inbox", target_tab: "inbox", hash: "#inbox" },
        { id: "mf-board", badge: "0", label: "queued tasks on Board", cta: "Board", target_tab: "board", hash: "#board" },
        { id: "mf-credits", badge: "500 Cr", label: "available in workspace pool", cta: "Credits", target_tab: "credits", hash: "#credits" },
      ],
    },
    entries: [
      {
        id: "entry-seed-qa",
        kind: "qa_card",
        seq: 1,
        role: "assistant",
        author: "Delivery-2",
        body: "Workspace **chinwag** on `main` has **1** change ready for review, **0** queued board tasks, and **500 Cr** available. Pairing uses **Claude Code** with independent review by **Codex CLI**.",
        sources: [
          { label: "Inbox · 1 waiting", target_tab: "inbox", hash: "#inbox" },
          { label: "Board · 0 active / 0 queued", target_tab: "board", hash: "#board" },
          { label: "Safety rules · 4 protected globs", target_tab: "agents", hash: "#agents" },
          { label: "Credits · 500 Cr available", target_tab: "credits", hash: "#credits" },
        ],
      },
      {
        id: "entry-run-run-local-1",
        kind: "run_card",
        seq: 1,
        run_id: "run-local-1",
        title: "Verify protected-path safety & test checks before merge",
        current_step_num: "10",
        current_step_label: "Waiting for you",
        current_step_display: "10 · Waiting for you",
        completed: false,
        verb_summary: "Searched 8 items · Read 4 files · Ran 3 checks",
        diff_target_id: "sample-walkthrough",
        steps: buildDefaultStepLadder(10, false),
      },
      {
        id: "entry-hitl-run-local-1",
        kind: "approval_card",
        seq: 1,
        approval_id: "hitl-run-local-1",
        item_id: "run-local-1",
        is_sample: false,
        status_badge: "Waiting for you",
        pause_badge: "Paused · 0 Cr",
        estimate_badge: "~20 Cr to finish",
        title: "Verify protected-path safety & test checks before merge",
        question: "Review workspace guardrails on `main` (open View diff → for safe sample preview)?",
        diff_summary: "No local diff recorded yet · Sample preview available",
        check_proof: "Automated test receipt not yet recorded · Independent review not yet recorded",
        diff_hash: "#walkthrough",
        settled: false,
        settled_decision: null,
        settled_receipt: null,
      },
      {
        id: "entry-mem-seed",
        kind: "memory_card",
        seq: 1,
        memory_id: "mem_default",
        note: "Run unit tests in an isolated sandbox before opening a review.",
        status: "saved",
      },
    ],
    history: {
      today: [
        {
          id: "thr-main",
          title: "Workspace scope & morning review",
          status: "Waiting for you",
          active: true,
          updated_at: "Today",
        },
      ],
      earlier: [],
    },
    memories: [
      {
        id: "mem_default",
        note: "Run unit tests in an isolated sandbox before opening a review.",
        status: "saved",
        updated_at: "Saved",
      },
    ],
    steering_chips: [
      { id: "chip-missed", label: "What did I miss?", prompt: "What did I miss?" },
      { id: "chip-why", label: "Why #sample?", prompt: "Why #sample-walkthrough?" },
      { id: "chip-credits", label: "Today's Credits", prompt: "Today's Credits" },
    ],
    links: {
      security_url: "https://chinwag.sh/security",
      founders_url: "https://chinwag.sh/pricing?talk=1&source=local_ui#founders",
      open_url: "https://chinwag.sh/open",
      pricing_url: "https://chinwag.sh/pricing",
    },
  };
}

function classifyInboxBucket(statusRaw) {
  const s = String(statusRaw || "").toLowerCase();
  if (
    s === "done" ||
    s === "shipped" ||
    s === "completed" ||
    s === "approved" ||
    s === "approved_pushed" ||
    s === "merged" ||
    s === "rejected"
  ) {
    return "done";
  }
  if (s === "running" || s === "in_progress" || s === "fixing_in_sandbox" || s === "queued") {
    return "running";
  }
  return "needs_you";
}

function normalizeInboxItem(raw, isSampleOverride = false) {
  if (!raw || typeof raw !== "object") return null;
  const isSample = Boolean(isSampleOverride || raw.is_sample || raw.id === "sample-walkthrough");
  const id = String(raw.id || raw.item_id || raw.task_id || (isSample ? "sample-walkthrough" : "item"));
  const status = String(raw.status || "needs_review").toLowerCase();
  const bucket = classifyInboxBucket(status);
  const indep = raw.independent_review;
  const indepObj = typeof indep === "object" && indep !== null
    ? {
        passed: indep.passed === true,
        summary: !isAbsent(indep.summary)
          ? String(indep.summary)
          : indep.passed === true
            ? "Reviewed independently by a second coding tool."
            : "Independent review has not been recorded yet.",
        checks: Array.isArray(indep.checks)
          ? indep.checks
              .map((c) => (c && typeof c === "object" ? c.label : c))
              .filter((c) => !isAbsent(c))
              .map(String)
          : [],
      }
    : indep === true
      ? { passed: true, summary: "Reviewed independently by a second coding tool.", checks: [] }
      : null;

  const verif = typeof raw.verification === "object" && raw.verification !== null ? raw.verification : null;
  const normalizedTestPassed =
    typeof raw.test_passed === "boolean"
      ? raw.test_passed
      : typeof raw.tests_passed === "boolean"
        ? raw.tests_passed
        : verif && typeof verif.passed === "boolean" && verif.status !== "not_run"
          ? verif.passed
          : null;

  const filesArr = Array.isArray(raw.files) ? raw.files : null;
  const filesCount = !isAbsent(raw.files_changed)
    ? Number(raw.files_changed)
    : !isAbsent(raw.file_count)
      ? Number(raw.file_count)
      : filesArr
        ? filesArr.length
        : null;

  return {
    id,
    is_sample: isSample,
    title: String(raw.title || raw.heading || "Untitled change"),
    summary: !isAbsent(raw.summary) ? String(raw.summary) : !isAbsent(raw.reason) ? String(raw.reason) : null,
    why: !isAbsent(raw.why) ? String(raw.why) : null,
    status,
    bucket,
    tool_label: friendlyToolLabel(raw.tool_label || raw.driver_label || raw.driver || raw.tool),
    reviewer_label: friendlyToolLabel(raw.reviewer_label || raw.reviewer),
    independent_review: indepObj,
    risk_level: !isAbsent(raw.risk_level) ? String(raw.risk_level) : null,
    hold_reason: !isAbsent(raw.hold_reason) ? String(raw.hold_reason) : null,
    protected_path: !isAbsent(raw.protected_path) ? String(raw.protected_path) : null,
    needed_credits: Number.isFinite(Number(raw.needed_credits)) ? Number(raw.needed_credits) : null,
    files_changed: Number.isFinite(filesCount) ? filesCount : null,
    additions: Number.isFinite(Number(raw.additions)) ? Number(raw.additions) : null,
    deletions: Number.isFinite(Number(raw.deletions)) ? Number(raw.deletions) : null,
    credits_cost: Number.isFinite(Number(raw.credits_cost ?? raw.credits_used)) ? Number(raw.credits_cost ?? raw.credits_used) : null,
    branch: !isAbsent(raw.branch || raw.target_branch) ? String(raw.branch || raw.target_branch) : null,
    git_host: !isAbsent(raw.git_host) ? String(raw.git_host) : "GitHub",
    test_command: !isAbsent(raw.test_command) ? String(raw.test_command) : null,
    test_passed: normalizedTestPassed,
    test_duration_ms: Number.isFinite(Number(raw.test_duration_ms)) ? Number(raw.test_duration_ms) : null,
    started_at_ms: Number.isFinite(Number(raw.started_at_ms)) ? Number(raw.started_at_ms) : null,
    created_at: raw.updated_at || raw.created_at || null,
    files: filesArr,
  };
}

function normalizeBootstrap(raw) {
  const next = createEmptyData();
  if (!raw || typeof raw !== "object") return next;
  if (raw.ui_version) state.uiVersion = String(raw.ui_version);

  if (raw.repo && typeof raw.repo === "object") {
    const r = raw.repo;
    next.repo.name = !isAbsent(r.name) ? String(r.name) : null;
    next.repo.branch = !isAbsent(r.branch) ? String(r.branch) : null;
    next.repo.vcs = !isAbsent(r.vcs) ? String(r.vcs) : "git";
    next.repo.git_host = !isAbsent(r.git_host) ? String(r.git_host) : "GitHub";
    next.repo.initialized = r.initialized !== false;
    next.repo.cursor_detected = Boolean(r.cursor_detected);
    next.repo.cursor_rules_count = Number(r.cursor_rules_count) || 0;
    next.repo.github_connected = Boolean(r.github_connected);
    next.repo.linear_connected = Boolean(r.linear_connected);
  }

  if (raw.inbox && typeof raw.inbox === "object") {
    const rawItems = Array.isArray(raw.inbox.items) ? raw.inbox.items : [];
    next.inbox.items = rawItems.map((it) => normalizeInboxItem(it, false)).filter(Boolean);

    if (raw.inbox.sample_walkthrough && typeof raw.inbox.sample_walkthrough === "object") {
      const mergedSample = {
        ...DEFAULT_SAMPLE_WALKTHROUGH,
        ...raw.inbox.sample_walkthrough,
        is_sample: true,
        files: Array.isArray(raw.inbox.sample_walkthrough.files) && raw.inbox.sample_walkthrough.files.length > 0
          ? raw.inbox.sample_walkthrough.files
          : DEFAULT_SAMPLE_WALKTHROUGH.files,
      };
      next.inbox.sample_walkthrough = normalizeInboxItem(mergedSample, true);
      next.inbox.sample_walkthrough.files = mergedSample.files;
    }

    const c = raw.inbox.counts || {};
    const calcNeeds = next.inbox.items.filter((i) => i.bucket === "needs_you").length;
    const calcRun = next.inbox.items.filter((i) => i.bucket === "running").length;
    const calcDone = next.inbox.items.filter((i) => i.bucket === "done").length;
    next.inbox.counts = {
      needs_decision: Number.isFinite(Number(c.needs_decision)) ? Number(c.needs_decision) : calcNeeds,
      running: Number.isFinite(Number(c.running)) ? Number(c.running) : calcRun,
      done: Number.isFinite(Number(c.done)) ? Number(c.done) : calcDone,
    };
  }

  if (raw.board && typeof raw.board === "object") {
    const s = raw.board.summary || {};
    const shippedCount = Number(s.shipped_count) || 0;
    next.board.summary = {
      shipped_count: shippedCount,
      hours_saved: shippedCount > 0 ? Number(s.hours_saved) || 0 : 0,
      baseline_explainer: !isAbsent(s.baseline_explainer)
        ? String(s.baseline_explainer)
        : next.board.summary.baseline_explainer,
      credits_used: Number(s.credits_used) || 0,
    };

    const cols = raw.board.columns;
    if (Array.isArray(cols)) {
      for (const col of cols) {
        if (!col || typeof col !== "object") continue;
        const rawKey = String(col.id || col.key || col.status || "").toLowerCase().replace(/\s+/g, "_");
        // Backend `ui_workbench_run.rs` emits column IDs `queued | active | review | shipped`,
        // which map onto client column buckets `queued | in_progress | needs_review | shipped`.
        const key = rawKey === "active" ? "in_progress" : rawKey === "review" ? "needs_review" : rawKey;
        const list = Array.isArray(col.items) ? col.items : Array.isArray(col.cards) ? col.cards : [];
        if (key in next.board.columns) {
          next.board.columns[key] = list;
        }
      }
    } else if (cols && typeof cols === "object") {
      for (const key of ["queued", "in_progress", "needs_review", "shipped"]) {
        if (Array.isArray(cols[key])) next.board.columns[key] = cols[key];
      }
    }
  }

  if (raw.agents && typeof raw.agents === "object") {
    const a = raw.agents;
    if (Array.isArray(a.detected_tools) && a.detected_tools.length > 0) {
      next.agents.detected_tools = a.detected_tools.map((t) => ({
        id: normalizeDetectedToolId(t.id || t.kind || t.name || "tool"),
        label: friendlyToolLabel(t.label || t.name || t.id || "Coding tool"),
        installed: typeof t.installed === "boolean"
          ? t.installed
          : t.detected !== false && t.status !== "missing" && t.status !== "not_installed",
        version: !isAbsent(t.version) ? String(t.version) : null,
        setup_command: !isAbsent(t.setup_command) ? String(t.setup_command) : "chinwag doctor",
      }));
    }
    if (!isAbsent(a.driver_tool)) next.agents.driver_tool = normalizeToolKind(a.driver_tool);
    if (!isAbsent(a.reviewer_tool)) next.agents.reviewer_tool = normalizeToolKind(a.reviewer_tool);
    if (!isAbsent(a.test_verifier_tool)) next.agents.test_verifier_tool = normalizeToolKind(a.test_verifier_tool);
    if (!isAbsent(a.security_verifier_tool)) next.agents.security_verifier_tool = normalizeToolKind(a.security_verifier_tool);
    if ([50, 100, 150, 200].includes(Number(a.review_tier_credits))) {
      next.agents.review_tier_credits = Number(a.review_tier_credits);
    }
    if (a.workflow && typeof a.workflow === "object") {
      next.agents.workflow = {
        independent_review: a.workflow.independent_review !== false,
        protect_sensitive_paths: a.workflow.protect_sensitive_paths !== false,
        auto_test_before_review: a.workflow.auto_test_before_review !== false,
      };
      if (!isAbsent(a.workflow.driver_tool)) {
        next.agents.driver_tool = normalizeToolKind(a.workflow.driver_tool);
      }
      if (!isAbsent(a.workflow.reviewer_tool)) {
        next.agents.reviewer_tool = normalizeToolKind(a.workflow.reviewer_tool);
      }
      if (!isAbsent(a.workflow.test_verifier_tool)) {
        next.agents.test_verifier_tool = normalizeToolKind(a.workflow.test_verifier_tool);
      }
      if (!isAbsent(a.workflow.security_verifier_tool)) {
        next.agents.security_verifier_tool = normalizeToolKind(a.workflow.security_verifier_tool);
      }
      const wfCredits = Number(a.workflow.review_tier_credits);
      if ([50, 100, 150, 200].includes(wfCredits)) {
        next.agents.review_tier_credits = wfCredits;
      } else {
        const mappedCredits = creditsForReviewMode(a.workflow.review_mode);
        if (mappedCredits !== null) next.agents.review_tier_credits = mappedCredits;
      }
      if (Array.isArray(a.workflow.protected_paths)) {
        next.agents.protected_paths = a.workflow.protected_paths.map(String);
      }
    }
    ensureDistinctPairingSlots(next.agents);
    if (Array.isArray(a.protected_paths)) {
      next.agents.protected_paths = a.protected_paths.map(String);
    }
    if (Array.isArray(a.learned_rules)) {
      next.agents.learned_rules = a.learned_rules
        .map((r, idx) => (typeof r === "string"
          ? { id: `rule-${idx}`, text: r, source_label: "Repository rule" }
          : {
              id: String(r.id || `rule-${idx}`),
              text: String(r.text || r.rule || r.description || ""),
              source_label: !isAbsent(r.source_label || r.source) ? String(r.source_label || r.source) : "Learned from review",
            }))
        .filter((r) => !isAbsent(r.text));
    }
  }

  if (raw.credits && typeof raw.credits === "object") {
    const c = raw.credits;
    const avail = Number(c.available_credits);
    if (Number.isFinite(avail)) {
      next.credits.available = true;
      next.credits.available_credits = Math.max(0, Math.round(avail));
    }
    next.credits.next_expiry_at = !isAbsent(c.next_expiry_at) ? String(c.next_expiry_at) : null;
    next.credits.next_expiry_credits = Number.isFinite(Number(c.next_expiry_credits))
      ? Number(c.next_expiry_credits)
      : null;
    next.credits.plan_tier = !isAbsent(c.plan_tier) ? String(c.plan_tier) : "Free Starter Trial";
    if (!isAbsent(c.pack_expiry_notice)) {
      next.credits.pack_expiry_notice = String(c.pack_expiry_notice);
    }
    if (!isAbsent(c.pricing_url)) {
      next.credits.pricing_url = String(c.pricing_url);
    }

    const canonicalPackSku = (rawSku) => {
      const s = String(rawSku || "").toLowerCase();
      if (s === "pack_50" || s === "starter" || s === "developer" || s === "developer_50") return "pack_50";
      if (s === "pack_160" || s === "team" || s === "growth_160") return "pack_160";
      if (s === "pack_560" || s === "growth" || s === "scale_560") return "pack_560";
      if (s === "pack_1000" || s === "scale" || s === "volume" || s === "org_volume_1000") return "pack_1000";
      return s;
    };

    const packsArr = Array.isArray(c.packs) ? c.packs : [];
    const tranches = [];
    for (const p of packsArr) {
      if (!p || typeof p !== "object") continue;
      const skuKey = canonicalPackSku(p.pack_sku || p.sku || p.id || "");
      const catTarget = next.credits.catalog.find((cp) => cp.sku === skuKey);
      if (catTarget && Number.isFinite(Number(p.price_usd)) && Number.isFinite(Number(p.credits || p.credits_granted))) {
        catTarget.price_usd = Number(p.price_usd);
        catTarget.credits = Number(p.credits || p.credits_granted);
        if (!isAbsent(p.label || p.name)) catTarget.label = String(p.label || p.name);
        if (!isAbsent(p.rate_note || p.summary)) catTarget.rate_note = String(p.rate_note || p.summary);
        if (Number.isFinite(Number(p.expires_months))) catTarget.expires_months = Number(p.expires_months);
      }
      if (!isAbsent(p.remaining_credits) || !isAbsent(p.expires_at)) {
        tranches.push({
          label: String(p.label || p.name || "Credit pack"),
          remaining_credits: Number(p.remaining_credits ?? p.credits ?? 0),
          expires_at: p.expires_at || null,
        });
      }
    }
    if (Array.isArray(c.tranches)) {
      for (const t of c.tranches) {
        if (t && typeof t === "object") {
          tranches.push({
            label: String(t.label || t.name || "Credit pack"),
            remaining_credits: Number(t.remaining_credits ?? t.credits ?? 0),
            expires_at: t.expires_at || null,
          });
        }
      }
    }
    next.credits.tranches = tranches;

    if (c.auto_refill && typeof c.auto_refill === "object") {
      next.credits.auto_refill = {
        enabled: Boolean(c.auto_refill.enabled),
        threshold_credits: Number(c.auto_refill.threshold_credits) || 250,
        pack_sku: canonicalPackSku(c.auto_refill.pack_sku || "pack_160") || "pack_160",
        monthly_cap_usd: Number(c.auto_refill.monthly_cap_usd) || 500,
      };
    }
    if (Array.isArray(c.receipts)) {
      next.credits.receipts = c.receipts.map((rc, i) => ({
        id: String(rc.id || `rc-${i}`),
        title: String(rc.title || rc.action || rc.label || rc.description || "Credit activity"),
        delta_credits: Number.isFinite(Number(rc.delta_credits ?? rc.credits))
          ? Number(rc.delta_credits ?? rc.credits)
          : null,
        created_at: rc.created_at || rc.when || rc.timestamp || null,
      }));
    }
  }

  if (raw.privacy && typeof raw.privacy === "object") {
    next.privacy.bind_addr = String(raw.privacy.bind_addr || "127.0.0.1");
    next.privacy.port = Number(raw.privacy.port) || next.privacy.port;
    next.privacy.code_leaves_machine = Boolean(raw.privacy.code_leaves_machine);
    if (!isAbsent(raw.privacy.summary)) next.privacy.summary = String(raw.privacy.summary);
    if (!isAbsent(raw.privacy.ciso_review_url)) {
      next.privacy.ciso_review_url = String(raw.privacy.ciso_review_url);
    }
    if (typeof raw.privacy.telemetry_enabled === "boolean") {
      next.privacy.telemetry_enabled = raw.privacy.telemetry_enabled;
      setTelemetryOptOut(!raw.privacy.telemetry_enabled);
    }
  }

  if (raw.invite && typeof raw.invite === "object") {
    if (!isAbsent(raw.invite.join_command)) next.invite.join_command = String(raw.invite.join_command);
    if (!isAbsent(raw.invite.referral_url)) next.invite.referral_url = String(raw.invite.referral_url);
    if (Number.isFinite(Number(raw.invite.bonus_credits))) next.invite.bonus_credits = Number(raw.invite.bonus_credits);
  }

  next.delivery2 = normalizeDelivery2State(raw.delivery2, next);

  return next;
}

function safeChinwagOutboundUrl(raw, fallback = "https://chinwag.sh/open") {
  const s = String(raw ?? "").trim();
  if (!s || /[\u0000-\u001F\u007F\s]/.test(s)) return fallback;
  const allowedPrefix =
    s === "https://chinwag.sh/security" ||
    s === "https://chinwag.sh/pricing" ||
    s.startsWith("https://chinwag.sh/pricing?") ||
    s.startsWith("https://chinwag.sh/pricing#") ||
    s === "https://chinwag.sh/open" ||
    s.startsWith("https://chinwag.sh/open?");
  if (!allowedPrefix) return fallback;
  const tailLower = s.slice("https://chinwag.sh/".length).toLowerCase();
  if (
    tailLower.includes("://") ||
    tailLower.includes("//") ||
    tailLower.includes("javascript:") ||
    tailLower.includes("data:") ||
    tailLower.includes("%2f%2f") ||
    tailLower.includes("%3a")
  ) {
    return fallback;
  }
  return s;
}

function normalizeDelivery2State(rawD2, baseData = null) {
  const def = createDefaultDelivery2State();
  if (baseData && baseData.inbox && baseData.board && baseData.credits) {
    const ready = Math.max(0, Number(baseData.inbox.counts.needs_decision) || 0);
    const active =
      (Array.isArray(baseData.board.columns.in_progress) ? baseData.board.columns.in_progress.length : 0) +
      (Array.isArray(baseData.board.columns.queued) ? baseData.board.columns.queued.length : 0);
    const availCr = baseData.credits.available_credits !== null ? baseData.credits.available_credits : 500;
    def.morning_focus.rows = [
      {
        id: "mf-inbox",
        badge: String(ready),
        label: ready === 1 ? "diff ready for your review" : "diffs ready for your review",
        cta: "Inbox",
        target_tab: "inbox",
        hash: "#inbox",
      },
      {
        id: "mf-board",
        badge: String(active),
        label: active === 1 ? "active task on Board" : "active tasks on Board",
        cta: "Board",
        target_tab: "board",
        hash: "#board",
      },
      {
        id: "mf-credits",
        badge: `${formatInt(availCr) || "500"} Cr`,
        label: "available in workspace pool",
        cta: "Credits",
        target_tab: "credits",
        hash: "#credits",
      },
    ];
  }

  if (!rawD2 || typeof rawD2 !== "object") return def;

  const out = { ...def };
  out.agent_name = "Delivery-2";
  out.seq = Math.max(1, Number(rawD2.seq) || 1);
  out.status = !isAbsent(rawD2.status) ? String(rawD2.status) : def.status;
  out.status_label = !isAbsent(rawD2.status_label) ? String(rawD2.status_label) : def.status_label;
  out.active_thread_id = !isAbsent(rawD2.active_thread_id) ? String(rawD2.active_thread_id) : "thr-main";

  if (rawD2.sync_radar && typeof rawD2.sync_radar === "object") {
    const sr = rawD2.sync_radar;
    out.sync_radar = {
      latency_ms: Number(sr.latency_ms) || 1,
      latency_label: !isAbsent(sr.latency_label) ? String(sr.latency_label) : "<200ms",
      surfaces: Array.isArray(sr.surfaces) && sr.surfaces.length === 4
        ? sr.surfaces.map((s, idx) => {
            const fb = def.sync_radar.surfaces[idx] || def.sync_radar.surfaces[0];
            const id = String(s.id || fb.id);
            const fallbackUrl = fb.connect_url || "https://chinwag.sh/open";
            return {
              id,
              label: String(s.label || fb.label),
              authorized: typeof s.authorized === "boolean" ? s.authorized : fb.authorized,
              in_thread: typeof s.in_thread === "boolean" ? s.in_thread : fb.in_thread,
              locked_in_thread: Boolean(s.locked_in_thread ?? fb.locked_in_thread),
              role_mode: String(s.role_mode || fb.role_mode),
              auth_status: String(
                id === "slack"
                  ? "Connected · ambient status cards only"
                  : s.auth_status || fb.auth_status,
              ),
              connect_url:
                id === "local"
                  ? null
                  : safeChinwagOutboundUrl(!isAbsent(s.connect_url) ? s.connect_url : fallbackUrl, fallbackUrl),
              policy_note: !isAbsent(s.policy_note) ? String(s.policy_note) : fb.policy_note,
            };
          })
        : def.sync_radar.surfaces,
    };
  }

  if (rawD2.morning_focus && typeof rawD2.morning_focus === "object") {
    const mf = rawD2.morning_focus;
    out.morning_focus = {
      seen: Boolean(mf.seen),
      collapsed: Boolean(mf.collapsed),
      rows:
        Array.isArray(mf.rows) && mf.rows.length === 3
          ? mf.rows.map((r, idx) => {
              const fb = def.morning_focus.rows[idx];
              return {
                id: String(r.id || fb.id),
                badge: String(r.badge ?? fb.badge),
                label: String(r.label || fb.label),
                cta: String(r.cta || fb.cta),
                target_tab: String(r.target_tab || fb.target_tab),
                hash: String(r.hash || fb.hash),
              };
            })
          : def.morning_focus.rows,
    };
  }

  if (Array.isArray(rawD2.entries)) {
    out.entries = rawD2.entries.filter((e) => e && typeof e === "object").map((e, i) => {
      const normalizedEntry = {
        ...e,
        id: String(e.id || `entry-${i}`),
        kind: String(e.kind || "qa_card"),
        seq: Math.max(1, Number(e.seq) || 1),
      };
      if (normalizedEntry.kind === "oauth_card") {
        normalizedEntry.challenge_url = safeChinwagOutboundUrl(
          e.challenge_url,
          "https://chinwag.sh/open",
        );
      }
      return normalizedEntry;
    });
  }

  if (rawD2.history && typeof rawD2.history === "object") {
    out.history = {
      today: Array.isArray(rawD2.history.today) ? rawD2.history.today : def.history.today,
      earlier: Array.isArray(rawD2.history.earlier) ? rawD2.history.earlier : [],
    };
  }

  if (Array.isArray(rawD2.memories)) {
    out.memories = rawD2.memories;
  }

  if (Array.isArray(rawD2.steering_chips) && rawD2.steering_chips.length > 0) {
    out.steering_chips = rawD2.steering_chips.map((c, idx) => ({
      id: String(c.id || `chip-${idx}`),
      label: String(c.label || "Prompt"),
      prompt: String(c.prompt || c.label || ""),
    }));
  }

  if (rawD2.links && typeof rawD2.links === "object") {
    out.links = {
      security_url: safeChinwagOutboundUrl(rawD2.links.security_url, def.links.security_url),
      founders_url: safeChinwagOutboundUrl(rawD2.links.founders_url, def.links.founders_url),
      open_url: safeChinwagOutboundUrl(rawD2.links.open_url, def.links.open_url),
      pricing_url: safeChinwagOutboundUrl(rawD2.links.pricing_url, def.links.pricing_url),
    };
  }

  return out;
}

function parseHunkLines(hunk) {
  if (!hunk) return { header: "@@ -1,1 +1,1 @@", lines: [] };
  if (typeof hunk === "string") {
    return parseRawUnifiedPatch(hunk)[0] || { header: "@@ -1,1 +1,1 @@", lines: [] };
  }
  const header = String(hunk.header || "@@ -1,1 +1,1 @@");
  const m = /@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(header);
  let oldLn = m ? Number(m[1]) : 1;
  let newLn = m ? Number(m[2]) : 1;
  const rawLines = Array.isArray(hunk.lines) ? hunk.lines : [];
  const lines = rawLines.map((ln) => {
    if (typeof ln === "string") {
      if (ln.startsWith("+")) {
        const res = { type: "add", old_ln: null, new_ln: newLn, text: ln.slice(1) };
        newLn += 1;
        return res;
      }
      if (ln.startsWith("-")) {
        const res = { type: "del", old_ln: oldLn, new_ln: null, text: ln.slice(1) };
        oldLn += 1;
        return res;
      }
      const text = ln.startsWith(" ") ? ln.slice(1) : ln;
      const res = { type: "ctx", old_ln: oldLn, new_ln: newLn, text };
      oldLn += 1;
      newLn += 1;
      return res;
    }
    const kind = String(ln.type || ln.kind || "ctx").toLowerCase();
    const normType = kind.startsWith("add") || kind === "+" ? "add" : kind.startsWith("del") || kind === "-" ? "del" : "ctx";
    const o = ln.old_ln ?? ln.old_line ?? (normType === "add" ? null : oldLn++);
    const n = ln.new_ln ?? ln.new_line ?? (normType === "del" ? null : newLn++);
    return {
      type: normType,
      old_ln: o,
      new_ln: n,
      text: String(ln.text ?? ln.content ?? ""),
    };
  });
  return { header, lines };
}

function parseRawUnifiedPatch(patchText) {
  const hunks = [];
  let current = null;
  let oldLn = 1;
  let newLn = 1;
  for (const rawLine of String(patchText || "").split("\n")) {
    if (rawLine.startsWith("@@")) {
      const m = /@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(rawLine);
      oldLn = m ? Number(m[1]) : 1;
      newLn = m ? Number(m[2]) : 1;
      current = { header: rawLine, lines: [] };
      hunks.push(current);
    } else if (current) {
      if (rawLine.startsWith("+") && !rawLine.startsWith("+++")) {
        current.lines.push({ type: "add", old_ln: null, new_ln: newLn++, text: rawLine.slice(1) });
      } else if (rawLine.startsWith("-") && !rawLine.startsWith("---")) {
        current.lines.push({ type: "del", old_ln: oldLn++, new_ln: null, text: rawLine.slice(1) });
      } else if (!rawLine.startsWith("\\ No newline")) {
        current.lines.push({
          type: "ctx",
          old_ln: oldLn++,
          new_ln: newLn++,
          text: rawLine.startsWith(" ") ? rawLine.slice(1) : rawLine,
        });
      }
    }
  }
  return hunks;
}

function normalizeDiffPayload(raw, fallbackItem) {
  const base = normalizeInboxItem({ ...(fallbackItem || {}), ...(raw || {}) }, fallbackItem && fallbackItem.is_sample);
  const rawFiles = Array.isArray(raw && raw.files)
    ? raw.files
    : Array.isArray(fallbackItem && fallbackItem.files)
      ? fallbackItem.files
      : [];
  const files = rawFiles.map((f) => {
    const hunks = Array.isArray(f.hunks) && f.hunks.length > 0
      ? f.hunks.map(parseHunkLines)
      : !isAbsent(f.patch || f.diff)
        ? parseRawUnifiedPatch(f.patch || f.diff)
        : [];
    let calcAdd = 0;
    let calcDel = 0;
    for (const h of hunks) {
      for (const l of h.lines) {
        if (l.type === "add") calcAdd += 1;
        else if (l.type === "del") calcDel += 1;
      }
    }
    return {
      path: String(f.path || f.file || "changed-file"),
      additions: Number.isFinite(Number(f.additions)) ? Number(f.additions) : calcAdd,
      deletions: Number.isFinite(Number(f.deletions)) ? Number(f.deletions) : calcDel,
      hunks,
    };
  });
  base.files = files;
  if (isAbsent(base.files_changed)) base.files_changed = files.length;
  if (isAbsent(base.additions)) base.additions = files.reduce((acc, f) => acc + f.additions, 0);
  if (isAbsent(base.deletions)) base.deletions = files.reduce((acc, f) => acc + f.deletions, 0);
  return base;
}

// ── 5 · Global Chrome, Overlays, Popovers & Modals ───────────────────────────

const dom = {
  repoPill: () => document.getElementById("repo-pill"),
  repoName: () => document.getElementById("repo-pill-name"),
  repoSep: () => document.getElementById("repo-pill-sep"),
  repoBranch: () => document.getElementById("repo-pill-branch"),
  headerTabs: () => document.getElementById("header-tabs"),
  mobileTabs: () => document.getElementById("mobile-tabrow"),
  badgeDesktop: () => document.getElementById("inbox-badge-desktop"),
  badgeMobile: () => document.getElementById("inbox-badge-mobile"),
  btnInvite: () => document.getElementById("btn-invite"),
  creditPill: () => document.getElementById("header-credit-pill"),
  creditSkeleton: () => document.getElementById("credit-pill-skeleton"),
  creditText: () => document.getElementById("credit-pill-text"),
  btnTheme: () => document.getElementById("btn-theme"),
  iconMoon: () => document.getElementById("theme-icon-moon"),
  iconSun: () => document.getElementById("theme-icon-sun"),
  btnPrivacy: () => document.getElementById("btn-privacy"),
  btnMobileMenu: () => document.getElementById("btn-mobile-menu"),
  btnD2Drawer: () => document.getElementById("btn-d2-drawer"),
  d2DrawerScrim: () => document.getElementById("d2-drawer-scrim"),
  d2Rail: () => document.getElementById("d2-rail"),
  d2RailToggleFixed: () => document.getElementById("d2-rail-toggle-fixed"),
  d2Track: () => document.getElementById("d2-track"),
  d2Spine: () => document.getElementById("d2-spine"),
  d2ComposerInput: () => document.getElementById("d2-composer-input"),
  main: () => document.getElementById("main"),
  sessionAlert: () => document.getElementById("session-alert-host"),
  viewRoot: () => (typeof document !== "undefined" ? document.getElementById("view-root") : null),
  popoverLayer: () => document.getElementById("popover-layer"),
  modalScrim: () => document.getElementById("modal-scrim"),
  modalLayer: () => document.getElementById("modal-layer"),
  toastRegion: () => document.getElementById("toast-region"),
  srAnnouncer: () => document.getElementById("sr-announcer"),
};

const toaster = typeof document !== "undefined" ? Motion.createToaster(dom.toastRegion()) : { show() {}, dismiss() {} };
const elapsedClock = Motion.createElapsedClock(formatElapsed);

let desktopTabsIndicator = { update() {}, destroy() {} };
let mobileTabsIndicator = { update() {}, destroy() {} };
let activePopoverTrigger = null;
let activeModalTrigger = null;
let closingPopoverReturnTrigger = null;
let closingModalReturnTrigger = null;
let popoverSeq = 0;
let modalSeq = 0;
let lowCreditBannerTracked = false;

function announce(text) {
  const sr = dom.srAnnouncer();
  if (!sr || isAbsent(text)) return;
  sr.textContent = "";
  requestAnimationFrame(() => {
    sr.textContent = String(text);
  });
}

function currentTheme() {
  if (typeof document === "undefined") return "stone";
  const attr = document.documentElement.getAttribute("data-theme");
  return attr === "dark" ? "dark" : "stone";
}

function syncThemeButton() {
  const isDark = currentTheme() === "dark";
  const btn = dom.btnTheme();
  const moon = dom.iconMoon();
  const sun = dom.iconSun();
  if (moon) moon.hidden = isDark;
  if (sun) sun.hidden = !isDark;
  if (btn) {
    const label = isDark ? "Switch to light theme" : "Switch to dark theme";
    btn.setAttribute("aria-label", label);
    btn.setAttribute("title", label);
  }
}

function toggleTheme() {
  const prev = currentTheme();
  const next = prev === "dark" ? "stone" : "dark";
  Motion.switchTheme(next);
  syncThemeButton();
  trackUiEvent("ui_theme_changed", {
    previous_theme: prev,
    theme: next,
  });
}

function showSessionExpiredBanner() {
  const host = dom.sessionAlert();
  if (!host || host.childElementCount > 0) return;
  const wrap = el(
    "div",
    { className: "container" },
    el(
      "div",
      { className: "banner banner-warning", role: "alert" },
      el(
        "div",
        { className: "banner-head" },
        ICONS.alert(false),
        el("strong", { className: "t-14 w600" }, "Local session refreshed"),
      ),
      el(
        "p",
        { className: "t-13 secondary" },
        "The local app restarted or refreshed its security token. Reload this tab to reconnect.",
      ),
      el(
        "div",
        { className: "banner-actions" },
        actionBtn({
          label: "Reload tab",
          variant: "primary",
          size: "sm",
          onClick: () => window.location.reload(),
        }),
      ),
    ),
  );
  host.appendChild(wrap);
}

function syncHeaderChrome() {
  const repo = state.data.repo;
  const pill = dom.repoPill();
  const nameEl = dom.repoName();
  const sepEl = dom.repoSep();
  const branchEl = dom.repoBranch();
  if (pill && nameEl && sepEl && branchEl) {
    if (!isAbsent(repo.name)) {
      pill.removeAttribute("data-empty");
      nameEl.textContent = repo.name;
      if (!isAbsent(repo.branch)) {
        sepEl.hidden = false;
        branchEl.hidden = false;
        branchEl.textContent = repo.branch;
      } else {
        sepEl.hidden = true;
        branchEl.hidden = true;
      }
    } else {
      pill.setAttribute("data-empty", "true");
      nameEl.textContent = "Select repository";
      sepEl.hidden = true;
      branchEl.hidden = true;
    }
  }

  // Inbox count badges (omit when 0 — never render "0")
  const needsCount = Math.max(0, Number(state.data.inbox.counts.needs_decision) || 0);
  for (const b of [dom.badgeDesktop(), dom.badgeMobile()]) {
    if (!b) continue;
    if (needsCount > 0) {
      b.textContent = String(needsCount);
      b.hidden = false;
    } else {
      b.textContent = "";
      b.hidden = true;
    }
  }

  // Credit balance pill — never display fake fallback balances on error
  const cPill = dom.creditPill();
  const cSkel = dom.creditSkeleton();
  const cText = dom.creditText();
  if (cPill && cText) {
    if (cSkel) cSkel.hidden = true;
    cText.hidden = false;
    clearNode(cText);
    if (!state.data.credits.available || state.data.credits.available_credits === null) {
      cPill.dataset.level = "unavailable";
      cPill.setAttribute("aria-label", "Credit balance unavailable. Open Credits.");
      cText.textContent = "Balance unavailable";
    } else {
      const bal = state.data.credits.available_credits;
      const fmt = formatInt(bal);
      if (bal <= 0) {
        cPill.dataset.level = "urgent";
        cPill.setAttribute("aria-label", "0 credits remaining, tasks paused. Open Credits.");
        cText.append(document.createTextNode("0 Cr · Paused"));
      } else if (bal < 150) {
        cPill.dataset.level = "low";
        cPill.setAttribute("aria-label", `${fmt} credits remaining, low balance. Open Credits.`);
        cText.append(
          document.createTextNode(`${fmt} Cr`),
          el("span", { className: "credit-suffix" }, " · Low"),
        );
        if (!lowCreditBannerTracked) {
          lowCreditBannerTracked = true;
          trackUiEvent("ui_low_credit_banner_shown", {
            credits_remaining_bucket: creditsBucket(bal),
            recommended_pack_slug: "growth_160",
          });
        }
      } else {
        cPill.dataset.level = "ok";
        cPill.setAttribute("aria-label", `${fmt} credits remaining. Open Credits.`);
        cText.append(
          document.createTextNode(`${fmt}`),
          el("span", { className: "credit-suffix" }, " credits left"),
        );
      }
    }
  }

  // Active navigation tab state
  const viewNames = {
    inbox: "Inbox",
    board: "Board",
    agents: "Agents & Rules",
    credits: "Credits",
  };
  document.title = `${viewNames[state.view] || "Inbox"} · chinwag`;
  for (const nav of [dom.headerTabs(), dom.mobileTabs()]) {
    if (!nav) continue;
    for (const link of nav.querySelectorAll("a[data-route]")) {
      if (link.dataset.route === state.view) {
        link.setAttribute("aria-current", "page");
      } else {
        link.removeAttribute("aria-current");
      }
    }
  }
  desktopTabsIndicator.update();
  mobileTabsIndicator.update();
}

// ── Popovers ──

async function closePopover(options = {}) {
  const opts = options && typeof options === "object" && !("target" in options) ? options : {};
  const immediate = Boolean(opts.immediate);
  const restoreFocus = opts.restoreFocus !== undefined ? Boolean(opts.restoreFocus) : !immediate;
  const layer = dom.popoverLayer();
  if (!layer || layer.hidden) return;
  const seq = ++popoverSeq;
  const prevTrigger = activePopoverTrigger || closingPopoverReturnTrigger;
  activePopoverTrigger = null;
  closingPopoverReturnTrigger = immediate ? null : prevTrigger;
  if (prevTrigger) {
    prevTrigger.setAttribute("aria-expanded", "false");
  }
  const pop = layer.querySelector(".popover");
  if (!immediate && pop) {
    pop.dataset.state = "closing";
    await Motion.settled(pop);
    if (seq !== popoverSeq) return;
  }
  closingPopoverReturnTrigger = null;
  clearNode(layer);
  layer.hidden = true;
  if (restoreFocus && prevTrigger && prevTrigger.isConnected) {
    prevTrigger.focus({ preventScroll: true });
  }
}

function openPopover(triggerEl, buildContent, variantClass = "", options = {}) {
  const layer = dom.popoverLayer();
  if (!layer) return;
  const opts = options && typeof options === "object" ? options : {};
  if (
    !opts.forceOpen &&
    activePopoverTrigger === triggerEl &&
    !layer.hidden &&
    !layer.querySelector('.popover[data-state="closing"]')
  ) {
    closePopover();
    return;
  }
  ++popoverSeq;
  closingPopoverReturnTrigger = null;
  clearNode(layer);
  if (activePopoverTrigger && activePopoverTrigger !== triggerEl) {
    activePopoverTrigger.setAttribute("aria-expanded", "false");
  }
  activePopoverTrigger = triggerEl || null;
  if (activePopoverTrigger) activePopoverTrigger.setAttribute("aria-expanded", "true");

  const scrim = el("div", { className: "popover-scrim", onClick: () => closePopover() });
  const pop = el(
    "div",
    {
      className: variantClass ? `popover ${variantClass}` : "popover",
      role: "dialog",
      "aria-modal": "false",
      dataset: { state: "open" },
    },
    buildContent((closeOpts) => closePopover(closeOpts)),
  );
  layer.append(scrim, pop);
  layer.hidden = false;
  const firstFocus = pop.querySelector("button, [href], input, select");
  if (firstFocus) firstFocus.focus({ preventScroll: true });
}

function openRepoPopover(triggerEl) {
  const repo = state.data.repo;
  openPopover(
    triggerEl,
    (close) => [
      el(
        "div",
        { className: "modal-head" },
        el("h2", { className: "t-16 w600" }, "Repository"),
        el("button", { type: "button", className: "btn-icon", "aria-label": "Close", onClick: close }, ICONS.close()),
      ),
      !isAbsent(repo.name)
        ? el(
            "div",
            { className: "section-head" },
            el("div", { className: "t-14 w500" }, repo.name),
            metaRow([
              fact(repo.branch, (b) => `Branch ${b}`),
              fact(repo.vcs, (v) => v.toUpperCase()),
            ]),
          )
        : el("p", { className: "t-13 secondary" }, "No repository initialized in this folder yet."),
      el("hr"),
      el("p", { className: "t-12 secondary" }, "To open chinwag in another repository, run this command inside that project folder:"),
      el("div", { className: "copy-field" }, "chinwag ui"),
      copyButton({
        label: "Copy launch command",
        textToCopy: "chinwag ui",
        okToast: "Launch command copied",
        onCopied: () => trackUiEvent("ui_repo_connected", { trigger_surface: "header_repo_pill", is_git_repo: true }),
      }),
    ],
    "popover-left",
  );
}

function openPrivacyPopover(triggerEl, options = {}) {
  const priv = state.data.privacy;
  const cisoUrl = priv.ciso_review_url || "https://chinwag.sh/pricing?talk=1&source=local_ui#founders";
  trackUiEvent("ui_privacy_popover_opened", {
    telemetry_state: isTelemetryOptedOut() ? "opted_out_ui" : "enabled",
  });
  openPopover(
    triggerEl,
    (close) => {
      const analyticsEnabled = !isTelemetryOptedOut();
      return [
        el(
          "div",
          { className: "modal-head" },
          el("h2", { className: "t-16 w600" }, "Local privacy"),
          el("button", { type: "button", className: "btn-icon", "aria-label": "Close", onClick: () => close() }, ICONS.close()),
        ),
        el(
          "div",
          { className: "section-head" },
          statusPill(`Loopback only · ${priv.bind_addr}:${priv.port}`, "success"),
          el("p", { className: "t-13 secondary" }, priv.summary),
        ),
        el("hr"),
        el(
          "div",
          { className: "pairing-head" },
          el(
            "div",
            { className: "section-head" },
            el("div", { className: "t-13 w500" }, "Anonymous product analytics"),
            el("p", { className: "t-12 muted" }, "Counts and screen events only — never code, file names, or prompts."),
          ),
          switchControl({
            checked: analyticsEnabled,
            label: "Send anonymous product analytics",
            onToggle: async (enabled) => {
              const optOut = !enabled;
              setTelemetryOptOut(optOut);
              try {
                const res = await apiRequest("POST", "/api/v4/telemetry/preferences", {
                  action: "set_enabled",
                  enabled: Boolean(enabled),
                });
                const effectiveEnabled =
                  res && typeof res.telemetry_enabled === "boolean"
                    ? res.telemetry_enabled
                    : Boolean(enabled);
                setTelemetryOptOut(!effectiveEnabled);
                if (!optOut && effectiveEnabled) {
                  trackUiEvent("ui_telemetry_opt_out_changed", {
                    opt_out_enabled: false,
                    preference_action: "opt_in",
                    telemetry_state: "enabled",
                  });
                }
                toaster.show(
                  !effectiveEnabled
                    ? "Anonymous analytics turned off"
                    : "Anonymous analytics turned on",
                );
              } catch (e) {
                toaster.show("Could not update analytics preference");
              }
            },
          }),
        ),
        el("hr"),
        el(
          "div",
          { className: "popover-links" },
          el(
            "a",
            {
              href: "https://chinwag.sh/security",
              target: "_blank",
              rel: "noopener noreferrer",
              className: "popover-link",
            },
            "Security & privacy overview ↗",
          ),
          el(
            "a",
            {
              href: cisoUrl,
              target: "_blank",
              rel: "noopener noreferrer",
              className: "popover-link",
              onClick: () => trackUiEvent("ui_founders_talk_clicked", { trigger_surface: "global_header" }),
            },
            "Request security review ↗",
          ),
        ),
      ];
    },
    "",
    options,
  );
}

function openMobileMenuPopover(triggerEl) {
  openPopover(triggerEl, (close) => [
    el(
      "div",
      { className: "modal-head" },
      el("h2", { className: "t-16 w600" }, "Menu"),
      el("button", { type: "button", className: "btn-icon", "aria-label": "Close", onClick: () => close() }, ICONS.close()),
    ),
    actionBtn({
      label: "Invite teammate · +250 Cr",
      variant: "secondary",
      onClick: () => {
        closePopover({ immediate: true });
        openInviteModal("global_header", triggerEl);
      },
    }),
    actionBtn({
      label: currentTheme() === "dark" ? "Switch to light theme" : "Switch to dark theme",
      variant: "secondary",
      onClick: () => {
        toggleTheme();
        close();
      },
    }),
    actionBtn({
      label: "Local privacy & analytics",
      variant: "secondary",
      onClick: () => {
        closePopover({ immediate: true });
        openPrivacyPopover(triggerEl, { forceOpen: true });
      },
    }),
  ]);
}

function openBaselinePopover(triggerEl) {
  const rows = [
    ["Small bug or CI check fix", "1.5 hrs", "Reproduce failure, patch, run local suite, open PR"],
    ["Standard feature or refactor", "3.5 hrs", "Implementation across 2–4 files plus unit tests"],
    ["Cross-checked multi-file change", "6.0 hrs", "Implementation, independent review, and edge-case tests"],
    ["Security, auth, or migration change", "8.0 hrs", "Careful validation across permissions and test fixtures"],
  ];
  openPopover(
    triggerEl,
    (close) => [
      el(
        "div",
        { className: "modal-head" },
        el("h2", { className: "t-16 w600" }, "How baseline time works"),
        el("button", { type: "button", className: "btn-icon", "aria-label": "Close", onClick: close }, ICONS.close()),
      ),
      el(
        "p",
        { className: "t-13 secondary" },
        "Hours saved only counts tasks you have approved and shipped. Each shipped task compares typical solo developer completion time against the minutes you spent reviewing.",
      ),
      el(
        "table",
        { className: "bench-table" },
        el(
          "thead",
          null,
          el("tr", null, el("th", null, "Task size"), el("th", null, "Human baseline"), el("th", null, "What it covers")),
        ),
        el(
          "tbody",
          null,
          rows.map(([kind, hrs, desc]) =>
            el("tr", null, el("td", { className: "w500" }, kind), el("td", { className: "num" }, hrs), el("td", { className: "secondary" }, desc)),
          ),
        ),
      ),
    ],
    "popover-wide",
  );
}

// ── Modals ──

async function closeModal(options = {}) {
  const opts = options && typeof options === "object" && !("target" in options) ? options : {};
  const immediate = Boolean(opts.immediate);
  const restoreFocus = opts.restoreFocus !== undefined ? Boolean(opts.restoreFocus) : !immediate;
  const layer = dom.modalLayer();
  const scrim = dom.modalScrim();
  if (!layer || layer.hidden) return;
  const seq = ++modalSeq;
  const prevTrigger = activeModalTrigger || closingModalReturnTrigger;
  activeModalTrigger = null;
  closingModalReturnTrigger = immediate ? null : prevTrigger;
  const modal = layer.querySelector(".modal");
  if (!immediate) {
    if (modal) modal.dataset.state = "closing";
    if (scrim) scrim.dataset.state = "closing";
    await Promise.all([modal ? Motion.settled(modal) : null, scrim ? Motion.settled(scrim) : null]);
    if (seq !== modalSeq) return;
  }
  closingModalReturnTrigger = null;
  clearNode(layer);
  layer.hidden = true;
  if (scrim) {
    scrim.hidden = true;
    delete scrim.dataset.state;
  }
  if (restoreFocus && prevTrigger && prevTrigger.isConnected) {
    prevTrigger.focus({ preventScroll: true });
  }
}

function openModal(triggerEl, buildModal, large = false) {
  closePopover({ immediate: true });
  const layer = dom.modalLayer();
  const scrim = dom.modalScrim();
  if (!layer || !scrim) return;
  ++modalSeq;
  closingModalReturnTrigger = null;
  activeModalTrigger = triggerEl || (typeof document !== "undefined" ? document.activeElement : null);
  clearNode(layer);
  scrim.hidden = false;
  scrim.dataset.state = "open";
  scrim.onclick = () => closeModal();

  const modal = el(
    "div",
    {
      className: large ? "modal modal-lg" : "modal",
      role: "dialog",
      "aria-modal": "true",
      dataset: { state: "open" },
    },
    buildModal((closeOpts) => closeModal(closeOpts)),
  );
  layer.appendChild(modal);
  layer.hidden = false;
  const focusTarget = modal.querySelector("input, textarea, select, button.btn-primary, button");
  if (focusTarget) focusTarget.focus({ preventScroll: true });
}

function resolveInviteReturnTrigger(fallbackTriggerEl = null) {
  const inviteBtn = dom.btnInvite();
  if (inviteBtn && typeof window !== "undefined" && typeof window.getComputedStyle === "function") {
    if (window.getComputedStyle(inviteBtn).display !== "none") {
      return inviteBtn;
    }
  } else if (inviteBtn && !fallbackTriggerEl) {
    return inviteBtn;
  }
  return fallbackTriggerEl || dom.btnMobileMenu() || inviteBtn;
}

function openInviteModal(triggerSurface = "global_header", fallbackTriggerEl = null) {
  const inv = state.data.invite;
  trackUiEvent("ui_invite_modal_opened", { trigger_surface: triggerSurface });
  openModal(resolveInviteReturnTrigger(fallbackTriggerEl), (close) => {
    let tab = "team";
    const panelTeam = el(
      "div",
      { role: "tabpanel" },
      el(
        "div",
        { className: "section-block" },
        el("p", { className: "t-14 secondary" }, "Teammates on your organization share your credit pool with $0 per-seat fees."),
        el("div", { className: "copy-field" }, inv.join_command),
        el(
          "div",
          { className: "modal-foot" },
          el("span", { className: "t-12 muted" }, "Run in terminal inside your shared repo"),
          el(
            "div",
            { className: "modal-foot-right" },
            actionBtn({ label: "Done", variant: "secondary", onClick: close }),
            copyButton({
              label: "Copy join command",
              variant: "primary",
              size: "",
              textToCopy: inv.join_command,
              okToast: "Team join command copied",
              onCopied: () =>
                trackUiEvent("ui_invite_copied", {
                  invite_kind: "intra_org_seat",
                  invite_format: "open_link",
                  includes_referral_link: false,
                }),
            }),
          ),
        ),
      ),
    );
    const bonus = formatInt(inv.bonus_credits) || "250";
    const panelReferral = el(
      "div",
      { role: "tabpanel", dataset: { inactive: "true" } },
      el(
        "div",
        { className: "section-block" },
        el(
          "p",
          { className: "t-14 secondary" },
          `Share chinwag with another engineering team. Both teams get +${bonus} bonus credits when they run their first verified review.`,
        ),
        el("div", { className: "copy-field" }, inv.referral_url),
        el(
          "div",
          { className: "modal-foot" },
          el("span", { className: "t-12 muted" }, `+${bonus} Cr bonus for both teams`),
          el(
            "div",
            { className: "modal-foot-right" },
            actionBtn({ label: "Done", variant: "secondary", onClick: close }),
            copyButton({
              label: "Copy invite link",
              variant: "primary",
              size: "",
              textToCopy: inv.referral_url,
              okToast: "Referral link copied",
              onCopied: () =>
                trackUiEvent("ui_invite_copied", {
                  invite_kind: "external_org_referral",
                  invite_format: "referral_url",
                  includes_referral_link: true,
                }),
            }),
          ),
        ),
      ),
    );

    const btnTeam = el(
      "button",
      {
        type: "button",
        "aria-selected": "true",
        onClick: () => {
          if (tab === "team") return;
          tab = "team";
          btnTeam.setAttribute("aria-selected", "true");
          btnRef.setAttribute("aria-selected", "false");
          delete panelTeam.dataset.inactive;
          panelReferral.dataset.inactive = "true";
        },
      },
      "Same team · $0 seat",
    );
    const btnRef = el(
      "button",
      {
        type: "button",
        "aria-selected": "false",
        onClick: () => {
          if (tab === "ref") return;
          tab = "ref";
          btnRef.setAttribute("aria-selected", "true");
          btnTeam.setAttribute("aria-selected", "false");
          delete panelReferral.dataset.inactive;
          panelTeam.dataset.inactive = "true";
        },
      },
      `Another team · +${bonus} Cr`,
    );

    return [
      el(
        "div",
        { className: "modal-head" },
        el("h2", { className: "t-18 w600" }, "Invite a teammate"),
        el("button", { type: "button", className: "btn-icon", "aria-label": "Close", onClick: close }, ICONS.close()),
      ),
      el("div", { className: "segmented", role: "tablist" }, btnTeam, btnRef),
      el("div", { className: "modal-panels-stack" }, panelTeam, panelReferral),
    ];
  });
}

function openNewTaskModal(triggerSurface = "board_header", initialTitle = "", chipSlug = null) {
  const modalOpenedProps = { trigger_surface: triggerSurface };
  if (chipSlug) modalOpenedProps.chip_slug = chipSlug;
  trackUiEvent("ui_board_task_modal_opened", modalOpenedProps);
  openModal(null, (close) => {
    const defaultTool = normalizeToolKind(state.data.agents.driver_tool || "claude_code");
    const titleInput = el("input", {
      type: "text",
      className: "input",
      placeholder: "e.g., Fix flaky webhook signature test in checkout",
      value: initialTitle,
      "aria-label": "Task title",
    });
    const errEl = el("p", { className: "field-error", hidden: true });
    const toolSelect = el(
      "select",
      { className: "select", "aria-label": "Assign coding tool" },
      el("option", { value: "claude_code", selected: defaultTool === "claude_code" }, "Claude Code"),
      el("option", { value: "codex_cli", selected: defaultTool === "codex_cli" }, "Codex CLI"),
      el("option", { value: "gemini_cli", selected: defaultTool === "gemini_cli" }, "Gemini CLI"),
      el("option", { value: "cursor", selected: defaultTool === "cursor" }, "Cursor"),
    );
    const workstreamSelect = el(
      "select",
      { className: "select", "aria-label": "Workstream" },
      el("option", { value: "engineering" }, "Engineering"),
      el("option", { value: "qa" }, "QA"),
      el("option", { value: "security" }, "Security"),
      el("option", { value: "design" }, "Design"),
      el("option", { value: "product" }, "Product"),
      el("option", { value: "docs" }, "Docs"),
    );
    const footerGroup = el("div", { className: "modal-foot-right" });
    const createBtn = actionBtn({
      label: "Add task",
      variant: "primary",
      onClick: async () => {
        const title = titleInput.value.trim();
        if (!title) {
          titleInput.setAttribute("aria-invalid", "true");
          errEl.textContent = "Enter a short description of what needs to be done.";
          errEl.hidden = false;
          titleInput.focus();
          return;
        }
        titleInput.removeAttribute("aria-invalid");
        errEl.hidden = true;
        const toolKind = normalizeToolKind(toolSelect.value);
        const ws = workstreamSelect.value;
        try {
          const outcome = await Motion.guardAction(
            createBtn,
            async () => {
              const res = await apiRequest("POST", "/api/v4/board/tasks", {
                title,
                tool: toolKind,
                workstream: ws,
              });
              try {
                await apiRequest("POST", "/api/bus/send", {
                  room: "#eng",
                  body: `New task (${ws}): ${title}`,
                });
              } catch (e) {
                /* best-effort local bus announcement */
              }
              const card = prependQueuedBoardTask(res && res.task, {
                title,
                workstream: ws,
                toolKind,
              });
              trackUiEvent("ui_board_task_created", {
                workstream: card.workstream,
                assigned_tool_kind: toolKind,
                has_target_files: false,
              });
              return res;
            },
            { group: footerGroup, busyLabel: "Adding…" },
          );
          if (!outcome) return;
          await close();
          toaster.show("Task added to Queued on Board");
          if (state.view === "board" || state.view === "inbox") renderCurrentView();
        } catch (err) {
          trackUiEvent("ui_action_failed", {
            failed_action: "board_task_create",
            error_category: "io_error",
          });
          toaster.show(err.message || "Could not queue task right now");
        }
      },
    });
    footerGroup.append(actionBtn({ label: "Cancel", variant: "secondary", onClick: close }), createBtn);

    return [
      el(
        "div",
        { className: "modal-head" },
        el("h2", { className: "t-18 w600" }, "New task"),
        el("button", { type: "button", className: "btn-icon", "aria-label": "Close", onClick: close }, ICONS.close()),
      ),
      el(
        "div",
        { className: "section-block" },
        el("label", { className: "t-13 w500" }, "What should be built or fixed"),
        titleInput,
        errEl,
      ),
      el(
        "div",
        { className: "pairing-selects" },
        el("div", { className: "section-block" }, el("label", { className: "t-13 w500" }, "Coding tool"), toolSelect),
        el("div", { className: "section-block" }, el("label", { className: "t-13 w500" }, "Category"), workstreamSelect),
      ),
      el("div", { className: "modal-foot" }, el("span", { className: "t-12 muted" }, "Runs in an isolated workspace first"), footerGroup),
    ];
  });
}

async function openCursorPreviewModal(triggerSurface = "agents_tab") {
  let previewRules = [];
  try {
    const res = await apiRequest("GET", "/api/v4/cursor/preview");
    previewRules = Array.isArray(res.preview_rules)
      ? res.preview_rules.map((r, i) => (typeof r === "string"
        ? { id: `cr-${i}`, name: `Cursor rule ${i + 1}`, summary: r }
        : {
            id: String(r.id || `cr-${i}`),
            name: String(r.name || r.file || r.title || `Rule ${i + 1}`),
            summary: String(r.summary || r.description || r.preview || "Project coding convention"),
          }))
      : [];
  } catch (err) {
    toaster.show("Could not read .cursor rules right now");
    return;
  }
  if (previewRules.length === 0) {
    previewRules = [
      { id: "cr-1", name: "TypeScript & test conventions", summary: "Run unit tests before opening a review; prefer explicit return types." },
    ];
  }
  trackUiEvent("ui_cursor_import_previewed", {
    trigger_surface: triggerSurface,
    discovered_rules_bucket: countBucket(previewRules.length),
  });

  openModal(
    null,
    (close) => {
      const selectedIds = new Set(previewRules.map((r) => r.id));
      const footerGroup = el("div", { className: "modal-foot-right" });
      const applyBtn = actionBtn({
        label: "Import selected rules",
        variant: "primary",
        onClick: async () => {
          if (selectedIds.size === 0) {
            toaster.show("Select at least one rule to import");
            return;
          }
          const outcome = await Motion.guardAction(
            applyBtn,
            async () => apiRequest("POST", "/api/v4/cursor/apply", { selected_ids: [...selectedIds] }),
            { group: footerGroup, busyLabel: "Importing…" },
          );
          if (!outcome) return;
          const count = Number(outcome.value && outcome.value.imported_count) || selectedIds.size;
          trackUiEvent("ui_cursor_import_completed", {
            import_outcome: "imported_clean",
            imported_agents_bucket: countBucket(count),
            sanitized_warnings_count: 0,
          });
          await refreshBootstrapQuietly();
          await close();
          toaster.show(outcome.value.message || `Imported ${count} Cursor rules`);
        },
      });
      footerGroup.append(
        actionBtn({
          label: "Cancel",
          variant: "secondary",
          onClick: () => {
            trackUiEvent("ui_cursor_import_completed", {
              import_outcome: "cancelled",
              imported_agents_bucket: "0",
              sanitized_warnings_count: 0,
            });
            close();
          },
        }),
        applyBtn,
      );

      return [
        el(
          "div",
          { className: "modal-head" },
          el("h2", { className: "t-18 w600" }, "Preview Cursor rules"),
          el("button", { type: "button", className: "btn-icon", "aria-label": "Close", onClick: close }, ICONS.close()),
        ),
        el(
          "p",
          { className: "t-13 secondary" },
          "Selected rules are shared with Claude Code, Codex CLI, and Gemini CLI so every tool follows the same repo standards. Your original .cursor files are untouched.",
        ),
        el(
          "table",
          { className: "cursor-table" },
          el("thead", null, el("tr", null, el("th", null, "Use"), el("th", null, "Rule"), el("th", null, "Summary"))),
          el(
            "tbody",
            null,
            previewRules.map((rule) => {
              const cb = el("input", {
                type: "checkbox",
                checked: true,
                "aria-label": `Import ${rule.name}`,
                onChange: () => {
                  if (cb.checked) selectedIds.add(rule.id);
                  else selectedIds.delete(rule.id);
                },
              });
              return el(
                "tr",
                null,
                el("td", null, cb),
                el("td", { className: "w500" }, rule.name),
                el("td", { className: "secondary" }, rule.summary),
              );
            }),
          ),
        ),
        el("div", { className: "modal-foot" }, el("span", { className: "t-12 muted" }, "Read-only import"), footerGroup),
      ];
    },
    true,
  );
}

// ── 6 · View 1: Inbox & Slide-Over / Split Review Sheet ──────────────────────

let sheetController = null;
let sheetElements = null;
let inboxFilterIndicator = { update() {}, destroy() {} };

function filteredInboxItems() {
  const all = state.data.inbox.items;
  if (state.inboxFilter === "needs_you") return all.filter((i) => i.bucket === "needs_you");
  if (state.inboxFilter === "running") return all.filter((i) => i.bucket === "running");
  if (state.inboxFilter === "done") return all.filter((i) => i.bucket === "done");
  return all;
}

function getItemById(id) {
  if (!id) return null;
  const sample = state.data.inbox.sample_walkthrough;
  if (id === "sample-walkthrough" || (sample && sample.id === id)) {
    return sample || { ...DEFAULT_SAMPLE_WALKTHROUGH };
  }
  return state.data.inbox.items.find((i) => i.id === id) || null;
}

function describeStatusPill(item) {
  const s = item.status;
  if (s === "needs_permission" || s === "paused_for_approval") {
    return statusPill("Needs permission", "warning", false);
  }
  if (s === "paused_low_credits") {
    return statusPill("Paused · Low credits", "urgent", false);
  }
  if (s === "paused_retry_limit") {
    return statusPill("Paused after 2 attempts", "urgent", false);
  }
  if (item.bucket === "running") {
    return statusPill("Running in sandbox", "neutral", true);
  }
  if (item.bucket === "done") {
    if (s === "rejected") return statusPill("Rejected", "danger", false);
    return statusPill("Shipped", "success", false);
  }
  return statusPill("Ready to review", "warning", false);
}

async function queueEngineeringTaskFromLauncher(rawTitle) {
  const trimmed = String(rawTitle || "").trim();
  if (!trimmed || state.pmLoading) return;
  const toolKind = normalizeToolKind(state.data.agents.driver_tool || "claude_code");
  state.pmLoading = true;
  state.launcherDraft = trimmed;
  renderCurrentView();
  try {
    const res = await apiRequest("POST", "/api/v4/board/tasks", {
      title: trimmed,
      tool: toolKind,
      workstream: "engineering",
    });
    const card = prependQueuedBoardTask(res && res.task, {
      title: trimmed,
      workstream: "engineering",
      toolKind,
    });
    trackUiEvent("ui_board_task_created", {
      workstream: card.workstream,
      assigned_tool_kind: toolKind,
      has_target_files: false,
    });
    state.launcherDraft = "";
    toaster.show("Task added to Queued on Board");
  } catch (err) {
    trackUiEvent("ui_action_failed", {
      failed_action: "board_task_create",
      error_category: "io_error",
    });
    toaster.show(err.message || "Could not queue task right now");
  } finally {
    state.pmLoading = false;
    renderCurrentView();
  }
}

function renderInboxView(root) {
  const workspace = el("div", {
    className: state.openItemId ? "inbox-workspace" : "inbox-workspace container",
    dataset: { sheetOpen: state.openItemId ? "true" : null },
  });
  const listPane = el("div", { className: "inbox-list-pane" });

  // View heading
  const viewHead = el(
    "div",
    { className: "view-head" },
    el("h1", { className: "t-20 w600" }, "Inbox"),
    el(
      "div",
      { className: "view-actions" },
      !state.walkthroughDone
        ? actionBtn({
            label: "15-second sample review",
            variant: "secondary",
            size: "sm",
            onClick: () => {
              trackUiEvent("ui_sample_walkthrough_triggered", {
                trigger_surface: "onboarding_banner",
              });
              navigate("#walkthrough");
            },
          })
        : null,
    ),
  );
  listPane.appendChild(viewHead);

  // Direct Engineering Task Launcher
  const pmInput = el("input", {
    type: "text",
    id: "ask-pm-input",
    className: "ask-input",
    value: state.launcherDraft || "",
    placeholder: "Describe a bug to fix, failing test, or feature to build…",
    "aria-label": "New engineering task",
    onInput: () => {
      state.launcherDraft = pmInput.value;
    },
    onKeydown: (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        if (pmInput.value.trim()) {
          queueEngineeringTaskFromLauncher(pmInput.value);
        } else {
          openNewTaskModal("onboarding_banner", "");
        }
      }
    },
  });
  const askSubmitBtn = actionBtn({
    label: state.pmLoading ? "Queueing…" : "Queue task",
    variant: "secondary",
    size: "sm",
    keycap: "⌘K",
    disabled: state.pmLoading,
    onClick: () => {
      if (pmInput.value.trim()) {
        queueEngineeringTaskFromLauncher(pmInput.value);
      } else {
        openNewTaskModal("onboarding_banner", "");
      }
    },
  });

  const quickChips = [
    { label: "Fix latest failing test", prompt: "Fix latest failing unit or CI test in this repository", slug: "scope_fix_last_test" },
    { label: "Add webhook retry backoff", prompt: "Add exponential retry backoff and idempotency guard to webhook handler", slug: "retry_backoff_webhook" },
    { label: "Audit auth & billing checks", prompt: "Audit auth and billing routes for missing input validation or rate limits", slug: "audit_auth_billing" },
  ];

  const askSection = el(
    "section",
    { className: "ask-section", "aria-label": "New engineering task" },
    el(
      "div",
      { className: "ask-bar" },
      el("label", { className: "ask-label", for: "ask-pm-input" }, "New task"),
      pmInput,
      askSubmitBtn,
    ),
    el(
      "div",
      { className: "ask-chips" },
      quickChips.map((chip) =>
        el(
          "button",
          {
            type: "button",
            className: "chip",
            onClick: () => {
              openNewTaskModal("onboarding_banner", chip.prompt, chip.slug);
            },
          },
          chip.label,
        ),
      ),
    ),
  );
  listPane.appendChild(askSection);

  // Compact 1-line setup status strip
  if (!state.onboardingDismissed) {
    const installedTools = state.data.agents.detected_tools.filter((t) => t.installed).length;
    const segments = [
      el("span", { className: "status-seg" }, state.data.repo.name ? `Repo ${state.data.repo.name} ready` : "Local workspace ready"),
      el("span", { className: "status-seg" }, `${installedTools} coding ${installedTools === 1 ? "tool" : "tools"} detected`),
      el(
        "span",
        { className: "status-seg" },
        state.data.agents.workflow.protect_sensitive_paths ? "Protected-path holds active" : "Safety rules configurable",
      ),
    ];
    if (state.data.repo.cursor_detected) {
      segments.push(
        el(
          "span",
          { className: "status-seg" },
          el(
            "button",
            {
              type: "button",
              className: "status-link",
              onClick: () => openCursorPreviewModal("onboarding_banner"),
            },
            "Import .cursor rules",
          ),
        ),
      );
    }
    const statusStrip = el(
      "div",
      { className: "status-bar" },
      el("div", { className: "status-segments" }, segments),
      el(
        "button",
        {
          type: "button",
          className: "btn-ghost btn-sm",
          onClick: () => {
            state.onboardingDismissed = true;
            try { localStorage.setItem("chinwag_onboarding_dismissed", "1"); } catch (e) {}
            trackUiEvent("ui_onboarding_dismissed", { steps_completed_count: 3 });
            renderCurrentView();
          },
        },
        "Hide",
      ),
    );
    listPane.appendChild(statusStrip);
  }

  // Segmented filter bar
  const counts = state.data.inbox.counts;
  const totalCount = state.data.inbox.items.length;
  const filters = [
    { id: "needs_you", label: "Needs you", count: counts.needs_decision, tel: "needs_review" },
    { id: "running", label: "In progress", count: counts.running, tel: "in_progress" },
    { id: "done", label: "Done", count: counts.done, tel: "done" },
    { id: "all", label: "All", count: totalCount, tel: "all" },
  ];
  const segThumb = el("span", { className: "seg-thumb", "aria-hidden": "true" });
  const segTrack = el(
    "div",
    { className: "segmented", role: "group", "aria-label": "Filter inbox items" },
    filters.map((f) =>
      el(
        "button",
        {
          type: "button",
          "aria-pressed": state.inboxFilter === f.id ? "true" : "false",
          onClick: () => {
            if (state.inboxFilter === f.id) return;
            state.inboxFilter = f.id;
            state.selectedIndex = 0;
            trackUiEvent("ui_inbox_filter_selected", {
              filter: f.tel,
              matching_items_bucket: countBucket(f.count),
            });
            renderCurrentView();
          },
        },
        el("span", null, f.label),
        f.count > 0 ? el("span", { className: "seg-count num" }, String(f.count)) : null,
      ),
    ),
    segThumb,
  );
  listPane.appendChild(el("div", { className: "inbox-filter-wrap" }, segTrack));

  // Uninitialized repository empty state
  if (state.data.repo.initialized === false) {
    trackUiEvent("ui_repo_uninitialized_viewed", { uninit_action: "viewed" });
    listPane.appendChild(
      el(
        "div",
        { className: "empty" },
        el("h2", { className: "empty-title" }, "Set up chinwag in this folder"),
        el("p", { className: "empty-body" }, "Initialize chinwag once in your repository so coding tools can run in isolated sandboxes and post diffs here."),
        el("div", { className: "copy-field" }, "chinwag init"),
        el(
          "div",
          { className: "empty-actions" },
          copyButton({
            label: "Copy chinwag init",
            variant: "primary",
            size: "",
            textToCopy: "chinwag init",
            okToast: "Setup command copied",
            onCopied: () => trackUiEvent("ui_repo_uninitialized_viewed", { uninit_action: "init_repo_clicked" }),
          }),
          actionBtn({
            label: "Preview sample review",
            variant: "secondary",
            onClick: () => navigate("#walkthrough"),
          }),
        ),
      ),
    );
  } else {
    const items = filteredInboxItems();
    if (state.selectedIndex >= items.length) state.selectedIndex = Math.max(0, items.length - 1);

    if (items.length === 0) {
      if (state.data.inbox.items.length === 0) {
        listPane.appendChild(
          el(
            "div",
            { className: "empty" },
            el("h2", { className: "empty-title" }, "Nothing needs your decision right now"),
            el(
              "p",
              { className: "empty-body" },
              "Queue an engineering task above, or step through a 15-second sample diff review to see how approvals and safety holds work.",
            ),
            el(
              "div",
              { className: "empty-actions" },
              actionBtn({
                label: "Preview 15-second sample review",
                variant: "primary",
                onClick: () => {
                  trackUiEvent("ui_sample_walkthrough_triggered", { trigger_surface: "inbox_empty_state" });
                  navigate("#walkthrough");
                },
              }),
              actionBtn({
                label: "Configure coding tools",
                variant: "secondary",
                onClick: () => navigate("#agents", "onboarding_cta"),
              }),
            ),
          ),
        );
      } else {
        listPane.appendChild(
          el(
            "p",
            { className: "filter-empty" },
            state.inboxFilter === "needs_you"
              ? "All caught up — no items waiting on your decision."
              : "No items in this view right now.",
          ),
        );
      }
    } else {
      let primaryAssigned = false;
      const listEl = el(
        "div",
        { className: "inbox-list", role: "list" },
        items.map((item, idx) => {
          const isCurrent = state.openItemId ? state.openItemId === item.id : idx === state.selectedIndex;
          const isPrimaryCard = !primaryAssigned && item.bucket === "needs_you" && !state.openItemId;
          if (isPrimaryCard) primaryAssigned = true;

          const ctaLabel =
            item.status === "needs_permission" || item.status === "paused_for_approval"
              ? "Review permission"
              : item.status === "paused_low_credits"
                ? "Add credits to resume"
                : item.bucket === "running"
                  ? "View progress"
                  : item.bucket === "done"
                    ? "View summary"
                    : "Review changes";

          const diffHref = item.is_sample ? "#walkthrough" : `#diff/${encodeURIComponent(item.id)}`;

          const elapsedNode =
            item.bucket === "running" && item.started_at_ms
              ? el(
                  "span",
                  { className: "meta-item duration", dataset: { elapsedStart: String(item.started_at_ms) } },
                  formatElapsed(Date.now() - item.started_at_ms),
                )
              : fact(item.created_at, formatRelativeTime);

          const card = el(
            "article",
            {
              className: "card inbox-card",
              role: "listitem",
              "aria-current": isCurrent ? "true" : null,
              dataset: { itemId: item.id },
            },
            el(
              "div",
              { className: "inbox-card-main" },
              el(
                "div",
                { className: "card-status" },
                describeStatusPill(item),
                item.independent_review && item.independent_review.passed
                  ? el("span", { className: "pill-provenance" }, "Independent review")
                  : null,
                item.is_sample ? el("span", { className: "pill-provenance" }, "Sample walkthrough") : null,
              ),
              el(
                "h2",
                { className: "card-title" },
                el(
                  "a",
                  {
                    href: diffHref,
                    onClick: (ev) => {
                      ev.preventDefault();
                      state.selectedIndex = idx;
                      navigate(diffHref);
                    },
                  },
                  item.title,
                ),
              ),
              !isAbsent(item.summary) ? el("p", { className: "card-reason" }, item.summary) : null,
              metaRow([
                fact(item.tool_label, (t) => `Prepared with ${t}`),
                fact(item.reviewer_label, (r) => `Reviewed by ${r}`),
                fact(item.files_changed, (n) => `${n} ${Number(n) === 1 ? "file" : "files"}`),
                !isAbsent(item.additions) || !isAbsent(item.deletions)
                  ? el("span", { className: "meta-item num" }, `+${item.additions || 0} / −${item.deletions || 0}`)
                  : null,
                item.test_passed === true ? el("span", { className: "meta-item" }, "Tests passed") : null,
                elapsedNode,
              ]),
            ),
            el(
              "div",
              { className: "card-cta" },
              actionBtn({
                label: ctaLabel,
                variant: isPrimaryCard ? "primary" : "secondary",
                keycap: isPrimaryCard ? "↵" : null,
                onClick: () => {
                  state.selectedIndex = idx;
                  navigate(diffHref);
                },
              }),
            ),
          );
          return card;
        }),
      );
      listPane.appendChild(listEl);
    }
  }

  workspace.appendChild(listPane);

  // Sheet stage for split / drawer / mobile review
  const scrim = el("div", {
    className: "sheet-scrim",
    hidden: !state.openItemId,
    onClick: () => closeReviewSheetAndNavigate(),
  });
  const sheetTitleEl = el("h2", { className: "t-16 w600 truncate", tabindex: "-1" }, "Review changes");
  const sheetHeadStatus = el("span");
  const sheetBody = el("div", { className: "sheet-body" });
  const sheetFoot = el("footer", { className: "sheet-foot" });

  const prevBtn = el(
    "button",
    {
      type: "button",
      className: "btn-icon",
      "aria-label": "Previous item (k)",
      title: "Previous item (k)",
      onClick: () => stepOpenSheetItem(-1, false),
    },
    ICONS.chevronUp(),
  );
  const nextBtn = el(
    "button",
    {
      type: "button",
      className: "btn-icon",
      "aria-label": "Next item (j)",
      title: "Next item (j)",
      onClick: () => stepOpenSheetItem(1, false),
    },
    ICONS.chevronDown(),
  );

  const sheetEl = el(
    "aside",
    {
      className: "sheet",
      role: "region",
      "aria-label": "Review changes",
      hidden: !state.openItemId,
    },
    el(
      "header",
      { className: "sheet-head" },
      el(
        "div",
        { className: "sheet-head-left" },
        el(
          "button",
          {
            type: "button",
            className: "btn-ghost btn-sm",
            onClick: () => closeReviewSheetAndNavigate(),
          },
          ICONS.chevronLeft(),
          el("span", null, "Inbox"),
        ),
        sheetTitleEl,
        sheetHeadStatus,
      ),
      el(
        "div",
        { className: "sheet-head-right" },
        prevBtn,
        nextBtn,
        actionBtn({
          label: "Close",
          variant: "ghost",
          size: "sm",
          keycap: "Esc",
          extraClass: "sheet-close-desktop",
          onClick: () => closeReviewSheetAndNavigate(),
        }),
      ),
    ),
    sheetBody,
    sheetFoot,
  );
  const sheetStage = el("div", { className: "sheet-stage" }, sheetEl);
  workspace.append(scrim, sheetStage);
  root.appendChild(workspace);

  inboxFilterIndicator = Motion.bindIndicator(segTrack, segThumb, "[aria-pressed='true']");
  sheetElements = { workspace, listPane, scrim, sheetEl, sheetTitleEl, sheetHeadStatus, sheetBody, sheetFoot };
  sheetController = Motion.createSheet(sheetEl, {
    scrim,
    titleEl: sheetTitleEl,
  });

  if (state.openItemId) {
    sheetController.open({ cold: !state.booted });
    populateOpenSheet(state.openItemId);
  }
  elapsedClock.poke();
}

async function closeReviewSheetAndNavigate() {
  if (sheetController && sheetController.state !== "closed") {
    await sheetController.close();
  }
  state.openItemId = null;
  navigate("#inbox");
}

function stepOpenSheetItem(delta, isRepeat = false) {
  const items = filteredInboxItems();
  if (items.length === 0) return;
  const curIdx = items.findIndex((i) => i.id === state.openItemId);
  const baseIdx = curIdx >= 0 ? curIdx : state.selectedIndex;
  const nextIdx = Math.max(0, Math.min(items.length - 1, baseIdx + delta));
  const target = items[nextIdx];
  if (!target || target.id === state.openItemId) return;
  state.selectedIndex = nextIdx;
  state.openItemId = target.id;
  state.sheetOpenedAtMs = Date.now();
  const nextHash = target.is_sample ? "#walkthrough" : `#diff/${encodeURIComponent(target.id)}`;
  history.replaceState(null, "", nextHash);
  if (sheetElements) {
    for (const card of sheetElements.listPane.querySelectorAll(".inbox-card")) {
      if (card.dataset.itemId === target.id) card.setAttribute("aria-current", "true");
      else card.removeAttribute("aria-current");
    }
    Motion.swapContent(
      [sheetElements.sheetBody, sheetElements.sheetFoot],
      () => populateOpenSheet(target.id),
      { repeat: isRepeat },
    );
  }
}

async function populateOpenSheet(itemId) {
  if (!sheetElements) return;
  const baseItem = getItemById(itemId) || {
    id: itemId,
    is_sample: itemId === "sample-walkthrough",
    title: `Change ${itemId}`,
    status: "needs_review",
    bucket: "needs_you",
  };

  sheetElements.sheetTitleEl.textContent = baseItem.title;
  clearNode(sheetElements.sheetHeadStatus);
  sheetElements.sheetHeadStatus.appendChild(describeStatusPill(baseItem));

  // Sample walkthrough or cached diff renders immediately
  if (baseItem.is_sample && Array.isArray(baseItem.files) && baseItem.files.length > 0) {
    const normalized = normalizeDiffPayload(baseItem, baseItem);
    state.diffCache.set(itemId, normalized);
    renderSheetRegions(normalized);
    return;
  }

  if (state.diffCache.has(itemId)) {
    renderSheetRegions(state.diffCache.get(itemId));
    return;
  }

  state.loadingDiffId = itemId;
  const fetchPromise = apiRequest("GET", `/api/v4/diff?id=${encodeURIComponent(itemId)}`)
    .then((raw) => {
      const normalized = normalizeDiffPayload(raw, baseItem);
      state.diffCache.set(itemId, normalized);
      return normalized;
    })
    .catch(() => {
      const fallback = normalizeDiffPayload(baseItem, baseItem);
      fallback.diff_unavailable = true;
      return fallback;
    });

  Motion.deferSkeleton(fetchPromise, () => {
    if (state.openItemId !== itemId || !sheetElements) return;
    clearNode(sheetElements.sheetBody);
    sheetElements.sheetBody.append(
      el("div", { className: "skeleton skeleton-card" }),
      el("div", { className: "skeleton skeleton-card" }),
    );
  });

  const detail = await fetchPromise;
  if (state.openItemId !== itemId || !sheetElements) return;
  state.loadingDiffId = null;
  renderSheetRegions(detail);

  trackUiEvent("ui_inbox_item_opened", {
    item_kind: detail.is_sample
      ? "sample_walkthrough"
      : detail.status === "needs_permission" || detail.status === "paused_for_approval"
        ? "guardrail_hold"
        : "pair_patch",
    item_status: detail.status === "needs_permission" ? "needs_permission" : "ready_to_review",
    files_changed_bucket: filesBucket(detail.files_changed || 0),
    lines_changed_bucket: linesBucket((detail.additions || 0) + (detail.deletions || 0) || 1),
    is_cross_model_verified: Boolean(detail.independent_review && detail.independent_review.passed),
    is_sample_walkthrough: Boolean(detail.is_sample),
  });
}

function buildPrMarkdownSummary(detail) {
  const lines = [`## ${detail.title}`, ""];
  if (!isAbsent(detail.summary)) lines.push(detail.summary, "");
  if (Array.isArray(detail.files) && detail.files.length > 0) {
    lines.push("### Files changed");
    for (const f of detail.files) {
      lines.push(`- \`${f.path}\` (+${f.additions} / −${f.deletions})`);
    }
    lines.push("");
  }
  if (detail.independent_review && detail.independent_review.summary) {
    lines.push("### Verification");
    lines.push(`- ${detail.independent_review.summary}`);
    for (const chk of detail.independent_review.checks || []) {
      lines.push(`- ${chk}`);
    }
  }
  return lines.join("\n");
}

function renderSheetRegions(detail) {
  if (!sheetElements) return;
  const { sheetTitleEl, sheetHeadStatus, sheetBody, sheetFoot } = sheetElements;
  sheetTitleEl.textContent = detail.title;
  clearNode(sheetHeadStatus);
  sheetHeadStatus.appendChild(describeStatusPill(detail));
  clearNode(sheetBody);
  clearNode(sheetFoot);

  // 1. Trust & provenance strip
  const trustPills = [];
  if (!isAbsent(detail.tool_label)) {
    trustPills.push(el("span", { className: "pill-provenance" }, `Prepared with ${detail.tool_label}`));
  }
  if (detail.independent_review && detail.independent_review.passed) {
    const revText = detail.reviewer_label
      ? `Reviewed by ${detail.reviewer_label} · Independent review`
      : "Independent review passed";
    trustPills.push(el("span", { className: "pill-provenance" }, revText));
  }
  if (!isAbsent(detail.risk_level)) {
    trustPills.push(el("span", { className: "pill-fn" }, `Risk: ${detail.risk_level}`));
  }
  if (detail.is_sample) {
    trustPills.push(el("span", { className: "pill-provenance" }, "Sample walkthrough · Read-only"));
  }
  if (trustPills.length > 0) {
    sheetBody.appendChild(el("div", { className: "trust-strip" }, trustPills));
  }

  // 2. Conditional Hold or Low-Credit Banner
  const needsPerm = detail.status === "needs_permission" || detail.status === "paused_for_approval";
  const lowCredPause = detail.status === "paused_low_credits";

  if (needsPerm && !detail.is_sample) {
    const bannerActions = el("div", { className: "banner-actions" });
    const allowOnceBtn = actionBtn({
      label: "Allow this once",
      variant: "primary",
      size: "sm",
      onClick: async () => {
        const res = await Motion.guardAction(
          allowOnceBtn,
          () => apiRequest("POST", "/api/v4/inbox/action", { id: detail.id, action: "allow_once" }),
          { group: bannerActions, busyLabel: "Granting…" },
        );
        if (!res) return;
        detail.status = "needs_review";
        trackUiEvent("ui_hold_approved_once", {
          hold_category: "protected_path",
          decision_latency_bucket: decisionLatencyBucket(Date.now() - state.sheetOpenedAtMs),
        });
        await Motion.resolveBanner(holdBanner, () => {
          clearNode(holdBanner);
          holdBanner.setAttribute("data-resolved", "");
          holdBanner.append(ICONS.check(), el("span", null, "Permission granted for this task. You can now approve and push below."));
        });
        renderSheetFooter(detail, sheetFoot, true);
        await refreshBootstrapQuietly();
      },
    });
    const keepHoldBtn = actionBtn({
      label: "Keep the hold",
      variant: "secondary",
      size: "sm",
      onClick: async () => {
        const res = await Motion.guardAction(
          keepHoldBtn,
          () => apiRequest("POST", "/api/v4/inbox/action", { id: detail.id, action: "reject", note: "Kept protected-path hold" }),
          { group: bannerActions, busyLabel: "Keeping hold…" },
        );
        if (!res) return;
        trackUiEvent("ui_hold_rejected", { hold_category: "protected_path" });
        toaster.show("Protected-path hold kept — changes were not applied");
        await refreshBootstrapQuietly();
        closeReviewSheetAndNavigate();
      },
    });
    bannerActions.append(
      allowOnceBtn,
      keepHoldBtn,
      actionBtn({
        label: "Edit protected paths",
        variant: "ghost",
        size: "sm",
        onClick: () => navigate("#agents"),
      }),
    );

    const pulseIcon = ICONS.alert(true);
    const holdBanner = el(
      "div",
      { className: "banner banner-warning", role: "region", "aria-label": "Permission required" },
      el("div", { className: "banner-head" }, pulseIcon, el("strong", { className: "t-14 w600" }, "Permission needed before pushing")),
      el(
        "p",
        { className: "t-13 secondary" },
        detail.hold_reason ||
          (detail.protected_path
            ? `This patch touches protected path ${detail.protected_path}. Grant one-time permission to enable pushing.`
            : "This patch touches a sensitive path protected by your repository rules."),
      ),
      bannerActions,
    );
    Motion.observeLoop(pulseIcon);
    sheetBody.appendChild(holdBanner);
  } else if (lowCredPause && !detail.is_sample) {
    const needed = detail.needed_credits || 50;
    const avail = state.data.credits.available_credits ?? 0;
    trackUiEvent("ui_credits_depleted_hold_shown", {
      workflow_fn: "ci_remediation",
      function_credits_cost: 50,
    });
    const pauseActions = el("div", { className: "banner-actions" });
    const topupBtn = actionBtn({
      label: "Buy Starter Pack · $50 (6,250 Cr)",
      variant: "primary",
      size: "sm",
      onClick: () => startCheckoutFlow(topupBtn, pauseActions, "pack_50", "depletion_hold_card"),
    });
    pauseActions.append(
      topupBtn,
      actionBtn({
        label: "All credit packs",
        variant: "secondary",
        size: "sm",
        onClick: () => navigate("#credits", "onboarding_cta"),
      }),
    );
    sheetBody.appendChild(
      el(
        "div",
        { className: "banner banner-urgent", role: "region", "aria-label": "Paused for low credits" },
        el("div", { className: "banner-head" }, ICONS.alert(false), el("strong", { className: "t-14 w600" }, "Paused — more credits needed")),
        el(
          "p",
          { className: "t-13 secondary" },
          `This step needs ${needed} Cr (${avail} Cr remaining). Your work in progress is saved locally and resumes as soon as credits are added.`,
        ),
        pauseActions,
      ),
    );
  }

  // 3. Plain-English Summary Block
  const dlRows = [];
  if (!isAbsent(detail.summary)) {
    dlRows.push(el("dt", null, "What changed"), el("dd", null, detail.summary));
  }
  if (!isAbsent(detail.why)) {
    dlRows.push(el("dt", null, "Why"), el("dd", null, detail.why));
  }
  if (!isAbsent(detail.files_changed)) {
    dlRows.push(
      el("dt", null, "Scope"),
      el(
        "dd",
        { className: "num" },
        `${detail.files_changed} ${detail.files_changed === 1 ? "file" : "files"} (+${detail.additions || 0} / −${detail.deletions || 0} lines)`,
      ),
    );
  }
  if (dlRows.length > 0) {
    sheetBody.appendChild(
      el(
        "section",
        { className: "sheet-summary-block", "aria-label": "Summary" },
        el("h3", { className: "t-14 w600" }, "Summary"),
        el("dl", { className: "summary-dl" }, dlRows),
      ),
    );
  }

  // 4. Verification Receipt ("Test results")
  const receiptRows = [];
  if (detail.independent_review && !isAbsent(detail.independent_review.summary)) {
    receiptRows.push(el("dt", null, "Independent check"), el("dd", null, detail.independent_review.summary));
  }
  if (!isAbsent(detail.test_command)) {
    receiptRows.push(el("dt", null, "Command"), el("dd", null, el("code", { className: "pill-code" }, detail.test_command)));
  }
  if (!isAbsent(detail.test_duration_ms)) {
    receiptRows.push(el("dt", null, "Duration"), el("dd", { className: "num" }, `${(detail.test_duration_ms / 1000).toFixed(1)}s`));
  }
  const checksList = (detail.independent_review && detail.independent_review.checks) || [];
  if (receiptRows.length > 0 || checksList.length > 0 || typeof detail.test_passed === "boolean") {
    const testBadge =
      detail.test_passed === true
        ? statusPill("Passed in local sandbox", "success")
        : detail.test_passed === false
          ? statusPill("Check failed", "danger")
          : statusPill("Not yet run", "neutral");
    const checkStatusLabel =
      detail.independent_review && detail.independent_review.passed === true
        ? "Verified"
        : "Local check";
    sheetBody.appendChild(
      el(
        "section",
        { className: "receipt-box", "aria-label": "Test results" },
        el(
          "div",
          { className: "receipt-head" },
          el("h3", { className: "t-14 w600" }, "Test results"),
          testBadge,
        ),
        receiptRows.length > 0 ? el("dl", { className: "receipt-grid" }, receiptRows) : null,
        checksList.length > 0
          ? el(
              "ul",
              { className: "activity-list" },
              checksList.map((chk) =>
                el("li", { className: "activity-row" }, el("span", null, chk), el("span", { className: "muted" }, checkStatusLabel)),
              ),
            )
          : null,
      ),
    );
  }

  // 5. GitHub-Standard Diff Viewer
  sheetBody.appendChild(renderDiffSection(detail));

  // 6. Expandable PR Summary Preview
  const mdSummary = buildPrMarkdownSummary(detail);
  const detailsBlock = el(
    "details",
    {
      className: "pr-summary-details",
      onToggle: () => {
        trackUiEvent("ui_step_strip_expanded", { expanded: detailsBlock.open });
      },
    },
    el("summary", null, "Preview pull request summary"),
    el("pre", { className: "pr-summary-pre" }, mdSummary),
  );
  sheetBody.appendChild(detailsBlock);

  // 7. Sticky Decision Footer
  renderSheetFooter(detail, sheetFoot, false);
}

function renderDiffSection(detail) {
  const files = Array.isArray(detail.files) ? detail.files : [];
  const section = el("section", { className: "diff-section", "aria-label": "Code changes" });

  const modeSeg = el(
    "div",
    { className: "segmented diff-mode-toggle", role: "group", "aria-label": "Diff layout" },
    el(
      "button",
      {
        type: "button",
        "aria-pressed": state.diffMode === "unified" ? "true" : "false",
        onClick: () => {
          if (state.diffMode === "unified") return;
          state.diffMode = "unified";
          trackUiEvent("ui_diff_mode_toggled", { diff_mode: "unified" });
          const nextSec = renderDiffSection(detail);
          section.replaceWith(nextSec);
        },
      },
      "Unified diff",
    ),
    el(
      "button",
      {
        type: "button",
        "aria-pressed": state.diffMode === "split" ? "true" : "false",
        onClick: () => {
          if (state.diffMode === "split") return;
          state.diffMode = "split";
          trackUiEvent("ui_diff_mode_toggled", { diff_mode: "split" });
          const nextSec = renderDiffSection(detail);
          section.replaceWith(nextSec);
        },
      },
      "Split diff",
    ),
  );

  const wrapBtn = el(
    "button",
    {
      type: "button",
      className: "chip diff-wrap-toggle",
      "aria-pressed": state.diffWrap ? "true" : "false",
      onClick: () => {
        state.diffWrap = !state.diffWrap;
        const nextSec = renderDiffSection(detail);
        section.replaceWith(nextSec);
      },
    },
    state.diffWrap ? "Wrap lines: On" : "Wrap lines",
  );

  section.appendChild(
    el(
      "div",
      { className: "diff-toolbar" },
      el("h3", { className: "t-14 w600" }, `Files changed (${files.length})`),
      el("div", { className: "view-actions" }, wrapBtn, modeSeg),
    ),
  );

  if (files.length === 0) {
    section.appendChild(
      el(
        "div",
        { className: "empty" },
        el("p", { className: "empty-body" }, detail.diff_unavailable ? "Diff preview unavailable for this item." : "No file line changes recorded yet."),
      ),
    );
    return section;
  }

  for (const file of files) {
    const tableEl = state.diffMode === "split" ? buildSplitDiffTable(file) : buildUnifiedDiffTable(file);
    section.appendChild(
      el(
        "div",
        { className: "diff-file" },
        el(
          "div",
          { className: "diff-file-head" },
          el("div", { className: "diff-file-head-left" }, el("code", { className: "t-12m w500" }, file.path)),
          el(
            "span",
            { className: "diff-counts" },
            el("span", { className: "add" }, `+${file.additions}`),
            el("span", { className: "del" }, `−${file.deletions}`),
          ),
        ),
        el("div", { className: "diff-scroll" }, tableEl),
      ),
    );
  }
  return section;
}

function buildUnifiedRow(ln) {
  const cls = ln.type === "add" ? "add" : ln.type === "del" ? "del" : "ctx";
  const sign = ln.type === "add" ? "+" : ln.type === "del" ? "−" : " ";
  return el(
    "tr",
    { className: cls },
    el("td", { className: "diff-ln" }, ln.old_ln !== null && ln.old_ln !== undefined ? String(ln.old_ln) : ""),
    el("td", { className: "diff-ln" }, ln.new_ln !== null && ln.new_ln !== undefined ? String(ln.new_ln) : ""),
    el("td", { className: "sign" }, sign),
    el("td", { className: "code-cell" }, el("code", null, ln.text)),
  );
}

function buildUnifiedDiffTable(file) {
  const tbody = el("tbody");
  for (const hunk of file.hunks || []) {
    tbody.appendChild(
      el("tr", { className: "hunk" }, el("td", { colspan: "4" }, hunk.header)),
    );
    const lines = hunk.lines || [];
    let i = 0;
    while (i < lines.length) {
      if (lines[i].type === "ctx") {
        let j = i;
        while (j < lines.length && lines[j].type === "ctx") j += 1;
        const runLen = j - i;
        if (runLen > 8) {
          for (let k = i; k < i + 3; k += 1) tbody.appendChild(buildUnifiedRow(lines[k]));
          const hiddenSlice = lines.slice(i + 3, j - 3);
          const expandRow = el(
            "tr",
            { className: "expand" },
            el(
              "td",
              { colspan: "4" },
              el(
                "button",
                {
                  type: "button",
                  className: "btn-ghost btn-sm",
                  onClick: () => {
                    const frag = document.createDocumentFragment();
                    for (const hl of hiddenSlice) frag.appendChild(buildUnifiedRow(hl));
                    expandRow.replaceWith(frag);
                  },
                },
                `Show ${hiddenSlice.length} unchanged lines`,
              ),
            ),
          );
          tbody.appendChild(expandRow);
          for (let k = j - 3; k < j; k += 1) tbody.appendChild(buildUnifiedRow(lines[k]));
        } else {
          for (let k = i; k < j; k += 1) tbody.appendChild(buildUnifiedRow(lines[k]));
        }
        i = j;
      } else {
        tbody.appendChild(buildUnifiedRow(lines[i]));
        i += 1;
      }
    }
  }
  return el(
    "table",
    { className: "diff-table", dataset: { wrap: state.diffWrap ? "true" : null } },
    el(
      "colgroup",
      null,
      el("col", { className: "diff-col-ln" }),
      el("col", { className: "diff-col-ln" }),
      el("col", { className: "diff-col-sign" }),
      el("col"),
    ),
    tbody,
  );
}

function buildSplitDiffTable(file) {
  const tbody = el("tbody");
  for (const hunk of file.hunks || []) {
    tbody.appendChild(el("tr", { className: "hunk" }, el("td", { colspan: "6" }, hunk.header)));
    const lines = hunk.lines || [];
    let i = 0;
    while (i < lines.length) {
      if (lines[i].type === "ctx") {
        const ln = lines[i];
        tbody.appendChild(
          el(
            "tr",
            null,
            el("td", { className: "diff-ln" }, String(ln.old_ln ?? "")),
            el("td", { className: "sign" }, " "),
            el("td", { className: "code-cell" }, el("code", null, ln.text)),
            el("td", { className: "diff-ln" }, String(ln.new_ln ?? "")),
            el("td", { className: "sign" }, " "),
            el("td", { className: "code-cell" }, el("code", null, ln.text)),
          ),
        );
        i += 1;
      } else {
        const dels = [];
        const adds = [];
        while (i < lines.length && lines[i].type === "del") {
          dels.push(lines[i]);
          i += 1;
        }
        while (i < lines.length && lines[i].type === "add") {
          adds.push(lines[i]);
          i += 1;
        }
        const max = Math.max(dels.length, adds.length);
        for (let k = 0; k < max; k += 1) {
          const d = dels[k] || null;
          const a = adds[k] || null;
          tbody.appendChild(
            el(
              "tr",
              null,
              el("td", { className: d ? "diff-ln split-del-ln" : "diff-ln split-empty" }, d ? String(d.old_ln ?? "") : ""),
              el("td", { className: d ? "sign split-del" : "sign split-empty" }, d ? "−" : ""),
              el("td", { className: d ? "code-cell split-del" : "code-cell split-empty" }, el("code", null, d ? d.text : "")),
              el("td", { className: a ? "diff-ln split-add-ln" : "diff-ln split-empty" }, a ? String(a.new_ln ?? "") : ""),
              el("td", { className: a ? "sign split-add" : "sign split-empty" }, a ? "+" : ""),
              el("td", { className: a ? "code-cell split-add" : "code-cell split-empty" }, el("code", null, a ? a.text : "")),
            ),
          );
        }
      }
    }
  }
  return el(
    "table",
    { className: "diff-table diff-split", dataset: { wrap: state.diffWrap ? "true" : null } },
    el(
      "colgroup",
      null,
      el("col", { className: "diff-col-ln" }),
      el("col", { className: "diff-col-sign" }),
      el("col", { className: "diff-col-split-code" }),
      el("col", { className: "diff-col-ln" }),
      el("col", { className: "diff-col-sign" }),
      el("col", { className: "diff-col-split-code" }),
    ),
    tbody,
  );
}

function renderSheetFooter(detail, sheetFoot, armPrimary = false) {
  clearNode(sheetFoot);
  const mdSummary = buildPrMarkdownSummary(detail);

  // HARD INVARIANT: SampleWalkthroughShipForbidden
  // Sample walkthrough NEVER renders real git push/apply actions or triggers live merge endpoints.
  if (detail.is_sample) {
    const finishBtn = actionBtn({
      label: "Finish walkthrough",
      variant: "primary",
      id: "sheet-primary-action",
      keycap: "⌘↵",
      onClick: () => {
        state.walkthroughDone = true;
        try { localStorage.setItem("chinwag_walkthrough_done", "1"); } catch (e) {}
        trackUiEvent("ui_sample_walkthrough_finished", {
          walkthrough_mode: "sample_item",
          is_under_15s: Date.now() - state.sheetOpenedAtMs < 15000,
        });
        toaster.show("Sample walkthrough complete. Queue an engineering task whenever you're ready.");
        closeReviewSheetAndNavigate();
      },
    });
    sheetFoot.append(
      el(
        "div",
        { className: "foot-context" },
        el("div", { className: "push-target" }, "Sample walkthrough"),
        el("div", { className: "foot-helper" }, "No files or branches in your repository will be modified."),
      ),
      el(
        "div",
        { className: "foot-actions" },
        copyButton({
          label: "Copy PR summary",
          variant: "secondary",
          size: "",
          textToCopy: mdSummary,
          okToast: "PR summary copied",
        }),
        finishBtn,
      ),
    );
    return;
  }

  // Post-reject Undo + 1-click Learned Repo Rule strip
  if (state.rejectedItems.has(detail.id)) {
    const reasonInput = el("input", {
      type: "text",
      className: "input",
      placeholder: "Optional: save a repository rule so tools avoid this next time…",
      "aria-label": "Save repository rule from rejection",
    });
    const saveRuleBtn = actionBtn({
      label: "Save rule",
      variant: "secondary",
      size: "sm",
      onClick: async () => {
        const note = reasonInput.value.trim();
        if (!note) return;
        state.data.agents.learned_rules.unshift({
          id: `rule-${Date.now()}`,
          text: note,
          source_label: "Saved from review",
        });
        try {
          await apiRequest("POST", "/api/v4/inbox/action", {
            id: detail.id,
            action: "request_changes",
            note,
          });
        } catch (e) {}
        toaster.show("Saved to Learned repo rules");
        closeReviewSheetAndNavigate();
      },
    });
    const quickReasons = [
      { label: "Wrong fix approach", cat: "incorrect_fix", rule: "Confirm root cause before changing retry or timeout constants." },
      { label: "Out of scope files", cat: "wrong_scope", rule: "Keep patches scoped strictly to the files named in the task." },
      { label: "Needs stronger tests", cat: "tests_insufficient", rule: "Add a regression test covering the failure case before requesting review." },
    ];
    sheetFoot.appendChild(
      el(
        "div",
        { className: "reject-strip" },
        el(
          "div",
          { className: "reject-strip-top" },
          el("span", { className: "t-14 w500" }, "Changes rejected — nothing was pushed."),
          actionBtn({
            label: "Undo reject",
            variant: "secondary",
            size: "sm",
            onClick: async () => {
              state.rejectedItems.delete(detail.id);
              try {
                await apiRequest("POST", "/api/v4/inbox/action", { id: detail.id, action: "undo_reject" });
              } catch (e) {}
              detail.status = "needs_review";
              renderSheetFooter(detail, sheetFoot, false);
              toaster.show("Rejection undone");
            },
          }),
        ),
        el(
          "div",
          { className: "chip-row" },
          el("span", { className: "t-12 muted" }, "Teach repo rule:"),
          quickReasons.map((qr) =>
            el(
              "button",
              {
                type: "button",
                className: "chip",
                onClick: () => {
                  state.data.agents.learned_rules.unshift({
                    id: `rule-${Date.now()}`,
                    text: qr.rule,
                    source_label: "Learned from rejection",
                  });
                  trackUiEvent("ui_diff_rejected", {
                    reject_reason_category: qr.cat,
                    is_sample_walkthrough: false,
                  });
                  toaster.show("Rule added to Agents & Rules");
                  closeReviewSheetAndNavigate();
                },
              },
              qr.label,
            ),
          ),
        ),
        el("div", { className: "reject-reason-form" }, reasonInput, saveRuleBtn),
      ),
    );
    return;
  }

  const blockedByHold =
    detail.status === "needs_permission" ||
    detail.status === "paused_for_approval" ||
    detail.status === "paused_low_credits";

  const targetBranch = detail.branch || state.data.repo.branch || "current branch";
  const hostName = detail.git_host || state.data.repo.git_host || "GitHub";

  const actionsGroup = el("div", { className: "foot-actions" });

  const rejectBtn = actionBtn({
    label: "Reject changes",
    variant: "ghost",
    onClick: async () => {
      const res = await Motion.guardAction(
        rejectBtn,
        () => apiRequest("POST", "/api/v4/inbox/action", { id: detail.id, action: "reject" }),
        { group: actionsGroup, busyLabel: "Rejecting…" },
      );
      if (!res) return;
      state.rejectedItems.add(detail.id);
      trackUiEvent("ui_diff_rejected", {
        reject_reason_category: "unspecified",
        is_sample_walkthrough: false,
      });
      renderSheetFooter(detail, sheetFoot, false);
      await refreshBootstrapQuietly();
    },
  });

  const requestChangesBtn = actionBtn({
    label: "Request changes",
    variant: "secondary",
    onClick: () => {
      openModal(requestChangesBtn, (close) => {
        const noteArea = el("input", {
          type: "text",
          className: "input",
          placeholder: "Tell the coding tool what to adjust…",
          "aria-label": "Revision instructions",
        });
        const footRight = el("div", { className: "modal-foot-right" });
        const sendBtn = actionBtn({
          label: "Send revision request",
          variant: "primary",
          onClick: async () => {
            const note = noteArea.value.trim();
            if (!note) {
              noteArea.focus();
              return;
            }
            const out = await Motion.guardAction(
              sendBtn,
              () => apiRequest("POST", "/api/v4/inbox/action", { id: detail.id, action: "request_changes", note }),
              { group: footRight, busyLabel: "Sending…" },
            );
            if (!out) return;
            await close();
            toaster.show("Revision requested — running in sandbox");
            await refreshBootstrapQuietly();
            closeReviewSheetAndNavigate();
          },
        });
        footRight.append(actionBtn({ label: "Cancel", variant: "secondary", onClick: close }), sendBtn);
        return [
          el(
            "div",
            { className: "modal-head" },
            el("h2", { className: "t-18 w600" }, "Request changes"),
            el("button", { type: "button", className: "btn-icon", "aria-label": "Close", onClick: close }, ICONS.close()),
          ),
          el("p", { className: "t-13 secondary" }, "Your feedback stays on this machine and re-runs verification in the sandbox."),
          noteArea,
          el("div", { className: "modal-foot" }, el("span", { className: "t-12 muted" }, "Re-runs local tests automatically"), footRight),
        ];
      });
    },
  });

  const approveBtn = actionBtn({
    label: "Approve & push to PR",
    variant: "primary",
    id: "sheet-primary-action",
    keycap: "⌘↵",
    disabled: blockedByHold,
    onClick: async () => {
      if (approveBtn.getAttribute("aria-disabled") === "true") return;
      try {
        const res = await Motion.guardAction(
          approveBtn,
          () => apiRequest("POST", "/api/v4/inbox/action", { id: detail.id, action: "approve", is_sample: false }),
          { group: actionsGroup, busyLabel: "Pushing…" },
        );
        if (!res) return;
        trackUiEvent("ui_diff_approved_and_pushed", {
          driver_tool_kind: normalizeToolKind(detail.tool_label),
          reviewer_tool_kind: normalizeToolKind(detail.reviewer_label || "codex_cli"),
          is_cross_model_verified: Boolean(detail.independent_review && detail.independent_review.passed),
          sandbox_tests_passed: detail.test_passed !== false,
          decision_latency_bucket: decisionLatencyBucket(Date.now() - state.sheetOpenedAtMs),
          is_sample_walkthrough: false,
        });
        toaster.show(res.value.message || `Approved and pushed to ${targetBranch}`);
        announce(`Approved and pushed ${detail.title}`);
        await refreshBootstrapQuietly();
        closeReviewSheetAndNavigate();
      } catch (err) {
        trackUiEvent("ui_action_failed", {
          failed_action: "approve_and_push",
          error_category: "git_conflict",
        });
        toaster.show(err.message || "Could not push changes — check git status");
      }
    },
  });

  if (armPrimary && !blockedByHold) {
    Motion.arm(approveBtn);
  }

  actionsGroup.append(
    copyButton({
      label: "Copy PR summary",
      variant: "ghost",
      size: "",
      textToCopy: mdSummary,
      okToast: "PR summary copied",
      onCopied: () => trackUiEvent("ui_speed_summary_copied", { copy_surface: "diff_sheet", summary_surface: "pr_markdown" }),
    }),
    rejectBtn,
    requestChangesBtn,
    approveBtn,
  );

  sheetFoot.append(
    el(
      "div",
      { className: "foot-context" },
      el("div", { className: "push-target" }, `This pushes to ${targetBranch} on ${hostName}.`),
      el(
        "div",
        { className: "foot-helper" },
        blockedByHold
          ? "Resolve the banner above before pushing."
          : "Sandbox tests passed locally.",
      ),
    ),
    actionsGroup,
  );
}

// ── 7 · View 2: Board (5 Executive Summary Tiles + 4 Calm Columns) ───────────

function filterBoardCard(card) {
  if (state.boardWorkstream === "all") return true;
  const ws = String(card.workstream || card.function || card.category || "engineering").toLowerCase();
  return ws === state.boardWorkstream;
}

function renderBoardView(root) {
  const summary = state.data.board.summary;
  const cols = state.data.board.columns;
  const inProgCount = cols.in_progress.length || state.data.inbox.counts.running;
  const needsRevCount = cols.needs_review.length || state.data.inbox.counts.needs_decision;

  trackUiEvent("ui_board_shipped_strip_seen", {
    shipped_bucket: shippedBucket(summary.shipped_count),
    hours_bucket: hoursBucket(summary.hours_saved),
    time_saved_baseline_documented: true,
  });

  const container = el("div", { className: "container" });
  const actionsGroup = el("div", { className: "view-actions" });

  const syncTarget = state.data.repo.linear_connected && !state.data.repo.github_connected ? "linear" : "github";
  const syncLabel = syncTarget === "linear" ? "Sync Linear · 0 Cr" : "Sync GitHub · 0 Cr";
  const syncBtn = actionBtn({
    label: syncLabel,
    variant: "secondary",
    size: "sm",
    onClick: async () => {
      trackUiEvent("ui_board_sync_clicked", { target: syncTarget });
      try {
        const out = await Motion.guardAction(
          syncBtn,
          () => apiRequest("POST", "/api/v4/board/sync", { target: syncTarget }),
          { group: actionsGroup, busyLabel: "Syncing…" },
        );
        if (!out) return;
        const synced = Number(out.value.synced_items) || 0;
        trackUiEvent("ui_board_sync_completed", {
          target: syncTarget,
          sync_outcome: "ok",
          synced_items_bucket: countBucket(synced),
        });
        toaster.show(out.value.message || `Synced ${synced} items · 0 credits charged`);
        await refreshBootstrapQuietly();
        if (state.view === "board") renderCurrentView();
      } catch (err) {
        toaster.show(err.message || "Could not sync right now");
      }
    },
  });

  const speedSummaryText = () => {
    const repoLabel = state.data.repo.name || "this repository";
    return `${repoLabel}: ${summary.shipped_count} verified changes shipped, ${summary.hours_saved} developer hours saved (${summary.credits_used} Cr used).`;
  };

  actionsGroup.append(
    syncBtn,
    copyButton({
      label: "Copy speed summary",
      variant: "secondary",
      size: "sm",
      textToCopy: speedSummaryText,
      okToast: "Speed summary copied",
      onCopied: () =>
        trackUiEvent("ui_speed_summary_copied", {
          copy_surface: "shipped_card",
          summary_surface: "clipboard",
        }),
    }),
    actionBtn({
      label: "+ New task",
      variant: "primary",
      size: "sm",
      onClick: () => openNewTaskModal("board_header"),
    }),
  );

  container.appendChild(
    el("div", { className: "view-head" }, el("h1", { className: "t-20 w600" }, "Board"), actionsGroup),
  );

  // 5 Executive Summary Tiles
  const tiles = [
    { label: "Shipped", value: formatInt(summary.shipped_count) || "0", sub: "Approved & merged" },
    { label: "In progress", value: formatInt(inProgCount) || "0", sub: "Running in sandbox" },
    { label: "Needs review", value: formatInt(needsRevCount) || "0", sub: "Waiting in Inbox" },
    {
      label: "Hours saved",
      value: summary.shipped_count > 0 ? `${summary.hours_saved} hrs` : "0 hrs",
      sub: "Shipped tasks only",
    },
    { label: "Credits used", value: formatCredits(summary.credits_used) || "0 Cr", sub: "Verified runs" },
  ];

  container.appendChild(
    el(
      "section",
      { className: "tiles-grid", "aria-label": "Delivery summary" },
      tiles.map((t) =>
        el(
          "div",
          { className: "tile" },
          el("span", { className: "tile-label" }, t.label),
          el("span", { className: "tile-value num" }, t.value),
          el("span", { className: "tile-sub" }, t.sub),
        ),
      ),
    ),
  );

  // Plain-English baseline explainer + 4-row human benchmark popover trigger
  const baselineBtn = el(
    "button",
    {
      type: "button",
      className: "status-link",
      "aria-haspopup": "dialog",
      "aria-expanded": "false",
      onClick: () => openBaselinePopover(baselineBtn),
    },
    "How baseline time works",
  );
  container.appendChild(
    el(
      "div",
      { className: "board-caption-row" },
      el("span", null, summary.baseline_explainer),
      baselineBtn,
    ),
  );

  // Workstream filter chips
  const workstreams = [
    { id: "all", label: "All" },
    { id: "engineering", label: "Engineering" },
    { id: "design", label: "Design" },
    { id: "product", label: "Product" },
    { id: "qa", label: "QA" },
    { id: "security", label: "Security" },
    { id: "docs", label: "Docs" },
  ];
  container.appendChild(
    el(
      "div",
      { className: "chip-row", role: "group", "aria-label": "Filter board by category" },
      workstreams.map((ws) =>
        el(
          "button",
          {
            type: "button",
            className: "chip",
            "aria-pressed": state.boardWorkstream === ws.id ? "true" : "false",
            onClick: () => {
              if (state.boardWorkstream === ws.id) return;
              state.boardWorkstream = ws.id;
              trackUiEvent("ui_board_filter_changed", { workstream: ws.id });
              renderCurrentView();
            },
          },
          ws.label,
        ),
      ),
    ),
  );

  // 4 Calm Columns
  const colSpecs = [
    { key: "queued", title: "Queued", empty: "No tasks queued." },
    { key: "in_progress", title: "In progress", empty: "Nothing running right now." },
    { key: "needs_review", title: "Needs review", empty: "No diffs waiting for review." },
    { key: "shipped", title: "Shipped", empty: "Approved changes appear here." },
  ];

  container.appendChild(
    el(
      "div",
      { className: "board-columns" },
      colSpecs.map((spec) => {
        const rawCards = Array.isArray(cols[spec.key]) ? cols[spec.key] : [];
        const cards = rawCards.filter(filterBoardCard);
        return el(
          "section",
          { className: "board-col", dataset: { col: spec.key }, "aria-label": spec.title },
          el(
            "div",
            { className: "board-col-head" },
            el("span", null, spec.title),
            cards.length > 0 ? el("span", { className: "muted num" }, String(cards.length)) : null,
          ),
          cards.length === 0
            ? el("p", { className: "board-col-empty" }, spec.empty)
            : cards.map((card, i) => {
                const cid = String(card.id || card.item_id || card.task_id || `${spec.key}-${i}`);
                const title = String(card.title || card.heading || "Task");
                const hasDiff = Boolean(card.has_diff || spec.key === "needs_review" || getItemById(cid));
                const wsLabel = !isAbsent(card.workstream || card.function) ? String(card.workstream || card.function) : null;
                return el(
                  "article",
                  { className: "card board-card" },
                  wsLabel ? el("span", { className: "pill-fn" }, wsLabel) : null,
                  el(
                    "h3",
                    { className: "board-card-title" },
                    el(
                      "a",
                      {
                        href: hasDiff ? `#diff/${encodeURIComponent(cid)}` : "#board",
                        onClick: (ev) => {
                          ev.preventDefault();
                          trackUiEvent("ui_board_card_opened", {
                            board_column: spec.key,
                            has_linked_diff: hasDiff,
                          });
                          if (hasDiff) {
                            navigate(`#diff/${encodeURIComponent(cid)}`);
                          } else {
                            toaster.show(`${title} (${spec.title})`);
                          }
                        },
                      },
                      title,
                    ),
                  ),
                  metaRow([
                    fact(friendlyToolLabel(card.tool_label || card.driver || card.seat)),
                    fact(card.hours_saved, (h) => `${h} hrs saved`),
                    fact(card.credits_used, formatCredits),
                    fact(card.updated_at || card.created_at, formatRelativeTime),
                  ]),
                );
              }),
        );
      }),
    ),
  );

  root.appendChild(container);
}

// ── 8 · View 3: Agents & Rules ───────────────────────────────────────────────

async function saveWorkflowSettings(mutatorOrPatch = {}, options = {}) {
  const initialAgents = state.data.agents;
  if (!state.committedWorkflow) {
    state.committedWorkflow = snapshotWorkflowState(initialAgents);
  }

  const draft = snapshotWorkflowState(initialAgents);
  let changedSlotIdx = Number.isInteger(options.changedSlotIdx) ? options.changedSlotIdx : -1;
  let nextTool = options.nextTool || null;
  let prevTool = options.prevTool || null;

  if (typeof mutatorOrPatch === "function") {
    mutatorOrPatch(draft);
  } else if (mutatorOrPatch && typeof mutatorOrPatch === "object") {
    if (typeof mutatorOrPatch.independent_review === "boolean") {
      draft.workflow.independent_review = mutatorOrPatch.independent_review;
    }
    if (typeof mutatorOrPatch.protect_sensitive_paths === "boolean") {
      draft.workflow.protect_sensitive_paths = mutatorOrPatch.protect_sensitive_paths;
    }
    if (typeof mutatorOrPatch.auto_test_before_review === "boolean") {
      draft.workflow.auto_test_before_review = mutatorOrPatch.auto_test_before_review;
    }
    if (!isAbsent(mutatorOrPatch.driver_tool)) {
      prevTool = prevTool || draft.driver_tool;
      nextTool = nextTool || mutatorOrPatch.driver_tool;
      if (changedSlotIdx < 0) changedSlotIdx = 0;
      draft.driver_tool = normalizeToolKind(mutatorOrPatch.driver_tool);
    }
    if (!isAbsent(mutatorOrPatch.reviewer_tool)) {
      prevTool = prevTool || draft.reviewer_tool;
      nextTool = nextTool || mutatorOrPatch.reviewer_tool;
      if (changedSlotIdx < 0) changedSlotIdx = 1;
      draft.reviewer_tool = normalizeToolKind(mutatorOrPatch.reviewer_tool);
    }
    if (!isAbsent(mutatorOrPatch.test_verifier_tool)) {
      prevTool = prevTool || draft.test_verifier_tool;
      nextTool = nextTool || mutatorOrPatch.test_verifier_tool;
      if (changedSlotIdx < 0) changedSlotIdx = 2;
      draft.test_verifier_tool = normalizeToolKind(mutatorOrPatch.test_verifier_tool);
    }
    if (!isAbsent(mutatorOrPatch.security_verifier_tool)) {
      prevTool = prevTool || draft.security_verifier_tool;
      nextTool = nextTool || mutatorOrPatch.security_verifier_tool;
      if (changedSlotIdx < 0) changedSlotIdx = 3;
      draft.security_verifier_tool = normalizeToolKind(mutatorOrPatch.security_verifier_tool);
    }
    if ([50, 100, 150, 200].includes(Number(mutatorOrPatch.review_tier_credits))) {
      draft.review_tier_credits = Number(mutatorOrPatch.review_tier_credits);
    }
    if (Array.isArray(mutatorOrPatch.protected_paths)) {
      draft.protected_paths = mutatorOrPatch.protected_paths.map(String);
    }
  }

  ensureDistinctPairingSlots(draft, changedSlotIdx, nextTool, prevTool);
  applyWorkflowSnapshot(initialAgents, draft);

  if (options.renderOptimistic) {
    renderCurrentView();
    if (options.restoreFocusId && typeof document !== "undefined") {
      const focusTarget = document.getElementById(options.restoreFocusId);
      if (focusTarget && typeof focusTarget.focus === "function") {
        focusTarget.focus();
      }
    }
  }

  const toastMessage = options.toastMessage || (mutatorOrPatch && mutatorOrPatch.toastMessage) || "Workflow settings saved";
  const silentToast = Boolean(options.silentToast || (mutatorOrPatch && mutatorOrPatch.silentToast));

  const payload = {
    independent_review: draft.workflow.independent_review,
    protect_sensitive_paths: draft.workflow.protect_sensitive_paths,
    auto_test_before_review: draft.workflow.auto_test_before_review,
    driver_tool: draft.driver_tool,
    reviewer_tool: draft.reviewer_tool,
    test_verifier_tool: draft.test_verifier_tool,
    security_verifier_tool: draft.security_verifier_tool,
    review_tier_credits: draft.review_tier_credits,
    review_mode: reviewModeForCredits(draft.review_tier_credits),
    protected_paths: [...draft.protected_paths],
  };

  const seq = (state.workflowSaveSeq || 0) + 1;
  state.workflowSaveSeq = seq;
  state.workflowSaveInFlight = (state.workflowSaveInFlight || 0) + 1;

  const runRequest = () => apiRequest("POST", "/api/v4/workflow", payload);
  const reqPromise = state.workflowSaveChain.then(runRequest, runRequest);
  state.workflowSaveChain = reqPromise.catch(() => {});

  try {
    const res = await reqPromise;
    const committed = snapshotWorkflowState(draft);
    if (res && res.workflow && typeof res.workflow === "object") {
      const w = res.workflow;
      committed.workflow = {
        independent_review: w.independent_review !== false,
        protect_sensitive_paths: w.protect_sensitive_paths !== false,
        auto_test_before_review: w.auto_test_before_review !== false,
      };
      if (!isAbsent(w.driver_tool)) committed.driver_tool = normalizeToolKind(w.driver_tool);
      if (!isAbsent(w.reviewer_tool)) committed.reviewer_tool = normalizeToolKind(w.reviewer_tool);
      if (!isAbsent(w.test_verifier_tool)) committed.test_verifier_tool = normalizeToolKind(w.test_verifier_tool);
      if (!isAbsent(w.security_verifier_tool)) committed.security_verifier_tool = normalizeToolKind(w.security_verifier_tool);
      if ([50, 100, 150, 200].includes(Number(w.review_tier_credits))) {
        committed.review_tier_credits = Number(w.review_tier_credits);
      }
      if (Array.isArray(w.protected_paths)) {
        committed.protected_paths = w.protected_paths.map(String);
      }
      ensureDistinctPairingSlots(committed);
    }
    state.committedWorkflow = committed;

    if (seq === state.workflowSaveSeq) {
      applyWorkflowSnapshot(state.data.agents, committed);
    }
    if (typeof options.onCommitted === "function") {
      options.onCommitted(committed);
    }
    if (!silentToast && seq === state.workflowSaveSeq) {
      const msg = typeof toastMessage === "function" ? toastMessage(committed) : toastMessage;
      toaster.show(msg);
    }
    return committed;
  } catch (err) {
    if (seq === state.workflowSaveSeq && state.committedWorkflow) {
      applyWorkflowSnapshot(state.data.agents, state.committedWorkflow);
      if (state.view === "agents") {
        renderCurrentView();
        if (options.restoreFocusId && typeof document !== "undefined") {
          const focusTarget = document.getElementById(options.restoreFocusId);
          if (focusTarget && typeof focusTarget.focus === "function") {
            focusTarget.focus();
          }
        }
      }
    }
    trackUiEvent("ui_action_failed", {
      failed_action: "guardrail_save",
      error_category: "io_error",
    });
    if (seq === state.workflowSaveSeq) {
      toaster.show(err.message || "Could not save workflow settings");
    }
    throw err;
  } finally {
    state.workflowSaveInFlight = Math.max(0, (state.workflowSaveInFlight || 1) - 1);
  }
}

function renderAgentsView(root) {
  const agents = state.data.agents;
  const wf = agents.workflow;
  const container = el("div", { className: "container" });
  container.appendChild(el("div", { className: "view-head" }, el("h1", { className: "t-20 w600" }, "Agents & Rules")));

  const stack = el("div", { className: "section-stack" });

  // Section 1: Detected Coding Tools + Cursor Import
  const toolsBlock = el(
    "section",
    { className: "section-block", "aria-label": "Detected coding tools" },
    el(
      "div",
      { className: "section-head" },
      el("h2", { className: "t-16 w600" }, "Detected coding tools"),
      el("p", { className: "t-13 secondary" }, "Chinwag coordinates the coding tools already installed on your machine. Bring your own subscriptions."),
    ),
    el(
      "div",
      { className: "tools-grid" },
      agents.detected_tools.map((tool) => {
        const tKind = normalizeToolKind(tool.id || tool.label);
        return el(
          "div",
          { className: "card tool-card" },
          el(
            "div",
            { className: "tool-card-top" },
            el(
              "div",
              { className: "tool-title-row" },
              el("span", { className: "t-14 w600" }, tool.label),
              statusPill(tool.installed ? "Ready" : "Not detected", tool.installed ? "success" : "neutral"),
            ),
            metaRow([fact(tool.version, (v) => `Version ${v}`)]),
          ),
          !tool.installed
            ? copyButton({
                label: "Copy install command",
                variant: "secondary",
                size: "sm",
                textToCopy: tool.setup_command,
                okToast: `Copied ${tool.label} setup command`,
                onCopied: () => trackUiEvent("ui_cli_setup_command_copied", { tool_kind: tKind }),
              })
            : el("span", { className: "t-12 muted" }, "Available for coding & review"),
        );
      }),
    ),
    el(
      "div",
      { className: "card cursor-import-card" },
      el(
        "div",
        { className: "section-head" },
        el(
          "div",
          { className: "t-14 w500" },
          state.data.repo.cursor_detected ? "Cursor rules detected in .cursor/" : "Share .cursor rules across all tools",
        ),
        el(
          "p",
          { className: "t-13 secondary" },
          "Preview and import conventions from .cursor/ so Claude Code, Codex CLI, and Gemini CLI follow identical project rules.",
        ),
      ),
      actionBtn({
        label: "Preview Cursor import",
        variant: "secondary",
        size: "sm",
        onClick: () => openCursorPreviewModal("agents_tab"),
      }),
    ),
  );
  stack.appendChild(toolsBlock);

  // Section 2: Independent Review (Dynamic 2 / 3 / 4 Tool Slots + Quad-Programming)
  const toolOptions = [
    { value: "claude_code", label: "Claude Code" },
    { value: "codex_cli", label: "Codex CLI" },
    { value: "gemini_cli", label: "Gemini CLI" },
    { value: "cursor", label: "Cursor" },
  ];

  const reviewTiers = [
    { credits: 50, slots: 2, mode: "review_handoff", title: "Review handoff · 50 Cr", desc: "Second tool reviews the diff before Inbox" },
    { credits: 100, slots: 2, mode: "pair_sandbox", title: "Pair sandbox · 100 Cr", desc: "Driver and reviewer iterate until tests pass" },
    { credits: 150, slots: 3, mode: "three_tool_check", title: "Three-tool check · 150 Cr", desc: "Adds a 3rd tool for edge-case & test verification" },
    { credits: 200, slots: 4, mode: "quad_programming", title: "Quad-programming · 200 Cr", desc: "Four independent tools: driver, code review, tests, and security audit" },
  ];

  ensureDistinctPairingSlots(agents);
  const activeTier = reviewTiers.find((t) => t.credits === agents.review_tier_credits) || reviewTiers[1];
  const activeSlots = activeTier.slots;

  const allSlotSpecs = [
    {
      slotIdx: 0,
      key: "driver_tool",
      label: "1. Writes the change (Driver)",
      ariaLabel: "Primary coding tool (Driver)",
    },
    {
      slotIdx: 1,
      key: "reviewer_tool",
      label: activeSlots === 2 ? "2. Reviews code & diff (Reviewer)" : "2. Reviews code & architecture (Reviewer)",
      ariaLabel: "Independent reviewer tool",
    },
    {
      slotIdx: 2,
      key: "test_verifier_tool",
      label: "3. Breaks edge cases & tests (Test Verifier)",
      ariaLabel: "Independent test verifier tool",
    },
    {
      slotIdx: 3,
      key: "security_verifier_tool",
      label: "4. Audits security, auth & migrations (Security Verifier)",
      ariaLabel: "Independent security verifier tool",
    },
  ];
  const visibleSlotSpecs = allSlotSpecs.slice(0, activeSlots);

  const installedToolSet = new Set(
    agents.detected_tools.filter((t) => t.installed).map((t) => normalizeDetectedToolId(t.id)),
  );
  const missingActiveToolLabels = visibleSlotSpecs
    .map((spec) => agents[spec.key])
    .filter((toolId, idx, arr) => arr.indexOf(toolId) === idx && !installedToolSet.has(toolId))
    .map((toolId) => friendlyToolLabel(toolId));

  const pairingSection = el(
    "section",
    { className: "section-block", "aria-label": "Independent review" },
    el(
      "div",
      { className: "card pairing-card" },
      el(
        "div",
        { className: "pairing-head" },
        el(
          "div",
          { className: "section-head" },
          el("h2", { className: "t-16 w600" }, "Independent review"),
          el(
            "p",
            { className: "t-13 secondary" },
            "A different coding tool checks every change so no tool grades its own homework.",
          ),
        ),
        switchControl({
          checked: wf.independent_review,
          label: "Enable independent review",
          onToggle: async (next) => {
            await saveWorkflowSettings({ independent_review: next });
            trackUiEvent("ui_guardrail_toggled", {
              guardrail_id: "independent_review",
              guardrail_enabled: next,
            });
          },
        }),
      ),
      el(
        "div",
        { className: "pairing-selects", dataset: { slots: String(activeSlots) } },
        visibleSlotSpecs.map((spec) => {
          const selectId = `pairing-slot-${spec.key}`;
          const selectEl = el(
            "select",
            {
              id: selectId,
              className: "select",
              "aria-label": spec.ariaLabel,
              onChange: () => {
                const prevTool = state.data.agents[spec.key];
                const nextTool = selectEl.value;
                if (prevTool === nextTool) return;
                saveWorkflowSettings(
                  {},
                  {
                    changedSlotIdx: spec.slotIdx,
                    nextTool,
                    prevTool,
                    renderOptimistic: true,
                    restoreFocusId: selectId,
                    toastMessage: (committed) =>
                      `${spec.label.replace(/^\d+\.\s*/, "")} set to ${friendlyToolLabel(committed[spec.key])}`,
                    onCommitted: (committed) => {
                      trackUiEvent("ui_cross_tool_pairing_updated", {
                        driver_tool_kind: committed.driver_tool,
                        reviewer_tool_kind: committed.reviewer_tool,
                        function_credits_cost: committed.review_tier_credits,
                      });
                    },
                  },
                ).catch(() => {});
              },
            },
            toolOptions.map((o) =>
              el("option", { value: o.value, selected: agents[spec.key] === o.value }, o.label),
            ),
          );
          return el(
            "div",
            { className: "section-block" },
            el("label", { className: "t-13 w500", for: selectId }, spec.label),
            selectEl,
          );
        }),
      ),
      missingActiveToolLabels.length > 0
        ? el(
            "p",
            { className: "t-12 secondary" },
            `${formatHumanList(missingActiveToolLabels)} ${missingActiveToolLabels.length === 1 ? "is" : "are"} not detected locally yet — copy ${missingActiveToolLabels.length === 1 ? "its" : "their"} install command under Detected coding tools above before running this check.`,
          )
        : null,
      el(
        "div",
        { className: "radio-cards", role: "radiogroup", "aria-label": "Review depth" },
        reviewTiers.map((tier) =>
          el(
            "button",
            {
              type: "button",
              role: "radio",
              className: "radio-card",
              "aria-checked": agents.review_tier_credits === tier.credits ? "true" : "false",
              onClick: () => {
                if (state.data.agents.review_tier_credits === tier.credits) return;
                saveWorkflowSettings(
                  { review_tier_credits: tier.credits },
                  {
                    renderOptimistic: true,
                    toastMessage: `Review depth set to ${tier.title}`,
                    onCommitted: (committed) => {
                      trackUiEvent("ui_cross_tool_pairing_updated", {
                        driver_tool_kind: committed.driver_tool,
                        reviewer_tool_kind: committed.reviewer_tool,
                        function_credits_cost: committed.review_tier_credits,
                      });
                    },
                  },
                ).catch(() => {});
              },
            },
            el("span", { className: "t-13 w600 num" }, tier.title),
            el("span", { className: "t-12 secondary" }, tier.desc),
          ),
        ),
      ),
    ),
  );
  stack.appendChild(pairingSection);

  // Section 3: Safety Rules & Protected Paths
  const globInput = el("input", {
    type: "text",
    className: "input",
    placeholder: "e.g., db/migrations/**",
    "aria-label": "Protected file path pattern",
  });
  const addGlobBtn = actionBtn({
    label: "Add path rule",
    variant: "secondary",
    size: "sm",
    onClick: () => {
      const val = globInput.value.trim();
      if (!val) {
        globInput.focus();
        return;
      }
      const curPaths = state.data.agents.protected_paths;
      if (!curPaths.includes(val)) {
        const nextPaths = [...curPaths, val];
        saveWorkflowSettings(
          { protected_paths: nextPaths },
          {
            renderOptimistic: true,
            toastMessage: `Protected path added: ${val}`,
            onCommitted: (committed) => {
              trackUiEvent("ui_protected_path_added", {
                path_category: "custom_glob",
                protected_paths_count_bucket: countBucket(committed.protected_paths.length),
              });
            },
          },
        ).catch(() => {});
      }
    },
  });

  const safetySection = el(
    "section",
    { className: "section-block", "aria-label": "Safety rules" },
    el(
      "div",
      { className: "section-head" },
      el("h2", { className: "t-16 w600" }, "Safety rules"),
      el("p", { className: "t-13 secondary" }, "Control when tasks pause for explicit approval before touching sensitive files."),
    ),
    el(
      "div",
      { className: "card rules-card" },
      el(
        "div",
        { className: "rule-toggle-row" },
        el(
          "div",
          { className: "section-head" },
          el("div", { className: "t-14 w500" }, "Protect sensitive paths"),
          el("p", { className: "t-13 secondary" }, "Pause and ask permission in Inbox before editing workflows, environment files, auth, or billing."),
        ),
        switchControl({
          checked: wf.protect_sensitive_paths,
          label: "Protect sensitive paths",
          onToggle: async (next) => {
            await saveWorkflowSettings({ protect_sensitive_paths: next });
            trackUiEvent("ui_guardrail_toggled", {
              guardrail_id: "protect_sensitive_paths",
              guardrail_enabled: next,
            });
          },
        }),
      ),
      el(
        "div",
        { className: "rule-toggle-row" },
        el(
          "div",
          { className: "section-head" },
          el("div", { className: "t-14 w500" }, "Run tests automatically before review"),
          el("p", { className: "t-13 secondary" }, "Run the test suite in an isolated workspace and pause automatically if 2 attempts fail."),
        ),
        switchControl({
          checked: wf.auto_test_before_review,
          label: "Run tests automatically before review",
          onToggle: async (next) => {
            await saveWorkflowSettings({ auto_test_before_review: next });
            trackUiEvent("ui_guardrail_toggled", {
              guardrail_id: "auto_test_before_review",
              guardrail_enabled: next,
            });
          },
        }),
      ),
      el(
        "div",
        { className: "glob-editor" },
        el("span", { className: "t-12 w500 secondary" }, "Protected file patterns"),
        el(
          "div",
          { className: "glob-chips" },
          agents.protected_paths.map((glob) =>
            el(
              "span",
              { className: "glob-chip" },
              el("span", null, glob),
              el(
                "button",
                {
                  type: "button",
                  "aria-label": `Remove ${glob}`,
                  onClick: () => {
                    const nextPaths = state.data.agents.protected_paths.filter((g) => g !== glob);
                    saveWorkflowSettings(
                      { protected_paths: nextPaths },
                      {
                        renderOptimistic: true,
                        toastMessage: `Removed protected path: ${glob}`,
                        onCommitted: (committed) => {
                          trackUiEvent("ui_protected_path_removed", {
                            path_category: "custom_glob",
                            protected_paths_count_bucket: countBucket(committed.protected_paths.length),
                          });
                        },
                      },
                    ).catch(() => {});
                  },
                },
                "×",
              ),
            ),
          ),
        ),
        el("div", { className: "glob-add-row" }, globInput, addGlobBtn),
      ),
    ),
  );
  stack.appendChild(safetySection);

  // Section 4: Learned Repo Rules
  const ruleInput = el("input", {
    type: "text",
    className: "input",
    placeholder: "Add a convention for every coding tool in this repo…",
    "aria-label": "New repository rule",
  });
  const learnedSection = el(
    "section",
    { className: "section-block", "aria-label": "Learned repository rules" },
    el(
      "div",
      { className: "section-head" },
      el("h2", { className: "t-16 w600" }, "Learned repository rules"),
      el("p", { className: "t-13 secondary" }, "Plain-English guidance shared with every tool so mistakes are not repeated."),
    ),
    el(
      "div",
      { className: "card rules-card" },
      agents.learned_rules.length === 0
        ? el(
            "div",
            { className: "glob-editor" },
            el("p", { className: "t-13 secondary" }, "No learned rules yet. Rejecting a diff or adding a rule below teaches every coding tool in this repo."),
          )
        : el(
            "div",
            { className: "learned-list" },
            agents.learned_rules.map((rule) =>
              el(
                "div",
                { className: "learned-row" },
                el(
                  "div",
                  { className: "section-head" },
                  el("span", { className: "t-14" }, rule.text),
                  el("span", { className: "t-12 muted" }, rule.source_label),
                ),
                el(
                  "div",
                  { className: "learned-actions" },
                  actionBtn({
                    label: "Remove",
                    variant: "ghost",
                    size: "sm",
                    onClick: () => {
                      agents.learned_rules = agents.learned_rules.filter((r) => r.id !== rule.id);
                      renderCurrentView();
                    },
                  }),
                ),
              ),
            ),
          ),
      el(
        "div",
        { className: "glob-editor" },
        el(
          "div",
          { className: "glob-add-row" },
          ruleInput,
          actionBtn({
            label: "Add rule",
            variant: "secondary",
            size: "sm",
            onClick: () => {
              const txt = ruleInput.value.trim();
              if (!txt) {
                ruleInput.focus();
                return;
              }
              agents.learned_rules.unshift({
                id: `rule-${Date.now()}`,
                text: txt,
                source_label: "Added manually",
              });
              toaster.show("Repository rule added");
              renderCurrentView();
            },
          }),
        ),
      ),
    ),
  );
  stack.appendChild(learnedSection);

  // Section 5: Workflow Integrations
  const integrations = [
    {
      title: "GitHub Actions CI autofix",
      status: "50 Cr per fix",
      desc: "Automatically prepare a tested patch when a pull request check fails.",
      snippet: "npx chinwag ci install-github-workflow",
      kind: "github_actions_yaml",
    },
    {
      title: "GitHub Projects sync",
      status: state.data.repo.github_connected ? "Connected · 0 Cr" : "0 Cr",
      desc: "Keep Board columns synced with GitHub Issues and Pull Requests.",
      snippet: "chinwag board connect github",
      kind: "github_projects_sync",
    },
    {
      title: "Linear sync",
      status: state.data.repo.linear_connected ? "Connected · 0 Cr" : "0 Cr",
      desc: "Mirror Linear issues and update status automatically on merge.",
      snippet: "chinwag board connect linear",
      kind: "linear_sync",
    },
    {
      title: "Slack review alerts",
      status: "0 Cr",
      desc: "Get a direct link to open Inbox diffs the moment tests finish.",
      snippet: "chinwag notify connect slack",
      kind: "slack_app",
    },
  ];

  stack.appendChild(
    el(
      "section",
      { className: "section-block", "aria-label": "Workflow integrations" },
      el("div", { className: "section-head" }, el("h2", { className: "t-16 w600" }, "Workflow integrations")),
      el(
        "div",
        { className: "tools-grid" },
        integrations.map((intg) =>
          el(
            "div",
            { className: "card tool-card" },
            el(
              "div",
              { className: "tool-card-top" },
              el("div", { className: "tool-title-row" }, el("span", { className: "t-14 w600" }, intg.title), el("span", { className: "pill-fn" }, intg.status)),
              el("p", { className: "t-13 secondary" }, intg.desc),
            ),
            copyButton({
              label: "Copy setup command",
              variant: "secondary",
              size: "sm",
              textToCopy: intg.snippet,
              okToast: `${intg.title} command copied`,
              onCopied: () => trackUiEvent("ui_integration_snippet_copied", { integration_kind: intg.kind }),
            }),
          ),
        ),
      ),
    ),
  );

  container.appendChild(stack);
  root.appendChild(container);
}

// ── 9 · View 4: Credits (12-Month Expiry, Burn Order & Auto-Refill) ──────────

function wizardPackSlugForSku(sku) {
  switch (String(sku || "").toLowerCase()) {
    case "pack_50":
      return "developer";
    case "pack_160":
      return "growth";
    case "pack_560":
      return "scale";
    case "pack_1000":
      return "volume";
    default:
      return "growth";
  }
}

async function startCheckoutFlow(btn, groupEl, packSku, triggerSurface = "credits_tab") {
  const pack = state.data.credits.catalog.find((p) => p.sku === packSku) || CATALOG_PACKS[0];
  const attemptId = uuidv4();
  trackUiEvent("ui_credits_checkout_clicked", {
    pack_slug: pack.telemetry_slug,
    pack_price_usd: pack.price_usd,
    pack_credits: pack.credits,
    trigger_surface: triggerSurface,
    checkout_attempt_id: attemptId,
  });

  try {
    const out = await Motion.guardAction(
      btn,
      () => apiRequest("POST", "/api/v4/credits/checkout", { pack_sku: pack.sku, trigger_surface: triggerSurface }),
      { group: groupEl, busyLabel: "Opening checkout…" },
    );
    if (!out) return;
    out.release();
    const wizardSlug = wizardPackSlugForSku(pack.sku);
    const url =
      (out.value && out.value.checkout_url) ||
      `https://chinwag.sh/pricing?pack=${encodeURIComponent(wizardSlug)}&source=local_ui&attempt=${encodeURIComponent(attemptId)}`;
    const win = typeof window !== "undefined" ? window.open(url, "_blank", "noopener,noreferrer") : null;
    if (!win) {
      toaster.show(`Checkout ready — open ${url}`);
    } else {
      toaster.show(`Opened ${pack.label} checkout ($${formatInt(pack.price_usd)})`);
    }
  } catch (err) {
    toaster.show(err.message || "Could not start checkout right now");
  }
}

function normalizePlanTierEnum(rawTier) {
  const s = String(rawTier || "trial").toLowerCase();
  if (["unenrolled", "free_trial", "trial", "developer", "growth", "scale", "org_volume"].includes(s)) return s;
  if (s.includes("starter") || s.includes("free")) return "free_trial";
  if (s.includes("team") || s === "pack_160") return "growth";
  if (s === "pack_50") return "developer";
  if (s === "pack_560") return "scale";
  if (s === "pack_1000") return "org_volume";
  return "trial";
}

function renderCreditsView(root) {
  const cred = state.data.credits;
  trackUiEvent("ui_credits_tab_viewed", {
    entry_trigger: "top_tab",
    credits_remaining_bucket: creditsBucket(cred.available_credits ?? 500),
    plan_tier: normalizePlanTierEnum(cred.plan_tier),
  });

  const container = el("div", { className: "container" });
  container.appendChild(
    el(
      "div",
      { className: "view-head" },
      el("h1", { className: "t-20 w600" }, "Credits"),
      actionBtn({
        label: "Invite teammate · +250 Cr",
        variant: "secondary",
        size: "sm",
        onClick: () => openInviteModal("credits_tab"),
      }),
    ),
  );

  const stack = el("div", { className: "section-stack" });

  // 1. Balance & Upfront 12-Month Expiry Summary Card
  const expiryLine =
    !isAbsent(cred.next_expiry_at) && Number.isFinite(cred.next_expiry_credits)
      ? `${formatInt(cred.next_expiry_credits)} Cr expire on ${formatDateShort(cred.next_expiry_at)}`
      : null;

  stack.appendChild(
    el(
      "section",
      { className: "card credits-banner", "aria-label": "Available credit balance" },
      el(
        "div",
        { className: "credits-banner-copy" },
        el(
          "div",
          { className: "card-status" },
          el("h2", { className: "t-16 w600" }, "Organization credit pool"),
          el(
            "span",
            { className: "pill-fn" },
            String(cred.plan_tier || "").includes("$0")
              ? cred.plan_tier
              : `$0 per teammate seat · ${cred.plan_tier}`,
          ),
        ),
        el("p", { className: "t-13 secondary" }, cred.pack_expiry_notice),
        expiryLine ? el("p", { className: "t-12 muted num" }, expiryLine) : null,
      ),
      el(
        "div",
        { className: "credits-balance-box" },
        el("span", { className: "t-12 secondary" }, "Available balance"),
        el(
          "span",
          { className: "t-24 w600 num" },
          cred.available && cred.available_credits !== null ? `${formatInt(cred.available_credits)} Cr` : "Balance unavailable",
        ),
      ),
    ),
  );

  // 2. Burn-Order Pack Stack
  const tranches = cred.tranches.length > 0
    ? cred.tranches
    : cred.available && cred.available_credits !== null
      ? [
          {
            label: cred.plan_tier === "trial" || cred.plan_tier === "free_trial" ? "Starter trial grant (used first)" : "Active credit pack",
            remaining_credits: cred.available_credits,
            expires_at: cred.next_expiry_at,
          },
        ]
      : [];

  if (tranches.length > 0) {
    stack.appendChild(
      el(
        "section",
        { className: "section-block", "aria-label": "Active credit packs" },
        el(
          "div",
          { className: "section-head" },
          el("h2", { className: "t-16 w600" }, "Active credit packs"),
          el("p", { className: "t-13 secondary" }, "Trial credits are used first. Paid packs are used in order of soonest expiration."),
        ),
        el(
          "div",
          { className: "tranche-stack" },
          tranches.map((tr) =>
            el(
              "div",
              { className: "tranche-row" },
              el("span", { className: "w500" }, tr.label),
              metaRow([
                fact(tr.remaining_credits, (n) => `${formatInt(n)} Cr remaining`, "num"),
                fact(tr.expires_at, (d) => `Expires ${formatDateShort(d)}`),
              ]),
            ),
          ),
        ),
      ),
    );
  }

  // 3. Buy a Credit Pack (4 Cards with 12-Month Expiry Upfront)
  const packsGrid = el("div", { className: "packs-grid" });
  for (const pack of cred.catalog) {
    const buyBtn = actionBtn({
      label: `Buy ${pack.label} · $${formatInt(pack.price_usd)}`,
      variant: pack.recommended ? "primary" : "secondary",
      onClick: () => startCheckoutFlow(buyBtn, packsGrid, pack.sku, "credits_tab"),
    });
    packsGrid.appendChild(
      el(
        "div",
        { className: "card pack-card" },
        el(
          "div",
          { className: "pack-card-top" },
          el(
            "div",
            { className: "tool-title-row" },
            el("span", { className: "t-16 w600" }, pack.label),
            pack.recommended ? statusPill("Recommended", "success") : null,
          ),
          el("div", { className: "t-24 w600 num" }, `$${formatInt(pack.price_usd)}`),
          el("div", { className: "t-14 w500 num" }, `${formatInt(pack.credits)} Cr`),
          el("p", { className: "t-12 secondary" }, pack.rate_note),
          el("p", { className: "t-12 muted" }, `Expires ${pack.expires_months} months after payment clears.`),
        ),
        buyBtn,
      ),
    );
  }
  stack.appendChild(
    el(
      "section",
      { className: "section-block", "aria-label": "Buy credit packs" },
      el(
        "div",
        { className: "view-head" },
        el(
          "div",
          { className: "section-head" },
          el("h2", { className: "t-16 w600" }, "Buy a credit pack"),
          el("p", { className: "t-13 secondary" }, "One-time prepaid packs shared across every repository and teammate in your organization."),
        ),
        el(
          "a",
          {
            href: cred.pricing_url || "https://chinwag.sh/pricing",
            target: "_blank",
            rel: "noopener noreferrer",
            className: "btn-secondary btn-sm",
          },
          el("span", null, "Compare packs on chinwag.sh →"),
        ),
      ),
      packsGrid,
    ),
  );

  // 4. Automatic Refill Card
  const ar = cred.auto_refill;
  const thresholdSelect = el(
    "select",
    { className: "select", "aria-label": "Refill when balance drops below" },
    [150, 250, 500].map((val) =>
      el("option", { value: String(val), selected: ar.threshold_credits === val }, `Below ${val} Cr`),
    ),
  );
  const packSelect = el(
    "select",
    { className: "select", "aria-label": "Refill pack" },
    cred.catalog.map((p) =>
      el("option", { value: p.sku, selected: ar.pack_sku === p.sku }, `${p.label} · $${formatInt(p.price_usd)}`),
    ),
  );
  const capSelect = el(
    "select",
    { className: "select", "aria-label": "Monthly spend cap" },
    [160, 500, 1000, 2500].map((cap) =>
      el("option", { value: String(cap), selected: ar.monthly_cap_usd === cap }, `Cap $${formatInt(cap)}/mo`),
    ),
  );

  const refillControls = el("div", { className: "autorefill-controls" });
  const saveRefillBtn = actionBtn({
    label: "Save refill settings",
    variant: "secondary",
    size: "sm",
    onClick: async () => {
      const payload = {
        enabled: ar.enabled,
        threshold_credits: Number(thresholdSelect.value) || 250,
        pack_sku: packSelect.value,
        monthly_cap_usd: Number(capSelect.value) || 500,
      };
      const out = await Motion.guardAction(
        saveRefillBtn,
        () => apiRequest("POST", "/api/v4/credits/autorefill", payload),
        { group: refillControls, busyLabel: "Saving…" },
      );
      if (!out) return;
      out.release();
      Object.assign(cred.auto_refill, payload);
      trackUiEvent("ui_low_credit_alert_toggled", {
        alert_enabled: payload.enabled,
        threshold_credits: payload.threshold_credits,
      });
      toaster.show("Automatic refill settings saved");
    },
  });

  refillControls.append(
    thresholdSelect,
    packSelect,
    capSelect,
    switchControl({
      checked: ar.enabled,
      label: "Enable automatic refill",
      onToggle: async (next) => {
        ar.enabled = next;
        const threshold = Number(thresholdSelect.value) || 250;
        await apiRequest("POST", "/api/v4/credits/autorefill", {
          enabled: next,
          threshold_credits: threshold,
          pack_sku: packSelect.value,
          monthly_cap_usd: Number(capSelect.value) || 500,
        });
        trackUiEvent("ui_low_credit_alert_toggled", {
          alert_enabled: next,
          threshold_credits: threshold,
        });
        toaster.show(next ? "Automatic refill enabled" : "Automatic refill turned off");
      },
    }),
    saveRefillBtn,
  );

  stack.appendChild(
    el(
      "section",
      { className: "card autorefill-card", "aria-label": "Automatic refill" },
      el(
        "div",
        { className: "section-head" },
        el("h2", { className: "t-16 w600" }, "Automatic refill"),
        el("p", { className: "t-13 secondary" }, "Optional top-up with a hard monthly spend cap so sandbox runs never pause mid-task."),
      ),
      refillControls,
    ),
  );

  // 5. Published Credit Cost Schedule (6+1 Rows)
  stack.appendChild(
    el(
      "section",
      { className: "section-block", "aria-label": "Published credit cost schedule" },
      el(
        "div",
        { className: "section-head" },
        el("h2", { className: "t-16 w600" }, "What each workflow costs"),
        el("p", { className: "t-13 secondary" }, "Predictable flat rates per workflow — never raw token surprises."),
      ),
      el(
        "div",
        { className: "card schedule-card" },
        PUBLISHED_COST_SCHEDULE.map((row) =>
          el(
            "div",
            { className: "schedule-row" },
            el(
              "div",
              { className: "section-head" },
              el("span", { className: "t-14 w500" }, row.label),
              el("span", { className: "t-12 secondary" }, row.detail),
            ),
            el("span", { className: "schedule-cost" }, row.cost),
          ),
        ),
      ),
    ),
  );

  // 6. Recent Receipts
  if (cred.receipts.length > 0) {
    stack.appendChild(
      el(
        "section",
        { className: "section-block", "aria-label": "Recent credit activity" },
        el("div", { className: "section-head" }, el("h2", { className: "t-16 w600" }, "Recent activity")),
        el(
          "div",
          { className: "card schedule-card" },
          cred.receipts.map((rc) =>
            el(
              "div",
              { className: "schedule-row" },
              el(
                "div",
                { className: "section-head" },
                el("span", { className: "t-14" }, rc.title),
                rc.created_at ? el("span", { className: "t-12 muted" }, formatRelativeTime(rc.created_at)) : null,
              ),
              rc.delta_credits !== null
                ? el(
                    "span",
                    { className: "schedule-cost" },
                    `${rc.delta_credits > 0 ? "+" : ""}${formatInt(rc.delta_credits)} Cr`,
                  )
                : null,
            ),
          ),
        ),
      ),
    );
  }

  // 7. Enterprise / Custom Volume Card
  stack.appendChild(
    el(
      "section",
      { className: "card enterprise-card", "aria-label": "Enterprise volume" },
      el(
        "div",
        { className: "section-head" },
        el("h2", { className: "t-15 w600" }, "Need annual invoicing, custom volume, or security review"),
        el("p", { className: "t-13 secondary" }, "Work directly with the founders on organization rollout and volume pricing."),
      ),
      el(
        "a",
        {
          href: "https://chinwag.sh/pricing?talk=1&source=local_ui#founders",
          target: "_blank",
          rel: "noopener noreferrer",
          className: "btn-secondary btn-sm",
          onClick: () => trackUiEvent("ui_founders_talk_clicked", { trigger_surface: "credits_tab" }),
        },
        el("span", null, "Talk to Founders →"),
      ),
    ),
  );

  container.appendChild(stack);
  root.appendChild(container);
}

// ── 9B · Persistent Left-Hand Delivery-2 Panel (v4.4 Phase 1) ────────────────

function isNarrowDrawerViewport() {
  return typeof window !== "undefined" && Number(window.innerWidth) > 0 && window.innerWidth < 960;
}

function isExpandedRailByDefault() {
  if (typeof window === "undefined") return true;
  const w = Number(window.innerWidth);
  return !Number.isFinite(w) || w === 0 || w >= 1440;
}

function isDelivery2RailExpanded() {
  if (isNarrowDrawerViewport()) return Boolean(state.d2DrawerOpen);
  if (typeof document === "undefined" || !document.documentElement) return true;
  const attr = document.documentElement.getAttribute("data-rail");
  if (attr === "expanded") return true;
  if (attr === "collapsed") return false;
  return isExpandedRailByDefault();
}

function syncDelivery2DrawerDom() {
  if (typeof document === "undefined" || !document.documentElement) return;
  const scrim = dom.d2DrawerScrim();
  const btn = dom.btnD2Drawer();
  const rail = dom.d2Rail();
  const narrow = isNarrowDrawerViewport();
  const open = Boolean(state.d2DrawerOpen && narrow);
  if (open) {
    document.documentElement.setAttribute("data-d2-drawer", "open");
  } else {
    document.documentElement.removeAttribute("data-d2-drawer");
  }
  if (scrim) scrim.hidden = !open;
  if (btn) btn.setAttribute("aria-expanded", open ? "true" : "false");
  if (rail) {
    if (narrow && !open) {
      rail.inert = true;
      rail.setAttribute("aria-hidden", "true");
    } else {
      rail.inert = false;
      rail.removeAttribute("aria-hidden");
    }
  }
}

function setDelivery2RailExpanded(nextExpanded, { persist = true, animate = true } = {}) {
  const expand = Boolean(nextExpanded);
  if (isNarrowDrawerViewport()) {
    if (expand && !state.d2DrawerOpen) {
      state.d2DrawerTriggerEl =
        typeof document !== "undefined" && document.activeElement
          ? document.activeElement
          : dom.btnD2Drawer();
    }
    state.d2DrawerOpen = expand;
    if (!expand && state.d2Popover) {
      state.d2Popover = null;
      state.d2FocusedSurface = null;
    }
    syncDelivery2DrawerDom();
    renderDelivery2Panel();
    if (expand) {
      requestAnimationFrame(() => {
        const input = dom.d2ComposerInput();
        if (input) input.focus();
      });
    } else {
      const restoreEl = state.d2DrawerTriggerEl || dom.btnD2Drawer();
      state.d2DrawerTriggerEl = null;
      if (restoreEl && typeof restoreEl.focus === "function") {
        restoreEl.focus();
      }
    }
    return Promise.resolve();
  }

  const prev = isDelivery2RailExpanded();
  if (!expand && state.d2Popover) {
    state.d2Popover = null;
    state.d2FocusedSurface = null;
  }
  const applyAttr = () => {
    if (typeof document !== "undefined" && document.documentElement) {
      document.documentElement.setAttribute("data-rail", expand ? "expanded" : "collapsed");
    }
    if (persist) {
      try {
        localStorage.setItem("chinwag.ui.rail", expand ? "expanded" : "collapsed");
      } catch (e) {}
    }
  };

  if (prev === expand || !animate) {
    applyAttr();
    renderDelivery2Panel();
    return Promise.resolve();
  }

  const railEl = dom.d2Rail();
  const trackEl = dom.d2Track();
  const spineEl = dom.d2Spine();
  const mainEl = dom.main();
  const p = Motion.animateRailToggle(railEl, trackEl, spineEl, mainEl, expand, applyAttr);
  renderDelivery2Panel();
  return Promise.resolve(p);
}

function toggleDelivery2Rail(trigger = "button") {
  const next = !isDelivery2RailExpanded();
  state.d2AutoCollapsedForSheet = false;
  state.d2PreSheetRail = null;
  trackUiEvent("ui_delivery2_rail_toggled", {
    next_state: next ? "expanded" : "collapsed",
    trigger,
  });
  return setDelivery2RailExpanded(next, { persist: true, animate: true });
}

function syncRailForOverlaySheet() {
  if (isNarrowDrawerViewport()) return;
  const vw = typeof window !== "undefined" && Number(window.innerWidth) > 0 ? Number(window.innerWidth) : 1440;
  const mainWithExpandedRail = vw - 320;
  if (state.openItemId && mainWithExpandedRail < 1120 && isDelivery2RailExpanded()) {
    state.d2PreSheetRail = "expanded";
    state.d2AutoCollapsedForSheet = true;
    setDelivery2RailExpanded(false, { persist: false, animate: true });
  } else if (state.d2AutoCollapsedForSheet && (!state.openItemId || mainWithExpandedRail >= 1120)) {
    const shouldRestore = state.d2PreSheetRail === "expanded";
    state.d2AutoCollapsedForSheet = false;
    state.d2PreSheetRail = null;
    if (shouldRestore) {
      setDelivery2RailExpanded(true, { persist: false, animate: true });
    }
  }
}

function isNodeInsideD2Rail(node) {
  let cur = node;
  while (cur) {
    if (cur.id === "d2-rail") return true;
    cur = cur.parentNode || null;
  }
  return false;
}

function focusDelivery2Composer() {
  const wasExpanded = isDelivery2RailExpanded();
  if (!wasExpanded) {
    setDelivery2RailExpanded(true, { persist: true, animate: true });
  }
  requestAnimationFrame(() => {
    const input = dom.d2ComposerInput();
    if (input) input.focus();
  });
}

function openD2Popover(kind, focusedSurface = null) {
  state.d2PopoverSeq += 1;
  if (state.d2Popover === kind && (!focusedSurface || state.d2FocusedSurface === focusedSurface)) {
    return closeD2Popover({ restoreFocus: true });
  }
  state.d2Popover = kind;
  state.d2FocusedSurface = focusedSurface;
  renderDelivery2Panel();
  return Promise.resolve();
}

async function closeD2Popover(options = {}) {
  const opts = options && typeof options === "object" ? options : {};
  const immediate = Boolean(opts.immediate);
  const restoreFocus = opts.restoreFocus !== undefined ? Boolean(opts.restoreFocus) : !immediate;
  if (!state.d2Popover) return;
  const prevKind = state.d2Popover;
  const seq = ++state.d2PopoverSeq;
  const track = dom.d2Track();
  const pop = track ? track.querySelector(".d2-pop") : null;
  if (!immediate && pop) {
    pop.dataset.state = "closing";
    await Motion.settled(pop);
    if (seq !== state.d2PopoverSeq) return;
  }
  state.d2Popover = null;
  state.d2FocusedSurface = null;
  renderDelivery2Panel();
  if (restoreFocus && typeof document !== "undefined") {
    const triggerId = prevKind === "history" ? "d2-btn-history" : "d2-btn-connections";
    const btn = document.getElementById(triggerId);
    if (btn) btn.focus();
  }
}

function applyDelivery2ServerPayload(rawD2, { forceInitial = false } = {}) {
  if (!rawD2 || typeof rawD2 !== "object") return false;
  const normalized = normalizeDelivery2State(rawD2, state.data);
  const incomingSeq = Math.max(1, Number(normalized.seq) || 1);
  const currentSeq = Number(state.d2LastCursorSeq) || 0;
  if (state.d2Loaded && !forceInitial && incomingSeq < currentSeq) {
    return false;
  }
  state.data.delivery2 = normalized;
  state.d2LastCursorSeq = Math.max(currentSeq, incomingSeq);
  state.d2Loaded = true;
  return true;
}

async function resumeDelivery2FromCursor() {
  const sinceSeq = Math.max(0, Number(state.d2LastCursorSeq) || 0);
  try {
    const raw = await apiRequest(
      "GET",
      `/api/v1/delivery2/state?since_seq=${encodeURIComponent(String(sinceSeq))}`,
    );
    if (!raw || typeof raw !== "object") return false;
    const liveSeq = Number(state.d2LastCursorSeq) || 0;
    const incomingSeq = Math.max(1, Number(raw.seq ?? raw.cursor_seq) || 1);
    if (state.d2Loaded && incomingSeq < liveSeq) {
      return false;
    }
    if (raw.unchanged && state.d2Loaded) {
      // Arbitrate strictly against the CURRENT live cursor immediately before committing!
      if (incomingSeq !== liveSeq || sinceSeq !== liveSeq) {
        return false;
      }
      if (raw.sync_radar && state.data.delivery2) {
        const norm = normalizeDelivery2State(raw, state.data);
        state.data.delivery2.sync_radar = norm.sync_radar;
        state.data.delivery2.status = norm.status;
        state.data.delivery2.status_label = norm.status_label;
        if (!state.d2Sending && !state.d2EditingMemId) {
          renderDelivery2Panel();
        }
      }
      return true;
    }
    const applied = applyDelivery2ServerPayload(raw);
    if (applied && !state.d2Sending && !state.d2EditingMemId) {
      renderDelivery2Panel();
    }
    return applied;
  } catch (e) {
    return false;
  }
}

async function startNewDelivery2Thread() {
  try {
    const res = await apiRequest("POST", "/api/v1/delivery2/thread", { action: "new" });
    if (res && res.state) applyDelivery2ServerPayload(res.state);
    state.d2Popover = null;
    state.d2ComposerError = null;
    renderDelivery2Panel();
    focusDelivery2Composer();
  } catch (err) {
    toaster.show(err && err.message ? err.message : "Could not create a new thread.");
  }
}

async function switchDelivery2Thread(threadId) {
  if (isAbsent(threadId)) return;
  try {
    const res = await apiRequest("POST", "/api/v1/delivery2/thread", {
      action: "switch",
      thread_id: threadId,
    });
    if (res && res.state) applyDelivery2ServerPayload(res.state);
    await closeD2Popover({ immediate: true, restoreFocus: false });
    renderDelivery2Panel();
  } catch (err) {
    toaster.show(err && err.message ? err.message : "Could not switch threads.");
  }
}

async function updateMorningFocus(patch) {
  const mf = state.data.delivery2.morning_focus;
  if (typeof patch.seen === "boolean") mf.seen = patch.seen;
  if (typeof patch.collapsed === "boolean") mf.collapsed = patch.collapsed;
  renderDelivery2Panel();
  try {
    const res = await apiRequest("POST", "/api/v1/delivery2/thread", {
      action: "morning_focus",
      ...patch,
    });
    if (res && res.state) applyDelivery2ServerPayload(res.state);
    renderDelivery2Panel();
  } catch (err) {
    toaster.show("Could not save Morning focus preference.");
  }
}

async function toggleSurfaceInThread(surfaceId, nextInThread) {
  const res = await apiRequest("POST", "/api/v1/delivery2/thread", {
    action: "connection",
    surface: surfaceId,
    in_thread: Boolean(nextInThread),
  });
  if (res && res.state) applyDelivery2ServerPayload(res.state);
  renderDelivery2Panel();
}

async function triggerSurfaceOAuthFlow(surfaceId, decision = "connect", cardNode = null, oauthMeta = null) {
  try {
    const reqBody = {
      kind: "oauth",
      surface: surfaceId,
      decision,
    };
    if (oauthMeta && typeof oauthMeta === "object") {
      if (!isAbsent(oauthMeta.oauth_state)) reqBody.oauth_state = String(oauthMeta.oauth_state);
      if (!isAbsent(oauthMeta.thread_id)) reqBody.thread_id = String(oauthMeta.thread_id);
    }
    const res = await apiRequest("POST", "/api/v1/delivery2/approval", reqBody);
    if (res && res.state) applyDelivery2ServerPayload(res.state);
    if (decision === "connect" || decision === "retry") {
      state.d2Popover = null;
      state.d2FocusedSurface = null;
      renderDelivery2Panel();
      const thr = typeof document !== "undefined" ? document.getElementById("d2-thread") : null;
      if (thr && typeof thr.scrollTo === "function") {
        thr.scrollTo({ top: thr.scrollHeight, behavior: "auto" });
      }
      return;
    }
    if (cardNode && (decision === "verify" || decision === "skip")) {
      const label = res && res.surface_label ? res.surface_label : surfaceId;
      const receiptText =
        decision === "verify"
          ? `${label} verified · 0 Cr while paused`
          : `Skipped ${label} sign-in for now · 0 Cr while paused`;
      await Motion.resolveBanner(cardNode, () => {
        clearNode(cardNode);
        cardNode.setAttribute("data-resolved", "");
        cardNode.append(ICONS.check(), el("span", null, receiptText));
      });
    }
    renderDelivery2Panel();
  } catch (err) {
    toaster.show(err && err.message ? err.message : "Connection verification failed.");
  }
}

async function submitDelivery2Approval(cardNode, btnEl, groupEl, entry, decision) {
  const approvalId = entry.approval_id || entry.id;
  const itemId = entry.item_id || approvalId;
  try {
    const wrapped = await Motion.guardAction(
      btnEl,
      () =>
        apiRequest("POST", "/api/v1/delivery2/approval", {
          id: approvalId,
          item_id: itemId,
          decision,
          is_sample: Boolean(entry.is_sample),
        }),
      { group: groupEl, busyLabel: decision === "approve" ? "Approving…" : "Denying…" },
    );
    if (!wrapped) return;
    const res = wrapped.value;
    const receipt =
      (res && res.receipt) ||
      (decision === "approve"
        ? "Approved by you · 0 Cr while paused"
        : "Denied by you · 0 Cr while paused");
    if (res && res.state) applyDelivery2ServerPayload(res.state);
    await Motion.resolveBanner(cardNode, () => {
      clearNode(cardNode);
      cardNode.setAttribute("data-resolved", "");
      cardNode.append(ICONS.check(), el("span", null, receipt));
    });
    renderDelivery2Panel();
    await refreshBootstrapQuietly();
  } catch (err) {
    toaster.show(err && err.message ? err.message : "Could not record approval decision.");
  }
}

async function mutateDelivery2Memory(memId, action, note = null) {
  try {
    const payload = { id: memId, action };
    if (note !== null) payload.note = note;
    const res = await apiRequest("POST", "/api/v1/delivery2/memory", payload);
    if (res && res.state) applyDelivery2ServerPayload(res.state);
    state.d2EditingMemId = null;
    state.d2EditingMemDraft = "";
    state.d2ComposerError = null;
    renderDelivery2Panel();
    return true;
  } catch (err) {
    const msg = err && err.message ? err.message : "Could not update workspace memory.";
    state.d2ComposerError = msg;
    toaster.show(msg);
    renderDelivery2Panel();
    return false;
  }
}

async function submitDelivery2Prompt(rawPrompt) {
  const prompt = String(rawPrompt ?? "").trim();
  if (!prompt || state.d2Sending) return false;

  const turnId = `turn-${uuidv4().slice(0, 8)}`;
  const abortCtrl = typeof AbortController !== "undefined" ? new AbortController() : null;
  state.d2ComposerError = null;
  state.d2Sending = true;
  state.d2ActiveTurnId = turnId;
  state.d2ActiveAbort = abortCtrl;
  renderDelivery2Panel();

  try {
    const res = await apiRequest(
      "POST",
      "/api/v1/delivery2/message",
      { prompt, turn_id: turnId },
      abortCtrl ? { signal: abortCtrl.signal } : null,
    );
    if (
      state.d2ActiveTurnId !== turnId ||
      (state.d2CancelledTurnIds && state.d2CancelledTurnIds.has(turnId))
    ) {
      return false;
    }

    state.d2ComposerDraft = "";
    state.d2ActiveAbort = null;
    if (res && res.state) {
      applyDelivery2ServerPayload(res.state);
    }

    const entry = res && res.entry && typeof res.entry === "object" ? res.entry : null;
    if (entry && entry.kind === "qa_card" && !entry.stopped && !isAbsent(entry.body)) {
      const fullBody = String(entry.body);
      state.d2StreamingEntryId = String(entry.id);
      state.d2StreamingText = "";
      renderDelivery2Panel();

      const streamer = Motion.createProportionalStreamer({
        onTick: (slice) => {
          state.d2StreamingText = slice;
          const bodyNode =
            typeof document !== "undefined"
              ? document.getElementById(`d2-qa-body-${entry.id}`)
              : null;
          if (bodyNode) {
            clearNode(bodyNode);
            appendChildren(bodyNode, renderHealedInlineMarkdown(slice));
          }
        },
        onFinish: () => {
          if (state.d2ActiveTurnId === turnId) {
            state.d2Sending = false;
            state.d2ActiveTurnId = null;
          }
          state.d2ActiveStreamer = null;
          state.d2StreamingEntryId = null;
          state.d2StreamingText = "";
          renderDelivery2Panel();
        },
      });

      if (streamer && typeof streamer.push === "function" && typeof streamer.markDone === "function") {
        state.d2ActiveStreamer = streamer;
        streamer.push(fullBody);
        streamer.markDone();
      } else {
        state.d2Sending = false;
        state.d2ActiveTurnId = null;
        state.d2StreamingEntryId = null;
        renderDelivery2Panel();
      }
    } else {
      state.d2Sending = false;
      state.d2ActiveTurnId = null;
      renderDelivery2Panel();
    }

    const thr = typeof document !== "undefined" ? document.getElementById("d2-thread") : null;
    if (thr && typeof thr.scrollTo === "function") {
      thr.scrollTo({ top: thr.scrollHeight, behavior: "auto" });
    }
    return true;
  } catch (err) {
    if (state.d2ActiveTurnId !== turnId) {
      return false;
    }
    state.d2Sending = false;
    state.d2ActiveTurnId = null;
    state.d2ActiveAbort = null;
    const msg = err && err.message ? err.message : "Delivery-2 could not process that message.";
    state.d2ComposerError = msg;
    toaster.show(msg);
    renderDelivery2Panel();
    return false;
  }
}

async function cancelDelivery2Turn() {
  if (!state.d2Sending && !state.d2ActiveStreamer) return false;
  const turnId = state.d2ActiveTurnId || "active";
  const stoppedEntryId = state.d2StreamingEntryId || null;
  const partialText = String(state.d2StreamingText || "");
  const truncatedLen = stoppedEntryId ? Array.from(partialText).length : 0;

  if (turnId && turnId !== "active" && state.d2CancelledTurnIds) {
    state.d2CancelledTurnIds.add(turnId);
    if (state.d2CancelledTurnIds.size > 64) {
      const oldest = state.d2CancelledTurnIds.values().next().value;
      if (oldest) state.d2CancelledTurnIds.delete(oldest);
    }
  }

  state.d2Sending = false;
  state.d2ActiveTurnId = null;
  if (state.d2ActiveAbort && typeof state.d2ActiveAbort.abort === "function") {
    try {
      state.d2ActiveAbort.abort();
    } catch (e) {}
  }
  state.d2ActiveAbort = null;
  if (state.d2ActiveStreamer && typeof state.d2ActiveStreamer.cancel === "function") {
    state.d2ActiveStreamer.cancel();
  }
  state.d2ActiveStreamer = null;

  if (state.data && state.data.delivery2 && Array.isArray(state.data.delivery2.entries)) {
    const healedPartial = healUnclosedInlineMarkdown(partialText);
    const clampedBody = stoppedEntryId && healedPartial.trim() ? healedPartial : "[Stopped]";
    const targetEntry = state.data.delivery2.entries.find(
      (e) =>
        e &&
        ((stoppedEntryId && String(e.id) === String(stoppedEntryId)) ||
          (!stoppedEntryId && turnId !== "active" && e.kind === "qa_card" && e.turn_id === turnId)),
    );
    if (targetEntry) {
      targetEntry.body = clampedBody;
      targetEntry.stopped = true;
      if (!stoppedEntryId || truncatedLen === 0) {
        targetEntry.sources = [];
      }
    }
  }

  state.d2StreamingEntryId = null;
  state.d2StreamingText = "";
  renderDelivery2Panel();

  try {
    const cancelPayload = {
      turn_id: turnId,
      truncated_len: truncatedLen,
    };
    if (stoppedEntryId) {
      cancelPayload.entry_id = stoppedEntryId;
    }
    const res = await apiRequest("POST", "/api/v1/delivery2/cancel", cancelPayload);
    if (res && res.state) applyDelivery2ServerPayload(res.state);
    renderDelivery2Panel();
  } catch (err) {
    // Keep clean stopped UI state even if network cancel races completion
  }
  return true;
}

function surfacePillState(surf) {
  if (!surf.authorized) return "needs_auth";
  if (surf.role_mode === "ambient_status_only") return "ambient";
  return "connected";
}

function buildDelivery2HistoryPopover(d2) {
  const todayList = Array.isArray(d2.history && d2.history.today) ? d2.history.today : [];
  const earlierList = Array.isArray(d2.history && d2.history.earlier) ? d2.history.earlier : [];

  const renderItem = (item) =>
    el(
      "button",
      {
        type: "button",
        className: "d2-history-item",
        "aria-current": item.active ? "true" : null,
        onClick: () => switchDelivery2Thread(item.id),
      },
      el("span", { className: "d2-history-title" }, item.title || "Thread"),
      el("span", { className: "d2-history-meta" }, item.status || item.updated_at || "Live"),
    );

  return el(
    "div",
    {
      className: "d2-history-pop d2-pop",
      id: "d2-history-popover",
      role: "dialog",
      "aria-label": "Recent threads",
      dataset: { state: "open" },
    },
    todayList.length > 0
      ? [el("div", { className: "d2-pop-group-label" }, "Today"), ...todayList.map(renderItem)]
      : null,
    earlierList.length > 0
      ? [el("div", { className: "d2-pop-group-label" }, "Earlier"), ...earlierList.map(renderItem)]
      : null,
  );
}

function buildDelivery2ConnectionsPopover(d2) {
  const surfaces = d2.sync_radar && Array.isArray(d2.sync_radar.surfaces) ? d2.sync_radar.surfaces : [];
  const rows = surfaces.map((surf) => {
    const isFocused = state.d2FocusedSurface === surf.id;
    let rightControl = null;
    if (surf.locked_in_thread) {
      rightControl = el("span", { className: "pill-fn" }, "Always in thread");
    } else if (!surf.authorized) {
      rightControl = actionBtn({
        label: "Connect",
        variant: "primary",
        size: "sm",
        onClick: () => triggerSurfaceOAuthFlow(surf.id, "connect"),
      });
    } else {
      rightControl = switchControl({
        checked: Boolean(surf.in_thread),
        label: `Include ${surf.label} in this thread`,
        disabled: false,
        onToggle: (next) => toggleSurfaceInThread(surf.id, next),
      });
    }

    return el(
      "div",
      {
        className: "d2-conn-row",
        dataset: {
          surface: surf.id,
          focused: isFocused ? "true" : null,
        },
      },
      el(
        "div",
        { className: "d2-conn-row-top" },
        el("span", { className: "d2-conn-name" }, surf.label),
        rightControl,
      ),
      el("div", { className: "d2-conn-auth" }, surf.auth_status),
      surf.policy_note ? el("div", { className: "d2-conn-policy" }, surf.policy_note) : null,
    );
  });

  return el(
    "div",
    {
      className: "d2-conn-pop d2-pop",
      id: "d2-connections-popover",
      role: "dialog",
      "aria-label": "Connections",
      dataset: { state: "open" },
    },
    el(
      "div",
      { className: "d2-conn-head" },
      el("span", { className: "d2-conn-title" }, "Connections"),
      el("span", { className: "d2-conn-sub" }, "Account auth · In thread"),
    ),
    el("div", { className: "d2-conn-list" }, rows),
    el(
      "div",
      { className: "d2-conn-foot" },
      el(
        "a",
        {
          href: safeChinwagOutboundUrl(
            d2.links && d2.links.security_url,
            "https://chinwag.sh/security",
          ),
          target: "_blank",
          rel: "noopener noreferrer",
          className: "d2-conn-link",
        },
        "Security ↗",
      ),
      el(
        "a",
        {
          href: safeChinwagOutboundUrl(
            d2.links && d2.links.founders_url,
            "https://chinwag.sh/pricing?talk=1&source=local_ui#founders",
          ),
          target: "_blank",
          rel: "noopener noreferrer",
          className: "d2-conn-link",
        },
        "Talk to Founders ↗",
      ),
    ),
  );
}

function renderDelivery2Entry(entry) {
  const kind = entry.kind;

  if (kind === "user_message") {
    return el("div", { className: "d2-user-msg", dataset: { entryId: entry.id } }, entry.body || "");
  }

  if (kind === "cancel_receipt") {
    return el(
      "div",
      { className: "d2-cancel-receipt", dataset: { entryId: entry.id } },
      entry.receipt || "Reply stopped by you · 0 Cr",
    );
  }

  if (kind === "run_card") {
    const runId = String(entry.run_id || "run-local-1");
    const steps = Array.isArray(entry.steps) && entry.steps.length === 12
      ? entry.steps
      : buildDefaultStepLadder(10, Boolean(entry.completed));
    const expanded = state.d2ExpandedSteps.has(entry.id);
    const diffHash =
      entry.diff_target_id && entry.diff_target_id !== "sample-walkthrough"
        ? `#diff/${encodeURIComponent(entry.diff_target_id)}`
        : "#walkthrough";

    const disclosureBody = el(
      "div",
      {
        className: "d2-disclosure-body",
        "aria-hidden": expanded ? "false" : "true",
        dataset: { open: expanded ? "true" : "false" },
      },
      el(
        "div",
        { className: "d2-disclosure-inner" },
        el(
          "div",
          { className: "d2-steps-list" },
          steps.map((st) =>
            el(
              "div",
              { className: "d2-step-row", dataset: { state: st.state || "pending" } },
              el("span", null, st.display || `${st.num} · ${st.label}`),
              el(
                "span",
                null,
                st.state === "done"
                  ? "Done"
                  : st.state === "waiting"
                    ? "Paused · 0 Cr"
                    : st.state === "active"
                      ? "Running"
                      : "",
              ),
            ),
          ),
        ),
      ),
    );
    disclosureBody.inert = !expanded;

    const stepsBtn = el(
      "button",
      {
        type: "button",
        className: "d2-disclosure-btn",
        "aria-expanded": expanded ? "true" : "false",
        onClick: () => {
          const next = !state.d2ExpandedSteps.has(entry.id);
          if (next) state.d2ExpandedSteps.add(entry.id);
          else state.d2ExpandedSteps.delete(entry.id);
          stepsBtn.setAttribute("aria-expanded", next ? "true" : "false");
          disclosureBody.dataset.open = next ? "true" : "false";
          disclosureBody.inert = !next;
          disclosureBody.setAttribute("aria-hidden", next ? "false" : "true");
        },
      },
      ICONS.chevronRight(),
      el("span", null, "Steps"),
    );

    return el(
      "article",
      {
        className: "d2-card d2-run-card",
        dataset: { entryId: entry.id, runId },
      },
      el(
        "div",
        { className: "d2-run-head" },
        el("span", { className: "d2-run-title" }, entry.title || "Scoped task"),
        el("span", { className: "d2-step-badge" }, entry.current_step_display || "10 · Waiting for you"),
      ),
      el(
        "div",
        { className: "d2-seg-bar", "aria-hidden": "true" },
        steps.map((st) => el("span", { className: "d2-seg", dataset: { state: st.state || "pending" } })),
      ),
      el(
        "div",
        { className: "d2-run-meta" },
        el("span", { className: "d2-verb-summary" }, entry.verb_summary || "Searched 8 items · Read 4 files · Ran 3 checks"),
        el(
          "div",
          { className: "d2-head-actions" },
          stepsBtn,
          el(
            "button",
            {
              type: "button",
              className: "d2-micro-btn",
              onClick: () => navigate(diffHash, "delivery2_run_card"),
            },
            "Diff →",
          ),
        ),
      ),
      disclosureBody,
    );
  }

  if (kind === "approval_card") {
    const cardNode = el("article", {
      className: "d2-card d2-hitl-card",
      dataset: {
        entryId: entry.id,
        approvalId: entry.approval_id || entry.id,
        runId: entry.item_id || "run-local-1",
      },
    });
    if (entry.settled) {
      cardNode.setAttribute("data-resolved", "");
      cardNode.append(
        ICONS.check(),
        el("span", null, entry.settled_receipt || "Approved by you · 0 Cr while paused"),
      );
      return cardNode;
    }

    const actionsGroup = el("div", { className: "d2-hitl-actions" });
    const approveBtn = actionBtn({
      label: "Approve & merge",
      variant: "primary",
      size: "sm",
      extraClass: "d2-hitl-primary",
      onClick: () => submitDelivery2Approval(cardNode, approveBtn, actionsGroup, entry, "approve"),
    });
    const denyBtn = actionBtn({
      label: "Deny",
      variant: "secondary",
      size: "sm",
      onClick: () => submitDelivery2Approval(cardNode, denyBtn, actionsGroup, entry, "deny"),
    });
    const viewDiffBtn = actionBtn({
      label: "View diff →",
      variant: "ghost",
      size: "sm",
      onClick: () => navigate(entry.diff_hash || "#walkthrough", "delivery2_hitl"),
    });
    actionsGroup.append(approveBtn, denyBtn, viewDiffBtn);

    cardNode.append(
      el(
        "div",
        { className: "d2-hitl-top" },
        el("span", { className: "d2-hitl-status" }, entry.status_badge || "Waiting for you"),
        el("span", { className: "d2-zero-cr-pill" }, entry.pause_badge || "Paused · 0 Cr"),
        entry.estimate_badge ? el("span", { className: "d2-zero-cr-pill" }, entry.estimate_badge) : null,
      ),
      el("div", { className: "d2-hitl-question" }, renderHealedInlineMarkdown(entry.question || entry.title || "")),
      el(
        "div",
        { className: "d2-hitl-proof" },
        entry.diff_summary ? el("span", null, entry.diff_summary) : null,
        entry.check_proof ? el("span", null, entry.check_proof) : null,
      ),
      actionsGroup,
    );
    return cardNode;
  }

  if (kind === "oauth_card") {
    const cardNode = el("article", {
      className: "d2-card d2-oauth-card",
      dataset: { entryId: entry.id, surface: entry.surface || "linear" },
    });
    if (entry.settled) {
      cardNode.setAttribute("data-resolved", "");
      cardNode.append(
        ICONS.check(),
        el("span", null, entry.settled_receipt || "Connection updated · 0 Cr while paused"),
      );
      return cardNode;
    }

    const safeChallengeUrl = safeChinwagOutboundUrl(
      entry.challenge_url,
      "https://chinwag.sh/open",
    );
    const activeThreadId =
      entry.thread_id ||
      (state.data && state.data.delivery2 && state.data.delivery2.active_thread_id) ||
      "thr-main";

    const actions = el(
      "div",
      { className: "d2-hitl-actions" },
      el(
        "a",
        {
          href: safeChallengeUrl,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "btn-primary btn-sm",
        },
        el("span", { className: "btn-label" }, `Connect ${entry.surface_label || "account"} ↗`),
      ),
      actionBtn({
        label: "Re-check connection",
        variant: "secondary",
        size: "sm",
        onClick: () =>
          triggerSurfaceOAuthFlow(entry.surface, "verify", cardNode, {
            oauth_state: entry.oauth_state || "",
            thread_id: activeThreadId,
          }),
      }),
      actionBtn({
        label: "Skip",
        variant: "ghost",
        size: "sm",
        onClick: () => triggerSurfaceOAuthFlow(entry.surface, "skip", cardNode),
      }),
    );

    cardNode.append(
      el(
        "div",
        { className: "d2-hitl-top" },
        el("span", { className: "d2-hitl-status" }, entry.title || "Sign in required"),
        el("span", { className: "d2-zero-cr-pill" }, entry.pause_badge || "Paused · 0 Cr"),
      ),
      el("div", { className: "d2-hitl-proof" }, entry.body || "Paused safely at 0 Cr until sign-in finishes."),
      actions,
    );
    return cardNode;
  }

  if (kind === "memory_card") {
    const memId = String(entry.memory_id || "mem_default");
    const cardNode = el("div", {
      className: "d2-mem-card",
      dataset: { entryId: entry.id, memoryId: memId },
    });

    if (state.d2EditingMemId === memId) {
      const inputEl = el("input", {
        type: "text",
        className: "input d2-mem-edit-input",
        value: state.d2EditingMemDraft,
        "aria-label": "Edit saved memory note",
        dataset: { memEditInput: memId },
        onInput: (ev) => {
          state.d2EditingMemDraft = ev.target.value;
        },
        onKeydown: (ev) => {
          if (ev.key === "Enter") {
            ev.preventDefault();
            if (typeof ev.stopPropagation === "function") ev.stopPropagation();
            mutateDelivery2Memory(memId, "edit", state.d2EditingMemDraft);
          } else if (ev.key === "Escape") {
            ev.preventDefault();
            if (typeof ev.stopPropagation === "function") ev.stopPropagation();
            state.d2EditingMemId = null;
            state.d2EditingMemDraft = "";
            renderDelivery2Panel();
          }
        },
      });
      cardNode.appendChild(
        el(
          "div",
          { className: "d2-mem-edit-row" },
          inputEl,
          actionBtn({
            label: "Save",
            variant: "primary",
            size: "sm",
            onClick: () => mutateDelivery2Memory(memId, "edit", state.d2EditingMemDraft),
          }),
          actionBtn({
            label: "Cancel",
            variant: "ghost",
            size: "sm",
            onClick: () => {
              state.d2EditingMemId = null;
              state.d2EditingMemDraft = "";
              renderDelivery2Panel();
            },
          }),
        ),
      );
      return cardNode;
    }

    if (entry.status === "undone") {
      cardNode.appendChild(
        el(
          "div",
          { className: "d2-mem-line" },
          el("span", { className: "muted" }, "Removed saved note"),
          el(
            "div",
            { className: "d2-mem-actions" },
            el(
              "button",
              {
                type: "button",
                className: "d2-micro-btn",
                onClick: () => mutateDelivery2Memory(memId, "restore"),
              },
              "Restore",
            ),
          ),
        ),
      );
      return cardNode;
    }

    cardNode.appendChild(
      el(
        "div",
        { className: "d2-mem-line" },
        el(
          "span",
          { className: "d2-mem-text" },
          el("strong", { className: "w600" }, "Saved: "),
          entry.note || "",
        ),
        el(
          "div",
          { className: "d2-mem-actions" },
          el(
            "button",
            {
              type: "button",
              className: "d2-micro-btn",
              onClick: async () => {
                await Motion.dipSwap(cardNode, () => {
                  state.d2EditingMemId = memId;
                  state.d2EditingMemDraft = String(entry.note || "");
                  renderDelivery2Panel();
                });
                const track = dom.d2Track();
                if (track) {
                  const inputs = Array.from(track.querySelectorAll(".d2-mem-edit-input"));
                  const inp =
                    inputs.find((n) => n.dataset && n.dataset.memEditInput === memId) ||
                    inputs[0] ||
                    null;
                  if (inp && typeof inp.focus === "function") {
                    inp.focus();
                  }
                }
              },
            },
            "Edit",
          ),
          el(
            "button",
            {
              type: "button",
              className: "d2-micro-btn",
              onClick: () => mutateDelivery2Memory(memId, "undo"),
            },
            "Undo",
          ),
        ),
      ),
    );
    return cardNode;
  }

  // Card 3C: Grounded Board/Repo Q&A Card + Collapsed Provenance
  const sources = Array.isArray(entry.sources) ? entry.sources : [];
  const srcOpen = state.d2ExpandedSources.has(entry.id);
  const shownBody =
    state.d2StreamingEntryId === entry.id ? state.d2StreamingText : String(entry.body || "");

  let provToggle = null;
  let provDisclosure = null;
  if (sources.length > 0) {
    provDisclosure = el(
      "div",
      {
        className: "d2-disclosure-body",
        "aria-hidden": srcOpen ? "false" : "true",
        dataset: { open: srcOpen ? "true" : "false" },
      },
      el(
        "div",
        { className: "d2-disclosure-inner" },
        el(
          "div",
          { className: "d2-prov-list" },
          sources.map((src) =>
            el(
              "button",
              {
                type: "button",
                className: "d2-prov-link",
                onClick: () => navigate(src.hash || "#inbox", "delivery2_provenance"),
              },
              el("span", { className: "truncate" }, src.label || "Workspace source"),
              el("span", { className: "muted" }, "Open →"),
            ),
          ),
        ),
      ),
    );
    provDisclosure.inert = !srcOpen;

    provToggle = el(
      "button",
      {
        type: "button",
        className: "d2-disclosure-btn",
        "aria-expanded": srcOpen ? "true" : "false",
        onClick: () => {
          const next = !state.d2ExpandedSources.has(entry.id);
          if (next) state.d2ExpandedSources.add(entry.id);
          else state.d2ExpandedSources.delete(entry.id);
          provToggle.setAttribute("aria-expanded", next ? "true" : "false");
          provDisclosure.dataset.open = next ? "true" : "false";
          provDisclosure.inert = !next;
          provDisclosure.setAttribute("aria-hidden", next ? "false" : "true");
        },
      },
      ICONS.chevronRight(),
      el("span", null, `Verified sources · ${sources.length} ${sources.length === 1 ? "item" : "items"}`),
    );
  }

  return el(
    "article",
    { className: "d2-card d2-qa-card", dataset: { entryId: entry.id } },
    el(
      "div",
      { className: "d2-qa-head" },
      el("span", { className: "d2-qa-author" }, entry.author || "Delivery-2"),
    ),
    el("div", { className: "d2-qa-body", id: `d2-qa-body-${entry.id}` }, renderHealedInlineMarkdown(shownBody)),
    provToggle,
    provDisclosure,
  );
}

function renderDelivery2Panel() {
  const track = dom.d2Track();
  const spine = dom.d2Spine();
  const fixedToggle = dom.d2RailToggleFixed();
  if (fixedToggle) {
    const expandedNow = isDelivery2RailExpanded();
    fixedToggle.setAttribute("aria-expanded", expandedNow ? "true" : "false");
    fixedToggle.setAttribute(
      "aria-label",
      expandedNow ? "Collapse Delivery-2 panel (⌘B)" : "Expand Delivery-2 panel (⌘B)",
    );
    fixedToggle.setAttribute(
      "title",
      expandedNow ? "Collapse Delivery-2 (⌘B)" : "Expand Delivery-2 (⌘B)",
    );
  }
  if (!track && !spine) return;

  const d2 = state.data.delivery2 || createDefaultDelivery2State();
  const prevActiveId =
    typeof document !== "undefined" && document.activeElement ? document.activeElement.id : null;

  const isReconnecting = state.transportMode === "poll_fallback" && state.reconnectCount > 0;
  const liveWord = state.d2Sending
    ? "Working"
    : isReconnecting
      ? "Reconnecting…"
      : d2.status_label || "Live";
  const statusTone = state.d2Sending
    ? "working"
    : isReconnecting || d2.status === "waiting_for_you"
      ? "warning"
      : "ok";

  const surfaces = d2.sync_radar && Array.isArray(d2.sync_radar.surfaces) ? d2.sync_radar.surfaces : [];
  const activeRunEntry = (d2.entries || []).find((e) => e && e.kind === "run_card") || null;
  const spineSteps =
    activeRunEntry && Array.isArray(activeRunEntry.steps) && activeRunEntry.steps.length === 12
      ? activeRunEntry.steps
      : buildDefaultStepLadder(10, false);

  // 1. Render 44px Vertical Spine (.d2-spine)
  if (spine) {
    clearNode(spine);
    spine.append(
      el(
        "div",
        { className: "d2-spine-top" },
        el(
          "button",
          {
            type: "button",
            className: "d2-rail-toggle",
            id: "d2-spine-toggle",
            "aria-expanded": "false",
            "aria-controls": "d2-rail",
            "aria-label": "Expand Delivery-2 panel (⌘B)",
            title: "Expand Delivery-2 (⌘B)",
            onClick: () => toggleDelivery2Rail("spine_toggle"),
          },
          ICONS.rail(),
        ),
        el(
          "div",
          { className: "d2-spine-dots", "aria-label": "Connected surfaces" },
          surfaces.map((s) =>
            el("span", {
              className: "d2-spine-dot",
              title: `${s.label}: ${s.auth_status}`,
              dataset: { state: surfacePillState(s) },
            }),
          ),
        ),
      ),
      el(
        "div",
        { className: "d2-spine-ladder", "aria-label": "Active run progress" },
        spineSteps.map((st) =>
          el("span", {
            className: "d2-spine-seg",
            title: st.display,
            dataset: { stepState: st.state || "pending" },
          }),
        ),
      ),
      el(
        "div",
        { className: "d2-spine-bottom" },
        el(
          "button",
          {
            type: "button",
            className: "d2-spine-compose",
            id: "d2-spine-compose",
            "aria-label": "Ask Delivery-2 (⌘J)",
            title: "Ask Delivery-2 (⌘J)",
            onClick: () => focusDelivery2Composer(),
          },
          ICONS.compose(),
        ),
      ),
    );
  }

  if (!track) return;
  clearNode(track);

  // 2. Render Zone 1: Header & 4-Surface <200ms Sync Radar (Zero voice stubs in Phase 1)
  const liveDot = el("span", {
    className: "d2-status-dot",
    "aria-hidden": "true",
    dataset: {
      tone: statusTone !== "ok" ? statusTone : null,
      live: state.d2Sending || statusTone === "ok" ? true : null,
    },
  });
  if (state.d2Sending || statusTone === "ok") {
    Motion.observeLoop(liveDot);
  }

  const zoneHead = el(
    "header",
    { className: "d2-zone-head" },
    el(
      "div",
      { className: "d2-head" },
      el(
        "button",
        {
          type: "button",
          className: "d2-rail-toggle",
          id: "d2-head-toggle",
          "aria-expanded": "true",
          "aria-controls": "d2-rail",
          "aria-label": "Collapse Delivery-2 panel (⌘B)",
          title: "Toggle Delivery-2 (⌘B)",
          onClick: () => toggleDelivery2Rail("header_toggle"),
        },
        ICONS.rail(),
      ),
      el(
        "div",
        { className: "d2-title-group" },
        el("span", { className: "d2-title" }, "Delivery-2"),
        el(
          "span",
          { className: "d2-status-wrap" },
          liveDot,
          el("span", { className: "d2-status-word", id: "d2-status-word" }, liveWord),
        ),
      ),
      el(
        "div",
        { className: "d2-head-actions" },
        el(
          "button",
          {
            type: "button",
            className: "d2-icon-btn",
            id: "d2-btn-new-thread",
            "aria-label": "New thread",
            title: "New thread",
            onClick: () => startNewDelivery2Thread(),
          },
          ICONS.plus(),
        ),
        el(
          "button",
          {
            type: "button",
            className: "d2-icon-btn",
            id: "d2-btn-history",
            "aria-haspopup": "dialog",
            "aria-expanded": state.d2Popover === "history" ? "true" : "false",
            "aria-label": "Recent threads",
            title: "Recent threads",
            onClick: () => openD2Popover("history"),
          },
          ICONS.clock(),
        ),
        el(
          "button",
          {
            type: "button",
            className: "d2-icon-btn",
            id: "d2-btn-collapse",
            "aria-label": "Collapse Delivery-2 (⌘B)",
            title: "Collapse (⌘B)",
            onClick: () => setDelivery2RailExpanded(false, { persist: true, animate: true }),
          },
          ICONS.chevronLeft(),
        ),
      ),
    ),
    el(
      "div",
      { className: "d2-sync-radar", "aria-label": "Workspace sync radar" },
      el(
        "div",
        { className: "d2-sync-pills" },
        surfaces.map((surf) =>
          el(
            "button",
            {
              type: "button",
              className: "d2-sync-pill",
              dataset: {
                surface: surf.id,
                state: surfacePillState(surf),
              },
              title: `${surf.label} · ${surf.auth_status}`,
              onClick: () => openD2Popover("connections", surf.id),
            },
            el("span", { className: "d2-sync-dot", "aria-hidden": "true" }),
            el("span", null, surf.label),
          ),
        ),
      ),
      el("span", { className: "d2-sync-latency" }, (d2.sync_radar && d2.sync_radar.latency_label) || "<200ms"),
    ),
    state.d2Popover === "history" ? buildDelivery2HistoryPopover(d2) : null,
  );

  // 3. Render Zone 2: Morning Focus 3-Row Deterministic Digest Card
  const mf = d2.morning_focus || { seen: false, collapsed: false, rows: [] };
  const zoneDigest = el(
    "section",
    { className: "d2-zone-digest", "aria-label": "Morning focus" },
    el(
      "div",
      { className: "d2-digest" },
      el(
        "div",
        { className: "d2-digest-head" },
        el(
          "span",
          { className: "d2-digest-title" },
          "Morning focus",
          mf.seen ? el("span", { className: "d2-digest-seen-tag" }, "Seen") : null,
        ),
        el(
          "div",
          { className: "d2-digest-controls" },
          !mf.seen
            ? el(
                "button",
                {
                  type: "button",
                  className: "d2-micro-btn",
                  id: "d2-btn-morning-seen",
                  onClick: () => updateMorningFocus({ seen: true }),
                },
                "Seen",
              )
            : null,
          el(
            "button",
            {
              type: "button",
              className: "d2-micro-btn",
              id: "d2-btn-morning-toggle",
              "aria-expanded": mf.collapsed ? "false" : "true",
              onClick: () => updateMorningFocus({ collapsed: !mf.collapsed }),
            },
            mf.collapsed ? "Show" : "Hide",
          ),
        ),
      ),
      !mf.collapsed
        ? el(
            "div",
            { className: "d2-digest-rows" },
            (mf.rows || []).map((row) =>
              el(
                "button",
                {
                  type: "button",
                  className: "d2-digest-row",
                  dataset: { targetTab: row.target_tab },
                  onClick: () => navigate(row.hash || `#${row.target_tab}`, "delivery2_morning_focus"),
                },
                el(
                  "span",
                  { className: "d2-digest-row-left" },
                  el("span", { className: "d2-digest-count" }, row.badge),
                  el("span", { className: "d2-digest-label" }, row.label),
                ),
                el("span", { className: "d2-digest-cta" }, `${row.cta} →`),
              ),
            ),
          )
        : null,
    ),
  );

  // 4. Render Zone 3: Cursor-Resumed Durable Stream Thread (role="log")
  const entries = Array.isArray(d2.entries) ? d2.entries : [];
  const zoneThread = el(
    "div",
    {
      className: "d2-thread",
      id: "d2-thread",
      role: "log",
      "aria-live": "polite",
      "aria-label": "Delivery-2 thread",
      dataset: { cursorSeq: String(d2.seq || 1) },
    },
    entries.length > 0
      ? entries.map((entry) => renderDelivery2Entry(entry))
      : el(
          "div",
          { className: "d2-card d2-qa-card" },
          el("div", { className: "d2-qa-author" }, "Delivery-2"),
          el(
            "div",
            { className: "d2-qa-body" },
            "Fresh thread ready. Ask Delivery-2 to scope a change, explain a diff, or save a repository note with ",
            el("code", { className: "pill-code" }, "Remember:"),
            ".",
          ),
        ),
  );

  // 5. Render Zone 4: Composer, Steering Chips & 2-Axis + Connections Popover
  const chips = Array.isArray(d2.steering_chips) ? d2.steering_chips : [];
  const composerInput = el("textarea", {
    id: "d2-composer-input",
    className: "d2-composer-input",
    rows: "2",
    placeholder: "Ask Delivery-2 to scope, explain, or steer… (⌘J)",
    "aria-label": "Ask Delivery-2",
    value: state.d2ComposerDraft,
    onInput: (ev) => {
      state.d2ComposerDraft = ev.target.value;
      if (state.d2ComposerError) state.d2ComposerError = null;
    },
    onKeydown: (ev) => {
      if (ev.key === "Enter" && !ev.shiftKey && !ev.metaKey && !ev.ctrlKey) {
        ev.preventDefault();
        submitDelivery2Prompt(composerInput.value);
      }
    },
  });

  const actionButton = state.d2Sending
    ? el(
        "button",
        {
          type: "button",
          id: "d2-btn-stop",
          className: "d2-stop-btn",
          "aria-label": "Stop Delivery-2 reply (⌘.)",
          title: "Stop reply (⌘.)",
          onClick: () => cancelDelivery2Turn(),
        },
        ICONS.stop(),
        el("span", null, "Stop"),
        el("kbd", { className: "keycap", "aria-hidden": "true" }, "⌘."),
      )
    : el(
        "button",
        {
          type: "button",
          id: "d2-btn-send",
          className: "d2-send-btn",
          "aria-label": "Send message to Delivery-2",
          onClick: () => submitDelivery2Prompt(composerInput.value),
        },
        ICONS.send(),
        el("span", null, "Send"),
      );

  const zoneComposer = el(
    "footer",
    { className: "d2-zone-composer" },
    state.d2Popover === "connections" ? buildDelivery2ConnectionsPopover(d2) : null,
    el(
      "div",
      { className: "d2-chip-strip", "aria-label": "Quick questions" },
      chips.map((ch) =>
        el(
          "button",
          {
            type: "button",
            className: "d2-chip",
            onClick: () => {
              state.d2ComposerDraft = ch.prompt;
              submitDelivery2Prompt(ch.prompt);
            },
          },
          ch.label,
        ),
      ),
    ),
    el(
      "div",
      { className: "d2-composer-box" },
      composerInput,
      el(
        "div",
        { className: "d2-composer-foot" },
        el(
          "button",
          {
            type: "button",
            id: "d2-btn-connections",
            className: "d2-conn-btn",
            "aria-haspopup": "dialog",
            "aria-expanded": state.d2Popover === "connections" ? "true" : "false",
            onClick: () => openD2Popover("connections"),
          },
          "+ Connections",
        ),
        el("div", { className: "d2-composer-right" }, actionButton),
      ),
    ),
    state.d2ComposerError
      ? el("div", { className: "d2-composer-error", role: "alert" }, state.d2ComposerError)
      : null,
  );

  track.append(zoneHead, zoneDigest, zoneThread, zoneComposer);

  if (prevActiveId === "d2-composer-input") {
    composerInput.focus();
  }
}

function bounceToDelivery2Run(runId = null) {
  setDelivery2RailExpanded(true, { persist: true, animate: true });
  renderDelivery2Panel();
  const track = dom.d2Track();
  let targetCard = null;
  if (track) {
    const cards = Array.from(track.querySelectorAll(".d2-card"));
    if (runId) {
      targetCard = cards.find((c) => c.dataset && c.dataset.runId === runId) || null;
    }
    if (!targetCard) {
      targetCard = track.querySelector(".d2-run-card") || cards[0] || null;
    }
  }
  if (targetCard) {
    Motion.flashDeliveryCard(targetCard);
  }
  const input = dom.d2ComposerInput();
  if (input) input.focus();
  trackUiEvent("ui_delivery2_deeplink_bounced", {
    target_found: Boolean(targetCard),
  });
  return Boolean(targetCard);
}

// ── 10 · Deep-Link Hash Router, Keyboard Shortcuts & Live Stream ─────────────

function parseHashRoute(hashStr) {
  const raw = String(hashStr || "").replace(/^#\/?/, "").trim();
  if (!raw || raw === "inbox") {
    return { view: "inbox", itemId: null, entryRoute: "inbox", focusDelivery2: false, runId: null };
  }
  if (raw === "delivery2" || raw === "focus=delivery2") {
    return { view: state.view || "inbox", itemId: null, entryRoute: "delivery2", focusDelivery2: true, runId: null };
  }
  if (raw.includes("focus=delivery2") || raw.startsWith("run=")) {
    let view = state.view || "inbox";
    let runId = null;
    for (const part of raw.split("&")) {
      const seg = part.trim();
      if (seg === "inbox" || seg === "board" || seg === "agents" || seg === "credits") {
        view = seg;
      } else if (seg.startsWith("run=")) {
        runId = decodeURIComponent(seg.slice(4)) || null;
      }
    }
    return { view, itemId: null, entryRoute: "delivery2", focusDelivery2: true, runId };
  }
  if (raw === "walkthrough") {
    return { view: "inbox", itemId: "sample-walkthrough", entryRoute: "walkthrough", focusDelivery2: false, runId: null };
  }
  if (raw.startsWith("diff/")) {
    const id = decodeURIComponent(raw.slice(5));
    return { view: "inbox", itemId: id || null, entryRoute: "diff", focusDelivery2: false, runId: null };
  }
  if (raw.startsWith("inbox/")) {
    const id = decodeURIComponent(raw.slice(6));
    return { view: "inbox", itemId: id || null, entryRoute: "diff", focusDelivery2: false, runId: null };
  }
  if (raw === "board") return { view: "board", itemId: null, entryRoute: "board", focusDelivery2: false, runId: null };
  if (raw === "agents" || raw === "rules") {
    return { view: "agents", itemId: null, entryRoute: "agents", focusDelivery2: false, runId: null };
  }
  if (raw === "credits" || raw === "billing") {
    return { view: "credits", itemId: null, entryRoute: "credits", focusDelivery2: false, runId: null };
  }
  return { view: "inbox", itemId: null, entryRoute: "inbox", focusDelivery2: false, runId: null };
}

function navigate(hash, navTrigger = "top_tab") {
  if (typeof window === "undefined") return;
  if (window.location.hash === hash) {
    applyRouteFromLocation(navTrigger);
  } else {
    pendingNavTrigger = navTrigger;
    window.location.hash = hash;
  }
}

let pendingNavTrigger = "hash_change";

function applyRouteFromLocation(trigger = pendingNavTrigger) {
  pendingNavTrigger = "hash_change";
  const popLayer = dom.popoverLayer();
  if (popLayer && !popLayer.hidden) {
    closePopover({ immediate: true });
  }
  const parsed = parseHashRoute(typeof window !== "undefined" ? window.location.hash : "#inbox");
  const prevView = state.view;
  const viewChanged = state.booted && prevView !== parsed.view;

  state.view = parsed.view;
  state.openItemId = parsed.itemId;
  if (parsed.itemId) state.sheetOpenedAtMs = Date.now();

  if (!parsed.focusDelivery2) {
    syncRailForOverlaySheet();
  }

  if (viewChanged) {
    trackUiEvent("ui_view_navigated", {
      previous_view: prevView,
      view: parsed.view,
      nav_trigger: trigger,
    });
  }
  syncHeaderChrome();
  renderCurrentView();

  if (parsed.focusDelivery2) {
    bounceToDelivery2Run(parsed.runId);
  }
}

function renderCurrentView() {
  const root = dom.viewRoot();
  if (!root) return;
  inboxFilterIndicator.destroy();
  clearNode(root);
  if (state.view === "board") {
    renderBoardView(root);
  } else if (state.view === "agents") {
    renderAgentsView(root);
  } else if (state.view === "credits") {
    renderCreditsView(root);
  } else {
    renderInboxView(root);
  }
  Motion.contentIn(root);
}

// Keyboard navigation: Cmd+B, Cmd+J, Cmd+., Cmd+K, region-scoped Cmd+Enter, Esc, j/k, g+i/b/a/c
let chordPrefixGAt = 0;

function isEditableTarget(target) {
  if (!target || typeof target.tagName !== "string") return false;
  const tag = target.tagName.toUpperCase();
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || Boolean(target.isContentEditable);
}

function findAncestorWithClass(node, cls) {
  let cur = node;
  while (cur) {
    if (cur.className && typeof cur.className === "string") {
      const parts = cur.className.split(/\s+/);
      if (parts.includes(cls)) return cur;
    }
    cur = cur.parentNode || null;
  }
  return null;
}

function isFocusableInD2Drawer(node, rootTrack) {
  if (!node || node.hidden || node.disabled || node.inert) return false;
  if (node.getAttribute("aria-disabled") === "true") return false;
  if (node.getAttribute("aria-hidden") === "true") return false;
  if (node.getAttribute("tabindex") === "-1") return false;
  let cur = node.parentNode || null;
  while (cur && cur !== rootTrack) {
    if (cur.hidden || cur.inert || cur.getAttribute("aria-hidden") === "true") return false;
    if (cur.dataset && cur.dataset.open === "false") return false;
    cur = cur.parentNode || null;
  }
  return true;
}

function handleGlobalKeydown(ev) {
  if (ev.defaultPrevented) return;
  const mod = Boolean(ev.metaKey || ev.ctrlKey);
  const activeNode = ev.target || (typeof document !== "undefined" ? document.activeElement : null);

  // Focus trap when < 960px Delivery-2 drawer is open
  if (ev.key === "Tab" && state.d2DrawerOpen && isNarrowDrawerViewport()) {
    const track = dom.d2Track();
    if (track) {
      const focusables = Array.from(
        track.querySelectorAll("button, a, textarea, input, select"),
      ).filter((n) => isFocusableInD2Drawer(n, track));
      if (focusables.length > 0) {
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const cur = typeof document !== "undefined" ? document.activeElement : null;
        if (ev.shiftKey && (cur === first || !focusables.includes(cur))) {
          ev.preventDefault();
          last.focus();
          return;
        }
        if (!ev.shiftKey && (cur === last || !focusables.includes(cur))) {
          ev.preventDefault();
          first.focus();
          return;
        }
      }
    }
  }

  // Cmd/Ctrl + B -> Toggle Persistent Left-Hand Delivery-2 Panel
  if (mod && !ev.altKey && (ev.key === "b" || ev.key === "B")) {
    ev.preventDefault();
    toggleDelivery2Rail("keyboard");
    return;
  }

  // Cmd/Ctrl + J -> Expand Delivery-2 (if collapsed) & focus Delivery-2 composer
  if (mod && !ev.altKey && (ev.key === "j" || ev.key === "J")) {
    ev.preventDefault();
    focusDelivery2Composer();
    return;
  }

  // Cmd/Ctrl + . -> Cancel active Delivery-2 reply
  if (mod && !ev.altKey && ev.key === ".") {
    if (state.d2Sending || state.d2ActiveStreamer) {
      ev.preventDefault();
      cancelDelivery2Turn();
    }
    return;
  }

  // Cmd/Ctrl + K -> Untouched Inbox Queue task launcher
  if (mod && (ev.key === "k" || ev.key === "K")) {
    ev.preventDefault();
    if (state.view !== "inbox") {
      navigate("#inbox", "keyboard");
    }
    requestAnimationFrame(() => {
      const input = document.getElementById("ask-pm-input");
      if (input) input.focus();
    });
    return;
  }

  // Cmd/Ctrl + Enter -> Region-scoped! Inside #d2-rail acts ONLY on Delivery-2, never Inbox sheet merge.
  if (mod && ev.key === "Enter") {
    if (isNodeInsideD2Rail(activeNode)) {
      if (activeNode && activeNode.id === "d2-composer-input") {
        ev.preventDefault();
        const draft = String(activeNode.value || state.d2ComposerDraft || "").trim();
        if (draft) {
          submitDelivery2Prompt(draft);
        }
        return;
      }
      if (isEditableTarget(activeNode)) {
        return;
      }
      const hitlCard = findAncestorWithClass(activeNode, "d2-hitl-card");
      if (hitlCard) {
        const hitlBtn = hitlCard.querySelector(".d2-hitl-primary");
        if (hitlBtn && hitlBtn.getAttribute("aria-disabled") !== "true" && !Motion.isArming(hitlBtn)) {
          ev.preventDefault();
          hitlBtn.click();
        }
      }
      return;
    }
    if (state.openItemId) {
      const primary = document.getElementById("sheet-primary-action");
      if (primary && primary.getAttribute("aria-disabled") !== "true" && !Motion.isArming(primary)) {
        ev.preventDefault();
        primary.click();
      }
      return;
    }
  }

  // Escape -> Close topmost overlay (d2Popover -> d2EditingMemId -> d2Drawer -> popover -> modal -> sheet)
  if (ev.key === "Escape") {
    if (state.d2Popover) {
      ev.preventDefault();
      closeD2Popover();
      return;
    }
    if (state.d2EditingMemId) {
      ev.preventDefault();
      state.d2EditingMemId = null;
      state.d2EditingMemDraft = "";
      renderDelivery2Panel();
      return;
    }
    if (state.d2DrawerOpen && isNarrowDrawerViewport()) {
      ev.preventDefault();
      setDelivery2RailExpanded(false, { persist: false, animate: true });
      return;
    }
    const popLayer = dom.popoverLayer();
    if (popLayer && !popLayer.hidden) {
      ev.preventDefault();
      closePopover();
      return;
    }
    const modLayer = dom.modalLayer();
    if (modLayer && !modLayer.hidden) {
      ev.preventDefault();
      closeModal();
      return;
    }
    if (state.openItemId) {
      ev.preventDefault();
      closeReviewSheetAndNavigate();
    }
    return;
  }

  if (isEditableTarget(activeNode) || isNodeInsideD2Rail(activeNode) || mod || ev.altKey) return;

  // g + i / b / a / c navigation chords
  const now = typeof performance !== "undefined" ? performance.now() : Date.now();
  if (ev.key === "g") {
    chordPrefixGAt = now;
    return;
  }
  if (now - chordPrefixGAt < 700) {
    chordPrefixGAt = 0;
    if (ev.key === "i") { ev.preventDefault(); navigate("#inbox", "keyboard"); return; }
    if (ev.key === "b") { ev.preventDefault(); navigate("#board", "keyboard"); return; }
    if (ev.key === "a") { ev.preventDefault(); navigate("#agents", "keyboard"); return; }
    if (ev.key === "c") { ev.preventDefault(); navigate("#credits", "keyboard"); return; }
  }

  if (state.view !== "inbox") return;

  if (ev.key === "j" || ev.key === "ArrowDown") {
    ev.preventDefault();
    if (state.openItemId) {
      stepOpenSheetItem(1, ev.repeat);
    } else {
      const items = filteredInboxItems();
      if (items.length > 0) {
        state.selectedIndex = Math.min(items.length - 1, state.selectedIndex + 1);
        renderCurrentView();
      }
    }
  } else if (ev.key === "k" || ev.key === "ArrowUp") {
    ev.preventDefault();
    if (state.openItemId) {
      stepOpenSheetItem(-1, ev.repeat);
    } else {
      const items = filteredInboxItems();
      if (items.length > 0) {
        state.selectedIndex = Math.max(0, state.selectedIndex - 1);
        renderCurrentView();
      }
    }
  } else if (ev.key === "Enter" && !state.openItemId) {
    const targetTag = activeNode && activeNode.tagName;
    if (targetTag === "BUTTON" || targetTag === "A") return;
    const items = filteredInboxItems();
    const sel = items[state.selectedIndex];
    if (sel) {
      ev.preventDefault();
      navigate(sel.is_sample ? "#walkthrough" : `#diff/${encodeURIComponent(sel.id)}`, "keyboard");
    }
  }
}

function wireKeyboardShortcuts() {
  document.addEventListener("keydown", handleGlobalKeydown);
}

// Single-use ticket stream (/api/bus/stream-ticket -> /api/bus/stream?ticket=...) + polling fallback
let activeEventSource = null;
let pollIntervalId = 0;
let streamRetryTimer = 0;

async function refreshBootstrapQuietly() {
  try {
    const hadInFlightAtStart = (state.workflowSaveInFlight || 0) > 0;
    const startSaveSeq = state.workflowSaveSeq || 0;
    const raw = await apiRequest("GET", "/api/v4/bootstrap");
    const fresh = normalizeBootstrap(raw);
    if (
      hadInFlightAtStart ||
      (state.workflowSaveInFlight || 0) > 0 ||
      (state.workflowSaveSeq || 0) !== startSaveSeq
    ) {
      applyWorkflowSnapshot(fresh.agents, snapshotWorkflowState(state.data.agents));
    } else {
      state.committedWorkflow = snapshotWorkflowState(fresh.agents);
    }
    // Read the CURRENT Delivery-2 cursor & snapshot AFTER `await` resolves so delayed
    // bootstrap responses can never roll back newer mutations applied while in flight.
    const livePrevD2 = state.data ? state.data.delivery2 : null;
    const livePrevSeq = Number(state.d2LastCursorSeq) || 0;
    const incomingSeq = Math.max(1, Number(fresh.delivery2 && fresh.delivery2.seq) || 1);
    if (state.d2Loaded && livePrevD2 && incomingSeq < livePrevSeq) {
      fresh.delivery2 = livePrevD2;
    } else {
      state.d2LastCursorSeq = Math.max(livePrevSeq, incomingSeq);
      state.d2Loaded = true;
    }
    state.data = fresh;
    state.bootstrapOk = true;
    syncHeaderChrome();
    if (!state.d2Sending && !state.d2EditingMemId) {
      renderDelivery2Panel();
    }
    return true;
  } catch (e) {
    return false;
  }
}

function startPollingFallback() {
  if (pollIntervalId) return;
  state.transportMode = "poll_fallback";
  pollIntervalId = window.setInterval(() => {
    if (!document.hidden) {
      Promise.all([resumeDelivery2FromCursor(), refreshBootstrapQuietly()]).then(([, ok]) => {
        if (ok && !state.openItemId && state.view === "inbox") {
          renderCurrentView();
        }
      });
    }
  }, 15000);
}

async function connectLiveStream(attempt = 1) {
  if (typeof EventSource === "undefined") {
    startPollingFallback();
    return;
  }
  try {
    const ticketRes = await apiRequest("POST", "/api/bus/stream-ticket", {});
    const ticket = ticketRes && ticketRes.ticket ? String(ticketRes.ticket) : "";
    if (!ticket) {
      startPollingFallback();
      return;
    }
    if (activeEventSource) {
      activeEventSource.close();
      activeEventSource = null;
    }
    const es = new EventSource(`/api/bus/stream?ticket=${encodeURIComponent(ticket)}`);
    activeEventSource = es;
    state.transportMode = "sse";

    let streamRefreshInFlight = false;
    const handleStreamNotification = async () => {
      if (streamRefreshInFlight) return;
      streamRefreshInFlight = true;
      try {
        const [, ok] = await Promise.all([resumeDelivery2FromCursor(), refreshBootstrapQuietly()]);
        if (ok && !state.openItemId && (state.view === "inbox" || state.view === "board")) {
          renderCurrentView();
        }
      } finally {
        streamRefreshInFlight = false;
      }
    };
    es.addEventListener("open", () => {
      if (state.reconnectCount > 0) {
        resumeDelivery2FromCursor();
      }
    });
    es.addEventListener("message", handleStreamNotification);
    es.addEventListener("bus_update", handleStreamNotification);

    es.onerror = () => {
      es.close();
      if (activeEventSource === es) activeEventSource = null;
      state.reconnectCount += 1;
      const bucket = state.reconnectCount === 1 ? "1" : state.reconnectCount <= 3 ? "2_3" : "4_plus";
      if (attempt < 3) {
        clearTimeout(streamRetryTimer);
        streamRetryTimer = window.setTimeout(() => {
          trackUiEvent("ui_sse_stream_reconnected", {
            transport_mode: "sse",
            reconnect_attempt_bucket: bucket,
          });
          connectLiveStream(attempt + 1);
        }, attempt * 2000);
      } else {
        trackUiEvent("ui_sse_stream_reconnected", {
          transport_mode: "poll_fallback",
          reconnect_attempt_bucket: bucket,
        });
        startPollingFallback();
      }
    };
  } catch (err) {
    startPollingFallback();
  }
}

// ── 11 · Boot Initialization ─────────────────────────────────────────────────

async function boot() {
  if (typeof document === "undefined") return;

  try {
    state.onboardingDismissed = localStorage.getItem("chinwag_onboarding_dismissed") === "1";
    state.walkthroughDone = localStorage.getItem("chinwag_walkthrough_done") === "1";
  } catch (e) {}

  syncThemeButton();

  // Wire header controls
  const appHeader = typeof document !== "undefined" ? document.getElementById("app-header") : null;
  if (appHeader) {
    appHeader.addEventListener("click", (ev) => {
      const popLayer = dom.popoverLayer();
      if (!popLayer || popLayer.hidden) return;
      const target = ev.target && typeof ev.target.closest === "function" ? ev.target : null;
      if (!target || !target.closest("button, a")) {
        closePopover();
      }
    });
  }

  const repoPill = dom.repoPill();
  if (repoPill) repoPill.addEventListener("click", () => openRepoPopover(repoPill));

  const btnInvite = dom.btnInvite();
  if (btnInvite) btnInvite.addEventListener("click", () => openInviteModal("global_header"));

  const btnTheme = dom.btnTheme();
  if (btnTheme) btnTheme.addEventListener("click", () => toggleTheme());

  const btnPrivacy = dom.btnPrivacy();
  if (btnPrivacy) btnPrivacy.addEventListener("click", () => openPrivacyPopover(btnPrivacy));

  const btnMobileMenu = dom.btnMobileMenu();
  if (btnMobileMenu) btnMobileMenu.addEventListener("click", () => openMobileMenuPopover(btnMobileMenu));

  const btnD2Drawer = dom.btnD2Drawer();
  if (btnD2Drawer) btnD2Drawer.addEventListener("click", () => toggleDelivery2Rail("mobile_drawer_btn"));

  const fixedRailBtn = dom.d2RailToggleFixed();
  if (fixedRailBtn) {
    clearNode(fixedRailBtn);
    fixedRailBtn.appendChild(ICONS.rail());
    fixedRailBtn.addEventListener("click", () => toggleDelivery2Rail("fixed_rail_toggle"));
  }

  const d2Scrim = dom.d2DrawerScrim();
  if (d2Scrim) {
    d2Scrim.addEventListener("click", () => setDelivery2RailExpanded(false, { persist: false, animate: true }));
  }

  syncDelivery2DrawerDom();

  document.addEventListener("click", (ev) => {
    if (!state.d2Popover) return;
    const t = ev.target;
    let cur = t;
    while (cur) {
      if (
        cur.id === "d2-history-popover" ||
        cur.id === "d2-connections-popover" ||
        cur.id === "d2-btn-history" ||
        cur.id === "d2-btn-connections" ||
        (cur.className && typeof cur.className === "string" && cur.className.includes("d2-sync-pill"))
      ) {
        return;
      }
      cur = cur.parentNode || null;
    }
    closeD2Popover({ restoreFocus: false });
  });

  window.addEventListener("resize", () => {
    syncDelivery2DrawerDom();
    syncRailForOverlaySheet();
  });

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.booted) {
      resumeDelivery2FromCursor();
    }
  });

  const creditPill = dom.creditPill();
  if (creditPill) {
    creditPill.addEventListener("click", () => {
      pendingNavTrigger = "credit_pill";
    });
  }

  for (const nav of [dom.headerTabs(), dom.mobileTabs()]) {
    if (!nav) continue;
    for (const a of nav.querySelectorAll("a[data-route]")) {
      a.addEventListener("click", () => {
        pendingNavTrigger = "top_tab";
      });
    }
  }

  // Bind gliding top-tab indicators
  const hdrTabs = dom.headerTabs();
  if (hdrTabs) {
    desktopTabsIndicator = Motion.bindIndicator(hdrTabs, hdrTabs.querySelector(".tab-ink"), "a[aria-current='page']");
  }
  const mobTabs = dom.mobileTabs();
  if (mobTabs) {
    mobileTabsIndicator = Motion.bindIndicator(mobTabs, mobTabs.querySelector(".tab-ink"), "a[aria-current='page']");
  }

  wireKeyboardShortcuts();
  window.addEventListener("hashchange", () => applyRouteFromLocation());

  // Initial bootstrap fetch
  const initialRoute = parseHashRoute(window.location.hash);
  state.view = initialRoute.view;
  state.openItemId = initialRoute.itemId;
  if (initialRoute.itemId) state.sheetOpenedAtMs = Date.now();

  await refreshBootstrapQuietly();

  if (!initialRoute.focusDelivery2) {
    syncRailForOverlaySheet();
  }
  syncHeaderChrome();
  renderDelivery2Panel();
  renderCurrentView();
  if (initialRoute.focusDelivery2) {
    bounceToDelivery2Run(initialRoute.runId);
  }
  state.booted = true;

  const bootElapsed = typeof performance !== "undefined" ? performance.now() - BOOT_PERF_MS : 120;
  const hasDeepLink = Boolean(window.location.hash && window.location.hash !== "#inbox");
  trackUiEvent("ui_session_started", {
    entry_route: initialRoute.entryRoute,
    entry_source: hasDeepLink ? "deep_link_open" : "cli_launch",
    has_deep_link: hasDeepLink,
    ui_theme: currentTheme(),
    viewport_bucket: viewportBucket(),
    boot_latency_ms_bucket: bootLatencyBucket(bootElapsed),
    inbox_badge_bucket: badgeBucket(state.data.inbox.counts.needs_decision),
  });

  if (hasDeepLink) {
    trackUiEvent("ui_deep_link_bounced", {
      deep_link_target: initialRoute.itemId ? "diff_item" : initialRoute.entryRoute,
      bounce_source: "direct_hash",
      target_found: true,
    });
  }

  // Visibility-aware 60s active session heartbeat
  window.setInterval(() => {
    if (!document.hidden) {
      state.activeMinutes = Math.min(1440, state.activeMinutes + 1);
      trackUiEvent("ui_heartbeat_active", {
        view: state.view,
        diff_sheet_open: Boolean(state.openItemId),
        active_minutes_session: state.activeMinutes,
      });
    }
  }, 60000);

  connectLiveStream(1);
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
}

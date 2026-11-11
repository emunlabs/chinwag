// /assets/v4/motion.js
// Temporal behavior for the local app. CSS owns the numbers; this file reads them.

const hasDom = typeof document !== "undefined" && typeof window !== "undefined";
const root = hasDom ? document.documentElement : null;
const RM = hasDom && typeof window.matchMedia === "function"
  ? window.matchMedia("(prefers-reduced-motion: reduce)")
  : { matches: false, addEventListener() {} };

export const ARM_GUARD_MS = 400;      // a newly enabled primary ignores activation this long
export const SKELETON_DELAY_MS = 300; // placeholders appear only after this
export const TOAST_MS = 4000;
export const FEEDBACK_MS = 1600;
export const SWAP_MIN_GAP_MS = 334;   // at most three content fades per second

// ── Reduced motion ──────────────────────────────────────────────────────────
export function prefersReducedMotion() { return Boolean(RM.matches); }
export function onReducedMotionChange(fn) { RM.addEventListener("change", () => fn(RM.matches)); }

// ── Token readers (motion.css is the single source of numbers) ─────────────
export function token(name) {
  if (!root) return "";
  return getComputedStyle(root).getPropertyValue(name).trim();
}
export function tokenMs(name) {
  const v = token(name), n = parseFloat(v);
  if (!Number.isFinite(n)) return 0;
  return /ms$/.test(v) ? n : n * 1000;
}

// ── Web Animations plumbing ────────────────────────────────────────────────
function play(el, frames, dur, ease, id, fill = "none") {
  if (!el || typeof el.animate !== "function") {
    return { id, finished: Promise.resolve(), cancel() {} };
  }
  const a = el.animate(frames, { duration: tokenMs(dur), easing: token(ease) || "linear", fill });
  a.id = id;
  return a;
}
const done = (a) => (a && a.finished ? a.finished.then(() => {}, () => {}) : Promise.resolve());
const twoFrames = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));

/** Resolves when every CSS transition, CSS animation, and scripted animation on `el` has ended.
 *  Resolves immediately when there is nothing to play, so no state machine waits on an event. */
export function settled(el) {
  if (!el || typeof el.getAnimations !== "function") return Promise.resolve();
  return Promise.all(el.getAnimations().map(done));
}

// ── Theme switch: one frame, no intermediate tints ─────────────────────────
export function switchTheme(next) {
  if (!root || (next !== "stone" && next !== "light" && next !== "dark")) return;
  const resolved = next === "dark" ? "dark" : "stone";
  root.setAttribute("data-theme-switching", "");
  root.setAttribute("data-theme", resolved);
  try {
    localStorage.setItem("chinwag_ui_theme", resolved);
    localStorage.setItem("chinwag.ui.theme", resolved === "dark" ? "dark" : "light");
  } catch (e) { /* storage unavailable: theme still applies */ }
  void getComputedStyle(root).backgroundColor;          // flush style while transitions are suppressed
  twoFrames().then(() => root.removeAttribute("data-theme-switching"));
}

// ── Scroll anchoring across a one-frame layout change (split open / close) ─
/** Keeps `el` at the same viewport height while `mutate()` rewrites the layout. One read, one write, one read. */
export function keepAnchored(el, getScroller, mutate) {
  if (!el) { mutate(); return; }
  const before = el.getBoundingClientRect().top;
  mutate();
  const delta = el.getBoundingClientRect().top - before;
  const scroller = getScroller ? getScroller() : null;
  if (delta && scroller) scroller.scrollTop += delta;
}
export function paneSettle(pane) {
  if (!pane || prefersReducedMotion()) return;
  play(pane, [{ opacity: 0.6 }, { opacity: 1 }], "--dur-fast", "--ease-standard", "pane-settle");
}

// ── Arrival ring ───────────────────────────────────────────────────────────
export function markArrived(el) {
  if (!el || prefersReducedMotion()) return;
  el.removeAttribute("data-arrived");
  requestAnimationFrame(() => {
    el.setAttribute("data-arrived", "");
    setTimeout(() => el.removeAttribute("data-arrived"), tokenMs("--dur-flash") + 34);
  });
}
/** Instant scroll, then show where we landed. Smooth scrolling is never used. */
export function jumpTo(el) {
  if (!el) return;
  el.scrollIntoView({ block: "start", behavior: "auto" });
  markArrived(el);
}

// ── Sheet state machine: opening → open → closing → removed ────────────────
export function createSheet(sheet, { scrim = null, titleEl, onRemoved } = {}) {
  let origin = null;
  const set = (s) => { sheet.dataset.state = s; if (scrim) scrim.dataset.state = s === "closing" ? "closing" : "open"; };
  return {
    get state() { return sheet.dataset.state || "closed"; },
    /** cold = true on a deep-link boot: the sheet is simply there. */
    open({ originEl = null, cold = false } = {}) {
      origin = originEl;
      sheet.hidden = false; if (scrim) scrim.hidden = false;
      set(cold || prefersReducedMotion() ? "open" : "opening");
      if (titleEl) titleEl.focus({ preventScroll: true });            // focus at 0 ms
      if (sheet.dataset.state === "opening") {
        settled(sheet).then(() => { if (sheet.dataset.state === "opening") sheet.dataset.state = "open"; });
      }
    },
    async close() {
      if (this.state === "closing" || this.state === "closed") return;
      set("closing");
      if (origin && origin.isConnected) origin.focus({ preventScroll: true });   // keyboard is live before the exit ends
      await Promise.all([settled(sheet), scrim ? settled(scrim) : null]);
      if (sheet.dataset.state !== "closing") return;                  // reopened mid-exit
      sheet.hidden = true; delete sheet.dataset.state;
      if (scrim) { scrim.hidden = true; delete scrim.dataset.state; }
      if (onRemoved) onRemoved(origin);
    },
  };
}

// ── j / k content swap: the sheet never moves ──────────────────────────────
let lastSwapAt = -Infinity;
/** `render()` replaces the body and footer content synchronously. */
export function swapContent(regions, render, { repeat = false } = {}) {
  render();
  regions.forEach((r) => { if (r && r.scrollTop) r.scrollTop = 0; });
  const now = performance.now();
  if (repeat || prefersReducedMotion() || now - lastSwapAt < SWAP_MIN_GAP_MS) return;
  lastSwapAt = now;
  regions.forEach((r) => { if (r) play(r, [{ opacity: 0 }, { opacity: 1 }], "--dur-swap", "--ease-standard", "content-in"); });
}
export function contentIn(el) {
  if (!el || prefersReducedMotion()) return;
  play(el, [{ opacity: 0 }, { opacity: 1 }], "--dur-swap", "--ease-standard", "content-in");
}

// ── Dip-swap: out, commit on the blank frame, in ───────────────────────────
export async function dipSwap(el, commit, { out = "--dur-dip-out", into = "--dur-dip-in" } = {}) {
  if (!el || prefersReducedMotion()) { commit(); return; }
  const a = play(el, [{ opacity: 1 }, { opacity: 0 }], out, "--ease-in-crisp", "dip-out", "forwards");
  await done(a);
  commit();
  const b = play(el, [{ opacity: 0 }, { opacity: 1 }], into, "--ease-standard", "dip-in");
  a.cancel();
  await done(b);
}
/** In-place row status change (pill): 90 out, 130 in. */
export function pillSwap(pill, commit) { return dipSwap(pill, commit, { out: "--dur-instant", into: "--dur-row-in" }); }

// ── FLIP: one layout pass, then transform only ─────────────────────────────
function followers(anchor) {
  const out = []; let n = anchor ? anchor.nextElementSibling : null;
  while (n) { out.push(n); n = n.nextElementSibling; }
  return out;
}
/** Runs `commit()` (which may change the height of `anchor`), then glides everything below into place. */
export function flipBelow(anchor, commit, dur = "--dur-dip-in") {
  const sibs = followers(anchor);
  const first = sibs.map((n) => n.getBoundingClientRect().top);       // read
  commit();                                                            // write
  if (prefersReducedMotion()) return Promise.resolve();
  const last = sibs.map((n) => n.getBoundingClientRect().top);        // read (one layout)
  const jobs = [];
  sibs.forEach((n, i) => {
    const dy = first[i] - last[i];
    if (Math.abs(dy) < 0.5) return;                                    // scroll anchoring already compensated
    jobs.push(done(play(n, [{ transform: `translate3d(0, ${dy}px, 0)` }, { transform: "translate3d(0, 0, 0)" }],
                        dur, "--ease-out-expo", "flip-settle")));
  });
  return Promise.all(jobs);
}
/** Permission granted, hold kept, request changed: fade, commit in the dark, close the gap. */
export async function resolveBanner(banner, commit) {
  stopPulse(banner);
  if (!banner || prefersReducedMotion()) { commit(); return; }
  const a = play(banner, [{ opacity: 1 }, { opacity: 0 }], "--dur-dip-out", "--ease-in-crisp", "dip-out", "forwards");
  await done(a);
  const gap = flipBelow(banner, commit);
  const b = play(banner, [{ opacity: 0 }, { opacity: 1 }], "--dur-dip-in", "--ease-standard", "dip-in");
  a.cancel();
  await Promise.all([gap, done(b)]);
}
/** A banner arriving in an open sheet (revision changed, retry limit, paused). */
export function insertBanner(prev, insert) {
  const settle = flipBelow(prev, insert, "--dur-banner");
  const banner = prev ? prev.nextElementSibling : null;
  if (banner && !prefersReducedMotion()) {
    play(banner, [{ opacity: 0 }, { opacity: 1 }], "--dur-banner", "--ease-standard", "dip-in");
  }
  return settle;
}

// ── Hold pulse and the shared heartbeat ────────────────────────────────────
const LOOPS = new Set(["live-breathe", "hold-pulse", "skeleton-breathe"]);
export function stopPulse(scope) {
  if (!scope) return;
  scope.querySelectorAll("[data-pulse]").forEach((n) => n.removeAttribute("data-pulse"));
}
/** Puts every ambient loop on the same phase so they breathe as one. Call after adding a loop. */
export function phaseLock() {
  if (!hasDom) return;
  requestAnimationFrame(() => {
    for (const a of document.getAnimations()) {
      if (LOOPS.has(a.animationName)) { try { a.startTime = 0; } catch (e) { /* leave unsynced */ } }
    }
  });
}
const loopWatch = hasDom && "IntersectionObserver" in window
  ? new IntersectionObserver((entries) => entries.forEach((e) =>
      e.target.toggleAttribute("data-offscreen", !e.isIntersecting)))
  : null;
/** Pauses a looping element while it is outside the viewport. Returns an unobserve function. */
export function observeLoop(el) {
  if (!el || !loopWatch) return () => {};
  loopWatch.observe(el); phaseLock();
  return () => { loopWatch.unobserve(el); el.removeAttribute("data-offscreen"); };
}

// ── Action guard: no double submits, no width jitter ───────────────────────
const inFlight = new WeakSet();
const armedAt = new WeakMap();
export function arm(btn) {
  if (!btn) return;
  btn.removeAttribute("aria-disabled");
  armedAt.set(btn, performance.now());
  btn.setAttribute("data-arming", "");
  setTimeout(() => btn.removeAttribute("data-arming"), ARM_GUARD_MS);
}
export function isArming(btn) {
  const t = armedAt.get(btn);
  return t !== undefined && performance.now() - t < ARM_GUARD_MS;
}
/** Wrap every action click in this. `run()` returns the request promise.
 *  Success: resolves { value, release } with the group still locked (the caller swaps the region).
 *  Failure: unlocks and rethrows. Ignored clicks resolve null. */
export async function guardAction(btn, run, { group = null, busyLabel = null } = {}) {
  if (!btn || inFlight.has(btn) || btn.getAttribute("aria-disabled") === "true" || isArming(btn)) return null;
  inFlight.add(btn);
  const width = btn.getBoundingClientRect().width;                    // read before any write
  const label = btn.querySelector(".btn-label");
  const idleText = label ? label.textContent : null;
  const peers = group
    ? [...group.querySelectorAll("button, a[role='button']")].filter((b) => b !== btn && b.getAttribute("aria-disabled") !== "true")
    : [];
  const widthHold = width > 0 && typeof btn.animate === "function"
    ? btn.animate([{ inlineSize: width + "px" }, { inlineSize: width + "px" }], { duration: 0, fill: "forwards" })
    : null;
  btn.setAttribute("aria-disabled", "true");
  btn.setAttribute("data-busy", "");
  if (label && busyLabel) label.textContent = busyLabel;
  peers.forEach((b) => { b.setAttribute("aria-disabled", "true"); b.setAttribute("data-held", ""); });
  const release = () => {
    inFlight.delete(btn);
    if (widthHold) widthHold.cancel();
    btn.removeAttribute("data-busy"); btn.removeAttribute("aria-disabled");
    if (label && idleText !== null) label.textContent = idleText;
    peers.forEach((b) => { b.removeAttribute("aria-disabled"); b.removeAttribute("data-held"); });
  };
  try { return { value: await run(), release }; }
  catch (err) { release(); throw err; }
}

// ── Clipboard / action feedback timer ──────────────────────────────────────
const feedbackTimers = new WeakMap();
export function actionFeedback(btn, ms = FEEDBACK_MS) {
  if (!btn) return;
  clearTimeout(feedbackTimers.get(btn));
  btn.setAttribute("data-feedback", "done");
  feedbackTimers.set(btn, setTimeout(() => btn.removeAttribute("data-feedback"), ms));
}
/** Copies text, then acknowledges. `say` is the toaster's show(); strings come from the caller. */
export async function copyWithFeedback(btn, text, say, okText, failText) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      throw new Error("clipboard_unavailable");
    }
    actionFeedback(btn);
    say(okText);
    return true;
  } catch (e) {
    say(failText);
    return false;
  }
}

// ── Toaster: one at a time ─────────────────────────────────────────────────
export function createToaster(region) {
  let node = null, timer = 0, life = TOAST_MS;
  const leave = async () => {
    const n = node; if (!n) return; node = null;
    n.dataset.state = "leaving"; await settled(n); n.remove();
  };
  const restart = () => { clearTimeout(timer); timer = setTimeout(leave, life); };
  if (region) {
    region.addEventListener("pointerenter", () => clearTimeout(timer));
    region.addEventListener("pointerleave", () => { if (node) restart(); });
    region.addEventListener("focusin", () => clearTimeout(timer));
    region.addEventListener("focusout", () => { if (node) restart(); });
  }
  return {
    async show(text, ms = TOAST_MS) {
      if (!region) return;
      life = ms;
      if (node && node.textContent === text) { restart(); return; }    // same message: reset the clock only
      if (node) await leave();
      node = document.createElement("div");
      node.className = "toast"; node.setAttribute("role", "status");
      node.textContent = text; node.dataset.state = "shown";
      region.append(node); restart();
    },
    dismiss: leave,
  };
}

// ── Gliding indicator (top-tab underline, segmented thumb) ─────────────────
export function moveIndicator(ind, target, { glide = true } = {}) {
  if (!ind || !target || !ind.parentElement || typeof ind.animate !== "function") return;
  const track = ind.parentElement;
  const t = track.getBoundingClientRect(), r = target.getBoundingClientRect(), f = ind.getBoundingClientRect();   // reads
  const x = r.left - t.left - track.clientLeft, w = r.width;
  const placed = ind.hasAttribute("data-placed");
  ind.getAnimations().forEach((a) => a.cancel());                     // an interrupted glide restarts from `f`
  ind.setAttribute("data-placed", "");
  const endFrame = { inlineSize: w + "px", transform: `translate3d(${x}px, 0, 0) scaleX(1)` };
  if (!glide || !placed || prefersReducedMotion() || f.width === 0 || w === 0) {
    const snap = ind.animate([endFrame, endFrame], { duration: 0, fill: "forwards" });
    snap.id = "indicator-snap";
    return;
  }
  const fx = f.left - t.left - track.clientLeft;
  const startFrame = { inlineSize: w + "px", transform: `translate3d(${fx}px, 0, 0) scaleX(${f.width / w})` };
  const anim = ind.animate([startFrame, endFrame], {
    duration: tokenMs("--dur-fast"),
    easing: token("--ease-out-expo") || "linear",
    fill: "forwards",
  });
  anim.id = "indicator-glide";
}
/** Call once per track. Call `.update()` after flipping aria-current / aria-pressed / aria-selected. */
export function bindIndicator(track, ind, currentSelector) {
  if (!track || !ind) return { update() {}, destroy() {} };
  const place = (glide) => {
    const cur = track.querySelector(currentSelector);
    if (!cur || getComputedStyle(ind).display === "none") { track.removeAttribute("data-ind"); return; }
    moveIndicator(ind, cur, { glide });
    track.setAttribute("data-ind", "on");
  };
  place(false);                                                        // boot: placed, never glided
  const ro = "ResizeObserver" in window ? new ResizeObserver(() => place(false)) : null;
  if (ro) ro.observe(track);
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => place(false));
  return { update: () => place(true), destroy: () => { if (ro) ro.disconnect(); } };
}

// ── Row settle: the row never flies; the list closes ranks ─────────────────
/** `mutate()` re-sorts or removes rows in one write. `departing` is the row whose place changes. */
export async function settleList(list, mutate, departing = null) {
  if (!list || prefersReducedMotion()) { mutate(); return; }
  let out = null;
  if (departing) {
    out = play(departing, [{ opacity: 1 }, { opacity: 0 }], "--dur-depart", "--ease-in-crisp", "row-depart", "forwards");
    await done(out);
  }
  const before = new Map([...list.children].map((n) => [n, n.getBoundingClientRect().top]));     // read
  mutate();                                                                                       // write
  const after = [...list.children].filter((n) => before.has(n))
    .map((n) => [n, before.get(n) - n.getBoundingClientRect().top]);                              // read (one layout)
  if (out) out.cancel();
  const limit = window.innerHeight;
  await Promise.all(after.map(([n, dy]) => {
    if (n === departing) {
      return done(play(n, [{ opacity: 0 }, { opacity: 1 }], "--dur-row-in", "--ease-standard", "row-arrive"));
    }
    if (Math.abs(dy) < 0.5 || Math.abs(dy) > limit) return null;
    return done(play(n, [{ transform: `translate3d(0, ${dy}px, 0)` }, { transform: "translate3d(0, 0, 0)" }],
                     "--dur-row", "--ease-out-expo", "row-glide"));
  }));
}

// ── Deferred placeholder: nothing shows for fast loads ─────────────────────
/** Calls `showSkeleton()` only if `pending` is still unresolved after 300 ms. Returns `pending`. */
export function deferSkeleton(pending, showSkeleton, ms = SKELETON_DELAY_MS) {
  const t = setTimeout(() => { showSkeleton(); phaseLock(); }, ms);
  return pending.finally(() => clearTimeout(t));
}

// ── Elapsed clock: one timer, writes only when the text changes ────────────
/** `format(ms)` returns the duration string defined by the visual system. */
export function createElapsedClock(format) {
  let timer = 0;
  const tick = () => {
    clearTimeout(timer);
    if (!hasDom) return;
    const nodes = document.querySelectorAll("[data-elapsed-start]");
    if (document.hidden || nodes.length === 0) return;                 // idle is still
    const now = Date.now();
    nodes.forEach((n) => {
      const s = format(Math.max(0, now - Number(n.dataset.elapsedStart)));
      if (n.textContent !== s) n.textContent = s;
    });
    timer = setTimeout(tick, 1000 - (Date.now() % 1000));
  };
  if (hasDom) document.addEventListener("visibilitychange", tick);
  return {
    poke: tick,
    stop: () => {
      clearTimeout(timer);
      if (hasDom) document.removeEventListener("visibilitychange", tick);
    },
  };
}

// ── Delivery-2 Rail Toggle (single-frame grid snap + GPU clip/counter-translate) ─
let railAnimGenCounter = 0;

export function animateRailToggle(railEl, trackEl, spineEl, mainEl, nextExpanded, applyAttr) {
  const myGen = ++railAnimGenCounter;
  if (railEl) {
    if (Array.isArray(railEl._d2ActiveAnims)) {
      for (const prevAnim of railEl._d2ActiveAnims) {
        if (prevAnim && typeof prevAnim.cancel === "function") {
          try {
            prevAnim.cancel();
          } catch {}
        }
      }
    }
    railEl._d2ActiveAnims = [];
    railEl._d2AnimGen = myGen;
  }
  const canAnimate = Boolean(railEl && !prefersReducedMotion());
  if (canAnimate && railEl.dataset) {
    railEl.dataset.railAnimating = nextExpanded ? "expanding" : "collapsing";
  }
  keepAnchored(
    mainEl,
    () => (hasDom ? document.getElementById("view-root") || document.scrollingElement || document.documentElement : null),
    applyAttr,
  );
  if (!canAnimate) {
    if (railEl && railEl.dataset && railEl._d2AnimGen === myGen) {
      delete railEl.dataset.railAnimating;
    }
    return Promise.resolve();
  }
  const activeAnims = [];
  const jobs = [];
  if (trackEl && typeof trackEl.animate === "function") {
    const frames = nextExpanded
      ? [
          { transform: "translate3d(-276px, 0, 0)", opacity: 0.72 },
          { transform: "translate3d(0, 0, 0)", opacity: 1 },
        ]
      : [
          { transform: "translate3d(0, 0, 0)", opacity: 1 },
          { transform: "translate3d(-276px, 0, 0)", opacity: 0 },
        ];
    const anim = play(trackEl, frames, "--dur-rail", "--ease-out-expo", "d2-rail-track");
    if (anim) activeAnims.push(anim);
    jobs.push(done(anim));
  }
  if (nextExpanded && typeof railEl.animate === "function") {
    const clipFrames = [{ clipPath: "inset(0 276px 0 0)" }, { clipPath: "inset(0 0px 0 0)" }];
    const anim = play(railEl, clipFrames, "--dur-rail", "--ease-out-expo", "d2-rail-clip");
    if (anim) activeAnims.push(anim);
    jobs.push(done(anim));
  }
  if (spineEl && !nextExpanded && typeof spineEl.animate === "function") {
    const anim = play(spineEl, [{ opacity: 0 }, { opacity: 1 }], "--dur-rail-fade", "--ease-standard", "d2-spine-in");
    if (anim) activeAnims.push(anim);
    jobs.push(done(anim));
  }
  if (railEl) {
    railEl._d2ActiveAnims = activeAnims;
  }
  return Promise.all(jobs).finally(() => {
    if (railEl && railEl._d2AnimGen === myGen) {
      railEl._d2ActiveAnims = [];
      if (railEl.dataset) delete railEl.dataset.railAnimating;
    }
  });
}

// ── Delivery-2 Amber Deep-Link Bounce Ring (640ms) ─────────────────────────
export function flashDeliveryCard(cardEl) {
  if (!cardEl) return;
  cardEl.scrollIntoView({ block: "nearest", behavior: "auto" });
  if (prefersReducedMotion()) return;
  cardEl.removeAttribute("data-handoff-flash");
  requestAnimationFrame(() => {
    cardEl.setAttribute("data-handoff-flash", "true");
    setTimeout(() => cardEl.removeAttribute("data-handoff-flash"), tokenMs("--dur-flash") + 40);
  });
}

// ── Proportional 1/8 Live Reply Streamer (60ms tick, 1200ms post-done cap) ─
export function createProportionalStreamer({ onTick, onFinish } = {}) {
  let targetText = "";
  let shownLen = 0;
  let tickTimer = 0;
  let hardCapTimer = 0;
  let doneMarked = false;
  let finished = false;

  const clearTimers = () => {
    clearTimeout(tickTimer);
    clearTimeout(hardCapTimer);
    tickTimer = 0;
    hardCapTimer = 0;
  };

  const commitAll = () => {
    if (finished) return;
    finished = true;
    clearTimers();
    shownLen = targetText.length;
    if (typeof onTick === "function") onTick(targetText, true);
    if (typeof onFinish === "function") onFinish(targetText);
  };

  const step = () => {
    tickTimer = 0;
    if (finished) return;
    const remaining = targetText.length - shownLen;
    if (remaining <= 0) {
      if (doneMarked) commitAll();
      return;
    }
    const delta = Math.max(4, Math.ceil(remaining / 8));
    shownLen = Math.min(targetText.length, shownLen + delta);
    const slice = targetText.slice(0, shownLen);
    if (typeof onTick === "function") onTick(slice, shownLen >= targetText.length && doneMarked);
    if (shownLen >= targetText.length && doneMarked) {
      commitAll();
      return;
    }
    tickTimer = setTimeout(step, 60);
  };

  return {
    push(nextFullText) {
      targetText = String(nextFullText ?? "");
      if (prefersReducedMotion()) {
        shownLen = targetText.length;
        if (typeof onTick === "function") onTick(targetText, doneMarked);
        if (doneMarked) commitAll();
        return;
      }
      if (!tickTimer && !finished) {
        step();
      }
    },
    markDone() {
      doneMarked = true;
      if (prefersReducedMotion() || shownLen >= targetText.length) {
        commitAll();
        return;
      }
      clearTimeout(hardCapTimer);
      hardCapTimer = setTimeout(commitAll, 1200);
      if (!tickTimer) step();
    },
    cancel() {
      if (finished) return;
      finished = true;
      clearTimers();
    },
    flushNow: commitAll,
  };
}

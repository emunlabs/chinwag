// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Real `chinwag ui-gate` headless Chromium CDP + HTTP `<a href>` link inspector and
//! fail-closed `UiGateSurface` validator (`CHWG-0251` · `INV-UI-DESKTOP-CLICK-AND-LINK-QA-01`).
//!
//! Replaces the historical `NOT_IMPLEMENTED` stub with:
//! 1. **Live Headless Chromium / CDP Inspector (`--url <url> [--out <audit.json>]`):**
//!    Drives `1440×900` Desktop (Light + Dark) and `390×844` Mobile viewports over the
//!    Chrome DevTools Protocol (pure-Rust RFC-6455 WebSocket client), verifying:
//!    - Zero horizontal or vertical text/pill overflow (`scrollWidth <= clientWidth`,
//!      `scrollHeight <= clientHeight` on constrained containers and pills),
//!    - Every visible `<button>`, `[role="button"]`, popover/modal trigger, and `<select>`
//!      inset geometry (`width`/`height`, parent clipping, horizontal/vertical padding collapse,
//!      and label inset overflow),
//!    - HTTP `200` (`0` `404`/`5xx`/unreachable) on every internal and outbound `<a href>` link,
//!    - Emitting a signed, structured `UiAuditReportV1` JSON consumed by `chinwag-ci ui-gate`.
//! 2. **Fail-Closed `UiGateSurface` Validator (`--surface local-app|site|docs|all` / `--audit-json`):**
//!    Fails closed (`passed: false`, `ok: false`, exit `1`) whenever `--url`, `--surface local-app`,
//!    or `--audit-json` yields `0` `1440×900` desktop records or `0` `390×844` mobile records,
//!    or when any geometry, interactive control, link, or static pricing/docs invariant fails.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use rustix::fs::{AtFlags, CWD, FileType, statat};
use rustix::process::{Pid, Signal, kill_process_group};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub const INV_UI_DESKTOP_CLICK_AND_LINK_QA: &str = "INV-UI-DESKTOP-CLICK-AND-LINK-QA-01";
pub const INV_UI_GEOMETRY_GATE: &str = "INV-UI-GEOMETRY-GATE-01";
pub const MISSING_TARGET_REFUSAL: &str = "ui-gate requires `--url <http(s)://...>` or `--surface <local-app|site|docs|all> --audit-json <path>`; not gate evidence";

/// Target surface evaluated by `chinwag ui-gate` and `chinwag-ci ui-gate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UiGateSurface {
    #[serde(rename = "local-app")]
    LocalApp,
    #[serde(rename = "site")]
    Site,
    #[serde(rename = "docs")]
    Docs,
    #[serde(rename = "all")]
    All,
}

impl UiGateSurface {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "local-app" | "local_app" | "localapp" | "app" => Ok(Self::LocalApp),
            "site" | "website" => Ok(Self::Site),
            "docs" | "doc" | "documentation" => Ok(Self::Docs),
            "all" | "both" => Ok(Self::All),
            other => Err(format!(
                "invalid --surface `{other}`: expected `local-app`, `site`, `docs`, or `all`"
            )),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalApp => "local-app",
            Self::Site => "site",
            Self::Docs => "docs",
            Self::All => "all",
        }
    }
}

/// Broken `<a href>` link entry recorded by `chinwag ui-gate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokenLinkRecordV1 {
    pub href: String,
    pub status: u16,
    pub reason: String,
}

/// Single viewport pass record inside `UiAuditReportV1`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UiAuditViewportRecordV1 {
    pub path: String,
    pub viewport: String,
    pub color_scheme: String,
    pub status: u16,
    pub check: Value,
    pub console: Vec<String>,
    pub pageerrors: Vec<String>,
    #[serde(rename = "badRequests")]
    pub bad_requests: Vec<String>,
    #[serde(rename = "brokenLinks")]
    pub broken_links: Vec<BrokenLinkRecordV1>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub discovered_links: Vec<String>,
}

/// Cryptographically signed UI audit report (`UiAuditReportV1`) emitted by `chinwag ui-gate --url`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UiAuditReportV1 {
    pub schema: String,
    pub url: String,
    pub ticket_id: String,
    pub generated_at_unix: u64,
    pub links_verified: usize,
    pub broken_links: Vec<BrokenLinkRecordV1>,
    pub records: Vec<UiAuditViewportRecordV1>,
    pub payload_sha256_hex: String,
    pub runner_ed25519_pk_hex: String,
    pub runner_ed25519_sig_hex: String,
}

impl UiAuditReportV1 {
    fn canonical_signing_bytes(&self) -> Result<Vec<u8>, String> {
        let records_val =
            serde_json::to_value(&self.records).map_err(|e| format!("serialize records: {e}"))?;
        let broken_val = serde_json::to_value(&self.broken_links)
            .map_err(|e| format!("serialize broken_links: {e}"))?;
        let unsigned = json!({
            "broken_links": broken_val,
            "generated_at_unix": self.generated_at_unix,
            "links_verified": self.links_verified,
            "records": records_val,
            "schema": self.schema,
            "ticket_id": self.ticket_id,
            "url": self.url,
        });
        crate::regression_ratchet::to_rfc8785_jcs_string(&unsigned)
            .map(String::into_bytes)
            .map_err(|e| format!("canonicalize UiAuditReportV1: {e}"))
    }

    pub fn build_signed(
        url: &str,
        ticket_id: &str,
        links_verified: usize,
        broken_links: Vec<BrokenLinkRecordV1>,
        records: Vec<UiAuditViewportRecordV1>,
    ) -> Result<Self, String> {
        let signer = EphemeralGateSigner::generate()?;
        let generated_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut report = Self {
            schema: "UiAuditReportV1".to_owned(),
            url: url.to_owned(),
            ticket_id: ticket_id.to_owned(),
            generated_at_unix,
            links_verified,
            broken_links,
            records,
            payload_sha256_hex: String::new(),
            runner_ed25519_pk_hex: signer.pk_hex(),
            runner_ed25519_sig_hex: String::new(),
        };
        let canonical = report.canonical_signing_bytes()?;
        report.payload_sha256_hex = hex_encode(&Sha256::digest(&canonical));
        let sig = signer.sign(&canonical);
        report.runner_ed25519_sig_hex = hex_encode(&sig.to_bytes());
        report.verify_signature()?;
        Ok(report)
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        if self.schema != "UiAuditReportV1" {
            return Err(format!("unexpected schema `{}`", self.schema));
        }
        let canonical = self.canonical_signing_bytes()?;
        let expected_sha = hex_encode(&Sha256::digest(&canonical));
        if self.payload_sha256_hex != expected_sha {
            return Err("UiAuditReportV1 payload_sha256_hex mismatch".to_owned());
        }
        let pk_bytes = hex_decode_exact::<32>(&self.runner_ed25519_pk_hex)
            .map_err(|e| format!("invalid runner_ed25519_pk_hex: {e}"))?;
        let sig_bytes = hex_decode_exact::<64>(&self.runner_ed25519_sig_hex)
            .map_err(|e| format!("invalid runner_ed25519_sig_hex: {e}"))?;
        let vk = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| format!("invalid Ed25519 verifying key: {e}"))?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(&canonical, &sig)
            .map_err(|e| format!("UiAuditReportV1 signature verification failed: {e}"))
    }
}

/// Single deterministic invariant, geometry, interactive control, or link violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiGateViolationV1 {
    pub invariant: String,
    pub target: String,
    pub detail: String,
}

/// Cryptographically signed UI Gate receipt (`UiGateReceiptV1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiGateReceiptV1 {
    pub ok: bool,
    pub schema: String,
    pub command: String,
    pub document_id: String,
    pub org_id_hash: String,
    pub ticket_id: String,
    pub surface: String,
    pub commit_sha: String,
    pub repo_path: String,
    pub host_arch: String,
    pub passed: bool,
    pub html_files_scanned: usize,
    pub markdown_files_scanned: usize,
    pub audit_records_verified: usize,
    pub desktop_1440x900_records: usize,
    pub mobile_390x844_records: usize,
    pub interactive_controls_verified: usize,
    pub links_verified: usize,
    pub invariants_verified: Vec<String>,
    pub violations: Vec<UiGateViolationV1>,
    pub artifacts_git_ref: String,
    pub payload_sha256_hex: String,
    pub runner_ed25519_pk_hex: String,
    pub runner_ed25519_sig_hex: String,
}

impl UiGateReceiptV1 {
    fn canonical_signing_bytes(&self) -> Result<Vec<u8>, String> {
        let violations_val = serde_json::to_value(&self.violations)
            .map_err(|e| format!("serialize violations: {e}"))?;
        let unsigned = json!({
            "artifacts_git_ref": self.artifacts_git_ref,
            "audit_records_verified": self.audit_records_verified,
            "command": self.command,
            "commit_sha": self.commit_sha,
            "desktop_1440x900_records": self.desktop_1440x900_records,
            "document_id": self.document_id,
            "host_arch": self.host_arch,
            "html_files_scanned": self.html_files_scanned,
            "interactive_controls_verified": self.interactive_controls_verified,
            "invariants_verified": self.invariants_verified,
            "links_verified": self.links_verified,
            "markdown_files_scanned": self.markdown_files_scanned,
            "mobile_390x844_records": self.mobile_390x844_records,
            "ok": self.ok,
            "org_id_hash": self.org_id_hash,
            "passed": self.passed,
            "repo_path": self.repo_path,
            "schema": self.schema,
            "surface": self.surface,
            "ticket_id": self.ticket_id,
            "violations": violations_val,
        });
        crate::regression_ratchet::to_rfc8785_jcs_string(&unsigned)
            .map(String::into_bytes)
            .map_err(|e| format!("canonicalize UiGateReceiptV1: {e}"))
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        let canonical = self.canonical_signing_bytes()?;
        let expected_sha = hex_encode(&Sha256::digest(&canonical));
        if self.payload_sha256_hex != expected_sha {
            return Err("UiGateReceiptV1 payload_sha256_hex mismatch".to_owned());
        }
        let pk_bytes = hex_decode_exact::<32>(&self.runner_ed25519_pk_hex)?;
        let sig_bytes = hex_decode_exact::<64>(&self.runner_ed25519_sig_hex)?;
        let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| e.to_string())?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(&canonical, &sig)
            .map_err(|e| format!("UiGateReceiptV1 signature invalid: {e}"))
    }
}

struct EphemeralGateSigner {
    signing_key: SigningKey,
}

impl EphemeralGateSigner {
    fn generate() -> Result<Self, String> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        rand::rng().fill_bytes(&mut *seed);
        if seed.iter().all(|&b| b == 0) {
            return Err("CSPRNG returned all-zero seed".to_owned());
        }
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    fn pk_hex(&self) -> String {
        hex_encode(&self.signing_key.verifying_key().to_bytes())
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }
}

/// Pluggable browser inspector driver so deterministic unit/integration tests can exercise
/// both real headless Chromium CDP and controlled DOM/link fixtures.
pub trait UiInspectorDriver {
    fn inspect_url(
        &self,
        target_url: &str,
        timeout_ms: u64,
    ) -> Result<Vec<UiAuditViewportRecordV1>, String>;
}

/// Production Headless Chromium / Chrome DevTools Protocol (CDP) WebSocket inspector.
#[derive(Debug, Clone, Default)]
pub struct ChromiumCdpInspector {
    pub explicit_chrome_bin: Option<PathBuf>,
}

struct HeadlessBrowserGuard {
    child: Child,
    user_data_dir: PathBuf,
}

impl Drop for HeadlessBrowserGuard {
    fn drop(&mut self) {
        if let Ok(raw_pid) = i32::try_from(self.child.id())
            && raw_pid > 1
            && let Some(pgid) = Pid::from_raw(raw_pid)
        {
            let _ = kill_process_group(pgid, Signal::TERM);
            let deadline = Instant::now() + Duration::from_millis(250);
            loop {
                if let Ok(Some(_)) = self.child.try_wait() {
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            let _ = kill_process_group(pgid, Signal::KILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.user_data_dir);
    }
}

#[derive(Debug, Clone, Copy)]
struct ViewportSpec {
    label: &'static str,
    width: u32,
    height: u32,
    mobile: bool,
    color_scheme: &'static str,
}

const MANDATORY_VIEWPORTS: &[ViewportSpec] = &[
    ViewportSpec {
        label: "desktop-light",
        width: 1440,
        height: 900,
        mobile: false,
        color_scheme: "light",
    },
    ViewportSpec {
        label: "desktop-dark",
        width: 1440,
        height: 900,
        mobile: false,
        color_scheme: "dark",
    },
    ViewportSpec {
        label: "mobile",
        width: 390,
        height: 844,
        mobile: true,
        color_scheme: "light",
    },
];

/// In-page DOM, overflow, interactive button/popover, `<select>` inset, and `<a href>` audit script.
const JS_VIEWPORT_AUDIT_SCRIPT: &str = r###"
(() => new Promise((resolve) => {
  requestAnimationFrame(() => requestAnimationFrame(() => {
    setTimeout(() => {
      const vw = Math.round(window.innerWidth || document.documentElement.clientWidth || 0);
      const vh = Math.round(window.innerHeight || document.documentElement.clientHeight || 0);
      const docEl = document.documentElement;
      const body = document.body;
      const scrollWidth = Math.round(Math.max(
        docEl ? docEl.scrollWidth : 0,
        body ? body.scrollWidth : 0
      ));
      const scrollHeight = Math.round(Math.max(
        docEl ? docEl.scrollHeight : 0,
        body ? body.scrollHeight : 0
      ));
      const pageOverflow = scrollWidth > vw + 1;

      const selectorFor = (el) => {
        if (!el || !el.tagName) return "<node>";
        const tag = el.tagName.toLowerCase();
        if (el.id) return `${tag}#${el.id}`;
        const cls = typeof el.className === "string" && el.className.trim()
          ? "." + el.className.trim().split(/\s+/).slice(0, 2).join(".")
          : "";
        return `${tag}${cls}`;
      };

      const isVisible = (el) => {
        if (!el || !(el instanceof Element)) return false;
        const cs = window.getComputedStyle(el);
        if (cs.display === "none" || cs.visibility === "hidden" || parseFloat(cs.opacity || "1") === 0) {
          return false;
        }
        const r = el.getBoundingClientRect();
        return r.width > 0 || r.height > 0 || el.getClientRects().length > 0;
      };

      const pillOverflow = [];
      const verticalOverflow = [];

      if (docEl && body) {
        const docCs = window.getComputedStyle(docEl);
        const bodyCs = window.getComputedStyle(body);
        if ((docCs.overflowY === "hidden" || bodyCs.overflowY === "hidden") && scrollHeight > vh + 2) {
          verticalOverflow.push({
            selector: "document",
            scrollHeight,
            clientHeight: vh,
            reason: "root-vertical-overflow-clipped"
          });
        }
      }

      const pillCandidates = document.querySelectorAll(
        'button, [role="button"], .pill, .badge, .chip, .tag, [class*="pill"], [class*="badge"], [class*="chip"], [class*="tag"], [data-pill], nav a, summary, label'
      );
      for (const el of pillCandidates) {
        if (!isVisible(el)) continue;
        const cs = window.getComputedStyle(el);
        const cw = Math.round(el.clientWidth);
        const sw = Math.round(el.scrollWidth);
        const ch = Math.round(el.clientHeight);
        const sh = Math.round(el.scrollHeight);
        const clipsX = cs.overflowX === "hidden" || cs.overflowX === "clip" || cs.textOverflow === "ellipsis" || cs.whiteSpace === "nowrap";
        const clipsY = cs.overflowY === "hidden" || cs.overflowY === "clip";
        if (cw > 0 && sw > cw + 2 && (clipsX || el.matches('button,[role="button"],.pill,.badge,.chip,.tag,[class*="pill"],[class*="badge"]'))) {
          pillOverflow.push({
            selector: selectorFor(el),
            scrollWidth: sw,
            clientWidth: cw
          });
        }
        if (ch > 0 && sh > ch + 2 && clipsY) {
          verticalOverflow.push({
            selector: selectorFor(el),
            scrollHeight: sh,
            clientHeight: ch
          });
        }
      }

      // Check <select> inset geometry defects
      const selectEls = Array.from(document.querySelectorAll("select")).filter(isVisible);
      const selectGeometryDefects = [];
      for (const sel of selectEls) {
        const r = sel.getBoundingClientRect();
        const cs = window.getComputedStyle(sel);
        const selLabel = selectorFor(sel);
        if (r.width < 28 || r.height < 20) {
          selectGeometryDefects.push({ selector: selLabel, reason: `undersized:${Math.round(r.width)}x${Math.round(r.height)}` });
          continue;
        }
        if (r.left < -1 || r.right > vw + 1) {
          selectGeometryDefects.push({ selector: selLabel, reason: "clipped-viewport-bounds" });
        }
        const parent = sel.parentElement;
        if (parent) {
          const pcs = window.getComputedStyle(parent);
          if (pcs.overflowX === "hidden" || pcs.overflowX === "clip") {
            const pr = parent.getBoundingClientRect();
            if (r.right > pr.right + 1 || r.left < pr.left - 1) {
              selectGeometryDefects.push({ selector: selLabel, reason: "clipped-parent-inset" });
            }
          }
        }
        const padX = (parseFloat(cs.paddingLeft) || 0) + (parseFloat(cs.paddingRight) || 0);
        const padY = (parseFloat(cs.paddingTop) || 0) + (parseFloat(cs.paddingBottom) || 0);
        const borderY = (parseFloat(cs.borderTopWidth) || 0) + (parseFloat(cs.borderBottomWidth) || 0);
        const fontSize = parseFloat(cs.fontSize) || 14;
        if (r.width - padX < 16) {
          selectGeometryDefects.push({ selector: selLabel, reason: "collapsed-horizontal-inset" });
        }
        if (r.height - padY - borderY < fontSize * 0.85) {
          selectGeometryDefects.push({ selector: selLabel, reason: "clipped-vertical-text-inset" });
        }
        if (sel.clientWidth > 0 && sel.scrollWidth > sel.clientWidth + 2) {
          selectGeometryDefects.push({ selector: selLabel, reason: "label-overflows-select-inset" });
        }
      }

      // Collect <a href> links & check in-page #fragment anchors
      const discoveredLinks = [];
      const brokenFragmentLinks = [];
      for (const a of document.querySelectorAll("a[href]")) {
        const rawHref = (a.getAttribute("href") || "").trim();
        if (!rawHref || rawHref.startsWith("javascript:") || rawHref.startsWith("mailto:") || rawHref.startsWith("tel:") || rawHref.startsWith("data:") || rawHref.startsWith("blob:")) {
          continue;
        }
        if (rawHref.startsWith("#")) {
          const frag = rawHref.slice(1);
          if (frag && !document.getElementById(frag)) {
            let namedFound = false;
            try { namedFound = !!document.querySelector(`[name="${CSS.escape(frag)}"]`); } catch (_) {}
            if (!namedFound) {
              brokenFragmentLinks.push({ href: rawHref, status: 404, reason: "missing-fragment-anchor" });
            }
          }
          continue;
        }
        try {
          const resolved = new URL(rawHref, window.location.href);
          if (resolved.protocol === "http:" || resolved.protocol === "https:") {
            discoveredLinks.push(resolved.href);
          }
        } catch (_) {
          brokenFragmentLinks.push({ href: rawHref, status: 0, reason: "malformed-href" });
        }
      }

      // Exercise visible <button>, [role="button"], and popover/modal triggers safely
      const deadButtons = [];
      const popoverDefects = [];
      let buttonsExercised = 0;

      const blockSubmit = (e) => e.preventDefault();
      const blockAnchorNav = (e) => {
        const anchor = e.target && e.target.closest ? e.target.closest("a[href]") : null;
        if (anchor) {
          const h = (anchor.getAttribute("href") || "").trim();
          if (h && !h.startsWith("#")) e.preventDefault();
        }
      };
      const origOpen = window.open;
      const origAlert = window.alert;
      const origConfirm = window.confirm;
      const origPrompt = window.prompt;
      window.open = () => null;
      window.alert = () => {};
      window.confirm = () => false;
      window.prompt = () => null;
      document.addEventListener("submit", blockSubmit, true);
      document.addEventListener("click", blockAnchorNav, true);

      const controls = Array.from(document.querySelectorAll(
        'button, [role="button"], [popovertarget], [aria-haspopup]'
      ));
      for (const ctrl of controls) {
        const cs = window.getComputedStyle(ctrl);
        if (cs.display === "none" || cs.visibility === "hidden" || parseFloat(cs.opacity || "1") === 0) {
          continue;
        }
        if (ctrl.hasAttribute("disabled") || ctrl.getAttribute("aria-disabled") === "true") {
          continue;
        }
        const label = selectorFor(ctrl);
        const r = ctrl.getBoundingClientRect();
        if (r.width < 4 || r.height < 4) {
          deadButtons.push({ selector: label, reason: `zero-or-tiny-hitbox:${Math.round(r.width)}x${Math.round(r.height)}` });
          continue;
        }
        if (cs.pointerEvents === "none") {
          deadButtons.push({ selector: label, reason: "pointer-events-none" });
          continue;
        }

        const targetId = ctrl.getAttribute("popovertarget") || ctrl.getAttribute("aria-controls");
        if (targetId && !document.getElementById(targetId)) {
          popoverDefects.push({ selector: label, reason: `missing-target:#${targetId}` });
          continue;
        }

        ctrl.scrollIntoView({ block: "nearest", inline: "nearest" });
        const cr = ctrl.getBoundingClientRect();
        const cx = cr.left + cr.width / 2;
        const cy = cr.top + cr.height / 2;
        if (cx >= 0 && cx <= vw && cy >= 0 && cy <= vh) {
          const hit = document.elementFromPoint(cx, cy);
          if (hit && !ctrl.contains(hit) && !hit.contains(ctrl)) {
            const hitCs = window.getComputedStyle(hit);
            if (hitCs.pointerEvents !== "none") {
              deadButtons.push({ selector: label, reason: `obscured-by:${selectorFor(hit)}` });
              continue;
            }
          }
        }

        let clickError = null;
        const onErr = (ev) => {
          clickError = ev && ev.message ? String(ev.message) : "uncaught-click-error";
          if (ev && ev.preventDefault) ev.preventDefault();
        };
        window.addEventListener("error", onErr);
        try {
          buttonsExercised += 1;
          ctrl.click();
        } catch (err) {
          clickError = String(err);
        }
        window.removeEventListener("error", onErr);
        if (clickError) {
          deadButtons.push({ selector: label, reason: `click-exception:${clickError}` });
          continue;
        }

        if (targetId) {
          const popEl = document.getElementById(targetId);
          if (popEl && isVisible(popEl)) {
            const pr = popEl.getBoundingClientRect();
            if (pr.left < -2 || pr.right > vw + 2) {
              popoverDefects.push({ selector: selectorFor(popEl), reason: "popover-clipped-outside-viewport" });
            }
            try { ctrl.click(); } catch (_) {}
          }
        }
        for (const dlg of document.querySelectorAll("dialog[open]")) {
          const dr = dlg.getBoundingClientRect();
          if (dr.left < -2 || dr.right > vw + 2) {
            popoverDefects.push({ selector: selectorFor(dlg), reason: "dialog-clipped-outside-viewport" });
          }
          try { dlg.close(); } catch (_) {}
        }
      }

      document.removeEventListener("submit", blockSubmit, true);
      document.removeEventListener("click", blockAnchorNav, true);
      window.open = origOpen;
      window.alert = origAlert;
      window.confirm = origConfirm;
      window.prompt = origPrompt;

      // Raw template / brace artifact check
      const bodyText = body ? (body.innerText || "") : "";
      const artifacts = [];
      if (bodyText.includes("{{") && bodyText.includes("}}")) {
        artifacts.push("unrendered-double-brace-template");
      }

      resolve({
        vw,
        vh,
        scrollWidth,
        scrollHeight,
        pageOverflow,
        pillOverflow,
        verticalOverflow,
        buttonsExercised,
        selectsChecked: selectEls.length,
        deadButtons,
        popoverDefects,
        selectGeometryDefects,
        artifacts,
        tableBroken: [],
        discoveredLinks,
        brokenFragmentLinks
      });
    }, 20);
  }));
}))()
"###;

/// Resolves a local Headless Chrome / Chromium executable without hardcoded user paths.
pub fn resolve_chromium_binary(explicit: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
        return Err(format!(
            "configured Chromium binary `{}` does not exist",
            p.display()
        ));
    }
    if let Ok(env_bin) = std::env::var("CHINWAG_CHROME_BIN") {
        let trimmed = env_bin.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if p.is_file() {
                return Ok(p);
            }
            return Err(format!(
                "CHINWAG_CHROME_BIN `{trimmed}` does not point to an executable file"
            ));
        }
    }
    let candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ];
    for c in candidates {
        let p = Path::new(c);
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for bin_name in [
                "chromium",
                "chromium-browser",
                "google-chrome",
                "google-chrome-stable",
            ] {
                let candidate = dir.join(bin_name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(
        "no headless Chromium/Chrome binary found (install Chrome/Chromium or set CHINWAG_CHROME_BIN)"
            .to_owned(),
    )
}

impl UiInspectorDriver for ChromiumCdpInspector {
    fn inspect_url(
        &self,
        target_url: &str,
        timeout_ms: u64,
    ) -> Result<Vec<UiAuditViewportRecordV1>, String> {
        let chrome_bin = resolve_chromium_binary(self.explicit_chrome_bin.as_deref())?;
        let base_tmp = fs::canonicalize(std::env::temp_dir())
            .map_err(|e| format!("canonicalize temp_dir: {e}"))?;
        let tmp_st = statat(CWD, &base_tmp, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| format!("stat temp_dir: {e}"))?;
        if FileType::from_raw_mode(tmp_st.st_mode) != FileType::Directory {
            return Err(format!(
                "refusing non-directory temp root `{}`",
                base_tmp.display()
            ));
        }
        let mut nonce = [0_u8; 8];
        rand::rng().fill_bytes(&mut nonce);
        let user_data_dir = base_tmp.join(format!(
            "chinwag-uigate-cdp-{}-{}",
            std::process::id(),
            hex_encode(&nonce)
        ));
        fs::create_dir(&user_data_dir)
            .map_err(|e| format!("create headless Chrome profile dir: {e}"))?;
        fs::set_permissions(&user_data_dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod 0700 Chrome profile dir: {e}"))?;
        let prof_st = statat(CWD, &user_data_dir, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| format!("stat Chrome profile dir: {e}"))?;
        if FileType::from_raw_mode(prof_st.st_mode) != FileType::Directory
            || (prof_st.st_mode & 0o777) != 0o700
        {
            let _ = fs::remove_dir_all(&user_data_dir);
            return Err("unsafe mode or type on headless Chrome profile directory".to_owned());
        }

        let mut cmd = Command::new(&chrome_bin);
        cmd.process_group(0)
            .args([
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--disable-breakpad",
                "--no-crash-upload",
                "--disable-extensions",
                "--disable-sync",
                "--hide-scrollbars",
                "--mute-audio",
                "--remote-debugging-port=0",
                "--window-size=1440,900",
            ])
            .arg(format!("--user-data-dir={}", user_data_dir.display()))
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            let _ = fs::remove_dir_all(&user_data_dir);
            format!(
                "failed to spawn headless Chromium `{}`: {e}",
                chrome_bin.display()
            )
        })?;

        let stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| "missing Chromium stderr pipe".to_owned())?;
        let _guard = HeadlessBrowserGuard {
            child,
            user_data_dir,
        };

        let (tx, rx) = mpsc::channel::<Result<String, String>>();
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr_pipe);
            let mut sent = false;
            for line in reader.lines() {
                match line {
                    Ok(text) => {
                        if !sent && let Some(idx) = text.find("ws://") {
                            let ws_url = text[idx..].trim().to_owned();
                            let _ = tx.send(Ok(ws_url));
                            sent = true;
                        }
                    }
                    Err(e) => {
                        if !sent {
                            let _ = tx.send(Err(format!("Chromium stderr read error: {e}")));
                            sent = true;
                        }
                        break;
                    }
                }
            }
            if !sent {
                let _ = tx.send(Err(
                    "Chromium exited before advertising DevTools WebSocket endpoint".to_owned(),
                ));
            }
        });

        let ws_url = rx
            .recv_timeout(Duration::from_millis(timeout_ms))
            .map_err(|_| {
                format!("timed out after {timeout_ms}ms waiting for Chromium DevTools endpoint")
            })??;

        let mut cdp = CdpSession::connect(&ws_url, timeout_ms)?;
        let create_res = cdp.call(None, "Target.createTarget", json!({ "url": "about:blank" }))?;
        let target_id = create_res
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing targetId in Target.createTarget: {create_res}"))?
            .to_owned();
        let attach_res = cdp.call(
            None,
            "Target.attachToTarget",
            json!({ "targetId": target_id, "flatten": true }),
        )?;
        let session_id = attach_res
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing sessionId in Target.attachToTarget: {attach_res}"))?
            .to_owned();

        let _ = cdp.call(Some(&session_id), "Page.enable", json!({}))?;
        let _ = cdp.call(Some(&session_id), "Runtime.enable", json!({}))?;
        let _ = cdp.call(Some(&session_id), "Network.enable", json!({}))?;
        let _ = cdp.call(
            Some(&session_id),
            "Network.setCacheDisabled",
            json!({ "cacheDisabled": true }),
        )?;

        let parsed_target = ParsedHttpUrl::parse(target_url)?;
        let mut records = Vec::with_capacity(MANDATORY_VIEWPORTS.len());

        for vp in MANDATORY_VIEWPORTS {
            cdp.reset_navigation_telemetry();
            let _ = cdp.call(
                Some(&session_id),
                "Emulation.setDeviceMetricsOverride",
                json!({
                    "width": vp.width,
                    "height": vp.height,
                    "deviceScaleFactor": if vp.mobile { 2 } else { 1 },
                    "mobile": vp.mobile,
                }),
            )?;
            let _ = cdp.call(
                Some(&session_id),
                "Emulation.setEmulatedMedia",
                json!({
                    "features": [
                        { "name": "prefers-color-scheme", "value": vp.color_scheme }
                    ]
                }),
            )?;
            let nav_res = cdp.call(
                Some(&session_id),
                "Page.navigate",
                json!({ "url": target_url }),
            )?;
            if let Some(err_text) = nav_res.get("errorText").and_then(Value::as_str) {
                return Err(format!(
                    "CDP navigation failed on `{target_url}` ({}): {err_text}",
                    vp.label
                ));
            }
            cdp.wait_for_page_load(&session_id, timeout_ms)?;

            let eval_res = cdp.call(
                Some(&session_id),
                "Runtime.evaluate",
                json!({
                    "expression": JS_VIEWPORT_AUDIT_SCRIPT,
                    "awaitPromise": true,
                    "returnByValue": true,
                }),
            )?;
            if let Some(exc) = eval_res.get("exceptionDetails") {
                return Err(format!(
                    "CDP audit script threw exception on `{}`: {exc}",
                    vp.label
                ));
            }
            let mut check_val = eval_res
                .get("result")
                .and_then(|r| r.get("value"))
                .cloned()
                .ok_or_else(|| format!("missing audit value from Runtime.evaluate: {eval_res}"))?;

            let mut discovered_links = Vec::new();
            let mut broken_links = Vec::new();
            if let Some(obj) = check_val.as_object_mut() {
                if let Some(arr) = obj.remove("discoveredLinks").and_then(|v| {
                    v.as_array().map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                }) {
                    discovered_links = arr;
                }
                if let Some(frag_arr) = obj
                    .remove("brokenFragmentLinks")
                    .and_then(|v| serde_json::from_value::<Vec<BrokenLinkRecordV1>>(v).ok())
                {
                    broken_links.extend(frag_arr);
                }
            }

            let status = cdp.main_document_status.unwrap_or(0);
            records.push(UiAuditViewportRecordV1 {
                path: parsed_target.path_only(),
                viewport: vp.label.to_owned(),
                color_scheme: vp.color_scheme.to_owned(),
                status,
                check: check_val,
                console: cdp.console_errors.clone(),
                pageerrors: cdp.page_errors.clone(),
                bad_requests: cdp.bad_requests.clone(),
                broken_links,
                discovered_links,
            });
        }

        Ok(records)
    }
}

// ============================================================================
// Pure-Rust RFC-6455 WebSocket + CDP Session Client (`#![forbid(unsafe_code)]`)
// ============================================================================

struct CdpSession {
    ws: WsClient,
    next_id: u64,
    main_document_status: Option<u16>,
    console_errors: Vec<String>,
    page_errors: Vec<String>,
    bad_requests: Vec<String>,
    page_loaded: bool,
}

impl CdpSession {
    fn connect(ws_url: &str, timeout_ms: u64) -> Result<Self, String> {
        let ws = WsClient::connect(ws_url, timeout_ms)?;
        Ok(Self {
            ws,
            next_id: 1,
            main_document_status: None,
            console_errors: Vec::new(),
            page_errors: Vec::new(),
            bad_requests: Vec::new(),
            page_loaded: false,
        })
    }

    fn reset_navigation_telemetry(&mut self) {
        self.main_document_status = None;
        self.console_errors.clear();
        self.page_errors.clear();
        self.bad_requests.clear();
        self.page_loaded = false;
    }

    fn call(
        &mut self,
        session_id: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut msg = json!({
            "id": id,
            "method": method,
            "params": params,
        });
        if let Some(sid) = session_id
            && let Some(obj) = msg.as_object_mut()
        {
            obj.insert("sessionId".to_owned(), Value::String(sid.to_owned()));
        }
        let encoded = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
        self.ws.send_text(&encoded)?;

        loop {
            let text = self.ws.read_text()?;
            let incoming: Value =
                serde_json::from_str(&text).map_err(|e| format!("invalid CDP JSON frame: {e}"))?;
            if incoming.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(err) = incoming.get("error") {
                    return Err(format!("CDP `{method}` error: {err}"));
                }
                return Ok(incoming.get("result").cloned().unwrap_or_else(|| json!({})));
            }
            self.record_event(&incoming);
        }
    }

    fn wait_for_page_load(&mut self, session_id: &str, timeout_ms: u64) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        while !self.page_loaded {
            if Instant::now() > deadline {
                return Err(format!(
                    "timed out after {timeout_ms}ms waiting for Page.loadEventFired"
                ));
            }
            let text = self.ws.read_text()?;
            let incoming: Value =
                serde_json::from_str(&text).map_err(|e| format!("invalid CDP event JSON: {e}"))?;
            if incoming.get("sessionId").and_then(Value::as_str) == Some(session_id)
                || incoming.get("sessionId").is_none()
            {
                self.record_event(&incoming);
            }
        }
        Ok(())
    }

    fn record_event(&mut self, incoming: &Value) {
        let Some(method) = incoming.get("method").and_then(Value::as_str) else {
            return;
        };
        let params = incoming.get("params").unwrap_or(&Value::Null);
        match method {
            "Page.loadEventFired" => {
                self.page_loaded = true;
            }
            "Network.responseReceived" => {
                let rtype = params.get("type").and_then(Value::as_str).unwrap_or("");
                let status = params
                    .get("response")
                    .and_then(|r| r.get("status"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u16;
                let url = params
                    .get("response")
                    .and_then(|r| r.get("url"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if rtype == "Document" && self.main_document_status.is_none() && status > 0 {
                    self.main_document_status = Some(status);
                }
                if status >= 400 && !url.ends_with("/favicon.ico") {
                    self.bad_requests.push(format!("{status} {url}"));
                }
            }
            "Runtime.exceptionThrown" => {
                let text = params
                    .get("exceptionDetails")
                    .and_then(|d| d.get("text"))
                    .and_then(Value::as_str)
                    .unwrap_or("uncaught page exception");
                self.page_errors.push(text.to_owned());
            }
            "Runtime.consoleAPICalled"
                if params.get("type").and_then(Value::as_str) == Some("error") =>
            {
                let summary = params
                    .get("args")
                    .and_then(Value::as_array)
                    .map(|args| {
                        args.iter()
                            .filter_map(|a| {
                                a.get("value")
                                    .and_then(Value::as_str)
                                    .or_else(|| a.get("description").and_then(Value::as_str))
                            })
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_else(|| "console.error".to_owned());
                self.console_errors.push(summary);
            }
            _ => {}
        }
    }
}

struct WsClient {
    stream: TcpStream,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl WsClient {
    fn connect(ws_url: &str, timeout_ms: u64) -> Result<Self, String> {
        let rest = ws_url
            .strip_prefix("ws://")
            .ok_or_else(|| format!("expected ws:// URL, got `{ws_url}`"))?;
        let (host_port, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        let addr: SocketAddr = host_port
            .to_socket_addrs()
            .map_err(|e| format!("resolve `{host_port}`: {e}"))?
            .next()
            .ok_or_else(|| format!("no socket address for `{host_port}`"))?;
        let timeout = Duration::from_millis(timeout_ms.max(1000));
        let mut stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| format!("connect WebSocket `{host_port}`: {e}"))?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        let _ = stream.set_nodelay(true);

        let mut key_raw = [0_u8; 16];
        rand::rng().fill_bytes(&mut key_raw);
        let sec_key = base64_encode(&key_raw);
        let expected_accept = websocket_accept_key(&sec_key);

        let handshake = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host_port}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {sec_key}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        stream
            .write_all(handshake.as_bytes())
            .map_err(|e| format!("write WebSocket handshake: {e}"))?;

        let mut header_acc = Vec::with_capacity(1024);
        let mut scratch = [0_u8; 1024];
        let header_end = loop {
            let n = stream
                .read(&mut scratch)
                .map_err(|e| format!("read WebSocket handshake: {e}"))?;
            if n == 0 {
                return Err("EOF during WebSocket HTTP 101 upgrade".to_owned());
            }
            header_acc.extend_from_slice(&scratch[..n]);
            if let Some(pos) = find_subslice(&header_acc, b"\r\n\r\n") {
                break pos + 4;
            }
            if header_acc.len() > 32 * 1024 {
                return Err("oversized WebSocket upgrade headers".to_owned());
            }
        };

        let header_text = String::from_utf8_lossy(&header_acc[..header_end]);
        let mut lines = header_text.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        if !status_line.starts_with("HTTP/1.1 101") {
            return Err(format!(
                "WebSocket upgrade rejected with status `{status_line}`"
            ));
        }
        let mut accept_ok = false;
        for line in lines {
            if let Some((k, v)) = line.split_once(':')
                && k.trim().eq_ignore_ascii_case("sec-websocket-accept")
                && v.trim() == expected_accept
            {
                accept_ok = true;
            }
        }
        if !accept_ok {
            return Err("WebSocket upgrade missing valid Sec-WebSocket-Accept header".to_owned());
        }

        let leftover = header_acc[header_end..].to_vec();
        Ok(Self {
            stream,
            read_buf: leftover,
            read_pos: 0,
        })
    }

    fn read_exact_buffered(&mut self, out: &mut [u8]) -> Result<(), String> {
        let mut written = 0;
        while written < out.len() {
            if self.read_pos < self.read_buf.len() {
                let avail = self.read_buf.len() - self.read_pos;
                let take = avail.min(out.len() - written);
                out[written..written + take]
                    .copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + take]);
                self.read_pos += take;
                written += take;
                if self.read_pos == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
            } else {
                let n = self
                    .stream
                    .read(&mut out[written..])
                    .map_err(|e| format!("WebSocket read error: {e}"))?;
                if n == 0 {
                    return Err("WebSocket closed unexpectedly".to_owned());
                }
                written += n;
            }
        }
        Ok(())
    }

    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let mut header = Vec::with_capacity(14);
        header.push(0x80 | (opcode & 0x0f));
        let len = payload.len();
        if len <= 125 {
            header.push(0x80 | (len as u8));
        } else if len <= 65_535 {
            header.push(0x80 | 126);
            header.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            header.push(0x80 | 127);
            header.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mut mask = [0_u8; 4];
        rand::rng().fill_bytes(&mut mask);
        header.extend_from_slice(&mask);

        let mut masked = Vec::with_capacity(header.len() + payload.len());
        masked.extend_from_slice(&header);
        for (i, &b) in payload.iter().enumerate() {
            masked.push(b ^ mask[i & 3]);
        }
        self.stream
            .write_all(&masked)
            .map_err(|e| format!("WebSocket write error: {e}"))
    }

    fn send_text(&mut self, text: &str) -> Result<(), String> {
        self.send_frame(0x1, text.as_bytes())
    }

    fn read_text(&mut self) -> Result<String, String> {
        let mut message = Vec::new();
        loop {
            let mut hdr = [0_u8; 2];
            self.read_exact_buffered(&mut hdr)?;
            let fin = (hdr[0] & 0x80) != 0;
            let opcode = hdr[0] & 0x0f;
            let masked = (hdr[1] & 0x80) != 0;
            let len_code = (hdr[1] & 0x7f) as usize;
            let payload_len = if len_code == 126 {
                let mut ext = [0_u8; 2];
                self.read_exact_buffered(&mut ext)?;
                u16::from_be_bytes(ext) as usize
            } else if len_code == 127 {
                let mut ext = [0_u8; 8];
                self.read_exact_buffered(&mut ext)?;
                let raw = u64::from_be_bytes(ext);
                if raw > 64 * 1024 * 1024 {
                    return Err("WebSocket frame exceeds 64 MiB safety cap".to_owned());
                }
                raw as usize
            } else {
                len_code
            };
            let mut mask = [0_u8; 4];
            if masked {
                self.read_exact_buffered(&mut mask)?;
            }
            let mut payload = vec![0_u8; payload_len];
            if payload_len > 0 {
                self.read_exact_buffered(&mut payload)?;
                if masked {
                    for (i, b) in payload.iter_mut().enumerate() {
                        *b ^= mask[i & 3];
                    }
                }
            }
            match opcode {
                0x1 | 0x0 => {
                    message.extend_from_slice(&payload);
                    if fin {
                        return String::from_utf8(message)
                            .map_err(|e| format!("invalid UTF-8 in WebSocket text frame: {e}"));
                    }
                }
                0x8 => return Err("WebSocket closed by browser".to_owned()),
                0x9 => {
                    let _ = self.send_frame(0xA, &payload);
                }
                0xA => {}
                other => {
                    if fin && message.is_empty() {
                        return Err(format!("unexpected WebSocket opcode 0x{other:x}"));
                    }
                }
            }
        }
    }
}

// ============================================================================
// HTTP `<a href>` Link & Target Preflight Inspector
// ============================================================================

#[derive(Debug, Clone)]
struct ParsedHttpUrl {
    is_tls: bool,
    host: String,
    port: u16,
    path_and_query: String,
}

impl ParsedHttpUrl {
    fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        let (is_tls, rest) = if let Some(r) = trimmed.strip_prefix("http://") {
            (false, r)
        } else if let Some(r) = trimmed.strip_prefix("https://") {
            (true, r)
        } else {
            return Err(format!(
                "unsupported URL `{trimmed}`: expected `http://` or `https://`"
            ));
        };
        let without_frag = rest.split('#').next().unwrap_or(rest);
        let (authority, path_and_query) = match without_frag.find('/') {
            Some(idx) => (&without_frag[..idx], &without_frag[idx..]),
            None => (without_frag, "/"),
        };
        if authority.is_empty() {
            return Err(format!("missing host in URL `{trimmed}`"));
        }
        let default_port = if is_tls { 443 } else { 80 };
        let (host, port) = if authority.starts_with('[') {
            if let Some(end_bracket) = authority.find(']') {
                let h = &authority[..=end_bracket];
                let after = &authority[end_bracket + 1..];
                if let Some(p_str) = after.strip_prefix(':') {
                    let p = p_str
                        .parse::<u16>()
                        .map_err(|_| format!("invalid port in `{trimmed}`"))?;
                    (h.to_owned(), p)
                } else {
                    (h.to_owned(), default_port)
                }
            } else {
                return Err(format!("unclosed IPv6 host in `{trimmed}`"));
            }
        } else if let Some((h, p_str)) = authority.rsplit_once(':') {
            let p = p_str
                .parse::<u16>()
                .map_err(|_| format!("invalid port in `{trimmed}`"))?;
            (h.to_owned(), p)
        } else {
            (authority.to_owned(), default_port)
        };
        Ok(Self {
            is_tls,
            host,
            port,
            path_and_query: if path_and_query.is_empty() {
                "/".to_owned()
            } else {
                path_and_query.to_owned()
            },
        })
    }

    fn path_only(&self) -> String {
        self.path_and_query
            .split('?')
            .next()
            .unwrap_or("/")
            .to_owned()
    }

    fn origin(&self) -> String {
        let scheme = if self.is_tls { "https" } else { "http" };
        let default_port = if self.is_tls { 443 } else { 80 };
        if self.port == default_port {
            format!("{scheme}://{}", self.host)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }
}

/// Checks an `http://` or `https://` URL and returns its final HTTP status code (following up to 5 redirects).
pub fn check_http_url_status(url: &str, timeout_ms: u64) -> Result<u16, String> {
    let mut current = url.trim().to_owned();
    for _hop in 0..=5 {
        let parsed = ParsedHttpUrl::parse(&current)?;
        if parsed.is_tls {
            return check_https_via_curl(&current, timeout_ms);
        }
        let host_lookup = parsed.host.trim_matches(|c| c == '[' || c == ']');
        let addr = (host_lookup, parsed.port)
            .to_socket_addrs()
            .map_err(|e| format!("resolve `{}`: {e}", parsed.host))?
            .next()
            .ok_or_else(|| format!("no address for `{}`", parsed.host))?;
        let timeout = Duration::from_millis(timeout_ms.clamp(500, 15_000));
        let mut stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| format!("connect `{}:{}`: {e}", parsed.host, parsed.port))?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        let host_hdr = if parsed.port == 80 {
            parsed.host.clone()
        } else {
            format!("{}:{}", parsed.host, parsed.port)
        };
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: chinwag-ui-gate/1.0\r\nAccept: text/html,*/*\r\nConnection: close\r\n\r\n",
            parsed.path_and_query
        );
        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("write HTTP request to `{current}`: {e}"))?;

        let mut resp_buf = Vec::with_capacity(2048);
        let mut chunk = [0_u8; 1024];
        loop {
            let n = stream
                .read(&mut chunk)
                .map_err(|e| format!("read HTTP response from `{current}`: {e}"))?;
            if n == 0 {
                break;
            }
            resp_buf.extend_from_slice(&chunk[..n]);
            if find_subslice(&resp_buf, b"\r\n\r\n").is_some() || resp_buf.len() >= 8192 {
                break;
            }
        }
        let header_str = String::from_utf8_lossy(&resp_buf);
        let mut lines = header_str.lines();
        let status_line = lines
            .next()
            .ok_or_else(|| format!("empty HTTP response from `{current}`"))?;
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| format!("malformed HTTP status line `{status_line}`"))?;

        if matches!(status_code, 301 | 302 | 303 | 307 | 308) {
            let mut location: Option<String> = None;
            for line in lines {
                if line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':')
                    && k.trim().eq_ignore_ascii_case("location")
                {
                    location = Some(v.trim().to_owned());
                    break;
                }
            }
            if let Some(loc) = location {
                current = if loc.starts_with("http://") || loc.starts_with("https://") {
                    loc
                } else if loc.starts_with('/') {
                    format!("{}{}", parsed.origin(), loc)
                } else {
                    format!("{}/{}", parsed.origin(), loc)
                };
                continue;
            }
        }
        return Ok(status_code);
    }
    Err(format!("too many HTTP redirects for `{url}`"))
}

fn check_https_via_curl(url: &str, timeout_ms: u64) -> Result<u16, String> {
    let max_secs = (timeout_ms / 1000).clamp(2, 20).to_string();
    let curl_bin = std::env::var("CHINWAG_CURL_BIN")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "curl".to_owned());
    let output = Command::new(curl_bin)
        .args([
            "-sS",
            "-L",
            "--max-redirs",
            "5",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--connect-timeout",
            "5",
            "--max-time",
            &max_secs,
            "--proto",
            "=http,https",
            "--proto-redir",
            "=http,https",
            "-A",
            "chinwag-ui-gate/1.0",
            "--",
            url,
        ])
        .output()
        .map_err(|e| format!("invoke curl for `{url}`: {e}"))?;
    let code_str = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let status = code_str.parse::<u16>().unwrap_or(0);
    if status == 0 {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(format!("HTTPS link `{url}` unreachable: {stderr}"));
    }
    Ok(status)
}

// ============================================================================
// Fail-Closed Static + Audit JSON Validator (`UiGateSurface`)
// ============================================================================

const FORBIDDEN_PER_SEAT_STRINGS: &[&str] = &[
    "$24/seat",
    "$16/seat",
    "$60/seat",
    "$36/seat",
    "per human seat",
    "per agent seat",
    "/seat/mo",
];

#[derive(Default)]
struct AuditSummary {
    html_files_scanned: usize,
    markdown_files_scanned: usize,
    audit_records_verified: usize,
    desktop_1440x900_records: usize,
    mobile_390x844_records: usize,
    interactive_controls_verified: usize,
    links_verified: usize,
    violations: Vec<UiGateViolationV1>,
}

fn is_desktop_1440x900(rec: &Value) -> bool {
    let vw = rec
        .get("check")
        .and_then(|c| c.get("vw"))
        .and_then(Value::as_u64);
    let vh = rec
        .get("check")
        .and_then(|c| c.get("vh"))
        .and_then(Value::as_u64);
    matches!((vw, vh), (Some(1440), Some(900)))
}

fn is_mobile_390x844(rec: &Value) -> bool {
    let vw = rec
        .get("check")
        .and_then(|c| c.get("vw"))
        .and_then(Value::as_u64);
    let vh = rec
        .get("check")
        .and_then(|c| c.get("vh"))
        .and_then(Value::as_u64);
    matches!((vw, vh), (Some(390), Some(844)))
}

fn scan_static_repo(repo_dir: &Path, surface: UiGateSurface, summary: &mut AuditSummary) {
    if surface == UiGateSurface::LocalApp || !repo_dir.is_dir() {
        return;
    }
    let mut stack = vec![repo_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if ft.is_dir() {
                if matches!(
                    name.as_str(),
                    ".git" | "target" | "node_modules" | ".next" | "dist" | ".chinwag"
                ) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if matches!(ext.as_str(), "html" | "htm") {
                summary.html_files_scanned += 1;
            } else if matches!(ext.as_str(), "md" | "mdx") {
                summary.markdown_files_scanned += 1;
            } else {
                continue;
            }
            if let Ok(text) = fs::read_to_string(&path) {
                let lower = text.to_ascii_lowercase();
                for forbidden in FORBIDDEN_PER_SEAT_STRINGS {
                    if lower.contains(&forbidden.to_ascii_lowercase()) {
                        summary.violations.push(UiGateViolationV1 {
                            invariant: "INV-CREDIT-ONLY-PRICING-01".to_owned(),
                            target: path.display().to_string(),
                            detail: format!("forbidden pricing copy `{forbidden}`"),
                        });
                    }
                }
            }
        }
    }
}

fn verify_ui_audit_report_v1_raw_map(obj: &serde_json::Map<String, Value>) -> Result<(), String> {
    let schema = obj
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `schema` in UiAuditReportV1 object".to_owned())?;
    if schema != "UiAuditReportV1" {
        return Err(format!(
            "unexpected schema `{schema}`, expected `UiAuditReportV1`"
        ));
    }
    let url = obj
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `url` in UiAuditReportV1".to_owned())?;
    let ticket_id = obj
        .get("ticket_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `ticket_id` in UiAuditReportV1".to_owned())?;
    let generated_at_unix = obj
        .get("generated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing `generated_at_unix` in UiAuditReportV1".to_owned())?;
    let links_verified = obj
        .get("links_verified")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing `links_verified` in UiAuditReportV1".to_owned())?;
    let broken_links = obj
        .get("broken_links")
        .ok_or_else(|| "missing `broken_links` in UiAuditReportV1".to_owned())?;
    let records = obj
        .get("records")
        .ok_or_else(|| "missing `records` in UiAuditReportV1".to_owned())?;
    let payload_sha256_hex = obj
        .get("payload_sha256_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `payload_sha256_hex` in UiAuditReportV1".to_owned())?;
    let pk_hex = obj
        .get("runner_ed25519_pk_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `runner_ed25519_pk_hex` in UiAuditReportV1".to_owned())?;
    let sig_hex = obj
        .get("runner_ed25519_sig_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `runner_ed25519_sig_hex` in UiAuditReportV1".to_owned())?;

    let unsigned = json!({
        "broken_links": broken_links,
        "generated_at_unix": generated_at_unix,
        "links_verified": links_verified,
        "records": records,
        "schema": "UiAuditReportV1",
        "ticket_id": ticket_id,
        "url": url,
    });
    let canonical = crate::regression_ratchet::to_rfc8785_jcs_string(&unsigned)?.into_bytes();
    let expected_sha = hex_encode(&Sha256::digest(&canonical));
    if payload_sha256_hex != expected_sha {
        return Err("UiAuditReportV1 payload_sha256_hex mismatch".to_owned());
    }
    let pk_bytes = hex_decode_exact::<32>(pk_hex)
        .map_err(|e| format!("invalid runner_ed25519_pk_hex: {e}"))?;
    let sig_bytes = hex_decode_exact::<64>(sig_hex)
        .map_err(|e| format!("invalid runner_ed25519_sig_hex: {e}"))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("invalid Ed25519 verifying key: {e}"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(&canonical, &sig)
        .map_err(|e| format!("UiAuditReportV1 Ed25519 signature invalid: {e}"))
}

fn evaluate_audit_value(
    parsed: &Value,
    surface: UiGateSurface,
    source_label: &str,
    summary: &mut AuditSummary,
) -> Result<(), String> {
    let records: &[Value] = if let Some(arr) = parsed.as_array() {
        if matches!(surface, UiGateSurface::LocalApp | UiGateSurface::All) {
            summary.violations.push(UiGateViolationV1 {
                invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                target: source_label.to_owned(),
                detail: "fail-closed: unsigned top-level JSON array rejected on local-app/all; signed `UiAuditReportV1` object required".to_owned(),
            });
        }
        arr.as_slice()
    } else if let Some(obj) = parsed.as_object() {
        if let Err(sig_err) = verify_ui_audit_report_v1_raw_map(obj) {
            summary.violations.push(UiGateViolationV1 {
                invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                target: source_label.to_owned(),
                detail: format!("UiAuditReportV1 signature verification failed: {sig_err}"),
            });
        }
        if let Some(lc) = obj.get("links_verified").and_then(Value::as_u64) {
            summary.links_verified += lc as usize;
        }
        if let Some(broken) = obj.get("broken_links").and_then(Value::as_array) {
            for link in broken {
                summary.violations.push(UiGateViolationV1 {
                    invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                    target: format!("{source_label}:links"),
                    detail: format!("broken `<a href>` link: {link}"),
                });
            }
        }
        obj.get("records")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or_else(|| format!("missing `records` array in `{source_label}`"))?
    } else {
        return Err(format!(
            "expected `UiAuditReportV1` object or JSON array in `{source_label}`"
        ));
    };

    for (idx, rec) in records.iter().enumerate() {
        summary.audit_records_verified += 1;
        let path = rec
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let vp = rec
            .get("viewport")
            .and_then(Value::as_str)
            .unwrap_or("desktop");
        if is_desktop_1440x900(rec) {
            summary.desktop_1440x900_records += 1;
        } else if is_mobile_390x844(rec) {
            summary.mobile_390x844_records += 1;
        }
        let target = format!("{source_label}[{idx}]:{vp}:{path}");
        let status = rec.get("status").and_then(Value::as_u64).unwrap_or(0);
        if status != 200 {
            summary.violations.push(UiGateViolationV1 {
                invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                target: target.clone(),
                detail: format!("HTTP status {status}, expected 200"),
            });
        }
        let Some(check) = rec.get("check").and_then(Value::as_object) else {
            summary.violations.push(UiGateViolationV1 {
                invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                target,
                detail: "missing `check` geometry object".to_owned(),
            });
            continue;
        };
        if let Some(vw) = check.get("vw").and_then(Value::as_u64)
            && let Some(sw) = check.get("scrollWidth").and_then(Value::as_u64)
            && sw > vw + 1
        {
            summary.violations.push(UiGateViolationV1 {
                invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                target: target.clone(),
                detail: format!("horizontal viewport overflow: scrollWidth ({sw}) > vw ({vw})"),
            });
        }
        if check.get("pageOverflow") == Some(&Value::Bool(true)) {
            summary.violations.push(UiGateViolationV1 {
                invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                target: target.clone(),
                detail: "check.pageOverflow flagged horizontal overflow".to_owned(),
            });
        }
        for key in ["pillOverflow", "verticalOverflow", "elementOverflow"] {
            if let Some(arr) = check.get(key).and_then(Value::as_array)
                && !arr.is_empty()
            {
                summary.violations.push(UiGateViolationV1 {
                    invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                    target: target.clone(),
                    detail: format!("`check.{key}` reported {} overflow defect(s)", arr.len()),
                });
            }
        }
        if let Some(cnt) = check.get("buttonsExercised").and_then(Value::as_u64) {
            summary.interactive_controls_verified += cnt as usize;
        }
        if let Some(cnt) = check.get("selectsChecked").and_then(Value::as_u64) {
            summary.interactive_controls_verified += cnt as usize;
        }
        for key in [
            "deadButtons",
            "interactiveDefects",
            "popoverDefects",
            "selectGeometryDefects",
        ] {
            if let Some(arr) = check.get(key).and_then(Value::as_array)
                && !arr.is_empty()
            {
                summary.violations.push(UiGateViolationV1 {
                    invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                    target: target.clone(),
                    detail: format!(
                        "`check.{key}` reported {} control/inset defect(s): {}",
                        arr.len(),
                        arr[0]
                    ),
                });
            }
        }
        if let Some(broken) = check
            .get("brokenLinks")
            .and_then(Value::as_array)
            .or_else(|| rec.get("brokenLinks").and_then(Value::as_array))
            && !broken.is_empty()
        {
            summary.violations.push(UiGateViolationV1 {
                invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                target: target.clone(),
                detail: format!(
                    "detected {} broken `<a href>` link(s): {}",
                    broken.len(),
                    broken[0]
                ),
            });
        }
        for err_key in ["console", "pageerrors", "badRequests"] {
            if let Some(arr) = rec.get(err_key).and_then(Value::as_array)
                && !arr.is_empty()
            {
                summary.violations.push(UiGateViolationV1 {
                    invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                    target: target.clone(),
                    detail: format!(
                        "`{err_key}` reported {} runtime/network error(s)",
                        arr.len()
                    ),
                });
            }
        }
        if let Some(artifacts) = check.get("artifacts").and_then(Value::as_array)
            && !artifacts.is_empty()
        {
            summary.violations.push(UiGateViolationV1 {
                invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                target,
                detail: format!("raw template artifacts detected ({})", artifacts.len()),
            });
        }
    }
    Ok(())
}

fn mint_signed_receipt(
    surface: UiGateSurface,
    ticket_id: &str,
    commit_sha: &str,
    org_id_hash: &str,
    repo_label: &str,
    summary: AuditSummary,
) -> Result<UiGateReceiptV1, String> {
    let signer = EphemeralGateSigner::generate()?;
    let passed = summary.violations.is_empty();
    let doc_hash = hex_encode(&Sha256::digest(
        format!(
            "{org_id_hash}:{ticket_id}:{}:{commit_sha}",
            surface.as_str()
        )
        .as_bytes(),
    ));
    let mut receipt = UiGateReceiptV1 {
        ok: passed,
        schema: "UiGateReceiptV1".to_owned(),
        command: "chinwag ui-gate".to_owned(),
        document_id: format!("uigate-{}", &doc_hash[..16]),
        org_id_hash: org_id_hash.to_owned(),
        ticket_id: ticket_id.to_owned(),
        surface: surface.as_str().to_owned(),
        commit_sha: commit_sha.to_owned(),
        repo_path: repo_label.to_owned(),
        host_arch: std::env::consts::ARCH.to_owned(),
        passed,
        html_files_scanned: summary.html_files_scanned,
        markdown_files_scanned: summary.markdown_files_scanned,
        audit_records_verified: summary.audit_records_verified,
        desktop_1440x900_records: summary.desktop_1440x900_records,
        mobile_390x844_records: summary.mobile_390x844_records,
        interactive_controls_verified: summary.interactive_controls_verified,
        links_verified: summary.links_verified,
        invariants_verified: vec![
            INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
            INV_UI_GEOMETRY_GATE.to_owned(),
        ],
        violations: summary.violations,
        artifacts_git_ref: format!("refs/chinwag/artifacts/{ticket_id}"),
        payload_sha256_hex: String::new(),
        runner_ed25519_pk_hex: signer.pk_hex(),
        runner_ed25519_sig_hex: String::new(),
    };
    let canonical = receipt.canonical_signing_bytes()?;
    receipt.payload_sha256_hex = hex_encode(&Sha256::digest(&canonical));
    let sig = signer.sign(&canonical);
    receipt.runner_ed25519_sig_hex = hex_encode(&sig.to_bytes());
    receipt.verify_signature()?;
    Ok(receipt)
}

/// Runs a full live `--url` inspection with a custom or production [`UiInspectorDriver`],
/// verifies HTTP `200` on every discovered `<a href>` link, writes `UiAuditReportV1` when
/// `out_audit_path` is set, and returns `(UiAuditReportV1, UiGateReceiptV1)`.
#[allow(clippy::too_many_arguments)]
pub fn inspect_and_gate_url(
    driver: &dyn UiInspectorDriver,
    url: &str,
    out_audit_path: Option<&Path>,
    surface: UiGateSurface,
    ticket_id: &str,
    commit_sha: &str,
    org_id_hash: &str,
    timeout_ms: u64,
) -> Result<(UiAuditReportV1, UiGateReceiptV1), String> {
    let preflight_status = check_http_url_status(url, timeout_ms.min(5_000))
        .map_err(|e| format!("target URL `{url}` unreachable on preflight: {e}"))?;
    if preflight_status != 200 {
        return Err(format!(
            "target URL `{url}` returned HTTP {preflight_status} on preflight (expected 200)"
        ));
    }

    let mut records = driver.inspect_url(url, timeout_ms)?;

    let mut unique_links = BTreeSet::new();
    for rec in &records {
        for link in &rec.discovered_links {
            unique_links.insert(link.clone());
        }
    }

    let mut global_broken_links = Vec::new();
    for href in &unique_links {
        match check_http_url_status(href, timeout_ms.min(8_000)) {
            Ok(200) => {}
            Ok(code) => {
                global_broken_links.push(BrokenLinkRecordV1 {
                    href: href.clone(),
                    status: code,
                    reason: format!("HTTP {code} (expected 200)"),
                });
            }
            Err(err) => {
                global_broken_links.push(BrokenLinkRecordV1 {
                    href: href.clone(),
                    status: 0,
                    reason: err,
                });
            }
        }
    }

    for rec in &mut records {
        let mut per_rec_broken = rec.broken_links.clone();
        for gb in &global_broken_links {
            if rec.discovered_links.contains(&gb.href)
                && !per_rec_broken.iter().any(|b| b.href == gb.href)
            {
                per_rec_broken.push(gb.clone());
            }
        }
        let links_checked_here = rec.discovered_links.len();
        rec.broken_links.clone_from(&per_rec_broken);
        rec.discovered_links.clear();
        if let Some(obj) = rec.check.as_object_mut() {
            obj.insert(
                "linksChecked".to_owned(),
                Value::from(links_checked_here as u64),
            );
            obj.insert(
                "brokenLinks".to_owned(),
                serde_json::to_value(&per_rec_broken).unwrap_or_else(|_| json!([])),
            );
        }
    }

    let mut all_broken = global_broken_links;
    for rec in &records {
        for bl in &rec.broken_links {
            if !all_broken.iter().any(|b| b.href == bl.href) {
                all_broken.push(bl.clone());
            }
        }
    }

    let report =
        UiAuditReportV1::build_signed(url, ticket_id, unique_links.len(), all_broken, records)?;

    if let Some(out_path) = out_audit_path {
        let encoded = serde_json::to_string_pretty(&report)
            .map_err(|e| format!("serialize UiAuditReportV1: {e}"))?;
        crate::regression_ratchet::write_regular_file_atomic(
            out_path,
            format!("{encoded}\n").as_bytes(),
        )?;
    }

    let report_val =
        serde_json::to_value(&report).map_err(|e| format!("to_value UiAuditReportV1: {e}"))?;
    let mut summary = AuditSummary::default();
    evaluate_audit_value(&report_val, surface, url, &mut summary)?;
    enforce_dual_viewport(&mut summary, url);
    let receipt = mint_signed_receipt(surface, ticket_id, commit_sha, org_id_hash, url, summary)?;
    Ok((report, receipt))
}

fn enforce_dual_viewport(summary: &mut AuditSummary, target_label: &str) {
    if summary.desktop_1440x900_records == 0 {
        summary.violations.push(UiGateViolationV1 {
            invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
            target: target_label.to_owned(),
            detail: "fail-closed: 0 `1440x900` desktop viewport records verified".to_owned(),
        });
    }
    if summary.mobile_390x844_records == 0 {
        summary.violations.push(UiGateViolationV1 {
            invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
            target: target_label.to_owned(),
            detail: "fail-closed: 0 `390x844` mobile viewport records verified".to_owned(),
        });
    }
}

/// CLI entrypoint for `chinwag ui-gate`.
pub fn run_ui_gate(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let driver = ChromiumCdpInspector::default();
    run_ui_gate_with_driver(&driver, args, stdout, stderr)
}

/// Testable CLI entrypoint accepting any [`UiInspectorDriver`].
pub fn run_ui_gate_with_driver(
    driver: &dyn UiInspectorDriver,
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let mut url_arg: Option<String> = None;
    let mut out_arg: Option<PathBuf> = None;
    let mut receipt_out_arg: Option<PathBuf> = None;
    let mut surface_arg: Option<UiGateSurface> = None;
    let mut repo_arg: Option<PathBuf> = None;
    let mut audit_json_arg: Option<String> = None;
    let mut ticket_id = "CHWG-0251".to_owned();
    let mut commit_sha = "HEAD".to_owned();
    let mut org_hash = "local-org".to_owned();
    let mut timeout_ms: u64 = 20_000;
    let mut is_json = false;

    let mut i = 0;
    while i < args.len() {
        let raw = args[i].as_str();
        if matches!(raw, "--help" | "-h") {
            let _ = writeln!(
                stdout,
                "Usage: chinwag ui-gate [--url <http(s)://...>] [--out <audit.json>] [--surface <local-app|site|docs|all>] [--audit-json <path>] [--repo <path>] [--ticket <id>] [--json]"
            );
            return 0;
        }
        if raw == "--json" {
            is_json = true;
            i += 1;
            continue;
        }
        let (flag, val) = if let Some((f, v)) = raw.split_once('=') {
            i += 1;
            (f, v.to_owned())
        } else if i + 1 < args.len() {
            let v = args[i + 1].clone();
            i += 2;
            (raw, v)
        } else {
            return emit_refusal(
                is_json,
                &format!("missing value for `{raw}`; not gate evidence"),
                stdout,
                stderr,
            );
        };
        match flag {
            "--url" | "-u" => url_arg = Some(val),
            "--out" | "-o" => out_arg = Some(PathBuf::from(val)),
            "--receipt-out" => receipt_out_arg = Some(PathBuf::from(val)),
            "--surface" => match UiGateSurface::parse(&val) {
                Ok(s) => surface_arg = Some(s),
                Err(e) => return emit_refusal(is_json, &e, stdout, stderr),
            },
            "--repo" => repo_arg = Some(PathBuf::from(val)),
            "--audit-json" => audit_json_arg = Some(val),
            "--ticket" => ticket_id = val,
            "--commit" => commit_sha = val,
            "--org" | "--org-hash" => {
                let trimmed = val.trim();
                org_hash = if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    trimmed.to_ascii_lowercase()
                } else {
                    hex_encode(&Sha256::digest(trimmed.as_bytes()))
                };
            }
            "--timeout-ms" => {
                timeout_ms = val.parse::<u64>().unwrap_or(20_000);
            }
            other => {
                return emit_refusal(
                    is_json,
                    &format!("unknown flag `{other}`; not gate evidence"),
                    stdout,
                    stderr,
                );
            }
        }
    }

    // Mode A: Live `--url <url>` inspection via Headless Chromium CDP + HTTP link inspector
    if let Some(ref url) = url_arg {
        let surface = surface_arg.unwrap_or(UiGateSurface::LocalApp);
        match inspect_and_gate_url(
            driver,
            url,
            out_arg.as_deref(),
            surface,
            &ticket_id,
            &commit_sha,
            &org_hash,
            timeout_ms,
        ) {
            Ok((_report, receipt)) => {
                if let Some(ref rpath) = receipt_out_arg {
                    let enc = serde_json::to_string_pretty(&receipt).unwrap_or_default();
                    if let Err(e) = crate::regression_ratchet::write_regular_file_atomic(
                        rpath,
                        format!("{enc}\n").as_bytes(),
                    ) {
                        return emit_refusal(is_json, &e, stdout, stderr);
                    }
                }
                return finish_receipt_output(&receipt, is_json, stdout, stderr);
            }
            Err(err) => {
                return emit_refusal(is_json, &err, stdout, stderr);
            }
        }
    }

    // Mode B: Offline `--surface` / `--audit-json` validation
    if surface_arg.is_some() || audit_json_arg.is_some() {
        let surface = surface_arg.unwrap_or(UiGateSurface::LocalApp);
        let repo_dir = repo_arg.unwrap_or_else(|| PathBuf::from("."));
        let repo_label = repo_dir.display().to_string();
        let mut summary = AuditSummary::default();
        scan_static_repo(&repo_dir, surface, &mut summary);

        let audit_paths: Vec<PathBuf> = if let Some(ref raw) = audit_json_arg {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect()
        } else {
            let candidate = repo_dir.join(".chinwag/ui-audit-results.json");
            if crate::regression_ratchet::ensure_regular_file_no_follow(&candidate).is_ok() {
                vec![candidate]
            } else {
                Vec::new()
            }
        };

        let require_dual_viewport = matches!(surface, UiGateSurface::LocalApp | UiGateSurface::All)
            || audit_json_arg.is_some();

        if audit_paths.is_empty() && require_dual_viewport {
            summary.violations.push(UiGateViolationV1 {
                invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                target: repo_label.clone(),
                detail: "fail-closed: 0 `1440x900` desktop and 0 `390x844` mobile records verified"
                    .to_owned(),
            });
        } else {
            for apath in &audit_paths {
                if let Err(fs_err) = crate::regression_ratchet::ensure_regular_file_no_follow(apath)
                {
                    return emit_refusal(is_json, &fs_err, stdout, stderr);
                }
                let raw = match fs::read_to_string(apath) {
                    Ok(s) => s,
                    Err(e) => {
                        return emit_refusal(
                            is_json,
                            &format!("unable to read `{}`: {e}", apath.display()),
                            stdout,
                            stderr,
                        );
                    }
                };
                let parsed: Value = match serde_json::from_str(&raw) {
                    Ok(v) => v,
                    Err(e) => {
                        return emit_refusal(
                            is_json,
                            &format!("invalid JSON in `{}`: {e}", apath.display()),
                            stdout,
                            stderr,
                        );
                    }
                };
                if let Err(e) = evaluate_audit_value(
                    &parsed,
                    surface,
                    &apath.display().to_string(),
                    &mut summary,
                ) {
                    return emit_refusal(is_json, &e, stdout, stderr);
                }
            }
            if require_dual_viewport {
                enforce_dual_viewport(&mut summary, &repo_label);
            }
        }

        match mint_signed_receipt(
            surface,
            &ticket_id,
            &commit_sha,
            &org_hash,
            &repo_label,
            summary,
        ) {
            Ok(receipt) => {
                if let Some(ref opath) = out_arg {
                    let enc = serde_json::to_string_pretty(&receipt).unwrap_or_default();
                    if let Err(e) = crate::regression_ratchet::write_regular_file_atomic(
                        opath,
                        format!("{enc}\n").as_bytes(),
                    ) {
                        return emit_refusal(is_json, &e, stdout, stderr);
                    }
                }
                return finish_receipt_output(&receipt, true, stdout, stderr);
            }
            Err(e) => return emit_refusal(is_json, &e, stdout, stderr),
        }
    }

    // Mode C: Neither `--url` nor `--surface`/`--audit-json` -> fail closed with zero pass text!
    emit_refusal(is_json, MISSING_TARGET_REFUSAL, stdout, stderr)
}

fn finish_receipt_output(
    receipt: &UiGateReceiptV1,
    emit_json_stdout: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    if receipt.passed {
        if emit_json_stdout {
            if let Ok(enc) = serde_json::to_string_pretty(receipt) {
                let _ = writeln!(stdout, "{enc}");
            }
        } else {
            let _ = writeln!(
                stdout,
                "chinwag ui-gate: verified {} desktop (1440x900) + {} mobile (390x844) records, {} controls, {} links",
                receipt.desktop_1440x900_records,
                receipt.mobile_390x844_records,
                receipt.interactive_controls_verified,
                receipt.links_verified
            );
        }
        0
    } else {
        if emit_json_stdout && let Ok(enc) = serde_json::to_string_pretty(receipt) {
            let _ = writeln!(stdout, "{enc}");
        }
        for v in &receipt.violations {
            let _ = writeln!(
                stderr,
                "chinwag ui-gate FAILED [{}] {}: {}",
                v.invariant, v.target, v.detail
            );
        }
        1
    }
}

fn emit_refusal(is_json: bool, reason: &str, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if is_json {
        let refusal = json!({
            "ok": false,
            "passed": false,
            "command": "chinwag ui-gate",
            "error": reason,
        });
        let _ = writeln!(stdout, "{refusal}");
    }
    let _ = writeln!(stderr, "chinwag: {reason}");
    1
}

// ============================================================================
// Pure-Rust SHA-1 (RFC 3174) + Base64 (RFC 4648) + Hex Helpers for RFC-6455
// ============================================================================

fn websocket_accept_key(sec_key: &str) -> String {
    let mut input = Vec::with_capacity(sec_key.len() + 36);
    input.extend_from_slice(sec_key.as_bytes());
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64_encode(&sha1_digest(&input))
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0_u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let b = &chunk[i * 4..i * 4 + 4];
            *word = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), 0x5A82_7999_u32)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9_EBA1_u32)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDC_u32)
            } else {
                (b ^ c ^ d, 0xCA62_C1D6_u32)
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0_u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode_exact<const N: usize>(raw: &str) -> Result<[u8; N], String> {
    if raw.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, raw.len()));
    }
    let mut out = [0_u8; N];
    let bytes = raw.as_bytes();
    for (idx, slot) in out.iter_mut().enumerate() {
        let hi = decode_nibble(bytes[idx * 2])?;
        let lo = decode_nibble(bytes[idx * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn decode_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex byte 0x{b:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> (u8, String, String) {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_ui_gate(&args, &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn rfc6455_websocket_accept_vector_matches_spec() {
        assert_eq!(
            websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn missing_or_unreachable_target_fails_closed_without_pass_text() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = listener.local_addr().unwrap().port();
        drop(listener);
        let dead_url = format!("http://127.0.0.1:{closed_port}");

        for args in [
            vec![],
            vec!["--url", dead_url.as_str()],
            vec!["--ticket", "CHWG-0251"],
            vec!["--json", "--ticket", "CHWG-0251"],
        ] {
            let (code, out, err) = run(&args);
            assert_eq!(code, 1, "{args:?}");
            assert!(!err.is_empty());
            for forbidden in ["Passed", "✅", "● Brian", "actor", "\"ok\":true", "true"] {
                assert!(!out.contains(forbidden), "{args:?}: {out}");
            }
        }
    }

    #[test]
    fn surface_audit_json_fails_closed_on_missing_mobile_and_passes_dual_viewport() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("index.html"),
            "<!DOCTYPE html><html><body><h1>Credit-Only</h1></body></html>",
        )
        .unwrap();

        // 1. Desktop-only audit JSON MUST fail closed (`0` 390x844 mobile records)
        let desktop_only = dir.path().join("desktop-only.json");
        std::fs::write(
            &desktop_only,
            r#"[{"path":"/","viewport":"desktop","status":200,"check":{"vw":1440,"vh":900,"scrollWidth":1440,"pageOverflow":false,"artifacts":[],"tableBroken":[]},"console":[],"pageerrors":[],"badRequests":[]}]"#,
        )
        .unwrap();
        let (code_fail, out_fail, _err_fail) = run(&[
            "--surface",
            "site",
            "--repo",
            dir.path().to_str().unwrap(),
            "--audit-json",
            desktop_only.to_str().unwrap(),
            "--ticket",
            "CHWG-0251",
            "--json",
        ]);
        assert_eq!(code_fail, 1);
        let val_fail: Value = serde_json::from_str(out_fail.trim()).unwrap();
        assert_eq!(val_fail["ok"], false);
        assert_eq!(val_fail["passed"], false);

        // 2. Dual-viewport (1440x900 desktop + 390x844 mobile) passes and mints signed UiGateReceiptV1
        let dual_audit = dir.path().join("dual-audit.json");
        std::fs::write(
            &dual_audit,
            r#"[
              {"path":"/","viewport":"desktop-light","status":200,"check":{"vw":1440,"vh":900,"scrollWidth":1440,"pageOverflow":false,"artifacts":[],"tableBroken":[]},"console":[],"pageerrors":[],"badRequests":[]},
              {"path":"/","viewport":"mobile","status":200,"check":{"vw":390,"vh":844,"scrollWidth":390,"pageOverflow":false,"artifacts":[],"tableBroken":[]},"console":[],"pageerrors":[],"badRequests":[]}
            ]"#,
        )
        .unwrap();
        let (code_ok, out_ok, _err_ok) = run(&[
            "--surface",
            "site",
            "--repo",
            dir.path().to_str().unwrap(),
            "--audit-json",
            dual_audit.to_str().unwrap(),
            "--ticket",
            "CHWG-0251",
            "--json",
        ]);
        assert_eq!(code_ok, 0);
        let receipt: UiGateReceiptV1 = serde_json::from_str(out_ok.trim()).unwrap();
        assert!(receipt.ok);
        assert!(receipt.passed);
        assert_eq!(receipt.desktop_1440x900_records, 1);
        assert_eq!(receipt.mobile_390x844_records, 1);
        receipt.verify_signature().unwrap();
    }
}

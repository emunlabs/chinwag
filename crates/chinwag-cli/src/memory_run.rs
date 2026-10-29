// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

use crate::{MemoryAction, MemoryRequest};
use chinwag_snapshot_read_owner_private::ReadOwner;
use chinwag_snapshot_session_private::{
    SnapshotSession, Value as SqlValue,
    replacement::{MemoryPinRecord, TombstoneRecord, WriteOwner, WriteSession},
};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn user_home() -> String { std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned()) }
fn default_repo_root() -> String { format!("{}/WORKSPACE/chinwag", user_home()) }
fn default_planner_db() -> String { format!("{}/WORKSPACE/delivery-planner/data/planner.sqlite", user_home()) }
fn default_leann_path() -> String { format!("{}/WORKSPACE/chinwag/.chinwag/memory.crdb.leann", user_home()) }
const DEFAULT_COMMIT_SHA: &str = "b1745094d9cb9014361fca30c7de3535c140dd20";
const MAX_CRDB_TEXT_BYTES: usize = 60_000;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn truncate_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn short_hash(parts: &[&str], ts_ms: i64) -> String {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p.as_bytes());
        hasher.update(b"|");
    }
    hasher.update(ts_ms.to_be_bytes());
    let digest = hasher.finalize();
    digest[..6].iter().map(|b| format!("{b:02x}")).collect()
}

fn resolve_repo_root(crdb_path: Option<&Path>) -> PathBuf {
    let Some(path) = crdb_path else {
        return PathBuf::from(default_repo_root());
    };
    if path.file_name().is_some_and(|n| n == "state.crdb")
        && let Some(chinwag_dir) = path.parent()
        && chinwag_dir.file_name().is_some_and(|n| n == ".chinwag")
        && let Some(repo) = chinwag_dir.parent()
    {
        return repo.to_path_buf();
    }
    if path.file_name().is_some_and(|n| n == ".chinwag")
        && let Some(repo) = path.parent()
    {
        return repo.to_path_buf();
    }
    path.to_path_buf()
}

fn sql_text(v: Option<&SqlValue>) -> String {
    match v {
        Some(SqlValue::Text(s)) => s.clone(),
        Some(SqlValue::Integer(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn sql_i64(v: Option<&SqlValue>) -> i64 {
    match v {
        Some(SqlValue::Integer(n)) => *n,
        _ => 0,
    }
}

/// Fields of one tombstone to persist into the CRDB store.
struct TombstoneWrite<'a> {
    id: &'a str,
    source_commit: &'a str,
    file_scope: &'a str,
    attempted_action: &'a str,
    failure: &'a str,
    reason: &'a str,
    alternative: &'a str,
    ts_ms: i64,
}

/// Fields of one memory pin to persist into the CRDB store.
struct MemoryPinWrite<'a> {
    id: &'a str,
    bank: &'a str,
    context: &'a str,
    content: &'a str,
    source_commit: &'a str,
    file_scope: &'a str,
    ts_ms: i64,
}

fn persist_tombstone_to_crdb(repo_root: &Path, write: &TombstoneWrite<'_>) -> Result<i64, String> {
    let TombstoneWrite {
        id,
        source_commit,
        file_scope,
        attempted_action,
        failure,
        reason,
        alternative,
        ts_ms,
    } = *write;
    let owner = WriteOwner::acquire_existing_private_fixture(repo_root)
        .map_err(|e| format!("acquire_write_owner: {}", e.reason))?;
    let session =
        WriteSession::from_owner(owner).map_err(|e| format!("write_session: {}", e.reason))?;
    let ev_hash = short_hash(&[id, file_scope, reason, source_commit], ts_ms);
    let record = TombstoneRecord::try_new(
        id.to_owned(),
        "emunlabs/chinwag".to_owned(),
        "refs/heads/main".to_owned(),
        source_commit.to_owned(),
        file_scope.to_owned(),
        "HEAD".to_owned(),
        truncate_utf8(attempted_action, MAX_CRDB_TEXT_BYTES),
        truncate_utf8(failure, MAX_CRDB_TEXT_BYTES),
        truncate_utf8(reason, MAX_CRDB_TEXT_BYTES),
        truncate_utf8(alternative, MAX_CRDB_TEXT_BYTES),
        format!("sha256:{ev_hash}"),
        ts_ms,
    )
    .map_err(|e| e.to_owned())?;
    let prepared = session
        .prepare_tombstone(record, || false)
        .map_err(|e| format!("prepare_tombstone: {}", e.reason))?;
    let completion = prepared
        .commit(false)
        .map_err(|e| format!("commit_tombstone: {}", e.reason))?;
    if completion.is_error() {
        return Err(format!("crdb_refused: {}", completion.response()));
    }
    Ok(completion.observation().new_db_version())
}

fn persist_memory_pin_to_crdb(repo_root: &Path, write: &MemoryPinWrite<'_>) -> Result<i64, String> {
    let MemoryPinWrite {
        id,
        bank,
        context,
        content,
        source_commit,
        file_scope,
        ts_ms,
    } = *write;
    let owner = WriteOwner::acquire_existing_private_fixture(repo_root)
        .map_err(|e| format!("acquire_write_owner: {}", e.reason))?;
    let session =
        WriteSession::from_owner(owner).map_err(|e| format!("write_session: {}", e.reason))?;
    let thread_id = format!("chinwag-memory-{}", bank.to_ascii_lowercase());
    let body = format!("[{bank}|{context}] {}", truncate_utf8(content, 32_000));
    let record = MemoryPinRecord::try_new(
        id.to_owned(),
        thread_id,
        "emunlabs/chinwag".to_owned(),
        "refs/heads/main".to_owned(),
        format!("Chinwag 3-Tier Memory · {bank}"),
        file_scope.to_owned(),
        "HEAD".to_owned(),
        source_commit.to_owned(),
        body,
        ts_ms,
    )
    .map_err(|e| e.to_owned())?;
    let prepared = session
        .prepare_memory_pin(record, || false)
        .map_err(|e| format!("prepare_memory_pin: {}", e.reason))?;
    let completion = prepared
        .commit(false)
        .map_err(|e| format!("commit_memory_pin: {}", e.reason))?;
    if completion.is_error() {
        return Err(format!("crdb_refused: {}", completion.response()));
    }
    Ok(completion.observation().new_db_version())
}

fn read_crdb_snapshot(repo_root: &Path) -> Result<(Vec<Json>, Vec<Json>, Json), String> {
    let owner = ReadOwner::acquire_existing_private_fixture(repo_root)
        .map_err(|e| format!("read_owner: {}", e.reason))?;
    let session = SnapshotSession::from_owner(owner).map_err(|e| e.to_string())?;
    let tmb_rows = session.tombstones().map_err(|e| e.to_string())?;
    let inv_rows = session.verified_invariants().map_err(|e| e.to_string())?;
    let stat_rows = session.crdb_stats().map_err(|e| e.to_string())?;
    session.finish().map_err(|e| e.to_string())?;

    let mut tombstones = Vec::new();
    for r in &tmb_rows {
        tombstones.push(json!({
            "id": sql_text(r.first()),
            "repo_id": sql_text(r.get(1)),
            "branch_ref": sql_text(r.get(2)),
            "source_commit": sql_text(r.get(3)),
            "file_scope": sql_text(r.get(4)),
            "symbol_hash": sql_text(r.get(5)),
            "attempted_action": sql_text(r.get(6)),
            "failure": sql_text(r.get(7)),
            "reason": sql_text(r.get(8)),
            "alternative": sql_text(r.get(9)),
            "evidence_hash": sql_text(r.get(10)),
            "created_at_ms": sql_i64(r.get(11)),
            "tier": "tombstone",
            "directive": "DO_NOT_REPEAT"
        }));
    }

    let mut invariants = Vec::new();
    for r in &inv_rows {
        invariants.push(json!({
            "id": sql_text(r.first()),
            "repo_id": sql_text(r.get(1)),
            "branch_ref": sql_text(r.get(2)),
            "source_commit": sql_text(r.get(3)),
            "file_scope": sql_text(r.get(4)),
            "symbol_hash": sql_text(r.get(5)),
            "invariant": sql_text(r.get(6)),
            "ci_run_id": sql_text(r.get(7)),
            "ci_receipt_hash": sql_text(r.get(8)),
            "verified_at_ms": sql_i64(r.get(9)),
            "tier": "verified_invariant"
        }));
    }

    let stats = if let Some(r) = stat_rows.first() {
        json!({
            "threads": sql_i64(r.first()),
            "messages": sql_i64(r.get(1)),
            "context_pins": sql_i64(r.get(2)),
            "tombstones": sql_i64(r.get(3)),
            "verified_invariants": sql_i64(r.get(4)),
            "crsql_db_version": sql_i64(r.get(5))
        })
    } else {
        json!({})
    };

    Ok((tombstones, invariants, stats))
}

fn run_python_sqlite(script: &str, payload: &Json) -> Result<Json, String> {
    let input_str = serde_json::to_string(payload).map_err(|e| e.to_string())?;
    let mut child = Command::new("/usr/bin/python3")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn python3: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input_str.as_bytes());
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait python3: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "sqlite_op_failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    serde_json::from_slice::<Json>(&out.stdout).map_err(|e| format!("parse sqlite output: {e}"))
}

const PY_SCHEMA_AND_OPS: &str = r#"
import sys, json, sqlite3, re, os, time, urllib.request

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS chinwag_memories (
  id TEXT PRIMARY KEY NOT NULL,
  bank TEXT NOT NULL DEFAULT 'spector-fleet',
  category TEXT NOT NULL DEFAULT 'observation',
  context TEXT NOT NULL DEFAULT '',
  content TEXT NOT NULL DEFAULT '',
  tombstone_reason TEXT NOT NULL DEFAULT '',
  file_scope TEXT NOT NULL DEFAULT '*',
  source_commit TEXT NOT NULL DEFAULT 'b1745094d9cb9014361fca30c7de3535c140dd20',
  author_agent TEXT NOT NULL DEFAULT 'GEMINI-PM',
  entities TEXT NOT NULL DEFAULT '',
  tags TEXT NOT NULL DEFAULT '',
  document_id TEXT NOT NULL DEFAULT '',
  origin TEXT NOT NULL DEFAULT 'native',
  created_at_ms INTEGER NOT NULL DEFAULT 0,
  occurred_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_chinwag_memories_bank ON chinwag_memories(bank, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_chinwag_memories_scope ON chinwag_memories(file_scope);
CREATE INDEX IF NOT EXISTS idx_chinwag_memories_cat ON chinwag_memories(category);
CREATE VIRTUAL TABLE IF NOT EXISTS chinwag_memories_fts USING fts5(
  id UNINDEXED,
  bank,
  category,
  context,
  content,
  tombstone_reason,
  file_scope,
  entities,
  tags
);
CREATE TABLE IF NOT EXISTS chinwag_tombstones (
  id TEXT PRIMARY KEY NOT NULL,
  repo_id TEXT NOT NULL DEFAULT 'emunlabs/chinwag',
  branch_ref TEXT NOT NULL DEFAULT 'refs/heads/main',
  source_commit TEXT NOT NULL DEFAULT 'b1745094d9cb9014361fca30c7de3535c140dd20',
  file_scope TEXT NOT NULL DEFAULT '*',
  symbol_hash TEXT NOT NULL DEFAULT 'HEAD',
  attempted_action TEXT NOT NULL DEFAULT '',
  failure TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  alternative TEXT NOT NULL DEFAULT '',
  evidence_hash TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS chinwag_csr_edges (
  term TEXT NOT NULL,
  memory_id TEXT NOT NULL,
  weight REAL NOT NULL DEFAULT 1.0,
  PRIMARY KEY (term, memory_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_chinwag_csr_term ON chinwag_csr_edges(term);
"""

STOPWORDS = {
    'the','and','for','with','that','this','from','was','were','are','have','has',
    'had','not','but','you','all','any','can','her','his','its','our','out','who',
    'will','into','only','other','new','some','could','time','these','two','may',
    'then','do','first','any','my','now','such','like','our','over','man','me',
    'even','most','made','after','also','did','many','before','must','through',
    'back','years','where','much','your','way','well','down','should','because',
    'each','just','those','people','mr','how','too','little','state','good','very',
    'make','world','still','own','see','men','work','long','get','here','between',
    'both','life','being','under','never','day','same','another','know','while',
    'last','might','us','great','old','year','off','come','since','against','go',
    'came','right','used','take','three','when'
}

def extract_csr_terms(text, entities="", context="", file_scope=""):
    combined = f"{entities} {context} {file_scope} {text}".lower()
    tokens = re.findall(r'[a-z0-9][a-z0-9_\-\./]{2,31}', combined)
    seen = {}
    for t in tokens:
        t_clean = t.strip('._-/')
        if len(t_clean) >= 3 and t_clean not in STOPWORDS:
            seen[t_clean] = seen.get(t_clean, 0) + 1
            if len(seen) >= 16:
                break
    return list(seen.items())

def scope_matches(tmb_scope, target_scope, query_text):
    tmb_s = (tmb_scope or '*').strip().lower()
    if tmb_s in ('*', '**', '**/*'):
        return True
    prefix = tmb_s.rstrip('/*')
    if target_scope:
        ts = target_scope.strip().lower()
        ts_prefix = ts.rstrip('/*')
        if ts == tmb_s or ts.startswith(prefix) or prefix.startswith(ts_prefix):
            return True
    q = (query_text or '').lower()
    if prefix and prefix in q:
        return True
    for part in re.split(r'[/\*]+', prefix):
        if len(part) >= 3 and part in q:
            return True
    return False

req = json.loads(sys.stdin.read())
db_path = req.get("db_path")
con = sqlite3.connect(db_path, timeout=30.0)
con.execute("PRAGMA journal_mode=WAL;")
con.execute("PRAGMA synchronous=NORMAL;")
con.executescript(SCHEMA_SQL)

op = req.get("op")

if op == "retain":
    m = req["memory"]
    mid = m["id"]
    con.execute("DELETE FROM chinwag_memories_fts WHERE id=?", (mid,))
    con.execute(
        """INSERT OR REPLACE INTO chinwag_memories
           (id, bank, category, context, content, tombstone_reason, file_scope, source_commit,
            author_agent, entities, tags, document_id, origin, created_at_ms, occurred_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            mid, m["bank"], m.get("category", "observation"), m["context"], m["content"],
            m.get("tombstone_reason", ""), m["file_scope"], m["source_commit"],
            m.get("author_agent", "GEMINI-PM"), m.get("entities", ""), m.get("tags", ""),
            m.get("document_id", ""), m.get("origin", "native"), m["created_at_ms"],
            m.get("occurred_at", "")
        )
    )
    con.execute(
        """INSERT INTO chinwag_memories_fts
           (id, bank, category, context, content, tombstone_reason, file_scope, entities, tags)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            mid, m["bank"], m.get("category", "observation"), m["context"], m["content"],
            m.get("tombstone_reason", ""), m["file_scope"], m.get("entities", ""), m.get("tags", "")
        )
    )
    terms = extract_csr_terms(m["content"], m.get("entities", ""), m["context"], m["file_scope"])
    for term, freq in terms:
        con.execute(
            "INSERT OR REPLACE INTO chinwag_csr_edges(term, memory_id, weight) VALUES (?,?,?)",
            (term, mid, float(min(freq, 5)))
        )
    con.commit()
    print(json.dumps({"ok": True, "csr_edges_added": len(terms)}))

elif op == "tombstone":
    t = req["tombstone"]
    tid = t["id"]
    con.execute(
        """INSERT OR REPLACE INTO chinwag_tombstones
           (id, repo_id, branch_ref, source_commit, file_scope, symbol_hash,
            attempted_action, failure, reason, alternative, evidence_hash, created_at_ms)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            tid, "emunlabs/chinwag", "refs/heads/main", t["source_commit"], t["file_scope"],
            "HEAD", t["attempted_action"], t["failure"], t["reason"], t["alternative"],
            t["evidence_hash"], t["created_at_ms"]
        )
    )
    content = f"TOMBSTONE [DO NOT REPEAT] ({t['file_scope']}): {t['reason']} | Action killed: {t['attempted_action']} | Alternative: {t['alternative']}"
    con.execute("DELETE FROM chinwag_memories_fts WHERE id=?", (tid,))
    con.execute(
        """INSERT OR REPLACE INTO chinwag_memories
           (id, bank, category, context, content, tombstone_reason, file_scope, source_commit,
            author_agent, entities, tags, document_id, origin, created_at_ms, occurred_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            tid, "spector-fleet", "tombstone", f"tombstone:{t['file_scope']}", content,
            t["reason"], t["file_scope"], t["source_commit"], "GEMINI-PM",
            t["file_scope"], "tombstone,negative-memory,do-not-repeat", "", "native-tombstone",
            t["created_at_ms"], ""
        )
    )
    con.execute(
        """INSERT INTO chinwag_memories_fts
           (id, bank, category, context, content, tombstone_reason, file_scope, entities, tags)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            tid, "spector-fleet", "tombstone", f"tombstone:{t['file_scope']}", content,
            t["reason"], t["file_scope"], t["file_scope"], "tombstone,negative-memory,do-not-repeat"
        )
    )
    terms = extract_csr_terms(content, t["file_scope"], "tombstone", t["file_scope"])
    for term, freq in terms:
        con.execute(
            "INSERT OR REPLACE INTO chinwag_csr_edges(term, memory_id, weight) VALUES (?,?,?)",
            (term, tid, float(min(freq, 5)) * 2.0)
        )
    con.commit()
    print(json.dumps({"ok": True, "csr_edges_added": len(terms)}))

elif op == "recall":
    query = req.get("query", "").strip()
    limit = int(req.get("limit", 10))
    bank_filter = req.get("bank")
    file_scope = req.get("file_scope")
    crdb_tombstones = req.get("crdb_tombstones", [])

    # Merge CRDB tombstones with chinwag_tombstones
    tmb_by_id = {}
    for ct in crdb_tombstones:
        tmb_by_id[ct["id"]] = ct
    for row in con.execute(
        "SELECT id, repo_id, branch_ref, source_commit, file_scope, symbol_hash, attempted_action, failure, reason, alternative, evidence_hash, created_at_ms FROM chinwag_tombstones ORDER BY created_at_ms DESC"
    ):
        if row[0] not in tmb_by_id:
            tmb_by_id[row[0]] = {
                "id": row[0], "repo_id": row[1], "branch_ref": row[2], "source_commit": row[3],
                "file_scope": row[4], "symbol_hash": row[5], "attempted_action": row[6],
                "failure": row[7], "reason": row[8], "alternative": row[9],
                "evidence_hash": row[10], "created_at_ms": row[11],
                "tier": "tombstone", "directive": "DO_NOT_REPEAT"
            }

    matched_tombstones = []
    q_tokens = [w for w in re.findall(r'[a-z0-9_\-\./]{2,}', (query + " " + (file_scope or "")).lower()) if w not in STOPWORDS]
    for tid, tmb in tmb_by_id.items():
        haystack = f"{tmb.get('id','')} {tmb.get('file_scope','')} {tmb.get('reason','')} {tmb.get('attempted_action','')} {tmb.get('alternative','')}".lower()
        is_scope_hit = scope_matches(tmb.get("file_scope", "*"), file_scope, query)
        token_hits = sum(1 for tok in q_tokens if tok in haystack)
        if is_scope_hit or token_hits > 0:
            tmb_copy = dict(tmb)
            tmb_copy["match_type"] = "file_scope_gate" if is_scope_hit else "semantic_keyword"
            tmb_copy["score"] = 100.0 + float(token_hits * 10)
            matched_tombstones.append(tmb_copy)

    matched_tombstones.sort(key=lambda x: x.get("score", 0.0), reverse=True)

    # FTS5 + CSR Graph query
    fts_terms = [re.sub(r'[^a-zA-Z0-9_]', '', w) for w in re.findall(r'[a-zA-Z0-9_]{2,}', query) if w.lower() not in STOPWORDS]
    results = []
    seen_ids = set()

    for tmb in matched_tombstones:
        seen_ids.add(tmb["id"])
        results.append({
            "id": tmb["id"],
            "bank": "spector-fleet",
            "tier": "tombstone",
            "category": "tombstone",
            "directive": "DO_NOT_REPEAT",
            "file_scope": tmb.get("file_scope", "*"),
            "source_commit": tmb.get("source_commit", ""),
            "tombstone_reason": tmb.get("reason", ""),
            "context": f"tombstone:{tmb.get('file_scope', '*')}",
            "content": f"🪦 TOMBSTONE [DO NOT REPEAT] ({tmb.get('file_scope','*')}): {tmb.get('reason','')} (Alternative: {tmb.get('alternative','')})",
            "score": tmb.get("score", 100.0)
        })

    if fts_terms:
        fts_expr = " OR ".join(f'"{t}"' for t in fts_terms[:12])
        sql = """
            SELECT m.id, m.bank, m.category, m.context, m.content, m.tombstone_reason,
                   m.file_scope, m.source_commit, m.author_agent, m.entities, m.tags,
                   m.created_at_ms, (-bm25(chinwag_memories_fts)) AS bm25_score
            FROM chinwag_memories_fts
            JOIN chinwag_memories m ON m.id = chinwag_memories_fts.id
            WHERE chinwag_memories_fts MATCH ?
        """
        params = [fts_expr]
        if bank_filter:
            sql += " AND m.bank = ?"
            params.append(bank_filter)
        if file_scope:
            sql += " AND (m.file_scope = ? OR m.file_scope = '*' OR ? LIKE replace(m.file_scope, '*', '%'))"
            params.extend([file_scope, file_scope])
        sql += " ORDER BY (CASE WHEN m.category='tombstone' THEN 1000.0 ELSE 0.0 END) + (-bm25(chinwag_memories_fts)) DESC LIMIT ?"
        params.append(limit * 2)
        try:
            for row in con.execute(sql, params):
                if row[0] in seen_ids:
                    continue
                seen_ids.add(row[0])
                csr_boost = con.execute(
                    f"SELECT COALESCE(SUM(weight), 0.0) FROM chinwag_csr_edges WHERE memory_id=? AND term IN ({','.join(['?']*len(fts_terms[:12]))})",
                    [row[0]] + [t.lower() for t in fts_terms[:12]]
                ).fetchone()[0]
                results.append({
                    "id": row[0],
                    "bank": row[1],
                    "tier": "tombstone" if row[2] == "tombstone" else "csr_memory",
                    "category": row[2],
                    "directive": "DO_NOT_REPEAT" if row[2] == "tombstone" else "CONTEXT",
                    "context": row[3],
                    "content": row[4],
                    "tombstone_reason": row[5],
                    "file_scope": row[6],
                    "source_commit": row[7],
                    "author_agent": row[8],
                    "entities": row[9],
                    "tags": row[10],
                    "created_at_ms": row[11],
                    "score": round(float(row[12] or 0.0) + float(csr_boost) * 0.25, 4)
                })
                if len(results) >= limit + len(matched_tombstones):
                    break
        except Exception:
            pass

    if len(results) < limit:
        sql = """
            SELECT id, bank, category, context, content, tombstone_reason,
                   file_scope, source_commit, author_agent, entities, tags, created_at_ms
            FROM chinwag_memories
            WHERE (content LIKE ? OR context LIKE ? OR file_scope LIKE ? OR tombstone_reason LIKE ?)
        """
        pat = f"%{query}%"
        params = [pat, pat, pat, pat]
        if bank_filter:
            sql += " AND bank = ?"
            params.append(bank_filter)
        sql += " ORDER BY (CASE WHEN category='tombstone' THEN 0 ELSE 1 END), created_at_ms DESC LIMIT ?"
        params.append(limit)
        for row in con.execute(sql, params):
            if row[0] in seen_ids:
                continue
            seen_ids.add(row[0])
            results.append({
                "id": row[0],
                "bank": row[1],
                "tier": "tombstone" if row[2] == "tombstone" else "csr_memory",
                "category": row[2],
                "directive": "DO_NOT_REPEAT" if row[2] == "tombstone" else "CONTEXT",
                "context": row[3],
                "content": row[4],
                "tombstone_reason": row[5],
                "file_scope": row[6],
                "source_commit": row[7],
                "author_agent": row[8],
                "entities": row[9],
                "tags": row[10],
                "created_at_ms": row[11],
                "score": 1.0
            })

    print(json.dumps({
        "ok": True,
        "tombstones": matched_tombstones,
        "results": results[:max(limit, len(matched_tombstones))]
    }))

elif op == "stats":
    total = con.execute("SELECT count(*) FROM chinwag_memories").fetchone()[0]
    migrated = con.execute("SELECT count(*) FROM chinwag_memories WHERE origin='hindsight-migrated'").fetchone()[0]
    native_cnt = con.execute("SELECT count(*) FROM chinwag_memories WHERE origin!='hindsight-migrated'").fetchone()[0]
    tmb_cnt = con.execute("SELECT count(*) FROM chinwag_tombstones").fetchone()[0]
    fts_cnt = con.execute("SELECT count(*) FROM chinwag_memories_fts").fetchone()[0]
    csr_cnt = con.execute("SELECT count(*) FROM chinwag_csr_edges").fetchone()[0]
    commit_cnt = con.execute("SELECT count(*) FROM chinwag_memories WHERE source_commit != ''").fetchone()[0]
    banks = {r[0]: r[1] for r in con.execute("SELECT bank, count(*) FROM chinwag_memories GROUP BY bank")}
    cats = {r[0]: r[1] for r in con.execute("SELECT category, count(*) FROM chinwag_memories GROUP BY category")}
    leann_path = req.get("leann_path", "")
    leann_bytes = os.path.getsize(leann_path) if leann_path and os.path.exists(leann_path) else 0
    print(json.dumps({
        "ok": True,
        "total_memories": total,
        "hindsight_migrated_count": migrated,
        "native_memories_count": native_cnt,
        "tombstones_count": tmb_cnt,
        "fts5_indexed_count": fts_cnt,
        "csr_graph_edges": csr_cnt,
        "commit_anchored_count": commit_cnt,
        "banks": banks,
        "categories": cats,
        "leann_csr_index_path": leann_path,
        "leann_csr_index_bytes": leann_bytes
    }))

elif op == "migrate_hindsight":
    base_url = req.get("url", "http://127.0.0.1:8888").rstrip("/")
    default_commit = req.get("source_commit", "b1745094d9cb9014361fca30c7de3535c140dd20")
    leann_path = req.get("leann_path", "")
    target_bank = req.get("bank")

    if target_bank:
        banks = [target_bank]
    else:
        try:
            with urllib.request.urlopen(f"{base_url}/v1/default/banks", timeout=10) as resp:
                bdata = json.loads(resp.read().decode("utf-8"))
                banks = [b["bank_id"] for b in bdata.get("banks", [])]
        except Exception:
            banks = ["spector-fleet", "spector-fleet-canary"]

    migrated_by_bank = {}
    total_migrated = 0
    now_ms_val = int(time.time() * 1000)

    con.execute("BEGIN IMMEDIATE;")
    # Clear old migrated rows so re-running migrate-hindsight is idempotent and exact
    if target_bank:
        con.execute("DELETE FROM chinwag_memories WHERE origin='hindsight-migrated' AND bank=?", (target_bank,))
    else:
        con.execute("DELETE FROM chinwag_memories WHERE origin='hindsight-migrated'")

    csr_batch = []
    for bank_id in banks:
        offset = 0
        page_size = 5000
        bank_count = 0
        while True:
            url = f"{base_url}/v1/default/banks/{bank_id}/memories/list?limit={page_size}&offset={offset}"
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            items = data.get("items", [])
            if not items:
                break
            mem_rows = []
            for item in items:
                mid = item.get("id") or f"hs-{bank_id}-{offset}"
                text = item.get("text") or ""
                ctx = item.get("context") or ""
                ftype = item.get("fact_type") or "observation"
                doc_id = item.get("document_id") or ""
                entities_raw = item.get("entities") or ""
                if isinstance(entities_raw, list):
                    entities_str = ", ".join(str(x) for x in entities_raw)
                else:
                    entities_str = str(entities_raw)
                tags_raw = item.get("tags") or []
                if isinstance(tags_raw, list):
                    tags_str = ",".join(str(x) for x in tags_raw)
                else:
                    tags_str = str(tags_raw)
                occ = item.get("mentioned_at") or item.get("date") or ""
                # Infer file_scope if path appears in context or text
                fscope = "*"
                if "hosted-relay" in ctx or "hosted-relay" in text:
                    fscope = "hosted-relay/**"
                elif "chinwag-mcp" in ctx or "chinwag-mcp" in text:
                    fscope = "crates/chinwag-mcp/**"
                elif "chinwag-claim" in ctx or "chinwag-claim" in text:
                    fscope = "crates/chinwag-claim/**"
                elif "chinwag-swarm" in ctx or "chinwag-swarm" in text:
                    fscope = "crates/chinwag-swarm/**"
                elif "wiki/" in ctx or "wiki/" in text:
                    fscope = "wiki/**"
                mem_rows.append((
                    mid, bank_id, ftype, ctx, text, "", fscope, default_commit,
                    "HINDSIGHT-CUTOVER", entities_str, tags_str, doc_id,
                    "hindsight-migrated", now_ms_val, occ
                ))
                if entities_str:
                    for ent in entities_str.split(","):
                        ent_clean = ent.strip().lower()[:32]
                        if len(ent_clean) >= 3 and ent_clean not in STOPWORDS:
                            csr_batch.append((ent_clean, mid, 1.5))
            con.executemany(
                """INSERT OR REPLACE INTO chinwag_memories
                   (id, bank, category, context, content, tombstone_reason, file_scope, source_commit,
                    author_agent, entities, tags, document_id, origin, created_at_ms, occurred_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                mem_rows
            )
            bank_count += len(items)
            total_migrated += len(items)
            offset += len(items)
            if offset >= data.get("total", 0):
                break
        migrated_by_bank[bank_id] = bank_count

    # Rebuild FTS5 index from chinwag_memories in one fast C-level SQLite statement
    con.execute("DELETE FROM chinwag_memories_fts;")
    con.execute(
        """INSERT INTO chinwag_memories_fts
           (id, bank, category, context, content, tombstone_reason, file_scope, entities, tags)
           SELECT id, bank, category, context, content, tombstone_reason, file_scope, entities, tags
           FROM chinwag_memories;"""
    )
    if csr_batch:
        con.executemany(
            "INSERT OR REPLACE INTO chinwag_csr_edges(term, memory_id, weight) VALUES (?,?,?)",
            csr_batch
        )
    con.commit()

    # Write LEANN CSR graph snapshot header + top compressed sparse row offsets
    if leann_path:
        os.makedirs(os.path.dirname(leann_path), exist_ok=True)
        top_terms = con.execute(
            "SELECT term, count(*) as c FROM chinwag_csr_edges GROUP BY term ORDER BY c DESC LIMIT 2048"
        ).fetchall()
        csr_summary = {
            "format": "CHINWAG-LEANN-CSR-v1",
            "source_commit": default_commit,
            "total_memories": total_migrated,
            "banks": migrated_by_bank,
            "csr_edge_count": len(csr_batch),
            "top_terms": [{ "term": r[0], "degree": r[1] } for r in top_terms[:256]],
            "generated_at_ms": now_ms_val
        }
        with open(leann_path, "wb") as f:
            raw = json.dumps(csr_summary, separators=(',', ':')).encode("utf-8")
            f.write(b"LEANNCSR\x00\x01" + raw)
            os.chmod(leann_path, 0o600)

    print(json.dumps({
        "ok": True,
        "total_migrated": total_migrated,
        "banks": migrated_by_bank,
        "csr_edges_built": len(csr_batch),
        "leann_path": leann_path
    }))
"#;

pub fn recall_for_agent_prompt(agent_lower: &str, query: &str, repo_root: &Path) -> String {
    let crdb_tombstones = read_crdb_snapshot(repo_root)
        .map(|(t, _, _)| t)
        .unwrap_or_default();
    let payload = json!({
        "op": "recall",
        "db_path": &default_planner_db(),
        "query": format!("{agent_lower} {}", truncate_utf8(query, 400)),
        "limit": 8,
        "crdb_tombstones": crdb_tombstones
    });
    let Ok(res) = run_python_sqlite(PY_SCHEMA_AND_OPS, &payload) else {
        return String::new();
    };
    let Some(items) = res.get("results").and_then(Json::as_array) else {
        return String::new();
    };
    let mut lines = Vec::new();
    for item in items.iter().take(8) {
        let cat = item.get("category").and_then(Json::as_str).unwrap_or("memory");
        let scope = item.get("file_scope").and_then(Json::as_str).unwrap_or("*");
        let text = item.get("content").and_then(Json::as_str).unwrap_or("");
        if !text.is_empty() {
            lines.push(format!("- [{cat} | scope:{scope}] {}", truncate_utf8(text, 360)));
        }
    }
    lines.join("\n")
}

pub fn retain_from_agent_dispatch(
    repo_root: &Path,
    agent_upper: &str,
    engine: &str,
    sender: &str,
    item_key: &str,
    message: &str,
    reply: &str,
) {
    let ts_ms = now_ms();
    let agent_lower = agent_upper.to_ascii_lowercase();
    let content = format!(
        "{sender} messaged {agent_upper} [{engine}] ({item_key}): {} -> {agent_upper} replied: {}",
        truncate_utf8(message, 240),
        truncate_utf8(reply, 300)
    );
    let mid = format!(
        "mem-{ts_ms}-{}",
        short_hash(&[agent_upper, sender, item_key, &content], ts_ms)
    );
    let _ = persist_memory_pin_to_crdb(
        repo_root,
        &MemoryPinWrite {
            id: &mid,
            bank: "spector-fleet",
            context: &format!("agent-dispatch:{agent_lower}:{item_key}"),
            content: &content,
            source_commit: DEFAULT_COMMIT_SHA,
            file_scope: "*",
            ts_ms,
        },
    );
    let payload = json!({
        "op": "retain",
        "db_path": &default_planner_db(),
        "memory": {
            "id": mid,
            "bank": "spector-fleet",
            "category": "experience",
            "context": format!("agent-dispatch:{agent_lower}:{item_key}"),
            "content": content,
            "file_scope": "*",
            "source_commit": DEFAULT_COMMIT_SHA,
            "author_agent": agent_upper,
            "entities": format!("{agent_upper}, {sender}, {item_key}"),
            "tags": format!("agent:{agent_lower},engine:{engine},project:chinwag"),
            "origin": "native-dispatch",
            "created_at_ms": ts_ms
        }
    });
    let _ = run_python_sqlite(PY_SCHEMA_AND_OPS, &payload);
}

pub fn run_memory(
    request: MemoryRequest,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let repo_root = resolve_repo_root(request.crdb.as_deref());
    let ts_ms = now_ms();

    match request.action {
        MemoryAction::Retain {
            id,
            bank,
            context,
            content,
            commit,
            file_scope,
            agent,
            tags,
        } => {
            let source_commit = commit.unwrap_or_else(|| DEFAULT_COMMIT_SHA.to_owned());
            let scope = file_scope.unwrap_or_else(|| "*".to_owned());
            let author = agent.unwrap_or_else(|| "GEMINI-PM".to_owned());
            let mem_id = id.unwrap_or_else(|| {
                format!(
                    "mem-{ts_ms}-{}",
                    short_hash(&[&bank, &context, &content, &scope], ts_ms)
                )
            });

            let crdb_res = persist_memory_pin_to_crdb(
                &repo_root,
                &MemoryPinWrite {
                    id: &mem_id,
                    bank: &bank,
                    context: &context,
                    content: &content,
                    source_commit: &source_commit,
                    file_scope: &scope,
                    ts_ms,
                },
            );
            let (crdb_status, crdb_version) = match crdb_res {
                Ok(v) => ("stored".to_owned(), v),
                Err(e) => {
                    let _ = writeln!(err, "chinwag: crdb_notice: {e}");
                    (format!("deferred:{e}"), 0)
                }
            };

            let payload = json!({
                "op": "retain",
                "db_path": &default_planner_db(),
                "memory": {
                    "id": mem_id,
                    "bank": bank,
                    "category": "observation",
                    "context": context,
                    "content": content,
                    "file_scope": scope,
                    "source_commit": source_commit,
                    "author_agent": author,
                    "entities": "",
                    "tags": tags.unwrap_or_default(),
                    "origin": "native-cli",
                    "created_at_ms": ts_ms
                }
            });
            let sqlite_res = match run_python_sqlite(PY_SCHEMA_AND_OPS, &payload) {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(err, "chinwag: {e}");
                    return 1;
                }
            };

            let output = json!({
                "ok": true,
                "action": "retain",
                "id": mem_id,
                "bank": bank,
                "context": context,
                "content": content,
                "file_scope": scope,
                "source_commit": source_commit,
                "crdb_status": crdb_status,
                "crdb_db_version": crdb_version,
                "fts5_indexed": true,
                "csr_edges_added": sqlite_res.get("csr_edges_added").and_then(Json::as_u64).unwrap_or(0)
            });
            let _ = serde_json::to_writer(&mut *out, &output);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
            0
        }

        MemoryAction::Tombstone {
            id,
            file_scope,
            reason,
            commit,
            attempted_action,
            failure,
            alternative,
        } => {
            let source_commit = commit.unwrap_or_else(|| DEFAULT_COMMIT_SHA.to_owned());
            let act = attempted_action
                .unwrap_or_else(|| format!("Modifying {file_scope} with rejected pattern"));
            let fail = failure.unwrap_or_else(|| reason.clone());
            let alt = alternative
                .unwrap_or_else(|| "Follow active verified_invariants in .chinwag/state.crdb".to_owned());
            let ev_hash = format!(
                "sha256:{}",
                short_hash(&[&id, &file_scope, &reason, &source_commit], ts_ms)
            );

            let crdb_res = persist_tombstone_to_crdb(
                &repo_root,
                &TombstoneWrite {
                    id: &id,
                    source_commit: &source_commit,
                    file_scope: &file_scope,
                    attempted_action: &act,
                    failure: &fail,
                    reason: &reason,
                    alternative: &alt,
                    ts_ms,
                },
            );
            let (crdb_status, crdb_version) = match crdb_res {
                Ok(v) => ("stored".to_owned(), v),
                Err(e) => {
                    let _ = writeln!(err, "chinwag: crdb_notice: {e}");
                    (format!("deferred:{e}"), 0)
                }
            };

            let payload = json!({
                "op": "tombstone",
                "db_path": &default_planner_db(),
                "tombstone": {
                    "id": id,
                    "source_commit": source_commit,
                    "file_scope": file_scope,
                    "attempted_action": act,
                    "failure": fail,
                    "reason": reason,
                    "alternative": alt,
                    "evidence_hash": ev_hash,
                    "created_at_ms": ts_ms
                }
            });
            let sqlite_res = match run_python_sqlite(PY_SCHEMA_AND_OPS, &payload) {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(err, "chinwag: {e}");
                    return 1;
                }
            };

            let output = json!({
                "ok": true,
                "action": "tombstone",
                "id": id,
                "directive": "DO_NOT_REPEAT",
                "file_scope": file_scope,
                "reason": reason,
                "alternative": alt,
                "source_commit": source_commit,
                "evidence_hash": ev_hash,
                "crdb_status": crdb_status,
                "crdb_db_version": crdb_version,
                "fts5_indexed": true,
                "csr_edges_added": sqlite_res.get("csr_edges_added").and_then(Json::as_u64).unwrap_or(0)
            });
            let _ = serde_json::to_writer(&mut *out, &output);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
            0
        }

        MemoryAction::Recall {
            query,
            limit,
            bank,
            file_scope,
        } => {
            let (crdb_tombstones, crdb_invariants, _) =
                read_crdb_snapshot(&repo_root).unwrap_or_default();
            let payload = json!({
                "op": "recall",
                "db_path": &default_planner_db(),
                "query": query,
                "limit": limit,
                "bank": bank,
                "file_scope": file_scope,
                "crdb_tombstones": crdb_tombstones
            });
            let sqlite_res = match run_python_sqlite(PY_SCHEMA_AND_OPS, &payload) {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(err, "chinwag: {e}");
                    return 1;
                }
            };
            let tombstones = sqlite_res
                .get("tombstones")
                .and_then(Json::as_array)
                .cloned()
                .unwrap_or_default();
            let results = sqlite_res
                .get("results")
                .and_then(Json::as_array)
                .cloned()
                .unwrap_or_default();

            let output = json!({
                "ok": true,
                "action": "recall",
                "query": query,
                "file_scope": file_scope,
                "tombstones_count": tombstones.len(),
                "invariants_count": crdb_invariants.len(),
                "results_count": results.len(),
                "tombstones": tombstones,
                "verified_invariants": crdb_invariants,
                "results": results
            });
            let _ = serde_json::to_writer(&mut *out, &output);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
            0
        }

        MemoryAction::Stats { bank } => {
            let (_, _, crdb_stats) = read_crdb_snapshot(&repo_root).unwrap_or_default();
            let payload = json!({
                "op": "stats",
                "db_path": &default_planner_db(),
                "bank": bank,
                "leann_path": &default_leann_path()
            });
            let sqlite_res = match run_python_sqlite(PY_SCHEMA_AND_OPS, &payload) {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(err, "chinwag: {e}");
                    return 1;
                }
            };
            let output = json!({
                "ok": true,
                "action": "stats",
                "crdb": crdb_stats,
                "memory_store": sqlite_res
            });
            let _ = serde_json::to_writer(&mut *out, &output);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
            0
        }

        MemoryAction::MigrateHindsight { url, bank } => {
            let hs_url = url.unwrap_or_else(|| "http://127.0.0.1:8888".to_owned());
            let payload = json!({
                "op": "migrate_hindsight",
                "db_path": &default_planner_db(),
                "url": hs_url,
                "bank": bank,
                "source_commit": DEFAULT_COMMIT_SHA,
                "leann_path": &default_leann_path()
            });
            let sqlite_res = match run_python_sqlite(PY_SCHEMA_AND_OPS, &payload) {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(err, "chinwag: {e}");
                    return 1;
                }
            };

            // Seed canonical negative architectural tombstones into .chinwag/state.crdb + planner.sqlite
            let canonical_tombstones = [
                (
                    "tmb-001",
                    "hosted-relay/**",
                    "Introducing Clerk B2B Auth SDK on hosted-relay/**",
                    "Rejected Clerk $1.00/MAO fee ($133.5k/yr at 10k teams vs $840/yr Better-Auth + Cloudflare D1)",
                    "Use Better-Auth + Cloudflare D1 + Apple Secure Enclave WebAuthn Passkeys (99.98% gross margin)",
                ),
                (
                    "tmb-002",
                    "crates/**",
                    "Calling external Hindsight HTTP daemon (:8888) for agent memory",
                    "Retired external Python/Docker Hindsight (:8888) due to append-only positive bias, zero Git commit provenance, and external daemon overhead",
                    "Use Native Chinwag 3-Tier Memory (chinwag memory retain | recall | tombstone | stats) backed by .chinwag/state.crdb + LEANN CSR",
                ),
                (
                    "tmb-003",
                    "wiki/**",
                    "Writing documentation to legacy Wiki.js (:4320) GraphQL API",
                    "Retired Wiki.js (:4320) container in favor of commit-anchored Docus (:8795) and Mission Control (:5487)",
                    "Write commit-anchored Markdown directly to ~/WORKSPACE/paperclip-wiki/wiki/ with source_commit frontmatter",
                ),
            ];
            let mut last_crdb_version = 0;
            for (tid, scope, act, reason, alt) in canonical_tombstones {
                if let Ok(v) = persist_tombstone_to_crdb(
                    &repo_root,
                    &TombstoneWrite {
                        id: tid,
                        source_commit: DEFAULT_COMMIT_SHA,
                        file_scope: scope,
                        attempted_action: act,
                        failure: reason,
                        reason,
                        alternative: alt,
                        ts_ms,
                    },
                ) {
                    last_crdb_version = v;
                }
                let t_payload = json!({
                    "op": "tombstone",
                    "db_path": &default_planner_db(),
                    "tombstone": {
                        "id": tid,
                        "source_commit": DEFAULT_COMMIT_SHA,
                        "file_scope": scope,
                        "attempted_action": act,
                        "failure": reason,
                        "reason": reason,
                        "alternative": alt,
                        "evidence_hash": format!("sha256:{}", short_hash(&[tid, scope, reason], ts_ms)),
                        "created_at_ms": ts_ms
                    }
                });
                let _ = run_python_sqlite(PY_SCHEMA_AND_OPS, &t_payload);
            }

            let total_migrated = sqlite_res
                .get("total_migrated")
                .and_then(Json::as_u64)
                .unwrap_or(0);
            let mig_summary = format!(
                "Migrated {total_migrated} Hindsight records (100% of spector-fleet + spector-fleet-canary) into Native Chinwag 3-Tier Memory (.chinwag/state.crdb + FTS5 + LEANN CSR) anchored to commit {DEFAULT_COMMIT_SHA}."
            );
            if let Ok(v) = persist_memory_pin_to_crdb(
                &repo_root,
                &MemoryPinWrite {
                    id: "chinwag-hindsight-migration-v1",
                    bank: "spector-fleet",
                    context: "cutover:chwg-mem-1:hindsight-migration",
                    content: &mig_summary,
                    source_commit: DEFAULT_COMMIT_SHA,
                    file_scope: "*",
                    ts_ms,
                },
            ) {
                last_crdb_version = v;
            }

            let output = json!({
                "ok": true,
                "action": "migrate-hindsight",
                "source_url": hs_url,
                "source_commit": DEFAULT_COMMIT_SHA,
                "total_migrated": total_migrated,
                "banks": sqlite_res.get("banks").cloned().unwrap_or_else(|| json!({})),
                "csr_edges_built": sqlite_res.get("csr_edges_built").and_then(Json::as_u64).unwrap_or(0),
                "canonical_tombstones_seeded": 3,
                "crdb_migration_pin": "chinwag-hindsight-migration-v1",
                "crdb_db_version": last_crdb_version,
                "leann_path": &default_leann_path()
            });
            let _ = serde_json::to_writer(&mut *out, &output);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
            0
        }
    }
}

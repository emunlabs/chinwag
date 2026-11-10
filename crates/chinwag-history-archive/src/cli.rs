// Copyright (c) 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{Archive, Manifest, digest, events, ingest, read_bounded};
use std::{io::Write, path::Path};
fn read_page(root: &str, id: &str, offset: usize) -> Result<serde_json::Value, String> {
    let event = Archive::open(Path::new(root))?.read_event(id)?;
    if offset > event.text.len() || !event.text.is_char_boundary(offset) {
        return Err("read offset is not a UTF8 boundary".into());
    }
    let mut end = (offset + 1024).min(event.text.len());
    while !event.text.is_char_boundary(end) {
        end -= 1;
    }
    Ok(
        serde_json::json!({"classification":"derived_context","id":event.id,"chat_id":event.chat_id,"timestamp_utc":event.timestamp_utc,"role":event.role,"channel":event.channel,"text":&event.text[offset..end],"supersedes":event.supersedes,"event_sha256":digest(event.canonical()?.as_bytes()),"evidence_count":event.evidence.len(),"offset":offset,"next_offset":if end<event.text.len(){Some(end)}else{None},"original_sender_authenticated":false}),
    )
}
fn inspect(input: &str, offset: usize) -> Result<serde_json::Value, String> {
    let source = events(Path::new(input))?;
    if offset > source.len() {
        return Err("inspection offset out of range".into());
    }
    let rows = source
        .iter()
        .skip(offset)
        .take(40)
        .map(|e| Ok(serde_json::json!({"id":e.id,"sha256":digest(e.canonical()?.as_bytes())})))
        .collect::<Result<Vec<_>, String>>()?;
    Ok(
        serde_json::json!({"classification":"derived_context_inspection","events":rows,"offset":offset,"next_offset":if offset+40<source.len(){Some(offset+40)}else{None}}),
    )
}
fn execute(args: &[String]) -> Result<serde_json::Value, String> {
    match args {
 [op,plan,expected] if op=="pull-plan"=>crate::PullPlan::load(Path::new(plan),expected)?.describe(),
 [op,plan,expected,root,flag] if op=="pull"&&flag=="--network"=>crate::pull(&crate::PullPlan::load(Path::new(plan),expected)?,Path::new(root),true),

 [op,input] if op=="inspect"=>inspect(input,0),
 [op,input,offset] if op=="inspect"=>inspect(input,offset.parse::<usize>().map_err(|e|e.to_string())?),
 [op,manifest,input,root] if op=="ingest"=>{
  let m:Manifest=serde_json::from_slice(&read_bounded(Path::new(manifest))?).map_err(|e|e.to_string())?;
  ingest(&m,Path::new(input),Path::new(root))
 }
 [op,root,query,limit] if op=="search"=>Archive::open(Path::new(root))?.search(query,limit.parse::<usize>().map_err(|e|e.to_string())?),
 [op,root,id] if op=="read-event"=>read_page(root,id,0),
 [op,root,id,offset] if op=="read-event"=>read_page(root,id,offset.parse::<usize>().map_err(|e|e.to_string())?),
 [op,root,id] if op=="get-evidence"=>{
  let event=Archive::open(Path::new(root))?.read_event(id)?;
  Ok(serde_json::json!({"classification":"derived_context_reference","id":event.id,"evidence":event.evidence,"authority":"none"}))
 }
 _=>Err("usage: chinwag history inspect EVENTS [OFFSET] | ingest MANIFEST EVENTS EMPTY0700ROOT | search ROOT QUERY LIMIT(1..20) | read-event ROOT ID [BYTE_OFFSET] | get-evidence ROOT ID".into())
 }
}
pub fn run_cli(args: &[String], out: &mut impl Write, err: &mut impl Write) -> u8 {
    match execute(args) {
        Ok(value) => {
            let encoded = value.to_string();
            if encoded.len() > 12288 {
                let _ = writeln!(err, "history: output exceeds12KiB; reduce search limit");
                return 2;
            }
            if writeln!(out, "{encoded}").is_ok() {
                0
            } else {
                1
            }
        }
        Err(e) => {
            let bounded = e.chars().take(512).collect::<String>();
            let _ = writeln!(err, "history: {bounded}");
            2
        }
    }
}

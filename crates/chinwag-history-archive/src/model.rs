// Copyright (c) 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub const MAX_INPUT: u64 = 8 * 1024 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum Role { User, Assistant }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum Channel { User, Commentary, Final }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
 pub id:String, pub chat_id:String, pub timestamp_utc:String, pub role:Role,
 pub channel:Channel, pub text:String, pub evidence:Vec<String>, pub supersedes:Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
 pub schema:u32, pub dataset_id:String, pub bucket:String, pub account_id:String,
 pub coordinator_chat_id:String, pub approved_events:BTreeMap<String,String>,
}
pub fn digest(bytes:&[u8])->String { format!("{:x}",Sha256::digest(bytes)) }
pub fn token(s:&str)->bool { !s.is_empty() && s.len()<=128 && s.bytes().all(|b|b.is_ascii_alphanumeric() || b"-_:".contains(&b)) }
impl Event {
 pub fn canonical(&self)->Result<String,String> { serde_json::to_string(self).map_err(|e|e.to_string()) }
 pub fn validate(&self)->Result<(),String> {
  let visible=matches!((&self.role,&self.channel),(Role::User,Channel::User)|(Role::Assistant,Channel::Commentary|Channel::Final));
  if !visible || !token(&self.id) || !token(&self.chat_id) || self.timestamp_utc.len()>40 || !self.timestamp_utc.ends_with('Z') || self.text.len()>16384 || self.evidence.len()>8 || self.evidence.iter().any(|e|e.len()>1024) || self.supersedes.as_ref().is_some_and(|s|!token(s)) || self.text.contains("PRIVATE KEY-----") { return Err("event outside visible-event policy".into()); }
  Ok(())
 }
}
impl Manifest {
 pub fn validate(&self)->Result<(),String> {
  if self.schema!=1 || !token(&self.dataset_id) || !token(&self.coordinator_chat_id) || self.bucket!="chinwag-coordinator-history" || self.account_id!="a9dce15ce0193da7d7f1d5dd3a53022b" || self.approved_events.len()>10000 || self.approved_events.iter().any(|(id,h)|!token(id)||h.len()!=64||!h.bytes().all(|b|b.is_ascii_hexdigit())) { return Err("manifest outside dedicated archive allowlist".into()); }
  Ok(())
 }
 pub fn approve(&self,event:&Event)->Result<String,String> {
  event.validate()?; let s=event.canonical()?;
  if event.chat_id!=self.coordinator_chat_id || self.approved_events.get(&event.id)!=Some(&digest(s.as_bytes())) {return Err("event lacks exact coordinator hash approval".into());}
  Ok(s)
 }
}

// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Transport and execution capacity describe arbitrary nodes without roster assumptions.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDescriptor {
    pub node_id: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub capabilities: NodeCapabilities,
    #[serde(default)]
    pub transport: NodeTransport,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCapabilities {
    #[serde(default)]
    pub max_concurrency: Option<u32>,
    #[serde(default)]
    pub memory_bytes: Option<u64>,
    #[serde(default)]
    pub gpu_count: Option<u32>,
    #[serde(default)]
    pub runtimes: Vec<SandboxRuntime>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeTransport {
    #[default]
    Local,
    Mesh {
        peer_id: String,
    },
    Endpoint {
        protocol: RemoteProtocol,
        endpoint: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionTarget {
    #[default]
    LocalProcess,
    MeshPeerSelector {
        #[serde(default)]
        required_labels: BTreeMap<String, String>,
        #[serde(default)]
        preferred_labels: BTreeMap<String, String>,
    },
    RemoteExec {
        protocol: RemoteProtocol,
        endpoint_template: String,
        workdir_template: String,
    },
    SandboxContainerOrVm {
        runtime: SandboxRuntime,
        image_or_profile: String,
        #[serde(default)]
        resource_limits: BTreeMap<String, u64>,
    },
    CloudSandbox {
        provider: String,
        region_or_pool: String,
        profile: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteProtocol {
    Ssh,
    Quic,
    Grpc,
    Http,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxRuntime {
    Oci,
    Bubblewrap,
    Firecracker,
    Tart,
    Nix,
    K8sJob,
}

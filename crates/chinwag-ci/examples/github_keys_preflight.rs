// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! One bounded public-issuer read using the actual production client. No token,
//! signing, workflow dispatch, CI delivery or remediation proof is performed.
use chinwag_ci::github::GithubEvidenceClient;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let result = match GithubEvidenceClient::new() {
        Ok(client) => client.issuer_keys().await.map(|_| ()),
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => {
            println!(
                "PUBLIC_FIXED_GITHUB_JWKS_HTTPS_AND_PARSE_VERIFIED;NO_CI_RUNTIME_OR_TOKEN_CLAIM"
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            // Display is a fixed category/status only; never Debug/source-chain
            // a request, response body, URL, token or authorization header.
            eprintln!("{error}");
            ExitCode::from(78)
        }
    }
}

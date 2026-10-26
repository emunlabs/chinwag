use chinwag_mcp_private_anchored::repository_http::RepositoryHttp;
pub fn forge() {
    let _owner = serde_json::from_str::<RepositoryHttp>("{}");
}

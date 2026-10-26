use chinwag_mcp_private_anchored::repository_http::ScopedHttpResponse;
pub fn forge() {
    let _response = serde_json::from_str::<ScopedHttpResponse<'static>>("{}");
}

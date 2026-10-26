use chinwag_mcp_private_anchored::repository_http::ScopedHttpResponse;
pub fn extract(response: ScopedHttpResponse<'_>) {
    let _raw = response.response;
}

use chinwag_mcp_private_anchored::repository_http::ScopedHttpResponse;
pub fn clone_response(response: ScopedHttpResponse<'_>) {
    let _copy = response.clone();
}

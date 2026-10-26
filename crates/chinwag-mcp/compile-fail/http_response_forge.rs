use chinwag_mcp_private_anchored::repository_http::ScopedHttpResponse;
pub fn forge<'a>() -> ScopedHttpResponse<'a> {
    ScopedHttpResponse {
        response: None,
        ..panic!("not executed")
    }
}

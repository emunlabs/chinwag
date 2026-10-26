use chinwag_mcp_private_anchored::repository_http::RepositoryHttp;
pub fn forge() -> RepositoryHttp {
    RepositoryHttp {
        owner: None,
        ..panic!("not executed")
    }
}

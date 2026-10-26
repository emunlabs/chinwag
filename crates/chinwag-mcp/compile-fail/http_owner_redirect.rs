use chinwag_mcp_private_anchored::repository_http::RepositoryHttp;
pub fn redirect(mut owner: RepositoryHttp) {
    owner.repository = "/foreign".into();
}

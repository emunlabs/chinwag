use chinwag_mcp_private_anchored::repository_http::RepositoryHttp;
pub async fn finish_live(
    mut owner: RepositoryHttp,
    request: http::Request<http_body_util::Full<bytes::Bytes>>,
) {
    let mut response = owner.request(request).await.unwrap();
    let _finished = owner.finish();
    let _frame = response.frame().await;
}

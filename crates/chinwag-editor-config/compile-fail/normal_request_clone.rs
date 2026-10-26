use chinwag_editor_config_private::{Editor, install::RepositoryRequest};
fn main() {
    let r = RepositoryRequest::new(std::path::Path::new("/owned"), Editor::Codex).unwrap();
    let _ = r.clone();
}

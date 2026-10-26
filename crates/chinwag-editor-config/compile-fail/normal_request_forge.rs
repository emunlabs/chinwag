use chinwag_editor_config_private::{Editor, install::RepositoryRequest};
fn main() {
    let _ = RepositoryRequest {
        repo: "/owned".into(),
        editor: Editor::Codex,
    };
}

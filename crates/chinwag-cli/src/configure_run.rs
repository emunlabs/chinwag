use crate::ConfigureRequest;
use chinwag_editor_config_private::install::{RepositoryRequest, configure};
use std::io::Write;
fn emit(out: &mut dyn Write, value: &serde_json::Value) -> bool {
    serde_json::to_writer(&mut *out, value).is_ok()
        && out.write_all(b"\n").is_ok()
        && out.flush().is_ok()
}
pub fn run_configure(request: ConfigureRequest, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let editor = request.editor.into_editor();
    let request = match RepositoryRequest::new(&request.repo, editor) {
        Ok(request) => request,
        Err(reason) => {
            let _ = writeln!(err, "chinwag: {reason}");
            return 2;
        }
    };
    match configure(request) {
        Ok(receipt) => {
            if emit(out, receipt.value()) {
                0
            } else {
                1
            }
        }
        Err(failure) => {
            let emitted = emit(out, failure.observation());
            let written = writeln!(err, "chinwag: {}", failure.reason()).is_ok();
            if emitted && written { 3 } else { 1 }
        }
    }
}

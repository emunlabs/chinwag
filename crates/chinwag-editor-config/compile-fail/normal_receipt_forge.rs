use chinwag_editor_config_private::install::ConfigureReceipt;
fn main() {
    let _ = ConfigureReceipt {
        value: serde_json::json!({}),
    };
}

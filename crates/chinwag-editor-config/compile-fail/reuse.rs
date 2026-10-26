use chinwag_editor_config_private::install::completion::Completed;
pub fn write_twice(owner: Box<Completed>) {
    let _ = owner.write_record();
    let _ = owner.write_record();
}

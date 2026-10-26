use chinwag_confirmed_initial_private::ConfirmedSigning;
fn redirect(token: ConfirmedSigning) {
    let _ = token.begin_initial(std::path::Path::new("/other-fixture"));
}
fn main() {}

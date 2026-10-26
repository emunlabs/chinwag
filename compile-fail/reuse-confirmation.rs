use chinwag_confirmed_initial_private::ConfirmedSigning;
fn reuse(token: ConfirmedSigning) {
    let _ = token.begin_initial();
    let _ = token.begin_initial();
}
fn main() {}

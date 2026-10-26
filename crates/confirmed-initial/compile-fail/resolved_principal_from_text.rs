use chinwag_confirmed_initial_private::{ResolvedPrincipal, SigningAttempt};
pub fn forge(text: String) {
    let _attempt = SigningAttempt::start_discovered(ResolvedPrincipal::from(text));
}

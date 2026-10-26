use chinwag_confirmed_initial_private::ResolvedPrincipal;
pub fn forge() {
    let _forged = serde_json::from_str::<ResolvedPrincipal>("{}");
}

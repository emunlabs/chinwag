use chinwag_confirmed_initial_private::ResolvedPrincipal;
pub fn forge() -> ResolvedPrincipal {
    ResolvedPrincipal {
        repo: "/synthetic".into(),
        principal: "fixture@chinwag.test".into(),
        ..panic!("not executed")
    }
}

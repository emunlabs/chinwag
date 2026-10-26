use chinwag_confirmed_initial_private::InitializationHandoff;
pub fn forge() -> InitializationHandoff {
    InitializationHandoff { repo: "/synthetic".into(), ..panic!("not executed") }
}

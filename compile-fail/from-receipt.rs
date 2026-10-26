use chinwag_confirmed_initial_private::SigningAttempt;
use chinwag_signing::{InitFailure, InitReceipt};
fn main() {
    let fake = InitReceipt::Refused {
        expected_public: [0; 32],
        failure: InitFailure::Principal,
    };
    let _ = SigningAttempt::from_receipt(fake);
}

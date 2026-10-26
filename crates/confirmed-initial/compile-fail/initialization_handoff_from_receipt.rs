use chinwag_confirmed_initial_private::{InitializationHandoff, LocalInitializationReceipt};
pub fn adopt(receipt: LocalInitializationReceipt) { let _forged = InitializationHandoff::from_receipt(receipt); }

// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

// Public calculation fixture for the real red/read/fix/green demonstration.
// The CI transport implementation does not inspect or fix it.
fn invoice_total(subtotal: i64, adjustment: i64) -> i64 {
    subtotal + adjustment
}

#[test]
fn invoice_total_matches_the_two_line_items() {
    for index in 0..128 {
        println!("invoice fixture diagnostic line {index}: subtotal=2 adjustment=3 expected_total=5");
        eprintln!("invoice fixture stderr context line {index}: checked signed integer inputs");
    }
    assert_eq!(invoice_total(2, 3), 5, "invoice calculation added an unrequested unit");
}

// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Monotone Access Tree AST, Lewko–Waters Tree-to-LSSS conversion, and exact Gaussian
//! elimination over the BLS12-381 scalar field $\mathbb{F}_r$.

use crate::AcuError;
use crate::keys::is_valid_seat_id;
use bls12_381::Scalar;
use ff::Field;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Monotone boolean/threshold access policy AST over seat or key-branch identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessTree {
    /// A leaf node bound to a specific seat ID or key branch ID (e.g., `"branch:8687872"` or `"acu:98939834"`).
    Leaf(String),
    /// A conjunctive ($n$-of-$n$) gate requiring all child subtrees to be satisfied.
    And(Vec<AccessTree>),
    /// A disjunctive ($1$-of-$n$) gate requiring at least one child subtree to be satisfied.
    Or(Vec<AccessTree>),
    /// A general $t$-of-$n$ threshold gate (`1 <= threshold <= children.len()`).
    Threshold {
        /// Minimum number of child subtrees required (`t`).
        threshold: usize,
        /// Ordered child subtrees (`n`).
        children: Vec<AccessTree>,
    },
}

/// Linear Secret Sharing Scheme (LSSS) matrix $(M, \rho)$ over $\mathbb{F}_r$ where the
/// target secret $s$ resides at coordinate $0$, i.e. the reconstruction target vector is
/// $e_0 = (1, 0, \dots, 0) \in \mathbb{F}_r^k$.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LsssMatrix {
    /// Number of columns $k$ in the matrix ($k \ge 1$).
    pub cols: usize,
    /// Ordered rows $(\rho(j), M_j)$ mapping row index $j$ to its seat ID and length-$k$ scalar row.
    pub rows: Vec<(String, Vec<Scalar>)>,
}

impl LsssMatrix {
    /// Convert a monotone [`AccessTree`] into an equivalent [`LsssMatrix`] over `bls12_381::Scalar`
    /// using the Lewko–Waters algorithm (EUROCRYPT 2011, Appendix G) with target vector $(1, 0, \dots, 0)$.
    pub fn from_tree(tree: &AccessTree) -> Result<Self, AcuError> {
        let mut cols = 1usize;
        let mut raw_rows: Vec<(String, Vec<Scalar>)> = Vec::new();
        Self::convert_node(tree, vec![Scalar::ONE], &mut cols, &mut raw_rows)?;
        if raw_rows.is_empty() {
            return Err(AcuError::EmptyPolicy);
        }
        for (_, row_vec) in &mut raw_rows {
            row_vec.resize(cols, Scalar::ZERO);
        }
        Ok(Self {
            cols,
            rows: raw_rows,
        })
    }

    fn convert_node(
        node: &AccessTree,
        parent_vec: Vec<Scalar>,
        cols: &mut usize,
        out_rows: &mut Vec<(String, Vec<Scalar>)>,
    ) -> Result<(), AcuError> {
        match node {
            AccessTree::Leaf(seat_id) => {
                if !is_valid_seat_id(seat_id) {
                    return Err(AcuError::InvalidSeatId);
                }
                out_rows.push((seat_id.clone(), parent_vec));
                Ok(())
            }
            AccessTree::Or(children) => {
                if children.is_empty() {
                    return Err(AcuError::InvalidAccessTree(
                        "OR gate must have at least one child",
                    ));
                }
                for child in children {
                    Self::convert_node(child, parent_vec.clone(), cols, out_rows)?;
                }
                Ok(())
            }
            AccessTree::And(children) => {
                if children.is_empty() {
                    return Err(AcuError::InvalidAccessTree(
                        "AND gate must have at least one child",
                    ));
                }
                let threshold = children.len();
                Self::convert_threshold(threshold, children, parent_vec, cols, out_rows)
            }
            AccessTree::Threshold {
                threshold,
                children,
            } => Self::convert_threshold(*threshold, children, parent_vec, cols, out_rows),
        }
    }

    fn convert_threshold(
        threshold: usize,
        children: &[AccessTree],
        mut parent_vec: Vec<Scalar>,
        cols: &mut usize,
        out_rows: &mut Vec<(String, Vec<Scalar>)>,
    ) -> Result<(), AcuError> {
        if children.is_empty() {
            return Err(AcuError::InvalidAccessTree(
                "threshold gate must have at least one child",
            ));
        }
        if threshold == 0 || threshold > children.len() {
            return Err(AcuError::InvalidThreshold {
                threshold,
                children: children.len(),
            });
        }
        // Pad parent's label vector with zeros up to the current global column count `c`.
        parent_vec.resize(*cols, Scalar::ZERO);
        let extra_cols = threshold - 1;
        *cols += extra_cols;

        for (idx, child) in children.iter().enumerate() {
            let x = Scalar::from((idx + 1) as u64);
            let mut child_vec = Vec::with_capacity(parent_vec.len() + extra_cols);
            child_vec.extend_from_slice(&parent_vec);
            let mut x_pow = x;
            for _ in 0..extra_cols {
                child_vec.push(x_pow);
                x_pow *= x;
            }
            Self::convert_node(child, child_vec, cols, out_rows)?;
        }
        Ok(())
    }

    /// Validate structural invariants of this LSSS matrix.
    pub fn validate(&self) -> Result<(), AcuError> {
        if self.cols == 0 || self.rows.is_empty() {
            return Err(AcuError::EmptyPolicy);
        }
        for (seat_id, row) in &self.rows {
            if !is_valid_seat_id(seat_id) {
                return Err(AcuError::InvalidSeatId);
            }
            if row.len() != self.cols {
                return Err(AcuError::DimensionMismatch {
                    expected: self.cols,
                    actual: row.len(),
                });
            }
        }
        Ok(())
    }
}

/// Solve for reconstruction weights $\{\omega_j\}_{j \in S}$ over $\mathbb{F}_r$ such that
///
/// $$\sum_{j \in S} \omega_j M_j = (1, 0, \dots, 0) \in \mathbb{F}_r^k$$
///
/// using exact Gauss–Jordan elimination over `bls12_381::Scalar`.
/// Returns `Err(AcuError::PolicyNotSatisfied)` if the rows indexed by `available_row_indices`
/// do not span $(1, 0, \dots, 0)$.
pub fn find_reconstruction_weights(
    matrix: &LsssMatrix,
    available_row_indices: &[usize],
) -> Result<Vec<(usize, Scalar)>, AcuError> {
    matrix.validate()?;
    if available_row_indices.is_empty() {
        return Err(AcuError::PolicyNotSatisfied);
    }

    // Deduplicate while preserving deterministic index order.
    let mut unique_indices = Vec::with_capacity(available_row_indices.len());
    let mut seen = BTreeSet::new();
    for &row_idx in available_row_indices {
        if row_idx >= matrix.rows.len() {
            return Err(AcuError::RowIndexOutOfBounds {
                index: row_idx,
                total_rows: matrix.rows.len(),
            });
        }
        if seen.insert(row_idx) {
            unique_indices.push(row_idx);
        }
    }

    let k = matrix.cols;
    let m = unique_indices.len();

    // Build the k x (m + 1) augmented matrix [A | e_0] where column `r` of A is M_{unique_indices[r]}^T
    // and the augmented RHS column `m` is e_0 = (1, 0, ..., 0)^T.
    let mut aug = vec![vec![Scalar::ZERO; m + 1]; k];
    for (col_var, &row_idx) in unique_indices.iter().enumerate() {
        let row_vec = &matrix.rows[row_idx].1;
        for (coord, &val) in row_vec.iter().enumerate() {
            aug[coord][col_var] = val;
        }
    }
    aug[0][m] = Scalar::ONE;

    // Gauss-Jordan elimination to Reduced Row Echelon Form (RREF).
    let mut pivot_col_for_row: Vec<Option<usize>> = vec![None; k];
    let mut pivot_row = 0usize;

    for col in 0..m {
        if pivot_row >= k {
            break;
        }
        let Some(found_row) = (pivot_row..k).find(|&r| !bool::from(aug[r][col].is_zero())) else {
            continue;
        };
        aug.swap(pivot_row, found_row);
        pivot_col_for_row[pivot_row] = Some(col);

        let pivot_val = aug[pivot_row][col];
        let pivot_inv: Option<Scalar> = pivot_val.invert().into();
        let pivot_inv = pivot_inv.ok_or(AcuError::PolicyNotSatisfied)?;

        for entry in &mut aug[pivot_row][col..=m] {
            *entry *= pivot_inv;
        }

        let pivot_slice = aug[pivot_row].clone();
        for (other_row, row_vals) in aug.iter_mut().enumerate() {
            if other_row == pivot_row {
                continue;
            }
            let factor = row_vals[col];
            if !bool::from(factor.is_zero()) {
                for (c, &p_val) in pivot_slice.iter().enumerate().skip(col) {
                    row_vals[c] -= factor * p_val;
                }
            }
        }

        pivot_row += 1;
    }

    // Check system consistency: any zero row on the LHS with a non-zero RHS means no solution exists.
    for r in 0..k {
        if pivot_col_for_row[r].is_none() && !bool::from(aug[r][m].is_zero()) {
            return Err(AcuError::PolicyNotSatisfied);
        }
    }

    // Extract the basic solution vector omega in F_r^m.
    let mut omega = vec![Scalar::ZERO; m];
    for r in 0..k {
        if let Some(col) = pivot_col_for_row[r] {
            omega[col] = aug[r][m];
        }
    }

    // Defense-in-depth verification: confirm Sum_{r=0..m} omega[r] * M_{unique_indices[r]} == e_0.
    let mut reconstructed = vec![Scalar::ZERO; k];
    for (col_var, &row_idx) in unique_indices.iter().enumerate() {
        let w = omega[col_var];
        if bool::from(w.is_zero()) {
            continue;
        }
        for (coord, &val) in matrix.rows[row_idx].1.iter().enumerate() {
            reconstructed[coord] += w * val;
        }
    }
    if reconstructed[0] != Scalar::ONE
        || reconstructed[1..].iter().any(|c| !bool::from(c.is_zero()))
    {
        return Err(AcuError::PolicyNotSatisfied);
    }

    let weights = unique_indices
        .into_iter()
        .zip(omega)
        .filter(|(_, w)| !bool::from(w.is_zero()))
        .collect();

    Ok(weights)
}

/// Compute the $\mathbb{F}_r$-rank of the submatrix formed by `row_indices`.
/// Used during `escalate_threshold` to determine the current Vandermonde degree of a threshold gate.
pub(crate) fn submatrix_rank(matrix: &LsssMatrix, row_indices: &[usize]) -> usize {
    if row_indices.is_empty() || matrix.cols == 0 {
        return 0;
    }
    let cols = matrix.cols;
    let mut sub: Vec<Vec<Scalar>> = row_indices
        .iter()
        .filter_map(|&idx| matrix.rows.get(idx).map(|(_, r)| r.clone()))
        .collect();
    let num_rows = sub.len();
    let mut rank = 0usize;

    for col in 0..cols {
        if rank >= num_rows {
            break;
        }
        let Some(found) = (rank..num_rows).find(|&r| !bool::from(sub[r][col].is_zero())) else {
            continue;
        };
        sub.swap(rank, found);
        let inv: Option<Scalar> = sub[rank][col].invert().into();
        let Some(inv) = inv else {
            continue;
        };
        for entry in &mut sub[rank][col..cols] {
            *entry *= inv;
        }
        let pivot_row = sub[rank].clone();
        for (r, row_vals) in sub.iter_mut().enumerate() {
            if r == rank {
                continue;
            }
            let factor = row_vals[col];
            if !bool::from(factor.is_zero()) {
                for (c, &p_val) in pivot_row.iter().enumerate().skip(col) {
                    row_vals[c] -= factor * p_val;
                }
            }
        }
        rank += 1;
    }
    rank
}

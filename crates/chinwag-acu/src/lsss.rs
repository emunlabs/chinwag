// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Monotone Access Tree AST, Lewko–Waters Tree-to-LSSS conversion with persisted gate-subtree
//! descriptors $\mathcal{D}_{\mathsf{gate}}$ (`ePrint v2` §1.5, §6.3 Op 2), non-ACU post-quantum
//! projection $\mathcal{T}_{\mathsf{conf}} = \mathcal{T}|_{\mathsf{ACU}=\mathsf{true}}$, and exact
//! Gauss–Jordan elimination over the `BLS12-381` scalar field $\mathbb{F}_r$.

use crate::AcuError;
use crate::framing::{lp64_str, read_scalar, read_u32_be};
use crate::keys::is_valid_seat_id;
use bls12_381::Scalar;
use ff::Field;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Maximum number of LSSS rows permitted in a serialized or in-memory policy matrix.
pub(crate) const MAX_SERIALIZED_ROWS: usize = 4096;
/// Maximum number of LSSS columns permitted in a serialized or in-memory policy matrix.
pub(crate) const MAX_SERIALIZED_COLS: usize = 4096;
/// Maximum number of threshold/boolean gate descriptors permitted in a serialized matrix.
pub(crate) const MAX_SERIALIZED_GATES: usize = 4096;

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

/// Child subtree partition $C_{g,c}$ inside a compiled [`GateDescriptor`], recording the shared
/// Vandermonde evaluation scalar $x_{g,c} \in \mathbb{F}_r^*$ inherited identically by every leaf
/// row $j \in C_{g,c}$ during [`crate::escalate_threshold`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateChild {
    /// Shared non-zero Vandermonde scalar $x_{g,c} \in \mathbb{F}_r^*$ for child subtree $C_{g,c}$.
    pub eval_scalar: Scalar,
    /// Sorted leaf row indices belonging to child subtree $C_{g,c}$.
    pub row_indices: Vec<usize>,
}

/// Compiled gate descriptor in $\mathcal{D}_{\mathsf{gate}}$ (`ePrint v2` §1.5 & §6.3 Op 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateDescriptor {
    /// Zero-based index of this gate inside [`LsssMatrix::gates`].
    pub gate_id: usize,
    /// Current threshold $t_g$ (`1 <= threshold <= children.len()`).
    pub threshold: usize,
    /// Ordered child subtrees $C_{g,1}, \dots, C_{g,n_g}$.
    pub children: Vec<GateChild>,
}

/// Linear Secret Sharing Scheme (LSSS) matrix $(M, \rho, \mathcal{D}_{\mathsf{gate}})$ over $\mathbb{F}_r$
/// where the target secret $s$ resides at coordinate $0$, i.e. the reconstruction target vector is
/// $e_0 = (1, 0, \dots, 0) \in \mathbb{F}_r^k$.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LsssMatrix {
    /// Number of columns $k$ in the matrix ($k \ge 1$).
    pub cols: usize,
    /// Ordered rows $(\rho(j), M_j)$ mapping row index $j$ to its seat ID and length-$k$ scalar row.
    pub rows: Vec<(String, Vec<Scalar>)>,
    /// Compiled gate-subtree descriptors $\mathcal{D}_{\mathsf{gate}}$ preserving nested child partitions.
    pub gates: Vec<GateDescriptor>,
}

impl LsssMatrix {
    /// Convert a monotone [`AccessTree`] into an equivalent [`LsssMatrix`] over `bls12_381::Scalar`
    /// using the Lewko–Waters algorithm (EUROCRYPT 2011, Appendix G) with target vector $(1, 0, \dots, 0)$
    /// and persisted gate-child subtree descriptors $\mathcal{D}_{\mathsf{gate}}$.
    pub fn from_tree(tree: &AccessTree) -> Result<Self, AcuError> {
        let mut cols = 1usize;
        let mut raw_rows: Vec<(String, Vec<Scalar>)> = Vec::new();
        let mut gates: Vec<GateDescriptor> = Vec::new();
        Self::convert_node(
            tree,
            vec![Scalar::ONE],
            &mut cols,
            &mut raw_rows,
            &mut gates,
        )?;
        if raw_rows.is_empty() {
            return Err(AcuError::EmptyPolicy);
        }
        for (_, row_vec) in &mut raw_rows {
            row_vec.resize(cols, Scalar::ZERO);
        }
        let matrix = Self {
            cols,
            rows: raw_rows,
            gates,
        };
        matrix.validate()?;
        Ok(matrix)
    }

    fn convert_node(
        node: &AccessTree,
        parent_vec: Vec<Scalar>,
        cols: &mut usize,
        out_rows: &mut Vec<(String, Vec<Scalar>)>,
        out_gates: &mut Vec<GateDescriptor>,
    ) -> Result<(), AcuError> {
        match node {
            AccessTree::Leaf(seat_id) => {
                if !is_valid_seat_id(seat_id) {
                    return Err(AcuError::InvalidSeatId);
                }
                if out_rows.len() >= MAX_SERIALIZED_ROWS {
                    return Err(AcuError::SerializationError(
                        "invalid AcuCiphertext dimensions",
                    ));
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
                Self::convert_threshold(1, children, parent_vec, cols, out_rows, out_gates)
            }
            AccessTree::And(children) => {
                if children.is_empty() {
                    return Err(AcuError::InvalidAccessTree(
                        "AND gate must have at least one child",
                    ));
                }
                let threshold = children.len();
                Self::convert_threshold(threshold, children, parent_vec, cols, out_rows, out_gates)
            }
            AccessTree::Threshold {
                threshold,
                children,
            } => {
                Self::convert_threshold(*threshold, children, parent_vec, cols, out_rows, out_gates)
            }
        }
    }

    fn convert_threshold(
        threshold: usize,
        children: &[AccessTree],
        mut parent_vec: Vec<Scalar>,
        cols: &mut usize,
        out_rows: &mut Vec<(String, Vec<Scalar>)>,
        out_gates: &mut Vec<GateDescriptor>,
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
        if out_gates.len() >= MAX_SERIALIZED_GATES {
            return Err(AcuError::SerializationError("too many gates in LsssMatrix"));
        }

        let gate_id = out_gates.len();
        out_gates.push(GateDescriptor {
            gate_id,
            threshold,
            children: Vec::new(),
        });

        parent_vec.resize(*cols, Scalar::ZERO);
        let extra_cols = threshold - 1;
        *cols = cols
            .checked_add(extra_cols)
            .filter(|&c| c <= MAX_SERIALIZED_COLS)
            .ok_or(AcuError::SerializationError(
                "invalid AcuCiphertext dimensions",
            ))?;

        let mut gate_children = Vec::with_capacity(children.len());
        for (idx, child) in children.iter().enumerate() {
            let x = Scalar::from((idx + 1) as u64);
            let mut child_vec = Vec::with_capacity(parent_vec.len() + extra_cols);
            child_vec.extend_from_slice(&parent_vec);
            let mut x_pow = x;
            for _ in 0..extra_cols {
                child_vec.push(x_pow);
                x_pow *= x;
            }
            let row_start = out_rows.len();
            Self::convert_node(child, child_vec, cols, out_rows, out_gates)?;
            let row_end = out_rows.len();
            gate_children.push(GateChild {
                eval_scalar: x,
                row_indices: (row_start..row_end).collect(),
            });
        }

        out_gates[gate_id].children = gate_children;
        Ok(())
    }

    /// Validate structural invariants of this LSSS matrix and its gate descriptors.
    pub fn validate(&self) -> Result<(), AcuError> {
        if self.cols == 0 || self.rows.is_empty() {
            return Err(AcuError::EmptyPolicy);
        }
        if self.cols > MAX_SERIALIZED_COLS
            || self.rows.len() > MAX_SERIALIZED_ROWS
            || self.gates.len() > MAX_SERIALIZED_GATES
        {
            return Err(AcuError::SerializationError(
                "invalid AcuCiphertext dimensions",
            ));
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
            if row.iter().all(|s| bool::from(s.is_zero())) {
                return Err(AcuError::InvalidAccessTree("LSSS row cannot be all zero"));
            }
        }
        for (expected_gid, gate) in self.gates.iter().enumerate() {
            if gate.gate_id != expected_gid || gate.threshold == 0 || gate.children.is_empty() {
                return Err(AcuError::SerializationError("malformed GateDescriptor"));
            }
            let mut seen_rows = BTreeSet::new();
            let mut seen_scalars = BTreeSet::new();
            for child in &gate.children {
                if bool::from(child.eval_scalar.is_zero())
                    || !seen_scalars.insert(child.eval_scalar.to_bytes())
                    || child.row_indices.is_empty()
                {
                    return Err(AcuError::SerializationError("malformed GateChild"));
                }
                for &r_idx in &child.row_indices {
                    if r_idx >= self.rows.len() || !seen_rows.insert(r_idx) {
                        return Err(AcuError::SerializationError(
                            "GateChild row index out of bounds or overlapping",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Retain only rows where `keep_mask[j] == true`, remapping all [`GateDescriptor`] indices cleanly.
    pub fn retain_rows(&mut self, keep_mask: &[bool]) -> Result<(), AcuError> {
        if keep_mask.len() != self.rows.len() {
            return Err(AcuError::DimensionMismatch {
                expected: self.rows.len(),
                actual: keep_mask.len(),
            });
        }
        let mut old_to_new: Vec<Option<usize>> = Vec::with_capacity(self.rows.len());
        let mut new_rows = Vec::new();
        for (idx, (keep, row)) in keep_mask.iter().zip(self.rows.iter()).enumerate() {
            let _ = idx;
            if *keep {
                old_to_new.push(Some(new_rows.len()));
                new_rows.push(row.clone());
            } else {
                old_to_new.push(None);
            }
        }
        if new_rows.is_empty() {
            return Err(AcuError::EmptyPolicy);
        }
        self.rows = new_rows;

        let mut updated_gates = Vec::with_capacity(self.gates.len());
        for gate in &self.gates {
            let mut remapped_children = Vec::new();
            for child in &gate.children {
                let mapped: Vec<usize> = child
                    .row_indices
                    .iter()
                    .filter_map(|&old| old_to_new.get(old).copied().flatten())
                    .collect();
                if !mapped.is_empty() {
                    remapped_children.push(GateChild {
                        eval_scalar: child.eval_scalar,
                        row_indices: mapped,
                    });
                }
            }
            if !remapped_children.is_empty() {
                let new_gid = updated_gates.len();
                updated_gates.push(GateDescriptor {
                    gate_id: new_gid,
                    threshold: gate.threshold,
                    children: remapped_children,
                });
            }
        }
        self.gates = updated_gates;
        self.validate()
    }

    /// Append an `OR`-equivalent warm-fork sibling leaf for `existing_row_idx`, updating nested
    /// [`GateDescriptor`] partitions so outer threshold gates keep the sibling inside the same child
    /// subtree $C_{g,c}$ while an inner `OR` gate assigns a fresh evaluation scalar.
    pub fn attach_sibling(
        &mut self,
        existing_row_idx: usize,
        new_seat_id: String,
    ) -> Result<usize, AcuError> {
        if !is_valid_seat_id(&new_seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
        if existing_row_idx >= self.rows.len() {
            return Err(AcuError::RowIndexOutOfBounds {
                index: existing_row_idx,
                total_rows: self.rows.len(),
            });
        }
        if self.rows.len() >= MAX_SERIALIZED_ROWS {
            return Err(AcuError::SerializationError(
                "invalid AcuCiphertext dimensions",
            ));
        }
        let cloned_vec = self.rows[existing_row_idx].1.clone();
        let new_row_idx = self.rows.len();
        self.rows.push((new_seat_id, cloned_vec));

        // Locate all gates containing `existing_row_idx`; the innermost has the smallest total leaf count
        // (breaking ties by largest `gate_id`, since `convert_threshold` allocates preorder `gate_id`s).
        let mut containing: Vec<(usize, usize, usize)> = Vec::new();
        for (gid, gate) in self.gates.iter().enumerate() {
            if let Some(cid) = gate
                .children
                .iter()
                .position(|c| c.row_indices.contains(&existing_row_idx))
            {
                let total_leaves: usize = gate.children.iter().map(|c| c.row_indices.len()).sum();
                containing.push((gid, cid, total_leaves));
            }
        }

        let innermost_gid = containing
            .iter()
            .min_by(|a, b| a.2.cmp(&b.2).then_with(|| b.0.cmp(&a.0)))
            .map(|x| x.0);

        let mut created_or_branch = false;
        for &(gid, cid, _) in &containing {
            if Some(gid) == innermost_gid
                && self.gates[gid].threshold == 1
                && self.gates[gid].children[cid].row_indices.len() == 1
            {
                let next_scalar = next_distinct_gate_scalar(&self.gates[gid]);
                self.gates[gid].children.push(GateChild {
                    eval_scalar: next_scalar,
                    row_indices: vec![new_row_idx],
                });
                created_or_branch = true;
            } else {
                self.gates[gid].children[cid].row_indices.push(new_row_idx);
            }
        }

        if !created_or_branch && self.gates.len() < MAX_SERIALIZED_GATES {
            let new_gid = self.gates.len();
            self.gates.push(GateDescriptor {
                gate_id: new_gid,
                threshold: 1,
                children: vec![
                    GateChild {
                        eval_scalar: Scalar::from(1u64),
                        row_indices: vec![existing_row_idx],
                    },
                    GateChild {
                        eval_scalar: Scalar::from(2u64),
                        row_indices: vec![new_row_idx],
                    },
                ],
            });
        }

        self.validate()?;
        Ok(new_row_idx)
    }

    /// Project any post-evolution classical [`LsssMatrix`] $(M_E, \rho_E)$ modulo the row span
    /// $W = \mathrm{span}(\{M_{E,j} : \rho_E(j) = \text{acu\_seat\_id}\}) \subset \mathbb{F}_r^k$
    /// to obtain the exact non-ACU post-quantum LSSS matrix $(M^{\mathsf{pq}}_{E}, \rho^{\mathsf{pq}}_{E})$
    /// (`ePrint v2` §6.3 Op 4 & Theorem 3(i), `ACU-V2-F03`).
    ///
    /// A non-ACU custodian subset $S$ spans $(1, 0, \dots, 0)$ in the returned $(k - \dim W)$-column
    /// matrix **if and only if** $e_0 \in \mathrm{span}(M_S \cup M_{\mathrm{ACU}})$, preserving every
    /// prior revocation, threshold escalation, warm-fork, and authorized seat insertion identically
    /// while assigning **zero** rows to `acu_seat_id`.
    pub fn project_non_acu_matrix(&self, acu_seat_id: &str) -> Result<Option<Self>, AcuError> {
        self.validate()?;
        if !is_valid_seat_id(acu_seat_id) {
            return Err(AcuError::InvalidSeatId);
        }

        let k = self.cols;
        let mut acu_rows: Vec<Vec<Scalar>> = Vec::new();
        let mut non_acu_rows: Vec<(String, Vec<Scalar>)> = Vec::new();
        for (seat, vec) in &self.rows {
            if seat == acu_seat_id {
                acu_rows.push(vec.clone());
            } else {
                non_acu_rows.push((seat.clone(), vec.clone()));
            }
        }

        if non_acu_rows.is_empty() || rows_span_target(k, &acu_rows) {
            return Ok(None);
        }
        if acu_rows.is_empty() {
            return Ok(Some(self.clone()));
        }

        // 1. Row-reduce M_ACU over F_r to a linearly independent basis w_1, ..., w_d of W.
        let w_basis = row_echelon_basis(k, &acu_rows);
        let d = w_basis.len();
        if d == 0 {
            let projected = Self {
                cols: k,
                rows: non_acu_rows,
                gates: Vec::new(),
            };
            projected.validate()?;
            return Ok(Some(projected));
        }

        // 2. Find the k - (d + 1) non-pivot columns of span(e_0, w_1, ..., w_d) so appending those
        // standard unit vectors completes (e_0, w_1, ..., w_d) to an invertible k x k basis B.
        let mut e0 = vec![Scalar::ZERO; k];
        e0[0] = Scalar::ONE;
        let mut u_rows = Vec::with_capacity(1 + d);
        u_rows.push(e0.clone());
        u_rows.extend(w_basis.iter().cloned());
        let pivot_cols = rref_pivot_columns(k, &u_rows);
        if pivot_cols.len() != 1 + d {
            return Err(AcuError::PolicyNotSatisfied);
        }

        let mut b_rows: Vec<Vec<Scalar>> = Vec::with_capacity(k);
        b_rows.push(e0);
        b_rows.extend(w_basis);
        for c in 0..k {
            if !pivot_cols.contains(&c) {
                let mut ec = vec![Scalar::ZERO; k];
                ec[c] = Scalar::ONE;
                b_rows.push(ec);
            }
        }
        if b_rows.len() != k {
            return Err(AcuError::PolicyNotSatisfied);
        }

        // 3. Invert B over F_r via [B | I_k] Gauss-Jordan elimination (k <= 128).
        let b_inv = invert_square_matrix(k, &b_rows)?;

        // 4. Map each non-ACU row m_j -> m_j * B^{-1} and drop W-coordinates 1..=d.
        let proj_cols = k - d;
        let mut projected_rows: Vec<(String, Vec<Scalar>)> = Vec::with_capacity(non_acu_rows.len());
        for (seat, m_row) in non_acu_rows {
            let mut tilde = vec![Scalar::ZERO; k];
            for (r, &m_val) in m_row.iter().enumerate() {
                if bool::from(m_val.is_zero()) {
                    continue;
                }
                for (c, &inv_val) in b_inv[r].iter().enumerate() {
                    tilde[c] += m_val * inv_val;
                }
            }
            let mut proj_vec = Vec::with_capacity(proj_cols);
            proj_vec.push(tilde[0]);
            proj_vec.extend_from_slice(&tilde[(1 + d)..k]);
            if proj_vec.iter().any(|s| !bool::from(s.is_zero())) {
                projected_rows.push((seat, proj_vec));
            }
        }

        if projected_rows.is_empty() {
            return Err(AcuError::PolicyNotSatisfied);
        }

        let projected = Self {
            cols: proj_cols,
            rows: projected_rows,
            gates: Vec::new(),
        };
        projected.validate()?;
        Ok(Some(projected))
    }

    /// Append a coalition-authorized row `(new_seat_id, new_row_vec)` (`ePrint v2` §6.3 Op 3),
    /// updating [`GateDescriptor`] metadata automatically when `new_row_vec` duplicates an existing
    /// sibling row or extends a root `1-of-n` gate.
    pub fn append_authorized_row(
        &mut self,
        new_seat_id: String,
        new_row_vec: Vec<Scalar>,
    ) -> Result<usize, AcuError> {
        if !is_valid_seat_id(&new_seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
        if new_row_vec.len() != self.cols {
            return Err(AcuError::DimensionMismatch {
                expected: self.cols,
                actual: new_row_vec.len(),
            });
        }
        if new_row_vec.iter().all(|s| bool::from(s.is_zero())) {
            return Err(AcuError::InvalidAccessTree("LSSS row cannot be all zero"));
        }
        if let Some(existing_idx) = self.rows.iter().position(|(_, v)| *v == new_row_vec) {
            return self.attach_sibling(existing_idx, new_seat_id);
        }
        if self.rows.len() >= MAX_SERIALIZED_ROWS {
            return Err(AcuError::SerializationError(
                "invalid AcuCiphertext dimensions",
            ));
        }
        let new_row_idx = self.rows.len();
        let is_unit_e0 = new_row_vec[0] == Scalar::ONE
            && new_row_vec[1..].iter().all(|s| bool::from(s.is_zero()));
        self.rows.push((new_seat_id, new_row_vec));
        if is_unit_e0
            && let Some(root_gate) = self.gates.first_mut()
            && root_gate.threshold == 1
        {
            let next_scalar = next_distinct_gate_scalar(root_gate);
            root_gate.children.push(GateChild {
                eval_scalar: next_scalar,
                row_indices: vec![new_row_idx],
            });
        }
        self.validate()?;
        Ok(new_row_idx)
    }

    /// Resolve a [`GateDescriptor`] index matching the exact leaf-row union `gate_row_indices`.
    pub fn resolve_gate_for_rows(&self, gate_row_indices: &[usize]) -> Result<usize, AcuError> {
        if gate_row_indices.is_empty() {
            return Err(AcuError::EmptyPolicy);
        }
        let mut target = BTreeSet::new();
        for &idx in gate_row_indices {
            if idx >= self.rows.len() {
                return Err(AcuError::RowIndexOutOfBounds {
                    index: idx,
                    total_rows: self.rows.len(),
                });
            }
            target.insert(idx);
        }

        let mut best: Option<usize> = None;
        for gate in &self.gates {
            let mut union = BTreeSet::new();
            for child in &gate.children {
                for &idx in &child.row_indices {
                    union.insert(idx);
                }
            }
            if union == target {
                match best {
                    None => best = Some(gate.gate_id),
                    Some(prev_gid) => {
                        if gate.children.len() > self.gates[prev_gid].children.len() {
                            best = Some(gate.gate_id);
                        }
                    }
                }
            }
        }
        best.ok_or(AcuError::InvalidAccessTree(
            "gate_row_indices do not match any compiled gate subtree",
        ))
    }

    /// Escalate gate `gate_id` by `delta_t` (`t_g -> t_g + delta_t <= n_g`), appending `delta_t`
    /// subtree-consistent Vandermonde columns $(x_{g,c}^{t_g}, \dots, x_{g,c}^{t_g + \Delta t - 1})$
    /// shared identically across every leaf row $j \in C_{g,c}$ (`ePrint v2` §6.3 Op 2).
    ///
    /// Returns, for each row $j \in 0..\ell$, the appended length-`delta_t` column tail.
    pub fn escalate_gate(
        &mut self,
        gate_id: usize,
        delta_t: usize,
    ) -> Result<Vec<Vec<Scalar>>, AcuError> {
        let Some(gate) = self.gates.get(gate_id) else {
            return Err(AcuError::InvalidAccessTree("gate_id out of bounds"));
        };
        let n_children = gate.children.len();
        if delta_t == 0 {
            return Err(AcuError::InvalidThreshold {
                threshold: gate.threshold,
                children: n_children,
            });
        }
        let new_threshold =
            gate.threshold
                .checked_add(delta_t)
                .ok_or(AcuError::InvalidThreshold {
                    threshold: usize::MAX,
                    children: n_children,
                })?;
        if new_threshold > n_children {
            return Err(AcuError::InvalidThreshold {
                threshold: new_threshold,
                children: n_children,
            });
        }
        let new_cols = self
            .cols
            .checked_add(delta_t)
            .filter(|&c| c <= MAX_SERIALIZED_COLS)
            .ok_or(AcuError::SerializationError(
                "invalid AcuCiphertext dimensions",
            ))?;

        let old_t = gate.threshold;
        let mut row_tails = vec![vec![Scalar::ZERO; delta_t]; self.rows.len()];
        for child in &gate.children {
            let x = child.eval_scalar;
            let mut powers = Vec::with_capacity(delta_t);
            let mut cur = scalar_pow(x, old_t as u64);
            for _ in 0..delta_t {
                powers.push(cur);
                cur *= x;
            }
            for &r_idx in &child.row_indices {
                row_tails[r_idx].clone_from(&powers);
            }
        }

        for (row_idx, (_, vec)) in self.rows.iter_mut().enumerate() {
            vec.extend_from_slice(&row_tails[row_idx]);
        }
        self.cols = new_cols;
        self.gates[gate_id].threshold = new_threshold;
        self.validate()?;
        Ok(row_tails)
    }

    /// Compute a canonical 32-byte SHA-256 digest binding `(cols, rows, gates)` so initial
    /// `RowPok` proofs cannot be cut-and-pasted into a synthetic policy matrix (`test_20`).
    #[must_use]
    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"chinwag.acu.v2.lsss-matrix");
        h.update((self.cols as u32).to_be_bytes());
        h.update((self.rows.len() as u32).to_be_bytes());
        let mut buf = Vec::new();
        for (seat_id, vec) in &self.rows {
            buf.clear();
            lp64_str(&mut buf, seat_id);
            h.update(&buf);
            for s in vec {
                h.update(s.to_bytes());
            }
        }
        buf.clear();
        self.encode_gates(&mut buf);
        h.update(&buf);
        h.finalize().into()
    }

    /// Serialize `self.gates` into canonical deterministic binary framing.
    pub(crate) fn encode_gates(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.gates.len() as u32).to_be_bytes());
        for gate in &self.gates {
            out.extend_from_slice(&(gate.threshold as u32).to_be_bytes());
            out.extend_from_slice(&(gate.children.len() as u32).to_be_bytes());
            for child in &gate.children {
                out.extend_from_slice(&child.eval_scalar.to_bytes());
                out.extend_from_slice(&(child.row_indices.len() as u32).to_be_bytes());
                for &idx in &child.row_indices {
                    out.extend_from_slice(&(idx as u32).to_be_bytes());
                }
            }
        }
    }

    /// Deserialize `GateDescriptor`s from canonical binary framing.
    pub(crate) fn decode_gates(
        bytes: &[u8],
        cursor: &mut usize,
        num_rows: usize,
    ) -> Result<Vec<GateDescriptor>, AcuError> {
        let num_gates = read_u32_be(bytes, cursor)? as usize;
        if num_gates > MAX_SERIALIZED_GATES {
            return Err(AcuError::SerializationError("too many gates in LsssMatrix"));
        }
        let mut gates = Vec::with_capacity(num_gates);
        for gate_id in 0..num_gates {
            let threshold = read_u32_be(bytes, cursor)? as usize;
            let num_children = read_u32_be(bytes, cursor)? as usize;
            if threshold == 0 || num_children == 0 || num_children > MAX_SERIALIZED_ROWS {
                return Err(AcuError::SerializationError("invalid GateDescriptor"));
            }
            let mut children = Vec::with_capacity(num_children);
            for _ in 0..num_children {
                let eval_scalar = read_scalar(bytes, cursor)?;
                let n_rows = read_u32_be(bytes, cursor)? as usize;
                if n_rows == 0 || n_rows > num_rows {
                    return Err(AcuError::SerializationError("invalid GateChild row count"));
                }
                let mut row_indices = Vec::with_capacity(n_rows);
                for _ in 0..n_rows {
                    let r_idx = read_u32_be(bytes, cursor)? as usize;
                    if r_idx >= num_rows {
                        return Err(AcuError::SerializationError(
                            "GateChild row index out of bounds",
                        ));
                    }
                    row_indices.push(r_idx);
                }
                children.push(GateChild {
                    eval_scalar,
                    row_indices,
                });
            }
            gates.push(GateDescriptor {
                gate_id,
                threshold,
                children,
            });
        }
        Ok(gates)
    }
}

fn next_distinct_gate_scalar(gate: &GateDescriptor) -> Scalar {
    let existing: BTreeSet<[u8; 32]> = gate
        .children
        .iter()
        .map(|c| c.eval_scalar.to_bytes())
        .collect();
    for cand in 1u64.. {
        let s = Scalar::from(cand);
        if !existing.contains(&s.to_bytes()) {
            return s;
        }
    }
    unreachable!("finite GateChild set leaves unbounded distinct scalars in F_r")
}

fn scalar_pow(base: Scalar, mut exp: u64) -> Scalar {
    let mut result = Scalar::ONE;
    let mut cur = base;
    while exp > 0 {
        if (exp & 1) == 1 {
            result *= cur;
        }
        cur = cur.square();
        exp >>= 1;
    }
    result
}

#[derive(Clone, Debug)]
enum ProjectedNode {
    AlwaysTrue,
    Subtree(AccessTree),
}

/// Compute the non-ACU post-quantum confidentiality projection
/// $\mathcal{T}_{\mathsf{conf}} = \mathcal{T}|_{\mathsf{ACU}=\mathsf{true}}$ (`ePrint v2` §1.5).
///
/// Substitutes `true` for every leaf matching `acu_seat_id` so the `ACU` operator receives **zero**
/// post-quantum rows while every non-ACU conjunctive and $t$-of-$n$ threshold gate is preserved
/// identically. Returns `Ok(None)` if the input policy depended exclusively on `acu_seat_id`.
pub fn project_non_acu(
    tree: &AccessTree,
    acu_seat_id: &str,
) -> Result<Option<AccessTree>, AcuError> {
    if !is_valid_seat_id(acu_seat_id) {
        return Err(AcuError::InvalidSeatId);
    }
    match project_node(tree, acu_seat_id)? {
        ProjectedNode::AlwaysTrue => Ok(None),
        ProjectedNode::Subtree(sub) => Ok(Some(sub)),
    }
}

fn project_node(node: &AccessTree, acu_seat_id: &str) -> Result<ProjectedNode, AcuError> {
    match node {
        AccessTree::Leaf(seat_id) => {
            if !is_valid_seat_id(seat_id) {
                return Err(AcuError::InvalidSeatId);
            }
            if seat_id == acu_seat_id {
                Ok(ProjectedNode::AlwaysTrue)
            } else {
                Ok(ProjectedNode::Subtree(AccessTree::Leaf(seat_id.clone())))
            }
        }
        AccessTree::Or(children) => {
            if children.is_empty() {
                return Err(AcuError::InvalidAccessTree(
                    "OR gate must have at least one child",
                ));
            }
            let mut subtrees = Vec::with_capacity(children.len());
            let mut any_true = false;
            for child in children {
                match project_node(child, acu_seat_id)? {
                    ProjectedNode::AlwaysTrue => any_true = true,
                    ProjectedNode::Subtree(sub) => subtrees.push(sub),
                }
            }
            if any_true {
                Ok(ProjectedNode::AlwaysTrue)
            } else if subtrees.len() == 1 {
                Ok(ProjectedNode::Subtree(
                    subtrees.pop().expect("len == 1 checked"),
                ))
            } else {
                Ok(ProjectedNode::Subtree(AccessTree::Or(subtrees)))
            }
        }
        AccessTree::And(children) => {
            if children.is_empty() {
                return Err(AcuError::InvalidAccessTree(
                    "AND gate must have at least one child",
                ));
            }
            let mut subtrees = Vec::with_capacity(children.len());
            for child in children {
                if let ProjectedNode::Subtree(sub) = project_node(child, acu_seat_id)? {
                    subtrees.push(sub);
                }
            }
            if subtrees.is_empty() {
                Ok(ProjectedNode::AlwaysTrue)
            } else if subtrees.len() == 1 {
                Ok(ProjectedNode::Subtree(
                    subtrees.pop().expect("len == 1 checked"),
                ))
            } else {
                Ok(ProjectedNode::Subtree(AccessTree::And(subtrees)))
            }
        }
        AccessTree::Threshold {
            threshold,
            children,
        } => {
            if children.is_empty() {
                return Err(AcuError::InvalidAccessTree(
                    "threshold gate must have at least one child",
                ));
            }
            if *threshold == 0 || *threshold > children.len() {
                return Err(AcuError::InvalidThreshold {
                    threshold: *threshold,
                    children: children.len(),
                });
            }
            let mut true_count = 0usize;
            let mut subtrees = Vec::with_capacity(children.len());
            for child in children {
                match project_node(child, acu_seat_id)? {
                    ProjectedNode::AlwaysTrue => true_count += 1,
                    ProjectedNode::Subtree(sub) => subtrees.push(sub),
                }
            }
            if true_count >= *threshold {
                Ok(ProjectedNode::AlwaysTrue)
            } else {
                let new_threshold = *threshold - true_count;
                if subtrees.len() == 1 && new_threshold == 1 {
                    Ok(ProjectedNode::Subtree(
                        subtrees.pop().expect("len == 1 checked"),
                    ))
                } else {
                    Ok(ProjectedNode::Subtree(AccessTree::Threshold {
                        threshold: new_threshold,
                        children: subtrees,
                    }))
                }
            }
        }
    }
}

/// Check whether an arbitrary collection of row vectors $R \subset \mathbb{F}_r^k$ spans the
/// secret target vector $e_0 = (1, 0, \dots, 0) \in \mathbb{F}_r^k$.
#[must_use]
pub fn rows_span_target(cols: usize, rows: &[Vec<Scalar>]) -> bool {
    if cols == 0 || rows.is_empty() {
        return false;
    }
    if rows.iter().any(|r| r.len() != cols) {
        return false;
    }
    let m = rows.len();
    let mut aug = vec![vec![Scalar::ZERO; m + 1]; cols];
    for (col_var, row_vec) in rows.iter().enumerate() {
        for (coord, &val) in row_vec.iter().enumerate() {
            aug[coord][col_var] = val;
        }
    }
    aug[0][m] = Scalar::ONE;

    let mut pivot_col_for_row: Vec<Option<usize>> = vec![None; cols];
    let mut pivot_row = 0usize;
    for col in 0..m {
        if pivot_row >= cols {
            break;
        }
        let Some(found_row) = (pivot_row..cols).find(|&r| !bool::from(aug[r][col].is_zero()))
        else {
            continue;
        };
        aug.swap(pivot_row, found_row);
        pivot_col_for_row[pivot_row] = Some(col);
        let inv_opt: Option<Scalar> = aug[pivot_row][col].invert().into();
        let Some(inv) = inv_opt else {
            return false;
        };
        for entry in &mut aug[pivot_row][col..=m] {
            *entry *= inv;
        }
        let pivot_copy = aug[pivot_row].clone();
        for (other_row, row_vals) in aug.iter_mut().enumerate() {
            if other_row == pivot_row {
                continue;
            }
            let factor = row_vals[col];
            if !bool::from(factor.is_zero()) {
                for (c, &p_val) in pivot_copy.iter().enumerate().skip(col) {
                    row_vals[c] -= factor * p_val;
                }
            }
        }
        pivot_row += 1;
    }

    for r in 0..cols {
        if pivot_col_for_row[r].is_none() && !bool::from(aug[r][m].is_zero()) {
            return false;
        }
    }
    true
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

    let mut aug = vec![vec![Scalar::ZERO; m + 1]; k];
    for (col_var, &row_idx) in unique_indices.iter().enumerate() {
        let row_vec = &matrix.rows[row_idx].1;
        for (coord, &val) in row_vec.iter().enumerate() {
            aug[coord][col_var] = val;
        }
    }
    aug[0][m] = Scalar::ONE;

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

    for r in 0..k {
        if pivot_col_for_row[r].is_none() && !bool::from(aug[r][m].is_zero()) {
            return Err(AcuError::PolicyNotSatisfied);
        }
    }

    let mut omega = vec![Scalar::ZERO; m];
    for r in 0..k {
        if let Some(col) = pivot_col_for_row[r] {
            omega[col] = aug[r][m];
        }
    }

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

fn row_echelon_basis(cols: usize, rows: &[Vec<Scalar>]) -> Vec<Vec<Scalar>> {
    let mut work: Vec<Vec<Scalar>> = rows.to_vec();
    let mut pivot_row = 0usize;
    for col in 0..cols {
        if pivot_row >= work.len() {
            break;
        }
        let Some(found) = (pivot_row..work.len()).find(|&r| !bool::from(work[r][col].is_zero()))
        else {
            continue;
        };
        work.swap(pivot_row, found);
        let inv: Option<Scalar> = work[pivot_row][col].invert().into();
        let Some(inv) = inv else {
            continue;
        };
        for entry in &mut work[pivot_row][col..cols] {
            *entry *= inv;
        }
        let pivot_copy = work[pivot_row].clone();
        for (r_idx, row_vals) in work.iter_mut().enumerate() {
            if r_idx == pivot_row {
                continue;
            }
            let factor = row_vals[col];
            if !bool::from(factor.is_zero()) {
                for (c, &p_val) in pivot_copy.iter().enumerate().skip(col) {
                    row_vals[c] -= factor * p_val;
                }
            }
        }
        pivot_row += 1;
    }
    work.truncate(pivot_row);
    work
}

fn rref_pivot_columns(cols: usize, rows: &[Vec<Scalar>]) -> BTreeSet<usize> {
    let mut work: Vec<Vec<Scalar>> = rows.to_vec();
    let mut pivots = BTreeSet::new();
    let mut pivot_row = 0usize;
    for col in 0..cols {
        if pivot_row >= work.len() {
            break;
        }
        let Some(found) = (pivot_row..work.len()).find(|&r| !bool::from(work[r][col].is_zero()))
        else {
            continue;
        };
        work.swap(pivot_row, found);
        let inv: Option<Scalar> = work[pivot_row][col].invert().into();
        let Some(inv) = inv else {
            continue;
        };
        for entry in &mut work[pivot_row][col..cols] {
            *entry *= inv;
        }
        let pivot_copy = work[pivot_row].clone();
        for (r_idx, row_vals) in work.iter_mut().enumerate() {
            if r_idx == pivot_row {
                continue;
            }
            let factor = row_vals[col];
            if !bool::from(factor.is_zero()) {
                for (c, &p_val) in pivot_copy.iter().enumerate().skip(col) {
                    row_vals[c] -= factor * p_val;
                }
            }
        }
        pivots.insert(col);
        pivot_row += 1;
    }
    pivots
}

fn invert_square_matrix(k: usize, rows: &[Vec<Scalar>]) -> Result<Vec<Vec<Scalar>>, AcuError> {
    let mut aug = vec![vec![Scalar::ZERO; 2 * k]; k];
    for (r, row) in rows.iter().enumerate() {
        aug[r][..k].copy_from_slice(&row[..k]);
        aug[r][k + r] = Scalar::ONE;
    }
    for col in 0..k {
        let found = (col..k)
            .find(|&r| !bool::from(aug[r][col].is_zero()))
            .ok_or(AcuError::PolicyNotSatisfied)?;
        aug.swap(col, found);
        let inv_opt: Option<Scalar> = aug[col][col].invert().into();
        let inv = inv_opt.ok_or(AcuError::PolicyNotSatisfied)?;
        for entry in &mut aug[col][col..(2 * k)] {
            *entry *= inv;
        }
        let pivot_copy = aug[col].clone();
        for (other, row_vals) in aug.iter_mut().enumerate() {
            if other == col {
                continue;
            }
            let factor = row_vals[col];
            if !bool::from(factor.is_zero()) {
                for (c, &p_val) in pivot_copy.iter().enumerate().skip(col) {
                    row_vals[c] -= factor * p_val;
                }
            }
        }
    }
    Ok(aug
        .into_iter()
        .map(|row| row[k..(2 * k)].to_vec())
        .collect())
}

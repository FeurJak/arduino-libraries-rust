//! MAC computation and verification for SAGA.
//!
//! Implements the core MAC operations:
//! - `compute_tag`: Issue a credential (requires secret key)
//! - `verify_tag`: Verify a credential (requires secret key)

use rand_core::{CryptoRng, RngCore};

use super::errors::SagaError;
use super::nizk::{compute_predicate, compute_tag_proof, verify_tag_proof, Predicate};
use super::smul;
use super::types::{Parameters, Point, PublicKey, Scalar, ScalarExt, SecretKey, MAX_ATTRS};

/// Schnorr-style NIZK proof for BBS-SAGA MAC correctness.
#[derive(Clone, Debug)]
pub struct Proof {
    /// Challenge scalar
    pub c: Scalar,
    /// Response for x
    pub s_x: Scalar,
    /// Responses for y_1..y_l (fixed size array)
    pub s_y_vec: [Scalar; MAX_ATTRS],
    /// Number of active responses
    pub(crate) num_attrs: usize,
}

impl Proof {
    /// Returns the active portion of s_y_vec
    #[inline]
    pub fn s_y_vec_slice(&self) -> &[Scalar] {
        &self.s_y_vec[..self.num_attrs]
    }
}

/// A SAGA credential tag (MAC with NIZK proof).
#[derive(Clone, Debug)]
pub struct Tag {
    /// The MAC point A
    pub g_a: Point,
    /// The randomness scalar e
    pub e: Scalar,
    /// NIZK proof of correct construction
    pub proof: Proof,
}

impl Tag {
    /// Verify the tag using the public key (holder-side verification).
    ///
    /// This verifies the NIZK proof that the tag was correctly computed.
    pub fn verify(&self, params: &Parameters, pk: &PublicKey, messages: &[Point]) -> bool {
        verify_tag_proof(params, pk, &self.g_a, &self.e, messages, &self.proof)
    }

    /// Create an unlinkable presentation from this tag.
    ///
    /// # Arguments
    /// * `rng` - Random number generator
    /// * `params` - Public parameters
    /// * `pk` - Issuer's public key
    /// * `messages` - Original attribute values
    pub fn get_predicate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        params: &Parameters,
        pk: &PublicKey,
        messages: &[Point],
    ) -> Result<Predicate, SagaError> {
        compute_predicate(rng, params, pk, self, messages)
    }
}

/// Compute a MAC (credential) for the given messages.
///
/// This is the credential issuance operation, performed by the issuer.
///
/// # Algorithm
///
/// 1. Sample random e such that x + e != 0
/// 2. Compute S = G_0 + Σ y_j * M_j
/// 3. Compute A = (x + e)^(-1) * S
/// 4. Generate NIZK proof of correct construction
///
/// # Arguments
/// * `rng` - Cryptographically secure random number generator
/// * `params` - Public parameters
/// * `sk` - Issuer's secret key
/// * `pk` - Issuer's public key
/// * `messages` - Attribute values as curve points
pub fn compute_tag<R: RngCore + CryptoRng>(
    rng: &mut R,
    params: &Parameters,
    sk: &SecretKey,
    pk: &PublicKey,
    messages: &[Point],
) -> Result<Tag, SagaError> {
    let l = params.num_attrs;

    if messages.len() != l {
        return Err(SagaError::LengthMismatch {
            expected: l,
            got: messages.len(),
        });
    }
    if sk.num_attrs != l {
        return Err(SagaError::LengthMismatch {
            expected: l,
            got: sk.num_attrs,
        });
    }

    // Sample e such that x + e != 0
    let e = loop {
        let e_try = Scalar::rand(rng);
        let sum = sk.x + e_try;
        if sum != Scalar::ZERO {
            break e_try;
        }
    };

    // S = G_0 + Σ y_j * M_j
    let mut g_s = params.pp_saga;
    for j in 0..l {
        g_s += smul(&messages[j], &sk.y_vec[j]);
    }

    // A = (x + e)^(-1) * S
    let sum = sk.x + e;
    if sum == Scalar::ZERO {
        return Err(SagaError::NonInvertible);
    }
    let inv = sum.invert();
    let g_a = smul(&g_s, &inv);

    // Generate NIZK proof
    let proof = compute_tag_proof(rng, params, pk, sk, &g_a, &e, messages);

    Ok(Tag { g_a, e, proof })
}

/// Verify a MAC (issuer side, requires secret key).
///
/// Verifies: (x + e) * A == G_0 + Σ y_j * M_j
///
/// # Arguments
/// * `params` - Public parameters
/// * `sk` - Issuer's secret key
/// * `tag` - The MAC to verify
/// * `messages` - The original messages
pub fn verify_tag(
    params: &Parameters,
    sk: &SecretKey,
    tag: &Tag,
    messages: &[Point],
) -> Result<bool, SagaError> {
    let l = params.num_attrs;

    if messages.len() != l || sk.num_attrs != l {
        return Err(SagaError::LengthMismatch {
            expected: l,
            got: messages.len(),
        });
    }

    // LHS = (x + e) * A
    let lhs = smul(&tag.g_a, &(sk.x + tag.e));

    // RHS = G_0 + Σ y_j * M_j
    let mut rhs = params.pp_saga;
    for j in 0..l {
        rhs += smul(&messages[j], &sk.y_vec[j]);
    }

    Ok(lhs == rhs)
}

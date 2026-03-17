//! Core types for the SAGA scheme.
//!
//! Uses fixed-size arrays to avoid heap allocations for no_std compatibility.

use rand_core::{CryptoRng, RngCore};

// Re-export curve25519-dalek types
pub use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
pub use curve25519_dalek::edwards::EdwardsPoint as Point;
pub use curve25519_dalek::scalar::Scalar;
pub use curve25519_dalek::traits::Identity;

use super::errors::SagaError;
use super::mac::{compute_tag, verify_tag, Tag};
use super::nizk::{verify_presentation, Presentation};
use super::smul;

/// Maximum number of attributes supported.
/// This is a compile-time constant to avoid heap allocations.
/// Adjust based on your use case (more attributes = more memory).
pub const MAX_ATTRS: usize = 8;

/// Extension trait for Point operations
pub trait PointExt {
    /// Returns the curve generator point (Ed25519 basepoint)
    fn generator() -> Point;
    /// Returns the identity (zero) point
    fn zero() -> Point;
    /// Serialize to compressed 32-byte format
    fn to_bytes(&self) -> [u8; 32];
    /// Deserialize from compressed 32-byte format
    fn from_bytes(bytes: &[u8; 32]) -> Option<Point>;
}

impl PointExt for Point {
    #[inline]
    fn generator() -> Point {
        ED25519_BASEPOINT_POINT
    }

    #[inline]
    fn zero() -> Point {
        Point::identity()
    }

    #[inline]
    fn to_bytes(&self) -> [u8; 32] {
        self.compress().to_bytes()
    }

    #[inline]
    fn from_bytes(bytes: &[u8; 32]) -> Option<Point> {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        let compressed = CompressedEdwardsY::from_slice(bytes).ok()?;
        compressed.decompress()
    }
}

/// Extension trait for Scalar operations
pub trait ScalarExt {
    /// Generate a random scalar
    fn rand<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar;
    /// Serialize to 32 bytes
    fn to_bytes(&self) -> [u8; 32];
    /// Deserialize from 32 bytes
    fn from_bytes(bytes: &[u8; 32]) -> Option<Scalar>;
}

impl ScalarExt for Scalar {
    #[inline]
    fn rand<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order_wide(&bytes)
    }

    #[inline]
    fn to_bytes(&self) -> [u8; 32] {
        *self.as_bytes()
    }

    #[inline]
    fn from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
        Some(Scalar::from_bytes_mod_order(*bytes))
    }
}

/// Public parameters from setup.
///
/// Contains the curve generator and derived points for the credential scheme.
#[derive(Clone, Debug)]
pub struct Parameters {
    /// The canonical curve generator G
    pub g: Point,
    /// pp_saga := G_0 (random point for MAC construction)
    pub pp_saga: Point,
    /// (G_1, ..., G_l) - one generator per attribute slot
    pub g_vec: [Point; MAX_ATTRS],
    /// Trapdoor vector (td_1, ..., td_l) where G_j = td_j * G
    /// Note: Currently unused, but kept for potential future extensions
    /// (e.g., hierarchical credential delegation)
    #[allow(dead_code)]
    pub(crate) td_vec: [Scalar; MAX_ATTRS],
    /// Number of active attributes (must be <= MAX_ATTRS)
    pub(crate) num_attrs: usize,
}

impl Parameters {
    /// Setup SAGA parameters for `l` attributes.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator
    /// * `l` - Number of attributes (must be <= MAX_ATTRS)
    ///
    /// # Returns
    /// Parameters or error if l > MAX_ATTRS
    pub fn setup<R: RngCore + CryptoRng>(rng: &mut R, l: usize) -> Result<Self, SagaError> {
        if l > MAX_ATTRS {
            return Err(SagaError::TooManyAttributes {
                max: MAX_ATTRS,
                requested: l,
            });
        }

        let g = Point::generator();

        // G0 = r * G
        let r = Scalar::rand(rng);
        let g0 = smul(&g, &r);

        // Sample td_1..td_l and compute G_j = td_j * G
        let mut td_vec = [Scalar::ZERO; MAX_ATTRS];
        let mut g_vec = [Point::identity(); MAX_ATTRS];

        for j in 0..l {
            td_vec[j] = Scalar::rand(rng);
            g_vec[j] = smul(&g, &td_vec[j]);
        }

        Ok(Self {
            g,
            pp_saga: g0,
            g_vec,
            td_vec,
            num_attrs: l,
        })
    }

    /// Returns the number of active attributes
    #[inline]
    pub fn num_attrs(&self) -> usize {
        self.num_attrs
    }

    /// Returns the active portion of g_vec
    #[inline]
    pub fn g_vec_slice(&self) -> &[Point] {
        &self.g_vec[..self.num_attrs]
    }
}

/// Secret key for the issuer.
#[derive(Clone)]
pub struct SecretKey {
    /// Main secret scalar
    pub(crate) x: Scalar,
    /// Per-attribute secret scalars (y_1..y_l)
    pub(crate) y_vec: [Scalar; MAX_ATTRS],
    /// Number of active attributes
    pub(crate) num_attrs: usize,
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretKey")
            .field("num_attrs", &self.num_attrs)
            .field("x", &"<redacted>")
            .field("y_vec", &"<redacted>")
            .finish()
    }
}

/// Public key for verification.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// X = x * G
    pub g_x: Point,
    /// Y_j = y_j * G_j for each attribute
    pub g_y_vec: [Point; MAX_ATTRS],
    /// Number of active attributes
    pub(crate) num_attrs: usize,
}

impl PublicKey {
    /// Returns the active portion of g_y_vec
    #[inline]
    pub fn g_y_vec_slice(&self) -> &[Point] {
        &self.g_y_vec[..self.num_attrs]
    }
}

/// Complete key pair containing parameters, public key, and secret key.
#[derive(Clone)]
pub struct KeyPair {
    params: Parameters,
    pk: PublicKey,
    sk: SecretKey,
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair")
            .field("params", &self.params)
            .field("pk", &self.pk)
            .field("sk", &"<redacted>")
            .finish()
    }
}

impl KeyPair {
    /// Setup a complete SAGA key pair with `l` attributes.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator  
    /// * `l` - Number of attributes (must be <= MAX_ATTRS)
    pub fn setup<R: RngCore + CryptoRng>(rng: &mut R, l: usize) -> Result<Self, SagaError> {
        let params = Parameters::setup(rng, l)?;
        let (sk, pk) = keygen(rng, &params)?;
        Ok(Self { params, pk, sk })
    }

    /// Returns a reference to the parameters
    #[inline]
    pub fn params(&self) -> &Parameters {
        &self.params
    }

    /// Returns a reference to the public key
    #[inline]
    pub fn pk(&self) -> &PublicKey {
        &self.pk
    }

    /// Issue a MAC (credential) for the given messages.
    ///
    /// # Arguments
    /// * `rng` - Random number generator
    /// * `messages` - Attribute values as curve points (length must match num_attrs)
    pub fn mac<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        messages: &[Point],
    ) -> Result<Tag, SagaError> {
        compute_tag(rng, &self.params, &self.sk, &self.pk, messages)
    }

    /// Verify a MAC (issuer side, requires secret key).
    ///
    /// # Arguments
    /// * `tag` - The MAC to verify
    /// * `messages` - The original messages
    pub fn verify_mac(&self, tag: &Tag, messages: &[Point]) -> Result<bool, SagaError> {
        verify_tag(&self.params, &self.sk, tag, messages)
    }

    /// Verify an unlinkable presentation (issuer side).
    ///
    /// # Arguments
    /// * `presentation` - The presentation from the holder
    /// * `c_j_vec` - The randomized commitments from the holder
    pub fn verify_presentation(
        &self,
        presentation: &Presentation,
        c_j_vec: &[Point],
    ) -> Result<bool, SagaError> {
        verify_presentation(&self.params, &self.sk, presentation, c_j_vec)
    }
}

/// Generate a key pair given parameters.
///
/// sk = (x, y_1..y_l)
/// pk = (X = xG, Y_j = y_j * G_j)
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    params: &Parameters,
) -> Result<(SecretKey, PublicKey), SagaError> {
    let l = params.num_attrs;

    let x = Scalar::rand(rng);
    let mut y_vec = [Scalar::ZERO; MAX_ATTRS];
    for j in 0..l {
        y_vec[j] = Scalar::rand(rng);
    }

    let g_x = smul(&params.g, &x);
    let mut g_y_vec = [Point::identity(); MAX_ATTRS];
    for j in 0..l {
        g_y_vec[j] = smul(&params.g_vec[j], &y_vec[j]);
    }

    Ok((
        SecretKey {
            x,
            y_vec,
            num_attrs: l,
        },
        PublicKey {
            g_x,
            g_y_vec,
            num_attrs: l,
        },
    ))
}

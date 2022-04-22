#![allow(non_snake_case)]

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

// Constants from draft-irtf-cfrg-vrf-11.
const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT: &[u8] = b"\x02";
const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK: &[u8] = b"\x00";
const PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT: &[u8] = b"\x03";
const PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK: &[u8] = b"\x00";

// Constants from https://c2sp.org/vrf-r255
const SUITE_STRING: &[u8] = b"\xFFc2sp.org/vrf-r255";
const B: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
const PT_LEN: usize = 32;
const C_LEN: usize = 16;
const Q_LEN: usize = 32;
const H_LEN: usize = 64;
type Hash = Sha512;
const NONCE_GENERATION_DOMAIN_SEPARATOR: &[u8] = b"\x81";
const ENCODE_TO_CURVE_DOMAIN_SEPARATOR: &[u8] = b"\x82";

/// Implements https://c2sp.org/vrf-r255#encode-to-curve.
fn encode_to_curve(encode_to_curve_salt: &[u8], alpha_string: &[u8]) -> RistrettoPoint {
    let mut hasher = Hash::new_with_prefix(SUITE_STRING);
    hasher.update(ENCODE_TO_CURVE_DOMAIN_SEPARATOR);
    hasher.update(encode_to_curve_salt);
    hasher.update(alpha_string);
    RistrettoPoint::from_uniform_bytes(&hasher.finalize().into())
}

/// A challenge value, an integer in the range `[0..1 << (8 * C_LEN)]`.
#[derive(Clone, Copy, Debug, Eq)]
struct Challenge(Scalar);

impl Challenge {
    /// Generates a challenge from the given ristretto255 group elements.
    ///
    /// Implements [draft-irtf-cfrg-vrf-11 Section 5.4.3].
    ///
    /// [draft-irtf-cfrg-vrf-11 Section 5.4.3]: https://www.ietf.org/archive/id/draft-irtf-cfrg-vrf-11.html#name-ecvrf-challenge-generation
    fn generate(points: [RistrettoPoint; 5]) -> Self {
        let mut hasher = Hash::new_with_prefix(SUITE_STRING);
        hasher.update(CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT);

        for point in points {
            hasher.update(point.compress().as_bytes());
        }

        hasher.update(CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK);
        let c_string = hasher.finalize();

        Self::from_bytes(c_string[..C_LEN].try_into().unwrap())
    }

    fn from_bytes(c_string: [u8; C_LEN]) -> Self {
        let mut tmp = [0; 32];
        tmp[0..C_LEN].copy_from_slice(&c_string);
        Challenge(
            Scalar::from_canonical_bytes(tmp)
                .expect("Byte strings of length C_LEN are always canonical"),
        )
    }

    fn to_bytes(&self) -> [u8; C_LEN] {
        self.0.to_bytes()[..C_LEN].try_into().unwrap()
    }
}

impl PartialEq for Challenge {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// A private key for the ristretto255 VRF.
#[derive(Clone, Copy, Debug)]
pub struct PrivateKey {
    x: Scalar,
    pk: PublicKey,
}

impl PrivateKey {
    /// Generates a new private key from the given randomness source.
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let x = Scalar::random(&mut rng);
        Self::from_scalar(x)
            .expect("negligible probability of sampling zero unless the RNG is broken")
    }

    /// Parses a private key from its byte encoding.
    ///
    /// Returns `None` if the given bytes are not a valid encoding of a ristretto255 VRF
    /// private key.
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        // curve25519-dalek does not provide a constant-time decoding operation.
        let x = Scalar::from_canonical_bytes(bytes)?;
        Self::from_scalar(x)
    }

    fn from_scalar(x: Scalar) -> Option<Self> {
        // We require validate_key = TRUE
        if x == Scalar::zero() {
            return None;
        }

        let Y = x * B;
        let Y_bytes = Y.compress();
        Some(PrivateKey {
            x,
            pk: PublicKey { Y, Y_bytes },
        })
    }

    /// Returns the byte encoding of this private key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.x.to_bytes()
    }

    /// Generates a deterministic nonce from this private key and the given input.
    ///
    /// Implements https://c2sp.org/vrf-r255#nonce-generation.
    fn generate_nonce(&self, h_string: &[u8]) -> Scalar {
        let mut hasher = Hash::new_with_prefix(SUITE_STRING);
        hasher.update(NONCE_GENERATION_DOMAIN_SEPARATOR);
        hasher.update(self.x.as_bytes());
        hasher.update(h_string);
        Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
    }

    /// Generates a correctness proof for the unique VRF hash output derived from the
    /// given input and this private key.
    ///
    /// Implements [draft-irtf-cfrg-vrf-11 Section 5.1].
    ///
    /// [draft-irtf-cfrg-vrf-11 Section 5.1]: https://www.ietf.org/archive/id/draft-irtf-cfrg-vrf-11.html#name-ecvrf-proving
    pub fn prove(&self, alpha_string: &[u8]) -> Proof {
        let H = encode_to_curve(self.pk.Y_bytes.as_bytes(), alpha_string);
        let h_string = H.compress();
        let Gamma = self.x * H;
        let k = self.generate_nonce(h_string.as_bytes());
        let c = Challenge::generate([self.pk.Y, H, Gamma, k * B, k * H]);
        let s = k + c.0 * self.x;

        Proof { Gamma, c, s }
    }
}

/// A public key for the ristretto255 VRF.
#[derive(Clone, Copy, Debug, Eq)]
pub struct PublicKey {
    Y: RistrettoPoint,
    Y_bytes: CompressedRistretto,
}

impl From<PrivateKey> for PublicKey {
    fn from(sk: PrivateKey) -> Self {
        sk.pk
    }
}

impl PartialEq<PublicKey> for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.Y_bytes == other.Y_bytes
    }
}

impl PublicKey {
    /// Parses a public key from its byte encoding.
    ///
    /// Returns `None` if the given bytes are not a valid encoding of a ristretto255 VRF
    /// public key (including the `validate_key = TRUE` check).
    ///
    /// Implements lines 1-3 of [draft-irtf-cfrg-vrf-11 Section 5.3], and
    /// [draft-irtf-cfrg-vrf-11 Section 5.4.5].
    ///
    /// [draft-irtf-cfrg-vrf-11 Section 5.3]: https://www.ietf.org/archive/id/draft-irtf-cfrg-vrf-11.html#name-ecvrf-verifying
    /// [draft-irtf-cfrg-vrf-11 Section 5.4.5]: https://www.ietf.org/archive/id/draft-irtf-cfrg-vrf-11.html#keycheck
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        CompressedRistretto::from_slice(&bytes)
            .decompress()
            // We require validate_key = TRUE
            .filter(|p| !p.eq(&RistrettoPoint::identity()))
            .map(|Y| {
                let Y_bytes = Y.compress();
                PublicKey { Y, Y_bytes }
            })
    }

    /// Returns the byte encoding of this public key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.Y_bytes.to_bytes()
    }

    /// Verifies that the given proof is valid for the given input under this public key.
    ///
    /// Returns the corresponding VRF hash output, or `None` if the proof is invalid.
    ///
    /// Implements lines 7-11 of [draft-irtf-cfrg-vrf-11 Section 5.3].
    ///
    /// [draft-irtf-cfrg-vrf-11 Section 5.3]: https://www.ietf.org/archive/id/draft-irtf-cfrg-vrf-11.html#name-ecvrf-verifying
    pub fn verify(&self, alpha_string: &[u8], pi: &Proof) -> Option<[u8; H_LEN]> {
        let H = encode_to_curve(self.Y_bytes.as_bytes(), alpha_string);
        let U = pi.s * B - pi.c.0 * self.Y;
        let V = pi.s * H - pi.c.0 * pi.Gamma;
        let c_prime = Challenge::generate([self.Y, H, pi.Gamma, U, V]);

        if pi.c == c_prime {
            Some(pi.to_hash())
        } else {
            None
        }
    }
}

/// A ristretto255 VRF proof.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Proof {
    Gamma: RistrettoPoint,
    c: Challenge,
    s: Scalar,
}

impl PartialEq for Proof {
    fn eq(&self, other: &Self) -> bool {
        self.Gamma == other.Gamma && self.c == other.c && self.s == other.s
    }
}

impl Proof {
    /// Parses a proof from its byte encoding.
    ///
    /// Returns `None` if the given bytes are not a valid encoding of a ristretto255 VRF
    /// proof.
    ///
    /// Implements [draft-irtf-cfrg-vrf-11 Section 5.4.4].
    ///
    /// [draft-irtf-cfrg-vrf-11 Section 5.4.4]: https://www.ietf.org/archive/id/draft-irtf-cfrg-vrf-11.html#name-ecvrf-decode-proof
    pub fn from_bytes(pi_string: [u8; PT_LEN + C_LEN + Q_LEN]) -> Option<Self> {
        let Gamma = CompressedRistretto::from_slice(&pi_string[0..PT_LEN]).decompress()?;
        let c = Challenge::from_bytes(pi_string[PT_LEN..PT_LEN + C_LEN].try_into().unwrap());
        let s = Scalar::from_canonical_bytes(
            pi_string[PT_LEN + C_LEN..PT_LEN + C_LEN + Q_LEN]
                .try_into()
                .unwrap(),
        )?;
        Some(Proof { Gamma, c, s })
    }

    /// Returns the byte encoding of this proof.
    ///
    /// Implements [line 8 of draft-irtf-cfrg-vrf-11 Section 5.1].
    ///
    /// [line 8 of draft-irtf-cfrg-vrf-11 Section 5.1]: https://www.ietf.org/archive/id/draft-irtf-cfrg-vrf-11.html#section-5.1-9.8
    pub fn to_bytes(&self) -> [u8; PT_LEN + C_LEN + Q_LEN] {
        let mut pi_string = [0u8; PT_LEN + C_LEN + Q_LEN];
        pi_string[0..PT_LEN].copy_from_slice(self.Gamma.compress().as_bytes());
        pi_string[PT_LEN..PT_LEN + C_LEN].copy_from_slice(&self.c.to_bytes());
        pi_string[PT_LEN + C_LEN..PT_LEN + C_LEN + Q_LEN].copy_from_slice(&self.s.to_bytes());
        pi_string
    }

    /// Derives the VRF hash output corresponding to the input for which this proof is
    /// valid.
    ///
    /// Implements [draft-irtf-cfrg-vrf-11 Section 5.2].
    ///
    /// [draft-irtf-cfrg-vrf-11 Section 5.2]: https://www.ietf.org/archive/id/draft-irtf-cfrg-vrf-11.html#name-ecvrf-proof-to-hash
    fn to_hash(&self) -> [u8; H_LEN] {
        assert_eq!(Hash::output_size(), H_LEN);
        let mut beta_string = Hash::new_with_prefix(SUITE_STRING);
        beta_string.update(PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT);
        beta_string.update(self.Gamma.compress().as_bytes());
        beta_string.update(PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK);
        beta_string.finalize().into()
    }
}

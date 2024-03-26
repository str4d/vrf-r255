//! This crate provides an [RFC 9381] Verifiable Random Function (VRF), which is the
//! public key version of a keyed cryptographic hash. Only the holder of the secret key
//! can compute the hash, but anyone with the public key can verify the correctness of the
//! hash.
//!
//! `vrf-r255` is built on the ristretto255 group specified in [RFC 9496]. More
//! specifically, it is an implementation of the [ECVRF-RISTRETTO255-SHA512] ciphersuite
//! of the [RFC 9381 ECVRF construction].
//!
//! [RFC 9381]: https://www.rfc-editor.org/rfc/rfc9381.html
//! [RFC 9496]: https://www.rfc-editor.org/rfc/rfc9496.html
//! [ECVRF-RISTRETTO255-SHA512]: https://c2sp.org/vrf-r255
//! [RFC 9381 ECVRF construction]: https://www.rfc-editor.org/rfc/rfc9381.html#name-elliptic-curve-vrf-ecvrf
//!
//! # Examples
//!
//! ```
//! use rand_core::OsRng;
//! use vrf_r255::{PublicKey, SecretKey};
//!
//! let sk = SecretKey::generate(OsRng);
//! let pk = PublicKey::from(sk);
//!
//! let msg = "Real World Cryptography".as_bytes();
//! let proof = sk.prove(msg);
//!
//! let hash_output = pk.verify(msg, &proof);
//! assert!(bool::from(hash_output.is_some()));
//! ```

#![deny(rustdoc::broken_intra_doc_links)]
#![allow(non_snake_case)]

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use subtle::{ConstantTimeEq, CtOption};

// Constants from RFC 9381.
const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT: &[u8] = b"\x02";
const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK: &[u8] = b"\x00";
const PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT: &[u8] = b"\x03";
const PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK: &[u8] = b"\x00";

// Constants from https://c2sp.org/vrf-r255
const SUITE_STRING: &[u8] = b"\xFFc2sp.org/vrf-r255";
use RISTRETTO_BASEPOINT_TABLE as B;
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
#[derive(Clone, Copy, Debug)]
struct Challenge(Scalar);

impl Challenge {
    /// Generates a challenge from the given ristretto255 group elements.
    ///
    /// Implements [RFC 9381 Section 5.4.3].
    ///
    /// [RFC 9381 Section 5.4.3]: https://www.rfc-editor.org/rfc/rfc9381.html#name-ecvrf-challenge-generation
    fn generate(points: [RistrettoPoint; 5]) -> Self {
        let mut hasher = Hash::new_with_prefix(SUITE_STRING);
        hasher.update(CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT);

        for point in points {
            hasher.update(point.compress().as_bytes());
        }

        hasher.update(CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK);
        let c_string = hasher.finalize();

        Self::parse(c_string[..C_LEN].try_into().unwrap())
    }

    /// Parses a challenge from its byte encoding.
    ///
    /// Equivalent to `string_to_int(c_string)` for [`ECVRF-RISTRETTO255-SHA512`].
    ///
    /// [`ECVRF-RISTRETTO255-SHA512`]: https://c2sp.org/vrf-r255#ecvrf-ristretto255-sha512
    fn parse(c_string: [u8; C_LEN]) -> Self {
        let mut tmp = [0; 32];
        tmp[0..C_LEN].copy_from_slice(&c_string);
        // Byte strings of length C_LEN are always canonical.
        Challenge(Scalar::from_canonical_bytes(tmp).unwrap())
    }

    /// Returns the byte encoding of this challenge.
    ///
    /// Equivalent to `int_to_string(c, cLen)` for [`ECVRF-RISTRETTO255-SHA512`].
    ///
    /// [`ECVRF-RISTRETTO255-SHA512`]: https://c2sp.org/vrf-r255#ecvrf-ristretto255-sha512
    fn encode(&self) -> [u8; C_LEN] {
        self.0.as_bytes()[..C_LEN].try_into().unwrap()
    }
}

impl ConstantTimeEq for Challenge {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // Challenges are guaranteed by construction to be length `C_LEN`.
        self.0.as_bytes()[..C_LEN].ct_eq(&other.0.as_bytes()[..C_LEN])
    }
}

/// A secret key for the ristretto255 VRF.
#[derive(Clone, Copy, Debug)]
pub struct SecretKey {
    x: Scalar,
    pk: PublicKey,
}

impl SecretKey {
    /// Generates a new secret key from the given randomness source.
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let x = Scalar::random(&mut rng);
        // Negligible probability of sampling zero unless the RNG is broken.
        Self::from_scalar(x).unwrap()
    }

    /// Parses a secret key from its byte encoding.
    ///
    /// Returns `None` if the given bytes are not a valid encoding of a ristretto255 VRF
    /// secret key.
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        let x = Scalar::from_canonical_bytes(bytes);
        x.and_then(Self::from_scalar)
    }

    fn from_scalar(x: Scalar) -> CtOption<Self> {
        let Y = &x * B;
        let Y_bytes = Y.compress();
        CtOption::new(
            SecretKey {
                x,
                pk: PublicKey { Y, Y_bytes },
            },
            // We require validate_key = TRUE.
            !Y_bytes.ct_eq(&CompressedRistretto::identity()),
        )
    }

    /// Returns the byte encoding of this secret key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.x.to_bytes()
    }

    /// Generates a deterministic nonce from this secret key and the given input.
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
    /// given input and this secret key.
    ///
    /// Implements [RFC 9381 Section 5.1].
    ///
    /// [RFC 9381 Section 5.1]: https://www.rfc-editor.org/rfc/rfc9381.html#name-ecvrf-proving
    pub fn prove(&self, alpha_string: &[u8]) -> Proof {
        let H = encode_to_curve(self.pk.Y_bytes.as_bytes(), alpha_string);
        let h_string = H.compress();
        let Gamma = self.x * H;
        let k = self.generate_nonce(h_string.as_bytes());
        let c = Challenge::generate([self.pk.Y, H, Gamma, &k * B, k * H]);
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

impl From<SecretKey> for PublicKey {
    fn from(sk: SecretKey) -> Self {
        sk.pk
    }
}

impl ConstantTimeEq for PublicKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.Y_bytes.ct_eq(&other.Y_bytes)
    }
}

impl PartialEq<PublicKey> for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.ct_eq(other).into()
    }
}

impl PublicKey {
    /// Parses a public key from its byte encoding.
    ///
    /// Returns `None` if the given bytes are not a valid encoding of a ristretto255 VRF
    /// public key (including the `validate_key = TRUE` check).
    ///
    /// Implements [lines 1-3] of [RFC 9381 Section 5.3], and
    /// [RFC 9381 Section 5.4.5].
    ///
    /// [lines 1-3]: https://www.rfc-editor.org/rfc/rfc9381.html#section-5.3-5.1
    /// [RFC 9381 Section 5.3]: https://www.rfc-editor.org/rfc/rfc9381.html#name-ecvrf-verifying
    /// [RFC 9381 Section 5.4.5]: https://www.rfc-editor.org/rfc/rfc9381.html#name-ecvrf-validate-key
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let Y_bytes = CompressedRistretto(bytes);
        Y_bytes
            .decompress()
            // We require validate_key = TRUE
            .filter(|_| !Y_bytes.eq(&CompressedRistretto::identity()))
            .map(|Y| PublicKey { Y, Y_bytes })
    }

    /// Returns the byte encoding of this public key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.Y_bytes.to_bytes()
    }

    /// Verifies that the given proof is valid for the given input under this public key.
    ///
    /// Returns the corresponding VRF hash output, or `None` if the proof is invalid.
    ///
    /// Implements [lines 7-11] of [RFC 9381 Section 5.3].
    ///
    /// [lines 7-11]: https://www.rfc-editor.org/rfc/rfc9381.html#section-5.3-5.7
    /// [RFC 9381 Section 5.3]: https://www.rfc-editor.org/rfc/rfc9381.html#name-ecvrf-verifying
    pub fn verify(&self, alpha_string: &[u8], pi: &Proof) -> CtOption<[u8; H_LEN]> {
        let H = encode_to_curve(self.Y_bytes.as_bytes(), alpha_string);
        let U = &pi.s * B - pi.c.0 * self.Y;
        let V = pi.s * H - pi.c.0 * pi.Gamma;
        let c_prime = Challenge::generate([self.Y, H, pi.Gamma, U, V]);

        CtOption::new(pi.derive_hash(), pi.c.ct_eq(&c_prime))
    }
}

/// A ristretto255 VRF proof.
#[derive(Clone, Copy, Debug)]
pub struct Proof {
    Gamma: RistrettoPoint,
    c: Challenge,
    s: Scalar,
}

impl ConstantTimeEq for Proof {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.Gamma.ct_eq(&other.Gamma) & self.c.ct_eq(&other.c) & self.s.ct_eq(&other.s)
    }
}

impl PartialEq for Proof {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Proof {
    /// Parses a proof from its byte encoding.
    ///
    /// Returns `None` if the given bytes are not a valid encoding of a ristretto255 VRF
    /// proof.
    ///
    /// Implements [RFC 9381 Section 5.4.4].
    ///
    /// [RFC 9381 Section 5.4.4]: https://www.rfc-editor.org/rfc/rfc9381.html#name-ecvrf-decode-proof
    pub fn from_bytes(pi_string: [u8; PT_LEN + C_LEN + Q_LEN]) -> Option<Self> {
        let Gamma = CompressedRistretto(pi_string[0..PT_LEN].try_into().expect("correct length"))
            .decompress();
        let c = Challenge::parse(pi_string[PT_LEN..PT_LEN + C_LEN].try_into().unwrap());
        let s = Scalar::from_canonical_bytes(
            pi_string[PT_LEN + C_LEN..PT_LEN + C_LEN + Q_LEN]
                .try_into()
                .unwrap(),
        );
        Gamma.zip(s.into()).map(|(Gamma, s)| Proof { Gamma, c, s })
    }

    /// Returns the byte encoding of this proof.
    ///
    /// Implements [line 8] of [RFC 9381 Section 5.1].
    ///
    /// [line 8]: https://www.rfc-editor.org/rfc/rfc9381.html#section-5.1-4.8
    /// [RFC 9381 Section 5.1]: https://www.rfc-editor.org/rfc/rfc9381.html#name-ecvrf-proving
    pub fn to_bytes(&self) -> [u8; PT_LEN + C_LEN + Q_LEN] {
        let mut pi_string = [0u8; PT_LEN + C_LEN + Q_LEN];
        pi_string[0..PT_LEN].copy_from_slice(self.Gamma.compress().as_bytes());
        pi_string[PT_LEN..PT_LEN + C_LEN].copy_from_slice(&self.c.encode());
        pi_string[PT_LEN + C_LEN..PT_LEN + C_LEN + Q_LEN].copy_from_slice(&self.s.to_bytes());
        pi_string
    }

    /// Derives the VRF hash output corresponding to the input for which this proof is
    /// valid.
    ///
    /// Implements [RFC 9381 Section 5.2].
    ///
    /// [RFC 9381 Section 5.2]: https://www.rfc-editor.org/rfc/rfc9381.html#name-ecvrf-proof-to-hash
    fn derive_hash(&self) -> [u8; H_LEN] {
        assert_eq!(Hash::output_size(), H_LEN);
        let mut beta_string = Hash::new_with_prefix(SUITE_STRING);
        beta_string.update(PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT);
        beta_string.update(self.Gamma.compress().as_bytes());
        beta_string.update(PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK);
        beta_string.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector() {
        let tv_sk = "3431c2b03533e280b23232e280b34e2c3132c2b03238e280b23131e280b34500";
        let tv_pk = "54136cd90d99fbd1d4e855d9556efea87ba0337f2a6ce22028d0f5726fcb854e";
        let tv_alpha = "633273702e6f72672f7672662d72323535";
        let tv_H = "f245308737c2a888ba56448c8cdbce9d063b57b147e063ce36c580194ef31a63";
        let tv_k_string = "b5eb28143d9defee6faa0c02ff0168b7ac80ea89fe9362845af15cabd100a91ed6251dfa52be36405576eca4a0970f91225b85c8813206d13bd8b42fd11a00fe";
        let tv_k = "d32fcc5ae91ba05704da9df434f22fd4c2c373fdd8294bbb58bf27292aeec00a";
        let tv_U = "9a30709d72de12d67f7af1cd8695ff16214d2d4600ae5f478873d2e7ed0ece73";
        let tv_V = "5e727d972b11f6490b0b1ba8147775bceb1a2cb523b381fa22d5a5c0e97d4744";
        let tv_pi = "0a97d961262fb549b4175c5117860f42ae44a123f93c476c439eddd1c0cff9265c805525233e2284dbed45e593b8eea31d5ca9734d72bcbba9738d5237f955f3b2422351149d1312503b6441a47c940c";
        let tv_beta = "dd653f0879b48c3ef69e13551239bec4cbcc1c18fe8894de2e9e1c790e18273603bf1c6c25d7a797aeff3c43fd32b974d3fcbd4bcce916007097922a3ea3a794";

        let tv_sk = hex::decode(tv_sk).unwrap();
        let tv_pk = hex::decode(tv_pk).unwrap();
        let tv_alpha = hex::decode(tv_alpha).unwrap();
        let tv_H = hex::decode(tv_H).unwrap();
        let tv_k_string = hex::decode(tv_k_string).unwrap();
        let tv_k = hex::decode(tv_k).unwrap();
        let tv_U = hex::decode(tv_U).unwrap();
        let tv_V = hex::decode(tv_V).unwrap();
        let tv_pi = hex::decode(tv_pi).unwrap();
        let tv_beta = hex::decode(tv_beta).unwrap();

        let sk = SecretKey::from_bytes(tv_sk.try_into().unwrap()).unwrap();
        let pk = PublicKey::from_bytes(tv_pk.try_into().unwrap()).unwrap();
        assert_eq!(PublicKey::from(sk), pk);

        let H = CompressedRistretto::from_slice(&tv_H)
            .unwrap()
            .decompress()
            .unwrap();
        assert_eq!(encode_to_curve(pk.Y_bytes.as_bytes(), &tv_alpha), H);

        let k = Scalar::from_canonical_bytes(tv_k.try_into().unwrap()).unwrap();
        assert_eq!(
            Scalar::from_bytes_mod_order_wide(&tv_k_string.try_into().unwrap()),
            k
        );
        assert_eq!(sk.generate_nonce(H.compress().as_bytes()), k);

        let U = CompressedRistretto::from_slice(&tv_U)
            .unwrap()
            .decompress()
            .unwrap();
        let V = CompressedRistretto::from_slice(&tv_V)
            .unwrap()
            .decompress()
            .unwrap();
        assert_eq!(&k * B, U);
        assert_eq!(k * H, V);

        let pi = Proof::from_bytes(tv_pi.try_into().unwrap()).unwrap();
        assert_eq!(sk.prove(&tv_alpha), pi);
        assert_eq!(
            pk.verify(&tv_alpha, &pi).unwrap(),
            <[u8; H_LEN]>::try_from(tv_beta).unwrap()
        );
    }
}

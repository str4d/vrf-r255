# vrf-r255

This crate provides an [RFC 9381] Verifiable Random Function (VRF), which is the
public key version of a keyed cryptographic hash. Only the holder of the secret
key can compute the hash, but anyone with the public key can verify the
correctness of the hash.

`vrf-r255` is built on the ristretto255 group specified in [RFC 9496]. More
specifically, it is an implementation of the [ECVRF-RISTRETTO255-SHA512]
ciphersuite of the [RFC 9381 ECVRF construction].

[RFC 9381]: https://www.rfc-editor.org/rfc/rfc9381.html
[RFC 9496]: https://www.rfc-editor.org/rfc/rfc9496.html
[ECVRF-RISTRETTO255-SHA512]: https://c2sp.org/vrf-r255
[RFC 9381 ECVRF construction]: https://www.rfc-editor.org/rfc/rfc9381.html#name-elliptic-curve-vrf-ecvrf

## Minimum Supported Rust Version

Rust **1.57** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer.
- MSRV is considered exempt from SemVer as noted above.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](../LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](../LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

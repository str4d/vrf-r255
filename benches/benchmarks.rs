use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand_core::OsRng;
use vrf_r255::{Proof, PublicKey, SecretKey};

fn encoding(c: &mut Criterion) {
    let sk = SecretKey::generate(OsRng);
    let sk_bytes = sk.to_bytes();
    c.bench_function("secretkey-from-bytes", |b| {
        b.iter(|| SecretKey::from_bytes(sk_bytes))
    });
    c.bench_function("secretkey-to-bytes", |b| b.iter(|| sk.to_bytes()));

    let pk = PublicKey::from(sk);
    let pk_bytes = pk.to_bytes();
    c.bench_function("publickey-from-bytes", |b| {
        b.iter(|| PublicKey::from_bytes(pk_bytes))
    });
    c.bench_function("publickey-to-bytes", |b| b.iter(|| pk.to_bytes()));

    let proof = sk.prove(&[]);
    let pi_string = proof.to_bytes();
    c.bench_function("proof-from-bytes", |b| {
        b.iter(|| Proof::from_bytes(pi_string))
    });
    c.bench_function("proof-to-bytes", |b| b.iter(|| proof.to_bytes()));
}

fn prove(c: &mut Criterion) {
    let sk = SecretKey::generate(OsRng);

    let alpha = [42; 512 * 1024];
    for alpha_len in [32, 512, 1024, alpha.len()] {
        let alpha_string = &alpha[..alpha_len];

        c.bench_with_input(BenchmarkId::new("prove", alpha_len), &alpha_len, |b, _| {
            b.iter(|| sk.prove(alpha_string))
        });
    }
}

fn verify(c: &mut Criterion) {
    let sk = SecretKey::generate(OsRng);
    let pk = PublicKey::from(sk);

    let invalid_pk = PublicKey::from(SecretKey::generate(OsRng));

    let alpha = [42; 512 * 1024];
    for alpha_len in [32, 512, 1024, alpha.len()] {
        let alpha_string = &alpha[..alpha_len];
        let proof = sk.prove(alpha_string);

        c.bench_with_input(
            BenchmarkId::new("verify-valid", alpha_len),
            &alpha_len,
            |b, _| b.iter(|| pk.verify(alpha_string, &proof)),
        );
        c.bench_with_input(
            BenchmarkId::new("verify-invalid", alpha_len),
            &alpha_len,
            |b, _| b.iter(|| invalid_pk.verify(alpha_string, &proof)),
        );
    }
}

criterion_group!(benches, encoding, prove, verify);
criterion_main!(benches);

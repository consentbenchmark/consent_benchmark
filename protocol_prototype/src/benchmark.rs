use criterion::{black_box, Criterion, criterion_group, criterion_main};
use crate::client::Client;
use ed25519_dalek::ed25519::signature::SignerMut;
use crate::idm::IdentityManager;
use crate::agent::Agent;
use ed25519_dalek::{SigningKey, VerifyingKey, Verifier};
use ed25519_dalek::Signature;
use crate::utils::{pok_prove, pok_verify};
use crate::utils::{PublicParams, generate_public_params, commit, hash_to_scalar};
use rand::rngs::OsRng;
use std::time::Instant;
use viadkim::{SigningKey as DkimSigningKey, SigningAlgorithm, DomainName, Selector, SignRequest, HeaderFields};
use viadkim::crypto::HashAlgorithm;
use viadkim::signer::Expiration;
use pkcs8::EncodePrivateKey;
use argon2::{Argon2, Algorithm, Version, Params};
use rsa::{RsaPrivateKey, RsaPublicKey};

pub fn benchmark_perform_action(c: &mut Criterion) {
    let mut csprng = OsRng;
    let mut signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    // Generate PublicParams once
    let public_params = generate_public_params();

    // Create instances with PublicParams
    let client = Client::new(String::from("default_user"), String::from("default_password"), 0, public_params.clone());
    let idm = IdentityManager::new(public_params.clone());
    let agent = Agent::new(public_params.clone());
    let (contract, s_a) = client.enroll();

    c.bench_function("client_enroll", |b| {
        b.iter(|| {
            let start_total = Instant::now();
            let (contract, s_a) = client.enroll();
            let total_duration = start_total.elapsed();
        })
    });

    c.bench_function("client_enroll_nohash", |b| {
        b.iter(|| {
            let (_contract, _s_a) = client.enroll_nohash();
        })
    });

    c.bench_function("client_enroll_sha256", |b| {
        b.iter(|| {
            let (_contract, _s_a) = client.enroll_sha256();
        })
    });

    // Create 256-bit attribute string
    let att = "a".repeat(32);
    let (com, r) = client.launch(att.clone());
    c.bench_function("client_launch", |b| {
        b.iter(|| {
            let start_total = Instant::now();
            let (com, r) = client.launch(att.clone());
            let total_duration = start_total.elapsed();

        })
    });

    c.bench_function("client_launch_nohash", |b| {
        b.iter(|| {
            let (_com, _r) = client.launch_nohash(att.clone());
        })
    });

    c.bench_function("client_launch_sha256", |b| {
        b.iter(|| {
            let (_com, _r) = client.launch_sha256(att.clone());
        })
    });


    let password = "default_password";
    let client_id: i32 = 0;

    c.bench_function("argon2_hash", |b| {
        b.iter(|| {
            let params = Params::new(65536, 3, 4, Some(32)).unwrap();
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let mut salt = [0u8; 16];
            salt[..4].copy_from_slice(&client_id.to_le_bytes());

            let mut h_id_bytes = [0u8; 32];
            argon2.hash_password_into(password.as_bytes(), &salt, &mut h_id_bytes).unwrap();

            black_box(h_id_bytes);
        })
    });

    let message = [hex::encode(com.compress().to_bytes()), hex::encode(client.get_id().to_be_bytes())].concat().into_bytes();
    let signature = signing_key.sign(&message);

    c.bench_function("idm", |b| {
        b.iter(|| {
            let signature = signing_key.sign(&message);
        })
    });

    // Create Ed25519 key for DKIM
    let dkim_private_key_pem = signing_key.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap().to_string();

    // Create email message with com and ID as body
    let email_body = String::from_utf8_lossy(&message).to_string();
    let email_msg = format!(
        "From: idm@example.com\r\n\
         To: agent@example.com\r\n\
         Subject: Consent Protocol Message\r\n\
         Date: Mon, 09 Nov 2025 12:00:00 +0000\r\n\
         \r\n\
         {}",
        email_body
    );

    let (header_str, body_str) = email_msg.split_once("\r\n\r\n").unwrap();
    let header: HeaderFields = header_str.parse().unwrap();
    let body = body_str.as_bytes();

    let dkim_key_pem = dkim_private_key_pem.clone();
    let domain = DomainName::new("example.com").unwrap();
    let selector = Selector::new("default").unwrap();

    c.bench_function("idm_dkim", |b| {
        b.iter(|| {
            let dkim_key = DkimSigningKey::from_pkcs8_pem(&dkim_key_pem).unwrap();
            let algorithm = SigningAlgorithm::from_parts(dkim_key.key_type(), HashAlgorithm::Sha256).unwrap();

            let mut request = SignRequest::new(
                domain.clone(),
                selector.clone(),
                algorithm,
                dkim_key
            );
            request.expiration = Expiration::Never;

            let runtime = tokio::runtime::Runtime::new().unwrap();
            let _sigs = runtime.block_on(async {
                viadkim::sign(header.clone(), body, [request]).await.unwrap()
            });
        })
    });

    let (h_id, r_id) = s_a;
    let (id, com_id) = contract;
    assert!(verifying_key.verify(&message, &signature).is_ok());
    assert_eq!(com, commit(h_id, hash_to_scalar(att.clone()), r, public_params.clone()));
    let pi = pok_prove(com_id, com, att.clone(), h_id, r_id, r, public_params.clone());

    c.bench_function("agent", |b| {
        b.iter(|| {
            let (h_id, r_id) = s_a;
            let (id, com_id) = contract;
            assert!(verifying_key.verify(&message, &signature).is_ok());
            assert_eq!(com, commit(h_id, hash_to_scalar(att.clone()), r, public_params.clone()));
            let pi = pok_prove(com_id, com, att.clone(), h_id, r_id, r, public_params.clone());
        })
    });

    let mut rng = OsRng;
    let bits = 2048;
    let agent_private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let agent_public_key = RsaPublicKey::from(&agent_private_key);

    // Client launch DKIM variant with RSA-OAEP encryption (with Argon2)
    c.bench_function("client_launch_dkim", |b| {
        b.iter(|| {
            let (_encrypted_com, _encrypted_r) = client.launch_dkim(att.clone(), &agent_public_key);
        })
    });

    // Client launch DKIM variant with RSA-OAEP encryption (with SHA256)
    c.bench_function("client_launch_dkim_sha256", |b| {
        b.iter(|| {
            let (_encrypted_com, _encrypted_r) = client.launch_dkim_sha256(att.clone(), &agent_public_key);
        })
    });

    let (encrypted_att, encrypted_r) = client.launch_dkim(att.clone(), &agent_public_key);

    c.bench_function("agent_verify_dkim", |b| {
        b.iter(|| {
            use rsa::Oaep;
            let padding = Oaep::new::<sha2::Sha256>();
            let _att_bytes = agent_private_key.decrypt(padding, &encrypted_att).unwrap();

            let padding = Oaep::new::<sha2::Sha256>();
            let _r_bytes = agent_private_key.decrypt(padding, &encrypted_r).unwrap();

            let (h_id, r_id) = s_a;
            let (id, com_id) = contract;
            assert!(verifying_key.verify(&message, &signature).is_ok());
            assert_eq!(com, commit(h_id, hash_to_scalar(att.clone()), r, public_params.clone()));
            let pi = pok_prove(com_id, com, att.clone(), h_id, r_id, r, public_params.clone());
        })
    });

    c.bench_function("consent verify", |b| {
        b.iter(|| {
            assert!(pok_verify(com_id, com, att.clone(), pi.0, pi.1, pi.2, pi.3, public_params.clone()));
        })
    });

    println!("Benchmark completed.");

}


criterion_group!(benches, benchmark_perform_action);
criterion_main!(benches);

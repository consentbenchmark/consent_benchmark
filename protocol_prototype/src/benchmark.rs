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
            let (contract, s_a) = client.enroll();
        })
    });

    let att = String::from("attribute");
    let (com, r) = client.launch(att.clone());
    c.bench_function("client_launch", |b| {
        b.iter(|| {
            let (com, r) = client.launch(att.clone());
        })
    });

    let message = [hex::encode(com.compress().to_bytes()), hex::encode(client.get_id().to_be_bytes())].concat().into_bytes();
    let signature = signing_key.sign(&message);
    
    c.bench_function("idm", |b| {
        b.iter(|| {
            let signature = signing_key.sign(&message);
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

    c.bench_function("consent verify", |b| {
        b.iter(|| {
            assert!(pok_verify(com_id, com, att.clone(), pi.0, pi.1, pi.2, pi.3, public_params.clone()));
        })
    });

    println!("Protocol flow completed: {:?}", hex::encode(com.compress().as_bytes()));

}


criterion_group!(benches, benchmark_perform_action);
criterion_main!(benches);
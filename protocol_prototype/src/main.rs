mod client;
mod idm;
mod agent;
pub mod benchmark;
mod utils;

use client::Client;
use ed25519_dalek::ed25519::signature::SignerMut;
use idm::IdentityManager;
use agent::Agent;
use ed25519_dalek::{SigningKey, VerifyingKey, Verifier};
use ed25519_dalek::Signature;
use utils::pok_prove;
use utils::{PublicParams, generate_public_params, commit, hash_to_scalar, schnorr_verify, pok_verify_no_idm};
use rand::rngs::OsRng;
fn main() {

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
    let att = String::from("attribute");
    let (com, r) = client.launch(att.clone());

    // idm signs the com
    let message = [hex::encode(com.compress().to_bytes()), hex::encode(client.get_id().to_be_bytes())].concat().into_bytes();
    let signature = signing_key.sign(&message);

    // agent generates consent
    let (h_id, r_id) = s_a;
    let (id, com_id) = contract;
    assert!(verifying_key.verify(&message, &signature).is_ok());
    assert_eq!(com, commit(h_id, hash_to_scalar(att.clone()), r, public_params.clone()));
    let pi = pok_prove(com_id, com, att, h_id, r_id, r, public_params.clone());
    println!("Protocol flow completed: {:?}", hex::encode(com.compress().as_bytes()));

    println!("\n--- No-IDM Variant Test ---");
    let (no_idm_contract, no_idm_secret_state) = client.enroll_no_idm();
    let no_idm_att = "test_attribute";
    let no_idm_sig = client.launch_no_idm(no_idm_att);

    let (no_idm_sk, no_idm_pk, no_idm_r_id) = no_idm_secret_state;
    let (_, no_idm_com_id) = no_idm_contract;

    assert!(schnorr_verify(no_idm_pk, no_idm_sig, no_idm_att.as_bytes()), "Schnorr signature verification failed");
    println!("Schnorr signature verified");

    let consent_no_idm = agent.verify_and_prove_no_idm(
        no_idm_com_id,
        no_idm_att.as_bytes(),
        no_idm_pk,
        no_idm_r_id,
        no_idm_sig,
    ).expect("Server verification failed");

    assert!(pok_verify_no_idm(
        no_idm_com_id,
        no_idm_att.as_bytes(),
        consent_no_idm.0,
        &consent_no_idm.1,
        &public_params
    ), "No-IDM consent verification failed");
    println!("No-IDM protocol flow completed successfully");
}

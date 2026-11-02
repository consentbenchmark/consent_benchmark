mod client;
mod agent;
pub mod benchmark;
mod utils;
mod consent;
mod jws;
mod oidc;
mod dkim;
mod ctap;
mod oid4vp;

use client::Client;
use agent::Agent;
use consent::{AgentSecret, com_to_nonce};
use ctap::{Authenticator, CoseAlg};
use dkim::{DkimAlg, DkimVerifier, EmailProvider};
use jws::{JwsAlg, JwsSigner};
use oid4vp::{Issuer, Wallet};
use oidc::OpenIdProvider;
use utils::{generate_public_params, pok_verify_no_idm, schnorr_verify};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use viadkim::header::HeaderFields;

// Runs the consent protocol once with every IdM variant
fn main() {
    // Generate PublicParams once
    let public_params = generate_public_params();

    // Create instances with PublicParams
    let client = Client::new(String::from("default_user"), String::from("default_password"), 0, public_params.clone());
    let agent = Agent::new(public_params.clone());

    let (contract, s_a) = client.enroll();
    let (id, com_id) = contract;
    let (h_id, r_id) = s_a;
    let id_str = id.to_string();
    let s_a = AgentSecret { h_id, r_id };
    let att = String::from("attribute");
    let (com, r) = client.launch(att.clone());
    let nonce = com_to_nonce(&com);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    println!("--- OIDC ---");
    for alg in [JwsAlg::Rs256, JwsAlg::EdDsa] {
        let provider = OpenIdProvider::new("https://op.example", alg);
        let contract = oidc::OidcContract {
            id: id_str.clone(),
            com_id,
            issuer: provider.issuer.clone(),
            pk_idm: provider.signer.verifier(),
            client_id: String::from("https://agent.example/consent"),
        };
        // agent signs the authentication request, client checks the nonce
        let agent_key = JwsSigner::generate(JwsAlg::Rs256);
        let request = oidc::agent_sign_request(&agent_key, &contract, "https://agent.example/cb", &com, "state");
        assert!(oidc::client_check_request(&request, &agent_key.verifier(), &com));
        // idm signs the id token
        let id_token = provider.issue_id_token(&id_str, &contract.client_id, &nonce, now);
        // agent generates consent
        let order = oidc::OidcOrder { id_token, com, r };
        let consent = oidc::agent_receive(&s_a, &contract, &att, &order, &public_params, now).expect("Agent verification failed");
        assert!(oidc::verify_consent(&contract, &att, &consent, &public_params), "OIDC consent verification failed");
        println!("OIDC {:?} protocol flow completed: {}", alg, &consent.id_token[..40]);
    }

    println!("\n--- CTAP ---");
    for alg in [CoseAlg::Es256, CoseAlg::EdDsa] {
        let (mut authenticator, credential) = Authenticator::make_credential("agent.example", id_str.as_bytes(), alg);
        let contract = ctap::CtapContract {
            id: id_str.clone(),
            com_id,
            credential,
            origin: String::from("https://agent.example"),
        };
        let client_data_json = ctap::client_data_json(&com, &contract.origin);
        let (authenticator_data, signature) = authenticator.get_assertion(&ctap::client_data_hash(&client_data_json));
        let assertion = ctap::Assertion {
            cred_id: authenticator.cred_id().to_vec(),
            authenticator_data,
            client_data_json,
            signature,
            user_handle: id_str.as_bytes().to_vec(),
        };
        let order = ctap::CtapOrder { assertion, com, r };
        let consent = ctap::agent_receive(&s_a, &contract, &att, &order, &public_params).expect("Agent verification failed");
        assert!(ctap::verify_consent(&contract, &att, &consent, &public_params), "CTAP consent verification failed");
        println!("CTAP {:?} protocol flow completed: {}", alg, hex::encode(&consent.assertion.signature[..16]));
    }

    println!("\n--- OID4VP ---");
    {
        let issuer = Issuer::new("https://pid.example", JwsAlg::Es256);
        let holder_signer = JwsSigner::generate(JwsAlg::Es256);
        let credential = issuer.issue(
            &holder_signer.verifier(),
            "urn:eudi:pid:1",
            &[("personal_administrative_number", json!(id_str)), ("given_name", json!("Alice"))],
            now,
        );
        let wallet = Wallet { holder_signer, credential };
        let contract = oid4vp::Oid4vpContract {
            id: id_str.clone(),
            com_id,
            issuer: issuer.iss.clone(),
            pk_issuer: issuer.signer.verifier(),
            client_id: String::from("https://agent.example/consent"),
            id_claim: String::from("personal_administrative_number"),
        };
        let agent_key = JwsSigner::generate(JwsAlg::Es256);
        let request = oid4vp::agent_sign_request(&agent_key, &contract, "https://agent.example/vp", &com);
        assert!(oid4vp::client_check_request(&request, &agent_key.verifier(), &com));
        let presentation = wallet.present(&["personal_administrative_number"], &nonce, &contract.client_id, now);
        let order = oid4vp::Oid4vpOrder { presentation, com, r };
        let consent = oid4vp::agent_receive(&s_a, &contract, &att, &order, &public_params, now).expect("Agent verification failed");
        assert!(oid4vp::verify_consent(&contract, &att, &consent, &public_params), "OID4VP consent verification failed");
        println!("OID4VP protocol flow completed: {} parts", consent.presentation.split('~').count());
    }

    println!("\n--- DKIM ---");
    let agent_private_key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let agent_public_key = RsaPublicKey::from(&agent_private_key);
    for alg in [DkimAlg::RsaSha256, DkimAlg::Ed25519Sha256] {
        let provider = EmailProvider::new("mail.example", "default", alg);
        let verifier = DkimVerifier::new(&provider);
        let contract = dkim::DkimContract {
            id: String::from("alice@mail.example"),
            com_id,
            provider_domain: provider.domain.clone(),
            agent_address: String::from("consent@agent.example"),
        };
        let (com, ciphertext) = client.launch_dkim(att.clone(), &agent_public_key);
        let (header, body) = dkim::compose_email(&contract.id, &contract.agent_address, &com, &ciphertext);
        let header_fields: HeaderFields = header.parse().unwrap();
        let signature_line = provider.sign(&header_fields, &body);
        let signed_header: HeaderFields = format!("{}{}", signature_line, header).parse().unwrap();
        let order = dkim::DkimOrder { header: signed_header, body };
        let (consent, recovered_att) = dkim::agent_receive(&s_a, &contract, &verifier, &agent_private_key, &order, &public_params).expect("Agent verification failed");
        assert_eq!(recovered_att, att);
        assert!(dkim::verify_consent(&verifier, &contract, &att, &consent, &public_params), "DKIM consent verification failed");
        println!("DKIM {:?} protocol flow completed: {}", alg, signature_line.lines().next().unwrap());
    }

    println!("\n--- No-IDM Variant Test ---");
    let (no_idm_contract, no_idm_secret_state) = client.enroll_no_idm();
    let no_idm_att = "test_attribute";
    let no_idm_sig = client.launch_no_idm(no_idm_att);

    let (_no_idm_sk, no_idm_pk, no_idm_r_id) = no_idm_secret_state;
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

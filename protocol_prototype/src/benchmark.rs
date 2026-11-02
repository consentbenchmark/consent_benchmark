use criterion::{black_box, Criterion, criterion_group, criterion_main};
use crate::client::Client;
use crate::agent::Agent;
use crate::consent::com_to_nonce;
use crate::ctap::{self, Authenticator, CoseAlg};
use crate::dkim::{self, DkimAlg, DkimVerifier, EmailProvider};
use crate::jws::{JwsAlg, JwsSigner};
use crate::oid4vp::{self, Issuer, Wallet};
use crate::oidc::{self, OpenIdProvider};
use crate::utils::{generate_public_params, pok_verify_no_idm, schnorr_keygen, schnorr_sign, schnorr_verify};
use crate::consent::AgentSecret;
use argon2::{Argon2, Algorithm, Version, Params};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use viadkim::header::HeaderFields;

pub fn benchmark_perform_action(c: &mut Criterion) {
    // Generate PublicParams once
    let public_params = generate_public_params();

    // Create instances with PublicParams
    let client = Client::new(String::from("default_user"), String::from("default_password"), 0, public_params.clone());
    let agent = Agent::new(public_params.clone());
    let (contract, s_a) = client.enroll_sha256();
    let (id, com_id) = contract;
    let (h_id, r_id) = s_a;
    let id_str = id.to_string();
    let s_a = AgentSecret { h_id, r_id };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    c.bench_function("client_enroll", |b| {
        b.iter(|| client.enroll())
    });

    c.bench_function("client_enroll_nohash", |b| {
        b.iter(|| client.enroll_nohash())
    });

    c.bench_function("client_enroll_sha256", |b| {
        b.iter(|| client.enroll_sha256())
    });

    // Create 256-bit attribute string
    let att = "a".repeat(32);
    let (com, r) = client.launch_sha256(att.clone());
    let nonce = com_to_nonce(&com);

    c.bench_function("client_launch", |b| {
        b.iter(|| client.launch(black_box(att.clone())))
    });

    c.bench_function("client_launch_nohash", |b| {
        b.iter(|| client.launch_nohash(black_box(att.clone())))
    });

    c.bench_function("client_launch_sha256", |b| {
        b.iter(|| client.launch_sha256(black_box(att.clone())))
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

            h_id_bytes
        })
    });

    // ---- OIDC: the IdM signs an ID token (JWT) with nonce = com, sub = ID ----
    for (name, alg) in [("oidc_rs256", JwsAlg::Rs256), ("oidc_eddsa", JwsAlg::EdDsa)] {
        let provider = OpenIdProvider::new("https://op.example", alg);
        let contract = oidc::OidcContract {
            id: id_str.clone(),
            com_id,
            issuer: provider.issuer.clone(),
            pk_idm: provider.signer.verifier(),
            client_id: String::from("https://agent.example/consent"),
        };
        let id_token = provider.issue_id_token(&id_str, &contract.client_id, &nonce, now);
        let order = oidc::OidcOrder { id_token, com, r };
        let consent = oidc::agent_receive(&s_a, &contract, &att, &order, &public_params, now).unwrap();
        assert!(oidc::verify_consent(&contract, &att, &consent, &public_params));

        c.bench_function(&format!("idm_{}", name), |b| {
            b.iter(|| provider.issue_id_token(black_box(&id_str), &contract.client_id, &nonce, now))
        });

        c.bench_function(&format!("agent_{}", name), |b| {
            b.iter(|| oidc::agent_receive(&s_a, &contract, black_box(&att), &order, &public_params, now))
        });

        c.bench_function(&format!("consent_verify_{}", name), |b| {
            b.iter(|| oidc::verify_consent(&contract, black_box(&att), &consent, &public_params))
        });

        if alg == JwsAlg::Rs256 {
            // The Agent (RP) signs the authentication request carrying the nonce, the Client checks it
            let agent_key = JwsSigner::generate(JwsAlg::Rs256);
            let agent_pk = agent_key.verifier();
            let request = oidc::agent_sign_request(&agent_key, &contract, "https://agent.example/cb", &com, "state");

            c.bench_function("agent_request_oidc", |b| {
                b.iter(|| oidc::agent_sign_request(&agent_key, &contract, "https://agent.example/cb", black_box(&com), "state"))
            });

            c.bench_function("client_check_request_oidc", |b| {
                b.iter(|| oidc::client_check_request(black_box(&request), &agent_pk, &com))
            });
        }
    }

    // ---- CTAP: the IdM is a FIDO authenticator, the challenge is com ----
    for (name, alg) in [("ctap_es256", CoseAlg::Es256), ("ctap_eddsa", CoseAlg::EdDsa)] {
        let (mut authenticator, credential) = Authenticator::make_credential("agent.example", id_str.as_bytes(), alg);
        let contract = ctap::CtapContract {
            id: id_str.clone(),
            com_id,
            credential,
            origin: String::from("https://agent.example"),
        };
        let client_data_json = ctap::client_data_json(&com, &contract.origin);
        let client_data_hash = ctap::client_data_hash(&client_data_json);
        let (authenticator_data, signature) = authenticator.get_assertion(&client_data_hash);
        let assertion = ctap::Assertion {
            cred_id: authenticator.cred_id().to_vec(),
            authenticator_data,
            client_data_json,
            signature,
            user_handle: id_str.as_bytes().to_vec(),
        };
        let order = ctap::CtapOrder { assertion, com, r };
        let consent = ctap::agent_receive(&s_a, &contract, &att, &order, &public_params).unwrap();
        assert!(ctap::verify_consent(&contract, &att, &consent, &public_params));

        c.bench_function(&format!("idm_{}", name), |b| {
            b.iter(|| authenticator.get_assertion(black_box(&client_data_hash)))
        });

        c.bench_function(&format!("agent_{}", name), |b| {
            b.iter(|| ctap::agent_receive(&s_a, &contract, black_box(&att), &order, &public_params))
        });

        c.bench_function(&format!("consent_verify_{}", name), |b| {
            b.iter(|| ctap::verify_consent(&contract, black_box(&att), &consent, &public_params))
        });

        c.bench_function(&format!("make_credential_{}", name), |b| {
            b.iter(|| Authenticator::make_credential("agent.example", black_box(id_str.as_bytes()), alg))
        });
    }

    c.bench_function("client_data_json_ctap", |b| {
        b.iter(|| ctap::client_data_json(black_box(&com), "https://agent.example"))
    });

    // ---- OID4VP: the IdM is an eID wallet, the key binding JWT carries nonce = com ----
    // ES256 is what the Swiyu and EUDI profiles require; EdDSA is the lower bound.
    for (name, alg) in [("oid4vp_es256", JwsAlg::Es256), ("oid4vp_eddsa", JwsAlg::EdDsa)] {
        let issuer = Issuer::new("https://pid.example", alg);
        let holder_signer = JwsSigner::generate(alg);
        let holder_pk = holder_signer.verifier();
        let claims = [
            ("personal_administrative_number", json!(id_str)),
            ("given_name", json!("Alice")),
            ("family_name", json!("Example")),
            ("birthdate", json!("1990-01-01")),
        ];
        let credential = issuer.issue(&holder_pk, "urn:eudi:pid:1", &claims, now);
        let wallet = Wallet { holder_signer, credential };
        let contract = oid4vp::Oid4vpContract {
            id: id_str.clone(),
            com_id,
            issuer: issuer.iss.clone(),
            pk_issuer: issuer.signer.verifier(),
            client_id: String::from("https://agent.example/consent"),
            id_claim: String::from("personal_administrative_number"),
        };
        let disclose = ["personal_administrative_number"];
        let presentation = wallet.present(&disclose, &nonce, &contract.client_id, now);
        let order = oid4vp::Oid4vpOrder { presentation, com, r };
        let consent = oid4vp::agent_receive(&s_a, &contract, &att, &order, &public_params, now).unwrap();
        assert!(oid4vp::verify_consent(&contract, &att, &consent, &public_params));

        c.bench_function(&format!("idm_{}", name), |b| {
            b.iter(|| wallet.present(&disclose, black_box(&nonce), &contract.client_id, now))
        });

        c.bench_function(&format!("agent_{}", name), |b| {
            b.iter(|| oid4vp::agent_receive(&s_a, &contract, black_box(&att), &order, &public_params, now))
        });

        c.bench_function(&format!("consent_verify_{}", name), |b| {
            b.iter(|| oid4vp::verify_consent(&contract, black_box(&att), &consent, &public_params))
        });

        if alg != JwsAlg::Es256 {
            continue;
        }

        // The Agent (verifier) signs the authorization request (JAR) carrying the nonce
        let agent_key = JwsSigner::generate(JwsAlg::Es256);
        let agent_pk = agent_key.verifier();
        let request = oid4vp::agent_sign_request(&agent_key, &contract, "https://agent.example/vp", &com);

        c.bench_function("agent_request_oid4vp", |b| {
            b.iter(|| oid4vp::agent_sign_request(&agent_key, &contract, "https://agent.example/vp", black_box(&com)))
        });

        c.bench_function("client_check_request_oid4vp", |b| {
            b.iter(|| oid4vp::client_check_request(black_box(&request), &agent_pk, &com))
        });

        c.bench_function("issue_oid4vp", |b| {
            b.iter(|| issuer.issue(&holder_pk, "urn:eudi:pid:1", black_box(&claims), now))
        });
    }

    // ---- DKIM: the IdM is the client's email provider ----
    let agent_private_key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let agent_public_key = RsaPublicKey::from(&agent_private_key);

    // Client launch DKIM variant: com plus RSA-OAEP encryption of (ref, att, r) (with Argon2)
    c.bench_function("client_launch_dkim", |b| {
        b.iter(|| client.launch_dkim(black_box(att.clone()), &agent_public_key))
    });

    // Client launch DKIM variant (with SHA256)
    c.bench_function("client_launch_dkim_sha256", |b| {
        b.iter(|| client.launch_dkim_sha256(black_box(att.clone()), &agent_public_key))
    });

    for (name, alg) in [("dkim_rsa", DkimAlg::RsaSha256), ("dkim_ed25519", DkimAlg::Ed25519Sha256)] {
        let provider = EmailProvider::new("mail.example", "default", alg);
        let verifier = DkimVerifier::new(&provider);
        let contract = dkim::DkimContract {
            id: String::from("alice@mail.example"),
            com_id,
            provider_domain: provider.domain.clone(),
            agent_address: String::from("consent@agent.example"),
        };
        let (com, ciphertext) = client.launch_dkim_sha256(att.clone(), &agent_public_key);
        let (header, body) = dkim::compose_email(&contract.id, &contract.agent_address, &com, &ciphertext);
        let header_fields: HeaderFields = header.parse().unwrap();
        let signature_line = provider.sign(&header_fields, &body);
        let signed_header: HeaderFields = format!("{}{}", signature_line, header).parse().unwrap();
        let order = dkim::DkimOrder { header: signed_header, body: body.clone() };
        let (consent, _att) = dkim::agent_receive(&s_a, &contract, &verifier, &agent_private_key, &order, &public_params).unwrap();
        assert!(dkim::verify_consent(&verifier, &contract, &att, &consent, &public_params));

        c.bench_function(&format!("idm_{}", name), |b| {
            b.iter(|| provider.sign(black_box(&header_fields), &body))
        });

        c.bench_function(&format!("agent_{}", name), |b| {
            b.iter(|| dkim::agent_receive(&s_a, &contract, &verifier, &agent_private_key, black_box(&order), &public_params))
        });

        c.bench_function(&format!("consent_verify_{}", name), |b| {
            b.iter(|| dkim::verify_consent(&verifier, &contract, black_box(&att), &consent, &public_params))
        });
    }

    // ---- Variant without IdM ----
    c.bench_function("client_enroll_no_idm", |b| {
        b.iter(|| client.enroll_no_idm())
    });

    c.bench_function("client_enroll_no_idm_sha256", |b| {
        b.iter(|| client.enroll_no_idm_sha256())
    });

    c.bench_function("client_enroll_no_idm_nohash", |b| {
        b.iter(|| client.enroll_no_idm_nohash())
    });

    c.bench_function("client_launch_no_idm", |b| {
        b.iter(|| client.launch_no_idm(black_box(&att)))
    });

    c.bench_function("client_launch_no_idm_sha256", |b| {
        b.iter(|| client.launch_no_idm_sha256(black_box(&att)))
    });

    c.bench_function("client_launch_no_idm_nohash", |b| {
        b.iter(|| client.launch_no_idm_nohash(black_box(&att)))
    });

    let (no_idm_contract, no_idm_secret_state) = client.enroll_no_idm_sha256();
    let no_idm_sig = client.launch_no_idm_sha256(&att);
    let (_no_idm_sk, no_idm_pk, no_idm_r_id) = no_idm_secret_state;
    let (_, no_idm_com_id) = no_idm_contract;

    c.bench_function("agent_verify_no_idm", |b| {
        b.iter(|| {
            agent.verify_and_prove_no_idm(
                no_idm_com_id,
                black_box(att.as_bytes()),
                no_idm_pk,
                no_idm_r_id,
                no_idm_sig,
            )
        })
    });

    let consent_no_idm = agent.verify_and_prove_no_idm(
        no_idm_com_id,
        att.as_bytes(),
        no_idm_pk,
        no_idm_r_id,
        no_idm_sig,
    ).unwrap();

    c.bench_function("consent_verify_no_idm", |b| {
        b.iter(|| {
            pok_verify_no_idm(
                no_idm_com_id,
                black_box(att.as_bytes()),
                consent_no_idm.0,
                &consent_no_idm.1,
                &public_params
            )
        })
    });

    // ---- Primitives ----
    let test_seed = [0u8; 32];
    c.bench_function("schnorr_keygen", |b| {
        b.iter(|| schnorr_keygen(black_box(test_seed)))
    });

    let (test_sk, test_pk) = schnorr_keygen(test_seed);
    let test_message = b"test message";

    c.bench_function("schnorr_sign", |b| {
        b.iter(|| schnorr_sign(black_box(test_sk), black_box(test_message)))
    });

    let test_sig = schnorr_sign(test_sk, test_message);

    c.bench_function("schnorr_verify", |b| {
        b.iter(|| schnorr_verify(black_box(test_pk), black_box(test_sig), black_box(test_message)))
    });

    for (name, alg) in [("rs256", JwsAlg::Rs256), ("eddsa", JwsAlg::EdDsa), ("es256", JwsAlg::Es256)] {
        let signer = JwsSigner::generate(alg);
        let verifier = signer.verifier();
        let sig = signer.sign_raw(test_message);

        c.bench_function(&format!("{}_sign", name), |b| {
            b.iter(|| signer.sign_raw(black_box(test_message)))
        });

        c.bench_function(&format!("{}_verify", name), |b| {
            b.iter(|| verifier.verify_raw(black_box(test_message), &sig))
        });
    }

    println!("Benchmark completed.");

}


criterion_group!(benches, benchmark_perform_action);
criterion_main!(benches);

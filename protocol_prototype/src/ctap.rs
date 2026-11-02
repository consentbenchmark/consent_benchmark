use crate::consent::{agent_core, com_to_nonce, verify_core, AgentSecret, Proof};
use crate::jws::JwsVerifier;
use crate::utils::PublicParams;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::{OsRng, RngCore};
use rsa::signature::{Signer as _, Verifier as _};
use serde_json::json;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoseAlg {
    // COSE -7: ECDSA with P-256 and SHA-256.
    Es256,
    // COSE -8: EdDSA (Ed25519).
    EdDsa,
}

enum AuthKey {
    Es256(p256::ecdsa::SigningKey),
    EdDsa(ed25519_dalek::SigningKey),
}

// The software authenticator (the IdM).  Holds one discoverable credential.
pub struct Authenticator {
    rp_id_hash: [u8; 32],
    cred_id: Vec<u8>,
    sign_count: u32,
    key: AuthKey,
}

// What the RP stores at registration (part of `contract`).
#[derive(Clone)]
pub struct CredentialRecord {
    pub cred_id: Vec<u8>,
    pub rp_id: String,
    pub alg: CoseAlg,
    pub public_key: JwsVerifier,
    pub user_handle: Vec<u8>,
}

// The `resp`: a WebAuthn assertion (authenticatorGetAssertion output plus the
// client data the platform assembled).
#[derive(Clone)]
pub struct Assertion {
    pub cred_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

impl Authenticator {
    // `authenticatorMakeCredential`: registration, done once at enrollment.
    pub fn make_credential(rp_id: &str, user_handle: &[u8], alg: CoseAlg) -> (Authenticator, CredentialRecord) {
        let mut cred_id = vec![0u8; 16];
        OsRng.fill_bytes(&mut cred_id);
        let (key, public_key) = match alg {
            CoseAlg::Es256 => {
                let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
                let pk = JwsVerifier::Es256(*sk.verifying_key());
                (AuthKey::Es256(sk), pk)
            }
            CoseAlg::EdDsa => {
                let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
                let pk = JwsVerifier::EdDsa(sk.verifying_key());
                (AuthKey::EdDsa(sk), pk)
            }
        };
        let rp_id_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        let auth = Authenticator { rp_id_hash, cred_id: cred_id.clone(), sign_count: 0, key };
        let record = CredentialRecord {
            cred_id,
            rp_id: rp_id.to_string(),
            alg,
            public_key,
            user_handle: user_handle.to_vec(),
        };
        (auth, record)
    }

    // `authenticatorGetAssertion` (`IdM.Query`): the authenticator receives
    // the 32-byte `clientDataHash`, builds `authenticatorData` and signs
    // `authenticatorData || clientDataHash`.
    pub fn get_assertion(&mut self, client_data_hash: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        self.sign_count = self.sign_count.wrapping_add(1);
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&self.rp_id_hash);
        auth_data.push(FLAG_UP | FLAG_UV);
        auth_data.extend_from_slice(&self.sign_count.to_be_bytes());

        let mut to_sign = Vec::with_capacity(37 + 32);
        to_sign.extend_from_slice(&auth_data);
        to_sign.extend_from_slice(client_data_hash);

        let signature = match &self.key {
            AuthKey::Es256(sk) => {
                let sig: p256::ecdsa::Signature = sk.sign(&to_sign);
                sig.to_der().as_bytes().to_vec()
            }
            AuthKey::EdDsa(sk) => sk.sign(&to_sign).to_bytes().to_vec(),
        };
        (auth_data, signature)
    }

    pub fn cred_id(&self) -> &[u8] {
        &self.cred_id
    }
}

// The platform (Client) builds `clientDataJSON` with `challenge = com`.
pub fn client_data_json(com: &RistrettoPoint, origin: &str) -> Vec<u8> {
    let v = json!({
        "type": "webauthn.get",
        "challenge": com_to_nonce(com),
        "origin": origin,
        "crossOrigin": false,
    });
    serde_json::to_vec(&v).unwrap()
}

pub fn client_data_hash(client_data_json: &[u8]) -> [u8; 32] {
    Sha256::digest(client_data_json).into()
}

// `Σ.Verify` for an assertion (WebAuthn Level 3, 7.2 "Verifying an
// Authentication Assertion", steps relevant to a single RP without
// extensions): credential, client data, rpIdHash, flags, signature.
pub fn verify_assertion(record: &CredentialRecord, origin: &str, com: &RistrettoPoint, a: &Assertion) -> bool {
    if a.cred_id != record.cred_id || a.user_handle != record.user_handle {
        return false;
    }
    let cd: serde_json::Value = match serde_json::from_slice(&a.client_data_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let s = |k: &str| cd.get(k).and_then(|v| v.as_str());
    if s("type") != Some("webauthn.get") || s("origin") != Some(origin) {
        return false;
    }
    if s("challenge") != Some(com_to_nonce(com).as_str()) {
        return false;
    }
    if a.authenticator_data.len() < 37 {
        return false;
    }
    let rp_id_hash: [u8; 32] = Sha256::digest(record.rp_id.as_bytes()).into();
    if a.authenticator_data[..32] != rp_id_hash {
        return false;
    }
    let flags = a.authenticator_data[32];
    if flags & FLAG_UP == 0 {
        return false;
    }
    let mut signed = Vec::with_capacity(a.authenticator_data.len() + 32);
    signed.extend_from_slice(&a.authenticator_data);
    signed.extend_from_slice(&client_data_hash(&a.client_data_json));

    match (&record.public_key, record.alg) {
        (JwsVerifier::Es256(pk), CoseAlg::Es256) => match p256::ecdsa::Signature::from_der(&a.signature) {
            Ok(sig) => pk.verify(&signed, &sig).is_ok(),
            Err(_) => false,
        },
        (JwsVerifier::EdDsa(pk), CoseAlg::EdDsa) => match ed25519_dalek::Signature::from_slice(&a.signature) {
            Ok(sig) => pk.verify(&signed, &sig).is_ok(),
            Err(_) => false,
        },
        _ => false,
    }
}

// `contract` for the CTAP variant: the credential record replaces `pk_IdM`.
#[derive(Clone)]
pub struct CtapContract {
    pub id: String,
    pub com_id: RistrettoPoint,
    pub credential: CredentialRecord,
    pub origin: String,
}

pub struct CtapOrder {
    pub assertion: Assertion,
    pub com: RistrettoPoint,
    pub r: Scalar,
}

pub struct CtapConsent {
    pub assertion: Assertion,
    pub com: RistrettoPoint,
    pub proof: Proof,
}

// `Agent.Receive`.
pub fn agent_receive(
    s_a: &AgentSecret,
    contract: &CtapContract,
    att: &str,
    order: &CtapOrder,
    pp: &PublicParams,
) -> Option<CtapConsent> {
    if order.assertion.user_handle != contract.id.as_bytes()
        || !verify_assertion(&contract.credential, &contract.origin, &order.com, &order.assertion)
    {
        return None;
    }
    let proof = agent_core(s_a, contract.com_id, order.com, att, order.r, pp)?;
    Some(CtapConsent { assertion: order.assertion.clone(), com: order.com, proof })
}

// `Verify`.
pub fn verify_consent(contract: &CtapContract, att: &str, consent: &CtapConsent, pp: &PublicParams) -> bool {
    consent.assertion.user_handle == contract.id.as_bytes()
        && verify_assertion(&contract.credential, &contract.origin, &consent.com, &consent.assertion)
        && verify_core(contract.com_id, consent.com, att, &consent.proof, pp)
}

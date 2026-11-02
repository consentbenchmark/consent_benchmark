use crate::consent::{agent_core, com_to_nonce, verify_core, AgentSecret, Proof};
use crate::jws::{b64url, b64url_decode, verify_compact, JwsAlg, JwsSigner, JwsVerifier};
use crate::utils::PublicParams;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// The credential issuer (PID provider).
pub struct Issuer {
    pub iss: String,
    pub signer: JwsSigner,
}

// An SD-JWT VC as held by the wallet: the issuer-signed JWT and all
// disclosures (`base64url([salt, name, value])`).
#[derive(Clone)]
pub struct SdJwtVc {
    pub issuer_jwt: String,
    pub disclosures: Vec<(String, String)>, // (claim name, encoded disclosure)
}

fn disclosure_digest(encoded: &str) -> String {
    b64url(&Sha256::digest(encoded.as_bytes()))
}

impl Issuer {
    pub fn new(iss: &str, alg: JwsAlg) -> Self {
        Issuer { iss: iss.to_string(), signer: JwsSigner::generate(alg) }
    }

    // Issues an SD-JWT VC with all `claims` selectively disclosable and the
    // holder key bound through `cnf`.  Done once (OpenID4VCI), at enrollment.
    pub fn issue(&self, holder_key: &JwsVerifier, vct: &str, claims: &[(&str, Value)], now: u64) -> SdJwtVc {
        let mut disclosures = Vec::with_capacity(claims.len());
        let mut sd = Vec::with_capacity(claims.len());
        for (name, value) in claims {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let disclosure = json!([b64url(&salt), name, value]);
            let encoded = b64url(serde_json::to_string(&disclosure).unwrap().as_bytes());
            sd.push(Value::String(disclosure_digest(&encoded)));
            disclosures.push((name.to_string(), encoded));
        }
        let payload = json!({
            "iss": self.iss,
            "vct": vct,
            "iat": now,
            "exp": now + 365 * 86400,
            "cnf": { "jwk": holder_key.to_jwk() },
            "_sd": sd,
            "_sd_alg": "sha-256",
        });
        let issuer_jwt = self.signer.sign_compact(&payload, &[("typ", "dc+sd-jwt"), ("kid", "pid-issuer-1")]);
        SdJwtVc { issuer_jwt, disclosures }
    }
}

// The wallet (the IdM at consent time).
pub struct Wallet {
    pub holder_signer: JwsSigner,
    pub credential: SdJwtVc,
}

impl Wallet {
    // `IdM.Query`: builds the presentation disclosing `disclose` and signs the
    // Key Binding JWT over `(nonce, aud, iat, sd_hash)`.
    pub fn present(&self, disclose: &[&str], nonce: &str, aud: &str, now: u64) -> String {
        let mut presentation = String::with_capacity(self.credential.issuer_jwt.len() + 512);
        presentation.push_str(&self.credential.issuer_jwt);
        presentation.push('~');
        for (name, encoded) in &self.credential.disclosures {
            if disclose.contains(&name.as_str()) {
                presentation.push_str(encoded);
                presentation.push('~');
            }
        }
        let sd_hash = b64url(&Sha256::digest(presentation.as_bytes()));
        let kb_payload = json!({
            "iat": now,
            "aud": aud,
            "nonce": nonce,
            "sd_hash": sd_hash,
        });
        let kb_jwt = self.holder_signer.sign_compact(&kb_payload, &[("typ", "kb+jwt")]);
        presentation.push_str(&kb_jwt);
        presentation
    }
}

// Verifies an SD-JWT VC presentation and returns the disclosed claims.
// Checks: issuer signature and `typ`, every disclosure digest is in `_sd`,
// KB-JWT signature under `cnf.jwk`, `typ`, `aud`, `nonce`, `sd_hash`.
// `now = Some(t)` also checks the credential's `exp >= t` (the Agent, at
// receipt); `Verify` passes `None` so that a consent stays verifiable later.
pub fn verify_presentation(
    presentation: &str,
    issuer_key: &JwsVerifier,
    expected_iss: &str,
    aud: &str,
    nonce: &str,
    now: Option<u64>,
) -> Option<serde_json::Map<String, Value>> {
    let kb_start = presentation.rfind('~')? + 1;
    let sd_part = &presentation[..kb_start];
    let kb_jwt = &presentation[kb_start..];
    if kb_jwt.is_empty() {
        return None;
    }
    let mut parts = sd_part.split('~');
    let issuer_jwt = parts.next()?;
    let issued = verify_compact(issuer_jwt, issuer_key)?;
    if issued.header.get("typ")?.as_str()? != "dc+sd-jwt" {
        return None;
    }
    let p = &issued.payload;
    if p.get("iss")?.as_str()? != expected_iss || p.get("_sd_alg")?.as_str()? != "sha-256" {
        return None;
    }
    if let Some(t) = now {
        if p.get("exp")?.as_u64()? < t {
            return None;
        }
    }
    let sd = p.get("_sd")?.as_array()?;
    let holder_key = JwsVerifier::from_jwk(p.get("cnf")?.get("jwk")?)?;

    let mut claims = serde_json::Map::new();
    for encoded in parts {
        if encoded.is_empty() {
            continue; // trailing separator before the KB-JWT
        }
        let digest = Value::String(disclosure_digest(encoded));
        if !sd.contains(&digest) {
            return None;
        }
        let d: Value = serde_json::from_slice(&b64url_decode(encoded)?).ok()?;
        let arr = d.as_array()?;
        if arr.len() != 3 {
            return None;
        }
        claims.insert(arr[1].as_str()?.to_string(), arr[2].clone());
    }

    let kb = verify_compact(kb_jwt, &holder_key)?;
    if kb.header.get("typ")?.as_str()? != "kb+jwt" {
        return None;
    }
    let k = &kb.payload;
    if k.get("aud")?.as_str()? != aud || k.get("nonce")?.as_str()? != nonce {
        return None;
    }
    let sd_hash = b64url(&Sha256::digest(sd_part.as_bytes()));
    if k.get("sd_hash")?.as_str()? != sd_hash {
        return None;
    }
    k.get("iat")?.as_u64()?;
    Some(claims)
}

// `contract` for the OpenID4VP variant.
#[derive(Clone)]
pub struct Oid4vpContract {
    pub id: String,
    pub com_id: RistrettoPoint,
    pub issuer: String,
    pub pk_issuer: JwsVerifier,
    // The verifier's `client_id` (the `aud` of the KB-JWT).
    pub client_id: String,
    // Which disclosed claim carries `ID`.
    pub id_claim: String,
}

pub struct Oid4vpOrder {
    pub presentation: String,
    pub com: RistrettoPoint,
    pub r: Scalar,
}

pub struct Oid4vpConsent {
    pub presentation: String,
    pub com: RistrettoPoint,
    pub proof: Proof,
}

// `Σ.Verify(pk_IdM, σ, com, ID)` for a presentation.
pub fn verify_presentation_for(contract: &Oid4vpContract, com: &RistrettoPoint, presentation: &str, now: Option<u64>) -> bool {
    match verify_presentation(
        presentation,
        &contract.pk_issuer,
        &contract.issuer,
        &contract.client_id,
        &com_to_nonce(com),
        now,
    ) {
        Some(claims) => claims.get(&contract.id_claim).and_then(|v| v.as_str()) == Some(contract.id.as_str()),
        None => false,
    }
}

// `Agent.Receive`.
pub fn agent_receive(
    s_a: &AgentSecret,
    contract: &Oid4vpContract,
    att: &str,
    order: &Oid4vpOrder,
    pp: &PublicParams,
    now: u64,
) -> Option<Oid4vpConsent> {
    if !verify_presentation_for(contract, &order.com, &order.presentation, Some(now)) {
        return None;
    }
    let proof = agent_core(s_a, contract.com_id, order.com, att, order.r, pp)?;
    Some(Oid4vpConsent { presentation: order.presentation.clone(), com: order.com, proof })
}

// `Verify`.
pub fn verify_consent(contract: &Oid4vpContract, att: &str, consent: &Oid4vpConsent, pp: &PublicParams) -> bool {
    verify_presentation_for(contract, &consent.com, &consent.presentation, None)
        && verify_core(contract.com_id, consent.com, att, &consent.proof, pp)
}

// The Agent (verifier) signs the OpenID4VP authorization request (JAR) that
// carries `nonce = com` and the DCQL query.  Reported separately.
pub fn agent_sign_request(agent_signer: &JwsSigner, contract: &Oid4vpContract, response_uri: &str, com: &RistrettoPoint) -> String {
    let payload = json!({
        "iss": contract.client_id,
        "client_id": contract.client_id,
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "response_uri": response_uri,
        "nonce": com_to_nonce(com),
        "dcql_query": {
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:1"] },
                "claims": [{ "path": [contract.id_claim] }]
            }]
        },
    });
    agent_signer.sign_compact(&payload, &[("typ", "oauth-authz-req+jwt")])
}

// The user's app checks the request before passing it to the wallet.
pub fn client_check_request(request: &str, agent_pk: &JwsVerifier, com: &RistrettoPoint) -> bool {
    match verify_compact(request, agent_pk) {
        Some(jws) => jws.payload.get("nonce").and_then(|v| v.as_str()) == Some(com_to_nonce(com).as_str()),
        None => false,
    }
}

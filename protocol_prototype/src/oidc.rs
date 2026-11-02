use crate::consent::{agent_core, com_to_nonce, verify_core, AgentSecret, Proof};
use crate::jws::{verify_compact, JwsAlg, JwsSigner, JwsVerifier};
use crate::utils::PublicParams;
use curve25519_dalek::{RistrettoPoint, Scalar};
use serde_json::json;

// The OpenID provider.  Issues ID tokens; nothing else is needed from it.
pub struct OpenIdProvider {
    pub issuer: String,
    pub signer: JwsSigner,
}

impl OpenIdProvider {
    pub fn new(issuer: &str, alg: JwsAlg) -> Self {
        OpenIdProvider { issuer: issuer.to_string(), signer: JwsSigner::generate(alg) }
    }

    // `IdM.Query`: sign `(com, ID)` as a standard ID token with
    // `nonce = base64url(com)` and `sub = ID`.
    pub fn issue_id_token(&self, sub: &str, aud: &str, nonce: &str, now: u64) -> String {
        let payload = json!({
            "iss": self.issuer,
            "sub": sub,
            "aud": aud,
            "nonce": nonce,
            "iat": now,
            "exp": now + 3600,
            "auth_time": now,
        });
        self.signer.sign_compact(&payload, &[("typ", "JWT"), ("kid", "op-key-1")])
    }
}

// `contract = (ID, com_ID, pk_IdM)` plus the OIDC-specific identifiers.
#[derive(Clone)]
pub struct OidcContract {
    pub id: String,
    pub com_id: RistrettoPoint,
    pub issuer: String,
    pub pk_idm: JwsVerifier,
    // The Agent's `client_id` at the OP (the `aud` of the ID token).
    pub client_id: String,
}

// `order = (com, r, σ)` where σ is the ID token.
pub struct OidcOrder {
    pub id_token: String,
    pub com: RistrettoPoint,
    pub r: Scalar,
}

// `consent = (σ, com, π)`.
pub struct OidcConsent {
    pub id_token: String,
    pub com: RistrettoPoint,
    pub proof: Proof,
}

// `Σ.Verify(pk_IdM, σ, com, ID)` for an ID token: signature, issuer,
// audience, subject and nonce.  `now = Some(t)` also checks `exp >= t`: the
// Agent does this when it receives the order; `Verify` passes `None`, since a
// consent must stay verifiable (e.g. by the Judge) after the token has expired.
pub fn verify_id_token(token: &str, contract: &OidcContract, com: &RistrettoPoint, now: Option<u64>) -> bool {
    let jws = match verify_compact(token, &contract.pk_idm) {
        Some(j) => j,
        None => return false,
    };
    let p = &jws.payload;
    let s = |k: &str| p.get(k).and_then(|v| v.as_str());
    s("iss") == Some(contract.issuer.as_str())
        && s("aud") == Some(contract.client_id.as_str())
        && s("sub") == Some(contract.id.as_str())
        && s("nonce").map(|n| n == com_to_nonce(com)).unwrap_or(false)
        && match now {
            Some(t) => p.get("exp").and_then(|v| v.as_u64()).map(|e| e >= t).unwrap_or(false),
            None => true,
        }
}

// `Agent.Receive(s_A, contract, att, order)`.
pub fn agent_receive(
    s_a: &AgentSecret,
    contract: &OidcContract,
    att: &str,
    order: &OidcOrder,
    pp: &PublicParams,
    now: u64,
) -> Option<OidcConsent> {
    if !verify_id_token(&order.id_token, contract, &order.com, Some(now)) {
        return None;
    }
    let proof = agent_core(s_a, contract.com_id, order.com, att, order.r, pp)?;
    Some(OidcConsent { id_token: order.id_token.clone(), com: order.com, proof })
}

// `Verify(contract, att, consent)`.
pub fn verify_consent(
    contract: &OidcContract,
    att: &str,
    consent: &OidcConsent,
    pp: &PublicParams,
) -> bool {
    verify_id_token(&consent.id_token, contract, &consent.com, None)
        && verify_core(contract.com_id, consent.com, att, &consent.proof, pp)
}

// The Agent (RP) signs the authentication request carrying `nonce = com`
// (OIDC Core 6.1, request object / RFC 9101).  Not part of `Agent.Receive`;
// reported separately.
pub fn agent_sign_request(
    agent_signer: &JwsSigner,
    contract: &OidcContract,
    redirect_uri: &str,
    com: &RistrettoPoint,
    state: &str,
) -> String {
    let payload = json!({
        "iss": contract.client_id,
        "aud": contract.issuer,
        "client_id": contract.client_id,
        "response_type": "id_token",
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "nonce": com_to_nonce(com),
        "state": state,
    });
    agent_signer.sign_compact(&payload, &[("typ", "oauth-authz-req+jwt")])
}

// The Client checks that its query was included in the Agent's signed
// request before redirecting to the OP.
pub fn client_check_request(request: &str, agent_pk: &JwsVerifier, com: &RistrettoPoint) -> bool {
    match verify_compact(request, agent_pk) {
        Some(jws) => jws.payload.get("nonce").and_then(|v| v.as_str()) == Some(com_to_nonce(com).as_str()),
        None => false,
    }
}

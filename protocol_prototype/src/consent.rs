use crate::jws::{b64url, b64url_decode};
use crate::utils::{commit, hash_to_scalar, pok_prove, pok_verify, PublicParams};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};

// The non-interactive proof of knowledge pi (ΠMULTEQ).
#[derive(Clone, Copy, Debug)]
pub struct Proof {
    pub ch: Scalar,
    pub resp1: Scalar,
    pub resp2: Scalar,
    pub resp3: Scalar,
}

// The Agent's secret `s_A = (h_ID, r_ID)`.
#[derive(Clone, Copy, Debug)]
pub struct AgentSecret {
    pub h_id: Scalar,
    pub r_id: Scalar,
}

pub fn com_bytes(com: &RistrettoPoint) -> [u8; 32] {
    com.compress().to_bytes()
}

// Encodes the query `com` as a nonce / challenge string (base64url of the
// 32-byte compressed Ristretto point).
pub fn com_to_nonce(com: &RistrettoPoint) -> String {
    b64url(&com_bytes(com))
}

// Decodes a nonce / challenge string back to the query `com`.
pub fn nonce_to_com(nonce: &str) -> Option<RistrettoPoint> {
    let bytes = b64url_decode(nonce)?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    CompressedRistretto::from_slice(&arr).ok()?.decompress()
}

// Steps 3 and 5 of `Agent.Receive`: check `com = Com(h_ID, att; r)` and
// produce the proof of knowledge.  The IdM-specific step 4 (verifying the
// IdM's response) is done by the variant modules.
pub fn agent_core(
    s_a: &AgentSecret,
    com_id: RistrettoPoint,
    com: RistrettoPoint,
    att: &str,
    r: Scalar,
    pp: &PublicParams,
) -> Option<Proof> {
    if com != commit(s_a.h_id, hash_to_scalar(att.to_string()), r, pp.clone()) {
        return None;
    }
    let (ch, resp1, resp2, resp3) =
        pok_prove(com_id, com, att.to_string(), s_a.h_id, s_a.r_id, r, pp.clone());
    Some(Proof { ch, resp1, resp2, resp3 })
}

// Step 4 of `Verify`: check the proof of knowledge.
pub fn verify_core(
    com_id: RistrettoPoint,
    com: RistrettoPoint,
    att: &str,
    proof: &Proof,
    pp: &PublicParams,
) -> bool {
    pok_verify(
        com_id,
        com,
        att.to_string(),
        proof.ch,
        proof.resp1,
        proof.resp2,
        proof.resp3,
        pp.clone(),
    )
}

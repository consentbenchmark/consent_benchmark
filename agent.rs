use crate::utils::{PublicParams, pok_prove, commit, hash_to_scalar, schnorr_verify, pok_prove_no_idm, NoIdmProof};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rsa::{RsaPrivateKey, Oaep};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub struct Agent {
    public_params: PublicParams,
}

impl Agent {
    pub fn new(public_params: PublicParams) -> Self {
        Agent { public_params }
    }

    pub fn verify_and_prove_no_idm(
        &self,
        com_id: (RistrettoPoint, RistrettoPoint),
        att: &[u8],
        pk_id: RistrettoPoint,
        r_id: (Scalar, Scalar),
        signature: (RistrettoPoint, Scalar),
    ) -> Option<(RistrettoPoint, NoIdmProof)> {
        if !schnorr_verify(pk_id, signature, att) {
            return None;
        }

        let proof = pok_prove_no_idm(com_id, att, pk_id, r_id, signature, &self.public_params);
        Some((signature.0, proof))
    }

}

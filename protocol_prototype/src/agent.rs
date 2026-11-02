use crate::utils::{PublicParams, pok_prove, commit, hash_to_scalar, schnorr_verify, pok_prove_no_idm, NoIdmProof};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

pub struct Agent {
    public_params: PublicParams,
}

impl Agent {
    pub fn new(public_params: PublicParams) -> Self {
        Agent { public_params }
    }

    // Agent.Receive without the IdM signature check (which depends on the IdM variant):
    // check com = Com(h_id, att; r) and produce the proof pi
    pub fn receive(
        &self,
        s_a: (Scalar, Scalar),
        com_id: RistrettoPoint,
        att: &str,
        com: RistrettoPoint,
        r: Scalar,
    ) -> Option<(Scalar, Scalar, Scalar, Scalar)> {
        let (h_id, r_id) = s_a;
        if com != commit(h_id, hash_to_scalar(att.to_string()), r, self.public_params.clone()) {
            return None;
        }
        Some(pok_prove(com_id, com, att.to_string(), h_id, r_id, r, self.public_params.clone()))
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

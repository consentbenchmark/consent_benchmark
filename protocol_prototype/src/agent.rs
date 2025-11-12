use crate::utils::{PublicParams, pok_prove, commit, hash_to_scalar};
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

}

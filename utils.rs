use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::{Sha256, Digest};
use rand_core::OsRng;

#[derive(Clone)]
pub struct PublicParams {
    pub g1: RistrettoPoint,
    pub g2: RistrettoPoint,
    pub g3: RistrettoPoint
}

pub struct Contract {
    pub id: String,
    pub com_id: RistrettoPoint
}

pub fn generate_public_params() -> PublicParams {
    let mut rng = rand::thread_rng();
    let g1 = RistrettoPoint::random(&mut rng);
    let g2 = RistrettoPoint::random(&mut rng);
    let g3 = RistrettoPoint::random(&mut rng);
    PublicParams { g1, g2, g3 }
}

pub fn commit(x1: Scalar, x2: Scalar, r: Scalar, pp: PublicParams) -> RistrettoPoint {
    let xr = [x1, x2, r];
    RistrettoPoint::multiscalar_mul(&xr, &[pp.g1, pp.g2, pp.g3])
}

pub fn hash_to_scalar(input: String) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    Scalar::from_bytes_mod_order(result.as_slice().try_into().unwrap())
}

pub fn pok_prove(com_id: RistrettoPoint, com: RistrettoPoint, att: String, h_id: Scalar, r_id: Scalar, r: Scalar, pp: PublicParams) -> (Scalar, Scalar, Scalar, Scalar) {
    let mut csprng = OsRng;
    let a = Scalar::random(&mut csprng);
    let b = Scalar::random(&mut csprng);
    let c = Scalar::random(&mut csprng);

    let com_1 = commit(a, Scalar::ZERO, b, pp.clone());
    let com_2 = commit(a, Scalar::ZERO, c, pp.clone());
    
    let mut hasher = Sha256::new();
    hasher.update(com_id.compress().as_bytes());
    hasher.update(com.compress().as_bytes());
    hasher.update(att.as_bytes());
    hasher.update(com_1.compress().as_bytes());
    hasher.update(com_2.compress().as_bytes());
    let result = hasher.finalize();
    let ch = Scalar::from_bytes_mod_order(result.as_slice().try_into().unwrap());
    let resp1 = a + ch * h_id;
    let resp2 = b + ch * r_id;
    let resp3 = c + ch * r;
    (ch, resp1, resp2, resp3)
}

pub fn pok_verify(com_id: RistrettoPoint, com: RistrettoPoint, att: String, ch: Scalar, resp1: Scalar, resp2: Scalar, resp3: Scalar, pp: PublicParams) -> bool {
    let com_1 = commit(resp1, Scalar::ZERO, resp2, pp.clone()) - ch*com_id;
    let com_2 = commit(resp1, ch*hash_to_scalar(att.clone()), resp3, pp.clone()) - ch*com;
    let mut hasher = Sha256::new();
    hasher.update(com_id.compress().as_bytes());
    hasher.update(com.compress().as_bytes());
    hasher.update(att.as_bytes());
    hasher.update(com_1.compress().as_bytes());
    hasher.update(com_2.compress().as_bytes());
    let result = hasher.finalize();
    let ch_ = Scalar::from_bytes_mod_order(result.as_slice().try_into().unwrap());
    ch == ch_
}

pub fn schnorr_keygen(seed: [u8; 32]) -> (Scalar, RistrettoPoint) {
    let sk = Scalar::from_bytes_mod_order(seed);
    let pk = sk * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    (sk, pk)
}

pub fn schnorr_sign(sk: Scalar, message: &[u8]) -> (RistrettoPoint, Scalar) {
    let mut csprng = OsRng;
    let r = Scalar::random(&mut csprng);
    let big_r = r * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    let mut hasher = Sha256::new();
    hasher.update(big_r.compress().as_bytes());
    hasher.update(message);
    let result = hasher.finalize();
    let h = Scalar::from_bytes_mod_order(result.as_slice().try_into().unwrap());

    let s = r + sk * h;
    (big_r, s)
}

pub fn schnorr_verify(pk: RistrettoPoint, signature: (RistrettoPoint, Scalar), message: &[u8]) -> bool {
    let (big_r, s) = signature;

    let mut hasher = Sha256::new();
    hasher.update(big_r.compress().as_bytes());
    hasher.update(message);
    let result = hasher.finalize();
    let h = Scalar::from_bytes_mod_order(result.as_slice().try_into().unwrap());

    let lhs = s * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    let rhs = big_r + h * pk;
    lhs == rhs
}

pub fn commit_pk(
    pk: RistrettoPoint,
    rho1: Scalar,
    rho2: Scalar,
    pp: &PublicParams
) -> (RistrettoPoint, RistrettoPoint) {
    let c1 = pk + rho1 * pp.g1;
    let c2 = rho1 * pp.g2 + rho2 * pp.g3;
    (c1, c2)
}

pub fn commit_point(
    point: RistrettoPoint,
    pp: &PublicParams
) -> (RistrettoPoint, RistrettoPoint) {
    (point, curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT - curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
}

pub struct NoIdmProof {
    pub e: Scalar,
    pub r1: Scalar,
    pub r2: (Scalar, Scalar),
}

pub fn pok_prove_no_idm(
    com_id: (RistrettoPoint, RistrettoPoint),
    att: &[u8],
    pk_id: RistrettoPoint,
    r_id: (Scalar, Scalar),
    signature: (RistrettoPoint, Scalar),
    pp: &PublicParams
) -> NoIdmProof {
    let mut csprng = OsRng;
    let (big_r, s) = signature;

    let mut hasher = Sha256::new();
    hasher.update(big_r.compress().as_bytes());
    hasher.update(att);
    let result = hasher.finalize();
    let h = Scalar::from_bytes_mod_order(result.as_slice().try_into().unwrap());

    let h_inv = h.invert();
    let a = s * h_inv;

    let alpha = Scalar::random(&mut csprng);
    let beta1 = Scalar::random(&mut csprng);
    let beta2 = Scalar::random(&mut csprng);

    let alpha_g = alpha * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    let c = commit_pk(alpha_g, beta1, beta2, pp);

    let mut hasher = Sha256::new();
    hasher.update(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    hasher.update(big_r.compress().as_bytes());
    hasher.update(att);
    hasher.update(com_id.0.compress().as_bytes());
    hasher.update(com_id.1.compress().as_bytes());
    hasher.update(c.0.compress().as_bytes());
    hasher.update(c.1.compress().as_bytes());
    let result = hasher.finalize();
    let e = Scalar::from_bytes_mod_order(result.as_slice().try_into().unwrap());

    let resp1 = alpha + e * a;
    let resp2_0 = beta1 + e * r_id.0;
    let resp2_1 = beta2 + e * r_id.1;

    NoIdmProof {
        e,
        r1: resp1,
        r2: (resp2_0, resp2_1),
    }
}

pub fn pok_verify_no_idm(
    com_id: (RistrettoPoint, RistrettoPoint),
    att: &[u8],
    big_r: RistrettoPoint,
    proof: &NoIdmProof,
    pp: &PublicParams
) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(big_r.compress().as_bytes());
    hasher.update(att);
    let result = hasher.finalize();
    let h = Scalar::from_bytes_mod_order(result.as_slice().try_into().unwrap());

    let h_inv = h.invert();

    let r1_g = proof.r1 * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    let com_r1 = commit_pk(r1_g, proof.r2.0, proof.r2.1, pp);

    let com_r_scaled = (h_inv * big_r, curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT - curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT);
    let shifted_com = (com_id.0 + com_r_scaled.0, com_id.1 + com_r_scaled.1);

    let c_prime = (com_r1.0 - proof.e * shifted_com.0, com_r1.1 - proof.e * shifted_com.1);

    let mut hasher = Sha256::new();
    hasher.update(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    hasher.update(big_r.compress().as_bytes());
    hasher.update(att);
    hasher.update(com_id.0.compress().as_bytes());
    hasher.update(com_id.1.compress().as_bytes());
    hasher.update(c_prime.0.compress().as_bytes());
    hasher.update(c_prime.1.compress().as_bytes());
    let result = hasher.finalize();
    let e_prime = Scalar::from_bytes_mod_order(result.as_slice().try_into().unwrap());

    proof.e == e_prime
}
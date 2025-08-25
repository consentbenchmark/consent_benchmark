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
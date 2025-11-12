use curve25519_dalek::{ristretto::RistrettoBasepointTable, scalar::Scalar, RistrettoPoint};
use rand_core::OsRng;
use hex;
use sha2::{Digest, Sha256};
use argon2::{Argon2, Algorithm, Version, Params};
use rsa::{RsaPublicKey, Oaep};
use crate::utils::{PublicParams, commit, hash_to_scalar};

pub struct Client {
    login: String,
    password: String,
    id: i32,
    public_params: PublicParams,
}

impl Client {
    pub fn new(login: String, password: String, id: i32, public_params: PublicParams) -> Self {
        Client {
            login,
            password,
            id,
            public_params,
        }
    }

    pub fn get_id(&self) -> i32 {
        self.id
    }
    pub fn enroll(&self) -> ((i32, RistrettoPoint), (Scalar, Scalar)) {
        let mut csprng = OsRng;
        let r_id = Scalar::random(&mut csprng);

        // Argon2id with RFC 9106 parameters
        let params = Params::new(65536, 3, 4, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut salt = [0u8; 16];
        salt[..4].copy_from_slice(&self.id.to_le_bytes());

        let mut h_id_bytes = [0u8; 32];
        argon2.hash_password_into(self.password.as_bytes(), &salt, &mut h_id_bytes).unwrap();

        //println!("Enrolled client with ID: {}", hex::encode(r_id.as_bytes()));
        //println!("Password hash: {}", hex::encode(h_id_bytes));
        let h_id = Scalar::from_bytes_mod_order(h_id_bytes);
        let com_id = commit(h_id, Scalar::ZERO, r_id, self.public_params.clone());
        //println!("Com_id: {}", hex::encode(com_id.compress().as_bytes()));
        let contract = (self.id, com_id);
        let s_a = (h_id, r_id);
        (contract, s_a)
    }

    pub fn launch(&self, att: String) -> (RistrettoPoint, Scalar) {
        let mut csprng = OsRng;
        let r = Scalar::random(&mut csprng);

        // Argon2id with RFC 9106 parameters
        let params = Params::new(65536, 3, 4, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut salt = [0u8; 16];
        salt[..4].copy_from_slice(&self.id.to_le_bytes());

        let mut h_id_bytes = [0u8; 32];
        argon2.hash_password_into(self.password.as_bytes(), &salt, &mut h_id_bytes).unwrap();

        let h_id = Scalar::from_bytes_mod_order(h_id_bytes);
        let com = commit(h_id, hash_to_scalar(att.clone()), r, self.public_params.clone());
        //println!("Com: {}", hex::encode(com.compress().as_bytes()));
        (com, r)
    }

    // Enrollment without password hashing (for benchmarking)
    pub fn enroll_nohash(&self) -> ((i32, RistrettoPoint), (Scalar, Scalar)) {
        let mut csprng = OsRng;
        let r_id = Scalar::random(&mut csprng);


        let mut h_id_bytes = [0u8; 32];
        let password_bytes = self.password.as_bytes();
        let copy_len = password_bytes.len().min(32);
        h_id_bytes[..copy_len].copy_from_slice(&password_bytes[..copy_len]);

        let h_id = Scalar::from_bytes_mod_order(h_id_bytes);
        let com_id = commit(h_id, Scalar::ZERO, r_id, self.public_params.clone());
        let contract = (self.id, com_id);
        let s_a = (h_id, r_id);
        (contract, s_a)
    }

    // Launch without password hashing (for benchmarking)
    pub fn launch_nohash(&self, att: String) -> (RistrettoPoint, Scalar) {
        let mut csprng = OsRng;
        let r = Scalar::random(&mut csprng);

        let mut h_id_bytes = [0u8; 32];
        let password_bytes = self.password.as_bytes();
        let copy_len = password_bytes.len().min(32);
        h_id_bytes[..copy_len].copy_from_slice(&password_bytes[..copy_len]);

        let h_id = Scalar::from_bytes_mod_order(h_id_bytes);
        let com = commit(h_id, hash_to_scalar(att.clone()), r, self.public_params.clone());
        (com, r)
    }

    // Launch with RSA-OAEP encryption (DKIM variant)
    pub fn launch_dkim(&self, att: String, agent_public_key: &RsaPublicKey) -> (Vec<u8>, Vec<u8>) {
        let mut csprng = OsRng;
        let r = Scalar::random(&mut csprng);

        let params = Params::new(65536, 3, 4, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut salt = [0u8; 16];
        salt[..4].copy_from_slice(&self.id.to_le_bytes());
        let mut h_id_bytes = [0u8; 32];
        argon2.hash_password_into(self.password.as_bytes(), &salt, &mut h_id_bytes).unwrap();

        let h_id = Scalar::from_bytes_mod_order(h_id_bytes);
        let com = commit(h_id, hash_to_scalar(att.clone()), r, self.public_params.clone());

        let padding = Oaep::new::<sha2::Sha256>();
        let att_bytes = att.as_bytes();
        let encrypted_att = agent_public_key.encrypt(&mut csprng, padding, att_bytes).unwrap();

        let padding = Oaep::new::<sha2::Sha256>();
        let r_bytes = r.to_bytes();
        let encrypted_r = agent_public_key.encrypt(&mut csprng, padding, &r_bytes).unwrap();

        (encrypted_att, encrypted_r)
    }

    // Enrollment with SHA256 instead of Argon2
    pub fn enroll_sha256(&self) -> ((i32, RistrettoPoint), (Scalar, Scalar)) {
        let mut csprng = OsRng;
        let r_id = Scalar::random(&mut csprng);

        let mut hasher = Sha256::new();
        hasher.update(self.password.as_bytes());
        let h_id_hash = hasher.finalize();

        let h_id = Scalar::from_bytes_mod_order(h_id_hash.as_slice().try_into().unwrap());
        let com_id = commit(h_id, Scalar::ZERO, r_id, self.public_params.clone());
        let contract = (self.id, com_id);
        let s_a = (h_id, r_id);
        (contract, s_a)
    }

    // Launch with SHA256 instead of Argon2
    pub fn launch_sha256(&self, att: String) -> (RistrettoPoint, Scalar) {
        let mut csprng = OsRng;
        let r = Scalar::random(&mut csprng);

        let mut hasher = Sha256::new();
        hasher.update(self.password.as_bytes());
        let h_id_hash = hasher.finalize();

        let h_id = Scalar::from_bytes_mod_order(h_id_hash.as_slice().try_into().unwrap());
        let com = commit(h_id, hash_to_scalar(att.clone()), r, self.public_params.clone());
        (com, r)
    }

    // Launch DKIM variant with SHA256 instead of Argon2
    pub fn launch_dkim_sha256(&self, att: String, agent_public_key: &RsaPublicKey) -> (Vec<u8>, Vec<u8>) {
        let mut csprng = OsRng;
        let r = Scalar::random(&mut csprng);

        let mut hasher = Sha256::new();
        hasher.update(self.password.as_bytes());
        let h_id_hash = hasher.finalize();

        let h_id = Scalar::from_bytes_mod_order(h_id_hash.as_slice().try_into().unwrap());
        let com = commit(h_id, hash_to_scalar(att.clone()), r, self.public_params.clone());

        let padding = Oaep::new::<sha2::Sha256>();
        let att_bytes = att.as_bytes();
        let encrypted_att = agent_public_key.encrypt(&mut csprng, padding, att_bytes).unwrap();

        let padding = Oaep::new::<sha2::Sha256>();
        let r_bytes = r.to_bytes();
        let encrypted_r = agent_public_key.encrypt(&mut csprng, padding, &r_bytes).unwrap();

        (encrypted_att, encrypted_r)
    }

}

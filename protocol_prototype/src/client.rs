use curve25519_dalek::{ristretto::RistrettoBasepointTable, scalar::Scalar, RistrettoPoint};
use rand_core::OsRng;
use hex;
use sha2::{Digest, Sha256};
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
        let mut hasher = Sha256::new();  
        hasher.update(self.password.as_bytes());  
        let h_id = hasher.finalize(); 
        //println!("Enrolled client with ID: {}", hex::encode(r_id.as_bytes()));
        //println!("Password hash: {}", hex::encode(h_id));
        let h_id = Scalar::from_bytes_mod_order(h_id.as_slice().try_into().unwrap());
        let com_id = commit(h_id, Scalar::ZERO, r_id, self.public_params.clone());
        //println!("Com_id: {}", hex::encode(com_id.compress().as_bytes()));
        let contract = (self.id, com_id);
        let s_a = (h_id, r_id);
        (contract, s_a)
    }

    pub fn launch(&self, att: String) -> (RistrettoPoint, Scalar) {
        let mut csprng = OsRng;
        let r = Scalar::random(&mut csprng);
        let h_id = hash_to_scalar(self.password.clone());
        //let h_id = Scalar::from_bytes_mod_order(h_id.as_slice().try_into().unwrap());
        let com = commit(h_id, hash_to_scalar(att.clone()), r, self.public_params.clone());
        //println!("Com: {}", hex::encode(com.compress().as_bytes()));
        (com, r)
    }   
    pub fn generate_request(&self) -> String {
        // Implement request generation logic
        format!("Client Request: ID={}, Login={}", self.id, self.login)
    }

    pub fn process_result(&self, result: &str) -> String {
        // Implement result processing logic
        format!("Processed Result for Client ID {}: {}", self.id, result)
    }
}
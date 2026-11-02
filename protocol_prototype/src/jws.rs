use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::signature::{Keypair as _, SignatureEncoding, Signer as _, Verifier as _};
use serde_json::Value;
use sha2::Sha256;

pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwsAlg {
    Rs256,
    EdDsa,
    Es256,
}

// A signing key for one of the supported JWS algorithms.
pub enum JwsSigner {
    Rs256(rsa::pkcs1v15::SigningKey<Sha256>),
    EdDsa(ed25519_dalek::SigningKey),
    Es256(p256::ecdsa::SigningKey),
}

// A verification key for one of the supported JWS algorithms.
#[derive(Clone)]
pub enum JwsVerifier {
    Rs256(rsa::pkcs1v15::VerifyingKey<Sha256>),
    EdDsa(ed25519_dalek::VerifyingKey),
    Es256(p256::ecdsa::VerifyingKey),
}

impl JwsSigner {
    // Generates a fresh key: RSA-2048, Ed25519 or P-256.
    pub fn generate(alg: JwsAlg) -> JwsSigner {
        match alg {
            JwsAlg::Rs256 => {
                let sk = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
                JwsSigner::Rs256(rsa::pkcs1v15::SigningKey::new(sk))
            }
            JwsAlg::EdDsa => JwsSigner::EdDsa(ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng)),
            JwsAlg::Es256 => JwsSigner::Es256(p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)),
        }
    }

    pub fn alg(&self) -> &'static str {
        match self {
            JwsSigner::Rs256(_) => "RS256",
            JwsSigner::EdDsa(_) => "EdDSA",
            JwsSigner::Es256(_) => "ES256",
        }
    }

    pub fn verifier(&self) -> JwsVerifier {
        match self {
            JwsSigner::Rs256(k) => JwsVerifier::Rs256(k.verifying_key()),
            JwsSigner::EdDsa(k) => JwsVerifier::EdDsa(k.verifying_key()),
            JwsSigner::Es256(k) => JwsVerifier::Es256(*k.verifying_key()),
        }
    }

    // Raw signature over `signing_input` in the JWS encoding (PKCS#1 v1.5
    // octet string, Ed25519 64 bytes, or ECDSA `r || s` 64 bytes).
    pub fn sign_raw(&self, signing_input: &[u8]) -> Vec<u8> {
        match self {
            JwsSigner::Rs256(k) => k.sign(signing_input).to_bytes().to_vec(),
            JwsSigner::EdDsa(k) => k.sign(signing_input).to_bytes().to_vec(),
            JwsSigner::Es256(k) => {
                let sig: p256::ecdsa::Signature = k.sign(signing_input);
                sig.to_bytes().to_vec()
            }
        }
    }

    // Produces a compact JWS `b64(header).b64(payload).b64(signature)`.
    // `extra_header` entries (e.g. `typ`, `kid`) are merged into the header.
    pub fn sign_compact(&self, payload: &Value, extra_header: &[(&str, &str)]) -> String {
        let mut header = serde_json::Map::new();
        header.insert("alg".into(), Value::String(self.alg().into()));
        for (k, v) in extra_header {
            header.insert((*k).into(), Value::String((*v).into()));
        }
        let header = Value::Object(header);
        let h = b64url(serde_json::to_string(&header).unwrap().as_bytes());
        let p = b64url(serde_json::to_string(payload).unwrap().as_bytes());
        let mut token = String::with_capacity(h.len() + p.len() + 400);
        token.push_str(&h);
        token.push('.');
        token.push_str(&p);
        let sig = self.sign_raw(token.as_bytes());
        token.push('.');
        token.push_str(&b64url(&sig));
        token
    }
}

impl JwsVerifier {
    pub fn alg(&self) -> &'static str {
        match self {
            JwsVerifier::Rs256(_) => "RS256",
            JwsVerifier::EdDsa(_) => "EdDSA",
            JwsVerifier::Es256(_) => "ES256",
        }
    }

    pub fn verify_raw(&self, signing_input: &[u8], sig: &[u8]) -> bool {
        match self {
            JwsVerifier::Rs256(k) => match rsa::pkcs1v15::Signature::try_from(sig) {
                Ok(s) => k.verify(signing_input, &s).is_ok(),
                Err(_) => false,
            },
            JwsVerifier::EdDsa(k) => match ed25519_dalek::Signature::from_slice(sig) {
                Ok(s) => k.verify(signing_input, &s).is_ok(),
                Err(_) => false,
            },
            JwsVerifier::Es256(k) => match p256::ecdsa::Signature::from_slice(sig) {
                Ok(s) => k.verify(signing_input, &s).is_ok(),
                Err(_) => false,
            },
        }
    }

    // Public key as a JWK (RFC 7517) value, used for the `cnf` claim of an
    // SD-JWT VC and for cross-checking with other JWT libraries.
    pub fn to_jwk(&self) -> Value {
        match self {
            JwsVerifier::Rs256(k) => {
                use rsa::traits::PublicKeyParts;
                let pk = k.as_ref();
                serde_json::json!({
                    "kty": "RSA",
                    "n": b64url(&pk.n().to_bytes_be()),
                    "e": b64url(&pk.e().to_bytes_be()),
                })
            }
            JwsVerifier::EdDsa(k) => serde_json::json!({
                "kty": "OKP", "crv": "Ed25519", "x": b64url(k.as_bytes()),
            }),
            JwsVerifier::Es256(k) => {
                let p = k.to_encoded_point(false);
                serde_json::json!({
                    "kty": "EC", "crv": "P-256",
                    "x": b64url(p.x().unwrap()),
                    "y": b64url(p.y().unwrap()),
                })
            }
        }
    }

    // Parses a JWK produced by [`JwsVerifier::to_jwk`].
    pub fn from_jwk(jwk: &Value) -> Option<JwsVerifier> {
        match jwk.get("kty")?.as_str()? {
            "EC" => {
                let x = b64url_decode(jwk.get("x")?.as_str()?)?;
                let y = b64url_decode(jwk.get("y")?.as_str()?)?;
                let mut sec1 = Vec::with_capacity(65);
                sec1.push(0x04);
                sec1.extend_from_slice(&x);
                sec1.extend_from_slice(&y);
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).ok().map(JwsVerifier::Es256)
            }
            "OKP" => {
                let x = b64url_decode(jwk.get("x")?.as_str()?)?;
                let arr: [u8; 32] = x.try_into().ok()?;
                ed25519_dalek::VerifyingKey::from_bytes(&arr).ok().map(JwsVerifier::EdDsa)
            }
            "RSA" => {
                let n = b64url_decode(jwk.get("n")?.as_str()?)?;
                let e = b64url_decode(jwk.get("e")?.as_str()?)?;
                let pk = rsa::RsaPublicKey::new(
                    rsa::BigUint::from_bytes_be(&n),
                    rsa::BigUint::from_bytes_be(&e),
                )
                .ok()?;
                Some(JwsVerifier::Rs256(rsa::pkcs1v15::VerifyingKey::new(pk)))
            }
            _ => None,
        }
    }
}

// A parsed compact JWS whose signature has NOT yet been checked.
pub struct ParsedJws<'a> {
    pub header: Value,
    pub payload: Value,
    pub signing_input: &'a str,
    pub signature: Vec<u8>,
}

// Splits and decodes a compact JWS.  Returns `None` on any format error.
pub fn parse_compact(token: &str) -> Option<ParsedJws<'_>> {
    let mut parts = token.splitn(3, '.');
    let h = parts.next()?;
    let p = parts.next()?;
    let s = parts.next()?;
    if s.contains('.') {
        return None;
    }
    let header: Value = serde_json::from_slice(&b64url_decode(h)?).ok()?;
    let payload: Value = serde_json::from_slice(&b64url_decode(p)?).ok()?;
    let signature = b64url_decode(s)?;
    let signing_input = &token[..h.len() + 1 + p.len()];
    Some(ParsedJws { header, payload, signing_input, signature })
}

// Parses a compact JWS and verifies its signature under `key`; the `alg`
// header must match the key's algorithm (no algorithm confusion).
pub fn verify_compact<'a>(token: &'a str, key: &JwsVerifier) -> Option<ParsedJws<'a>> {
    let jws = parse_compact(token)?;
    if jws.header.get("alg")?.as_str()? != key.alg() {
        return None;
    }
    if !key.verify_raw(jws.signing_input.as_bytes(), &jws.signature) {
        return None;
    }
    Some(jws)
}

use crate::consent::{agent_core, verify_core, AgentSecret, Proof};
use crate::utils::PublicParams;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use viadkim::crypto::{HashAlgorithm, SigningKey};
use viadkim::header::HeaderFields;
use viadkim::signer::{Expiration, SignRequest, Signer};
use viadkim::verifier::{Config, LookupTxt, VerificationStatus};
use viadkim::{DomainName, Selector, SigningAlgorithm};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DkimAlg {
    RsaSha256,
    Ed25519Sha256,
}

// The email provider (the IdM).
pub struct EmailProvider {
    pub domain: String,
    pub selector: String,
    key: SigningKey,
    algorithm: SigningAlgorithm,
    // The `selector._domainkey.domain` TXT record a verifier would fetch.
    pub key_record: String,
    runtime: tokio::runtime::Runtime,
}

impl EmailProvider {
    pub fn new(domain: &str, selector: &str, alg: DkimAlg) -> EmailProvider {
        let (key, key_record, algorithm) = match alg {
            DkimAlg::RsaSha256 => {
                let sk = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
                let spki = RsaPublicKey::from(&sk).to_public_key_der().unwrap();
                let record = format!("v=DKIM1; k=rsa; p={}", B64.encode(spki.as_bytes()));
                let pem = sk.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
                (SigningKey::from_pkcs8_pem(&pem).unwrap(), record, SigningAlgorithm::RsaSha256)
            }
            DkimAlg::Ed25519Sha256 => {
                let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
                let record = format!("v=DKIM1; k=ed25519; p={}", B64.encode(sk.verifying_key().as_bytes()));
                let pem = sk.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
                (SigningKey::from_pkcs8_pem(&pem).unwrap(), record, SigningAlgorithm::Ed25519Sha256)
            }
        };
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        EmailProvider { domain: domain.into(), selector: selector.into(), key, algorithm, key_record, runtime }
    }

    // `IdM.Query`: DKIM-sign the message.  Returns the `DKIM-Signature`
    // header line (with trailing CRLF) to prepend to the message header.
    pub fn sign(&self, header: &HeaderFields, body: &[u8]) -> String {
        debug_assert_eq!(SigningAlgorithm::from_parts(self.key.key_type(), HashAlgorithm::Sha256), Some(self.algorithm));
        let mut request = SignRequest::new(
            DomainName::new(self.domain.as_str()).unwrap(),
            Selector::new(self.selector.as_str()).unwrap(),
            self.algorithm,
            &self.key,
        );
        request.expiration = Expiration::Never;
        let mut signer = Signer::prepare_signing(header.clone(), [request]).unwrap();
        let _ = signer.process_body_chunk(body);
        let results = self.runtime.block_on(signer.sign());
        let output = results.into_iter().next().unwrap().unwrap();
        let mut line = output.format_header().to_string();
        line.push_str("\r\n");
        line
    }
}

// An in-memory stand-in for the DNS TXT lookup of the provider's key.
#[derive(Clone)]
pub struct StaticKeyLookup {
    pub records: Arc<Vec<(String, String)>>, // (fqdn with trailing dot, record)
}

impl LookupTxt for StaticKeyLookup {
    type Answer = Vec<io::Result<Vec<u8>>>;
    type Query<'a> = Pin<Box<dyn Future<Output = io::Result<Self::Answer>> + Send + 'a>>;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
        let domain = domain.to_owned();
        Box::pin(async move {
            match self.records.iter().find(|(d, _)| *d == domain) {
                Some((_, rec)) => Ok(vec![Ok(rec.as_bytes().to_vec())]),
                None => Err(io::Error::from(io::ErrorKind::NotFound)),
            }
        })
    }
}

// A DKIM verifier bound to one provider's key record.
pub struct DkimVerifier {
    lookup: StaticKeyLookup,
    config: Config,
    runtime: tokio::runtime::Runtime,
}

impl DkimVerifier {
    pub fn new(provider: &EmailProvider) -> DkimVerifier {
        let fqdn = format!("{}._domainkey.{}.", provider.selector, provider.domain);
        let lookup = StaticKeyLookup { records: Arc::new(vec![(fqdn, provider.key_record.clone())]) };
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        DkimVerifier { lookup, config: Config::default(), runtime }
    }

    // Returns true iff the message carries at least one passing DKIM
    // signature for `domain`.
    pub fn verify(&self, header: &HeaderFields, body: &[u8], domain: &str) -> bool {
        let results = self.runtime.block_on(viadkim::verify(&self.lookup, header, body, &self.config));
        results.iter().any(|r| {
            r.status == VerificationStatus::Success
                && r.signature.as_ref().map(|s| s.domain.to_string().eq_ignore_ascii_case(domain)).unwrap_or(false)
        })
    }
}

// The email the Client composes.  Body: `com` (hex) and the ciphertext
// (base64).  Returns the header block (CRLF-separated, parseable by viadkim)
// and the body bytes.
pub fn compose_email(from: &str, to: &str, com: &RistrettoPoint, ciphertext: &[u8]) -> (String, Vec<u8>) {
    let header = format!(
        "From: {from}\r\nTo: {to}\r\nSubject: Consent request\r\nDate: Mon, 09 Nov 2025 12:00:00 +0000\r\n"
    );
    let body = format!(
        "com={}\r\nconsent={}\r\n",
        hex::encode(com.compress().as_bytes()),
        B64.encode(ciphertext)
    );
    (header, body.into_bytes())
}

// The Client encrypts `(ref, att, r)` for the Agent with RSA-2048-OAEP-SHA256.
pub fn encrypt_order(agent_pk: &RsaPublicKey, reference: &[u8], att: &str, r: Scalar) -> Vec<u8> {
    assert_eq!(reference.len(), 16, "ref is a 16-byte reference");
    let mut plain = Vec::with_capacity(16 + att.len() + 32);
    plain.extend_from_slice(reference);
    plain.extend_from_slice(att.as_bytes());
    plain.extend_from_slice(&r.to_bytes());
    agent_pk.encrypt(&mut rand::rngs::OsRng, Oaep::new::<Sha256>(), &plain).unwrap()
}

// The Agent decrypts `(ref, att, r)`.
pub fn decrypt_order(agent_sk: &RsaPrivateKey, ciphertext: &[u8]) -> Option<([u8; 16], String, Scalar)> {
    let plain = agent_sk.decrypt(Oaep::new::<Sha256>(), ciphertext).ok()?;
    if plain.len() < 16 + 32 {
        return None;
    }
    let reference: [u8; 16] = plain[..16].try_into().ok()?;
    let r_bytes: [u8; 32] = plain[plain.len() - 32..].try_into().ok()?;
    let att = String::from_utf8(plain[16..plain.len() - 32].to_vec()).ok()?;
    let r = Option::from(Scalar::from_canonical_bytes(r_bytes))?;
    Some((reference, att, r))
}

// Extracts `com` and the ciphertext from a composed body.
pub fn parse_body(body: &[u8]) -> Option<(RistrettoPoint, Vec<u8>)> {
    let text = std::str::from_utf8(body).ok()?;
    let mut com = None;
    let mut ct = None;
    for line in text.lines() {
        if let Some(h) = line.strip_prefix("com=") {
            let bytes: [u8; 32] = hex::decode(h).ok()?.try_into().ok()?;
            com = CompressedRistretto::from_slice(&bytes).ok()?.decompress();
        } else if let Some(b) = line.strip_prefix("consent=") {
            ct = Some(B64.decode(b).ok()?);
        }
    }
    Some((com?, ct?))
}

fn from_address(header: &HeaderFields) -> Option<String> {
    let fields: &[viadkim::header::HeaderField] = header.as_ref();
    fields
        .iter()
        .find(|(name, _)| AsRef::<str>::as_ref(name).eq_ignore_ascii_case("From"))
        .and_then(|(_, body)| std::str::from_utf8(AsRef::<[u8]>::as_ref(body)).ok())
        .map(|s| s.trim().to_string())
}

// `contract` for the DKIM variant: `ID` is the client's email address and
// `pk_IdM` is the provider's key record.
#[derive(Clone)]
pub struct DkimContract {
    pub id: String,
    pub com_id: RistrettoPoint,
    pub provider_domain: String,
    pub agent_address: String,
}

// `order`: the DKIM-signed email.  `att` and `r` are inside the ciphertext.
pub struct DkimOrder {
    pub header: HeaderFields,
    pub body: Vec<u8>,
}

pub struct DkimConsent {
    pub header: HeaderFields,
    pub body: Vec<u8>,
    pub com: RistrettoPoint,
    pub proof: Proof,
}

// `Σ.Verify` for an email: DKIM passes for the provider's domain and the
// signed From field is `ID`.
pub fn verify_email(verifier: &DkimVerifier, contract: &DkimContract, header: &HeaderFields, body: &[u8]) -> bool {
    from_address(header).as_deref() == Some(contract.id.as_str())
        && verifier.verify(header, body, &contract.provider_domain)
}

// `Agent.Receive`: decrypt `(ref, att, r)`, verify DKIM, check `com`, prove.
// Returns the consent together with the recovered `att`.
pub fn agent_receive(
    s_a: &AgentSecret,
    contract: &DkimContract,
    verifier: &DkimVerifier,
    agent_sk: &RsaPrivateKey,
    order: &DkimOrder,
    pp: &PublicParams,
) -> Option<(DkimConsent, String)> {
    let (com, ciphertext) = parse_body(&order.body)?;
    let (_reference, att, r) = decrypt_order(agent_sk, &ciphertext)?;
    if !verify_email(verifier, contract, &order.header, &order.body) {
        return None;
    }
    let proof = agent_core(s_a, contract.com_id, com, &att, r, pp)?;
    Some((DkimConsent { header: order.header.clone(), body: order.body.clone(), com, proof }, att))
}

// `Verify`.
pub fn verify_consent(verifier: &DkimVerifier, contract: &DkimContract, att: &str, consent: &DkimConsent, pp: &PublicParams) -> bool {
    match parse_body(&consent.body) {
        Some((com, _)) if com == consent.com => {}
        _ => return false,
    }
    verify_email(verifier, contract, &consent.header, &consent.body)
        && verify_core(contract.com_id, consent.com, att, &consent.proof, pp)
}

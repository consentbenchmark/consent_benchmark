## Cryptographically Secure Digital Consent

To match the rust version used in measurements, run:
```
rustup default 1.91.0
```

To run the benchmarks:
```
cd protocol_prototype
cargo bench
```

Benchmark names are `<step>_<variant>` with steps `client_enroll`, `client_launch`,
`idm`, `agent` and `consent_verify`, and variants `oidc_eddsa`, `oidc_rs256`,
`ctap_eddsa`, `ctap_es256`, `oid4vp_eddsa`, `oid4vp_es256`, `dkim_ed25519`,
`dkim_rsa` and `no_idm`. The `_sha256` suffix on the client steps replaces
Argon2id by SHA256 as the password hash.

# Reqwest TLS + Proxy Demo (Rust + Tokio)

A small, well-documented CLI demonstrating:

- Explicit proxy via `--proxy URL` (HTTP/HTTPS).
- Mutual TLS (mTLS) with PEM client certificate and key.
- Optional TLS pinning: SPKI or full certificate SHA-256.
- Verbose server certificate details when pinning is not enabled.
- Progress display and session stats (TTFB, total time, bytes, throughput).

Built with `reqwest` over `rustls` and `tokio`.

## Install & Run

```bash
# Build
cargo build

# Help
cargo run -- --help

# Simple request
cargo run -- https://example.com

# With proxy
cargo run -- https://example.com --proxy http://localhost:8080

# With additional CA
cargo run -- https://example.com --ca-cert ./my-ca.pem

# mTLS (PEM pair)
cargo run -- https://mtls.example.com \
  --client-cert ./client.crt.pem \
  --client-key ./client.key.pem

# TLS pinning (SPKI hash base64)
# Derive SPKI hash from server cert (see below), then:
cargo run -- https://example.com --tls-pin "<base64>" --pin-type spki

# TLS pinning (full certificate hash, base64 or hex)
cargo run -- https://example.com --tls-pin "<base64|hex>" --pin-type cert

# Show more logs
cargo run -- https://example.com -v
```

## TLS Pinning: Deriving Hashes

Using OpenSSL to fetch and compute hashes from a server's leaf certificate:

```bash
# Fetch leaf certificate in PEM
openssl s_client -connect example.com:443 -servername example.com < /dev/null \
  | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > leaf.pem

# Full certificate SHA-256 (base64)
openssl x509 -in leaf.pem -outform DER | openssl sha256 -binary | openssl base64 -A

# SPKI SHA-256 (base64)
openssl x509 -in leaf.pem -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | openssl sha256 -binary | openssl base64 -A
```

Provide the resulting base64 string to `--tls-pin`. Hex is also accepted for `--pin-type cert`.

## Generating a Client PEM Pair (for mTLS)

```bash
# Generate a private key (PKCS#8, unencrypted)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client.key.pem

# Create a certificate signing request (CSR)
openssl req -new -key client.key.pem -out client.csr -subj "/CN=demo-client"

# Self-sign for demo (or have a CA sign it)
openssl x509 -req -in client.csr -signkey client.key.pem -days 365 -out client.crt.pem
```

Note: Encrypted keys are not supported in this demo.

## What the App Prints

- When pinning is disabled, it prints certificate subject, issuer, validity, SANs, and SPKI/cert hashes (base64).
- During download, it prints periodic progress with bytes and rough rate.
- At the end, it prints a summary: status, HTTP version, TTFB, total time, bytes, throughput.

## Design Notes

- Uses a custom rustls `ServerCertVerifier` to both (a) extract cert details for display and (b) enforce pinning when requested.
- Uses system roots (webpki) plus `--ca-cert` if supplied.
- Optional client auth by providing `--client-cert` and `--client-key` (PEM files).
- Proxy is configured explicitly via `--proxy` using reqwest's `Proxy::all`.

## Development

- Format: `cargo fmt`
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Test: `cargo test`

## Caveats

- DNS/connect/TLS phase timing is not broken out; TTFB and total time are shown.
- TLS version/cipher are not displayed; reqwest doesn't expose them directly through the stable API.
- Do not use `--insecure` outside of controlled demos.

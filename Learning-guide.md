# Learning Guide: HTTP Clients with Proxy, TLS, and Certificate Pinning in Rust

This guide provides a comprehensive reference for building HTTP clients in Rust using reqwest with advanced TLS features including proxy support, mutual TLS authentication, certificate inspection, and certificate pinning.

## Prerequisites

- Intermediate Rust knowledge (async/await, Result types, traits)
- Basic understanding of HTTP and HTTPS
- Familiarity with tokio async runtime
- Basic PKI concepts (certificates, private keys)

**Key Dependencies:**
- reqwest 0.12+ with rustls-tls feature
- rustls 0.23+
- tokio 1.0+ with runtime features
- tokio-rustls for direct TLS operations

---

## Part I: Overview & Core Concepts

### Introduction

Modern Rust HTTP clients require careful configuration when operating in enterprise environments or security-sensitive contexts. This guide addresses:

- **Proxy Configuration:** Routing traffic through HTTP/HTTPS proxies
- **Custom Trust Stores:** Adding internal or self-signed CAs
- **Mutual TLS (mTLS):** Client certificate authentication
- **Certificate Inspection:** Extracting and validating certificate properties
- **Certificate Pinning:** Enforcing specific certificates or public keys

This document focuses on **what these features are** (reference) and **why they matter** (explanation), not step-by-step project setup.

### Understanding the TLS Stack in Rust

#### TLS Backend Options

Rust offers two primary TLS backends for HTTP clients:

| Backend | Description | Trade-offs |
|---------|-------------|------------|
| **rustls** | Pure-Rust TLS implementation | Memory-safe, no C dependencies, modern protocols only (TLS 1.2+), smaller attack surface |
| **native-tls** | Platform TLS (OpenSSL/SChannel/Security.framework) | System certificate stores, legacy protocol support, platform-dependent behavior |

**Why rustls:** This guide focuses on rustls because:
- Memory safety guarantees (no C dependencies)
- Consistent behavior across platforms
- Modern TLS 1.2/1.3 only (removes legacy attack vectors)
- Fine-grained control via Rust APIs

#### Certificate Verification Flow

When an HTTPS connection is established:

1. **Handshake:** Client and server negotiate protocol version and cipher suite
2. **Server presents certificate chain:** Leaf certificate + intermediates
3. **Verification:** Client validates:
   - Certificate signature (signed by trusted CA)
   - Hostname matches certificate's Subject Alternative Names (SANs)
   - Certificate is within validity period
   - Chain of trust to a root CA in the trust store
4. **Custom verification:** Optional additional checks (pinning, policies)

#### Trust Stores

A **trust store** is a collection of trusted root CA certificates. By default:
- rustls uses **webpki-roots** (Mozilla's root CA program) or system roots via rustls-native-certs
- Additional CAs can be added for internal PKI or testing

**Trust precedence:**
1. System/bundled roots (default)
2. Custom roots added via add_root_certificate()
3. Both are combined (union, not replacement)

---

## Part II: Building HTTP Clients with reqwest

### Basic reqwest Client Configuration

The reqwest::ClientBuilder provides a fluent API for configuring HTTP clients.

#### Essential Configuration

```rust
use reqwest::{Client, ClientBuilder};
use std::time::Duration;

let client = ClientBuilder::new()
    .timeout(Duration::from_secs(30))              // Overall request timeout
    .connect_timeout(Duration::from_secs(10))      // TCP connection timeout
    .redirect(reqwest::redirect::Policy::limited(10)) // Follow up to 10 redirects
    .http2_adaptive_window(true)                   // Optimize HTTP/2 flow control
    .http2_keep_alive_timeout(Duration::from_secs(30))
    .pool_max_idle_per_host(2)                     // Connection pool size
    .build()?;
```

#### Key Settings Reference

| Method | Purpose | Default |
|--------|---------|---------|
| timeout(Duration) | Total request timeout (DNS + connect + transfer) | None (no timeout) |
| connect_timeout(Duration) | TCP connection establishment timeout | None |
| pool_max_idle_per_host(usize) | Max idle connections per host | Platform-dependent |
| redirect(Policy) | Redirect handling (none(), limited(n), custom()) | limited(10) |
| http2_adaptive_window(bool) | Enable HTTP/2 adaptive flow control | false |
| http2_keep_alive_timeout(Duration) | HTTP/2 ping interval | None |
| danger_accept_invalid_certs(bool) | **DANGEROUS:** Skip certificate verification | false |

**Why timeouts matter:** Without timeouts, clients can hang indefinitely on network issues. Set conservative timeouts and handle errors gracefully.

**Connection pooling:** reqwest reuses TCP connections to improve performance. Tune pool_max_idle_per_host based on expected concurrency.

### Proxy Configuration

#### HTTP/HTTPS Proxies

Proxies route requests through an intermediary server. Common use cases:
- Corporate networks requiring traffic inspection
- Load balancing or caching
- IP address masking

```rust
use reqwest::{Client, ClientBuilder, Proxy};

// Explicit proxy for all requests
let client = ClientBuilder::new()
    .proxy(Proxy::all("http://proxy.example.com:8080")?)
    .build()?;

// Separate proxies by protocol
let client = ClientBuilder::new()
    .proxy(Proxy::http("http://proxy.example.com:8080")?)
    .proxy(Proxy::https("https://secure-proxy.example.com:8443")?)
    .build()?;
```

#### Proxy API Reference

| Method | Behavior |
|--------|----------|
| Proxy::all(url) | Use proxy for HTTP and HTTPS |
| Proxy::http(url) | Use proxy only for HTTP requests |
| Proxy::https(url) | Use proxy only for HTTPS requests |
| proxy.basic_auth(user, pass) | Add HTTP Basic authentication to proxy |

#### Environment Variables vs Explicit Configuration

reqwest respects standard environment variables:
- HTTP_PROXY / http_proxy: Proxy for HTTP requests
- HTTPS_PROXY / https_proxy: Proxy for HTTPS requests
- NO_PROXY / no_proxy: Comma-separated hosts to bypass proxy

**When to use explicit configuration:**
- Environment variables are unreliable or untrusted
- Different clients need different proxies in the same process
- Fine-grained control over proxy behavior

**When to use environment variables:**
- Standard deployment environments (containers, CI)
- User-configurable proxy settings
- Simpler code (reqwest reads automatically)

#### Proxy Authentication

```rust
let proxy = Proxy::all("http://proxy.example.com:8080")?
    .basic_auth("username", "password");

let client = ClientBuilder::new().proxy(proxy).build()?;
```

**Security consideration:** Avoid hardcoding credentials. Use environment variables or secret management systems.

---

## Part III: TLS Certificate Management

### Custom Root Certificates

#### When to Add Custom CAs

Add custom root certificates when:
- Connecting to internal services with enterprise PKI
- Testing with self-signed certificates
- Using private or air-gapped certificate authorities
- Regulatory requirements for specific trust stores

#### Loading PEM Certificates

```rust
use reqwest::{Certificate, ClientBuilder};
use std::fs;

// Load a custom CA certificate
let ca_cert_pem = fs::read("internal-ca.pem")?;
let ca_cert = Certificate::from_pem(&ca_cert_pem)?;

let client = ClientBuilder::new()
    .add_root_certificate(ca_cert)
    .build()?;
```

#### Multiple Custom CAs

```rust
let client = ClientBuilder::new()
    .add_root_certificate(Certificate::from_pem(&ca1_pem)?)
    .add_root_certificate(Certificate::from_pem(&ca2_pem)?)
    .build()?;
```

**Important:** add_root_certificate() **adds** to the trust store; it does not replace system roots. Both custom and system roots are trusted.

#### PEM Format

PEM (Privacy-Enhanced Mail) is a base64-encoded format with header/footer markers:

```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKJ... (base64 data)
-----END CERTIFICATE-----
```

**File extensions:** .pem, .crt, .cer (content matters, not extension).

### Mutual TLS (mTLS) Authentication

#### What is mTLS?

Mutual TLS extends standard TLS by requiring **both** client and server to present certificates. The server verifies the client's identity via its certificate.

**Use cases:**
- API authentication (alternative to API keys/tokens)
- Service-to-service communication in microservices
- Zero-trust architectures
- High-security environments (finance, healthcare)

**Trade-offs:**
- **Pros:** Strong cryptographic authentication, no credentials in requests, certificate-based access control
- **Cons:** Complex key management, certificate rotation overhead, debugging complexity

#### Client Certificate Formats

reqwest expects **PEM-encoded** client certificates and private keys.

```rust
use reqwest::{Identity, ClientBuilder};
use std::fs;

// Load client certificate and private key
let cert_pem = fs::read("client.crt.pem")?;
let key_pem = fs::read("client.key.pem")?;

// Combine into single PEM (cert + key)
let mut combined_pem = cert_pem.clone();
combined_pem.push(b'\n');
combined_pem.extend_from_slice(&key_pem);

let identity = Identity::from_pem(&combined_pem)?;

let client = ClientBuilder::new()
    .identity(identity)
    .build()?;
```

#### Supported Key Formats

| Format | Description | OpenSSL Generation |
|--------|-------------|-------------------|
| **PKCS#8** | Modern standard (unencrypted) | openssl genpkey -algorithm RSA |
| **RSA Private Key** | Legacy RSA format | openssl genrsa |
| **EC Private Key** | Elliptic curve keys | openssl ecparam -genkey |

**Note:** reqwest with rustls only supports **unencrypted** private keys. Encrypted keys (password-protected PEM) are not supported directly. Decrypt before loading or use a different approach.

#### Generating Test Certificates

```bash
# Generate private key (PKCS#8, unencrypted)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client.key.pem

# Create certificate signing request (CSR)
openssl req -new -key client.key.pem -out client.csr -subj "/CN=demo-client"

# Self-sign for testing (or send CSR to CA for production)
openssl x509 -req -in client.csr -signkey client.key.pem -days 365 -out client.crt.pem
```

---

## Part IV: Advanced TLS: Inspection and Pinning

### TLS Certificate Inspection

#### Why Inspect Certificates?

Certificate inspection serves several purposes:

1. **Learning & Debugging:** Understand what certificates servers present
2. **Validation:** Verify certificate properties before trusting
3. **Pinning Preparation:** Extract hashes for certificate pinning
4. **Compliance:** Log certificate details for audit trails

#### The Inspection Challenge

reqwest does not expose server certificates directly through its stable API. To inspect certificates, you must:

1. Perform a **separate TLS handshake** using tokio-rustls with a custom verifier
2. Capture certificate details during verification
3. Use the captured data for logging or pinning decisions

#### Custom ServerCertVerifier Pattern

rustls allows custom certificate verification via the ServerCertVerifier trait.

```rust
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified};
use rustls::pki_types::{CertificateDer, ServerName};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct InspectingVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    captured_cert: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ServerCertVerifier for InspectingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Capture certificate DER bytes
        *self.captured_cert.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        
        // Delegate to default verifier
        self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }
    
    // Delegate signature verification methods...
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
```

#### Implementing a TLS Probe

A **TLS probe** is a separate connection that performs a handshake solely to inspect the certificate, then closes.

```rust
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use rustls::{ClientConfig, RootCertStore};

async fn probe_tls(host: &str, port: u16) -> anyhow::Result<Vec<u8>> {
    // Build rustls config with custom verifier
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        roots.add(cert)?;
    }
    
    let default_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()?;
    
    let captured = Arc::new(Mutex::new(None));
    let verifier = InspectingVerifier {
        inner: default_verifier,
        captured_cert: captured.clone(),
    };
    
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    
    Arc::get_mut(&mut config)
        .unwrap()
        .dangerous()
        .set_certificate_verifier(Arc::new(verifier));
    
    // Connect and handshake
    let tcp = TcpStream::connect((host, port)).await?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_owned())?;
    let _tls = connector.connect(server_name, tcp).await?;
    
    // Extract captured certificate
    Ok(captured.lock().unwrap().clone().unwrap())
}
```

**Note:** This probe is **separate** from the reqwest client. It does not affect the actual HTTP request.

#### Extracting Certificate Details

Use x509-parser to parse captured DER-encoded certificates:

```rust
use x509_parser::prelude::*;

fn parse_cert_details(der: &[u8]) -> anyhow::Result<()> {
    let (_, cert) = parse_x509_certificate(der)?;
    
    println!("Subject: {}", format_rdn(cert.subject()));
    println!("Issuer: {}", format_rdn(cert.issuer()));
    println!("Not Before: {}", cert.validity().not_before.to_rfc2822()?);
    println!("Not After: {}", cert.validity().not_after.to_rfc2822()?);
    
    // Extract SANs
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in san.value.general_names {
            match name {
                GeneralName::DNSName(dns) => println!("SAN DNS: {}", dns),
                GeneralName::IPAddress(ip) => println!("SAN IP: {:?}", ip),
                _ => {}
            }
        }
    }
    
    Ok(())
}
```

### Certificate Pinning

#### What is Certificate Pinning?

**Certificate pinning** restricts which certificates are trusted, beyond standard CA verification. Instead of trusting any certificate signed by a trusted CA, pinning enforces:

- A specific certificate (full-cert pinning)
- A specific public key (SPKI pinning)

**When to use pinning:**
- Mobile apps connecting to known backend servers
- High-security environments with known infrastructure
- Mitigating compromised or malicious CAs
- Regulatory requirements for specific trust models

**When NOT to use pinning:**
- Websites with frequent certificate rotation (operational complexity)
- Content from multiple origins (CDNs, third-party APIs)
- When certificate rotation is unpredictable
- Environments requiring emergency certificate changes

#### SPKI Pinning vs Full-Certificate Pinning

| Type | Pins | Rotation Impact | Recommended |
|------|------|-----------------|-------------|
| **SPKI (SubjectPublicKeyInfo)** | Public key only | Survives certificate renewal if key unchanged | ✅ **Preferred** |
| **Full Certificate** | Entire DER-encoded certificate | Breaks on any certificate change | Use only for short-lived deployments |

**SPKI pinning advantages:**
- Certificates can be renewed (new validity dates, updated SANs) without changing pins
- Supports key continuity across multiple certificates
- More operational flexibility

**Full-cert pinning risks:**
- Every certificate rotation requires updating clients
- Emergency re-keying (e.g., after private key compromise) requires client updates
- Higher operational burden

#### Deriving Pin Hashes

##### SPKI SHA-256 (Recommended)

```bash
# Extract server certificate
openssl s_client -connect example.com:443 -servername example.com < /dev/null \
  | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > cert.pem

# Compute SPKI SHA-256 (base64)
openssl x509 -in cert.pem -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | openssl sha256 -binary \
  | openssl base64 -A
```

**Output:** eW5J5bR6ksO8TYNO/wvZA+kXlrj2YqZsNk0NeNXFr8s= (example)

##### Full Certificate SHA-256

```bash
# Compute full certificate SHA-256 (base64)
openssl x509 -in cert.pem -outform DER \
  | openssl sha256 -binary \
  | openssl base64 -A
```

#### Implementing Pinning with Custom Verifier

```rust
#[derive(Debug)]
struct PinningVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    expected_spki_sha256: Vec<u8>,  // Expected SPKI hash
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Standard verification first
        self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
        
        // Additional pinning check
        let actual_spki_hash = compute_spki_sha256(end_entity.as_ref())?;
        
        if actual_spki_hash != self.expected_spki_sha256 {
            return Err(rustls::Error::General("Certificate pin mismatch".into()));
        }
        
        Ok(ServerCertVerified::assertion())
    }
    
    // ... delegate other methods ...
}

fn compute_spki_sha256(cert_der: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    use sha2::{Sha256, Digest};
    use x509_parser::prelude::*;
    
    let (_, cert) = parse_x509_certificate(cert_der)?;
    let spki = cert.tbs_certificate.subject_pki.subject_public_key.data;
    
    let mut hasher = Sha256::new();
    hasher.update(spki);
    Ok(hasher.finalize().to_vec())
}
```

#### Pin Rotation Strategy

Certificate pinning creates operational risk. Mitigate with:

1. **Pin multiple keys:** Include current + backup key
2. **Monitor expiration:** Alert well before certificates/keys expire
3. **Emergency rollback:** Maintain ability to push client updates quickly
4. **Gradual rollout:** Deploy new pins to subset of clients first
5. **Backup pins:** Pin both current and next-generation keys

```rust
struct PinningVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    allowed_pins: Vec<Vec<u8>>,  // Multiple acceptable SPKI hashes
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(&self, ...) -> Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(...)?;
        
        let actual_hash = compute_spki_sha256(end_entity.as_ref())?;
        
        if !self.allowed_pins.iter().any(|pin| pin == &actual_hash) {
            return Err(rustls::Error::General("No pin matched".into()));
        }
        
        Ok(ServerCertVerified::assertion())
    }
}
```

---

## Part V: Security Considerations

### Security Best Practices

#### Never Skip Verification in Production

```rust
// ❌ NEVER DO THIS IN PRODUCTION
let client = ClientBuilder::new()
    .danger_accept_invalid_certs(true)
    .build()?;
```

**Why this is dangerous:**
- Allows man-in-the-middle attacks
- Defeats the entire purpose of HTTPS
- Accepts expired, self-signed, or malicious certificates

**When it's acceptable:**
- Local development with self-signed certificates
- Automated testing in isolated environments
- Debugging TLS issues (temporarily, with extreme caution)

**Better alternatives:**
- Add self-signed CA to trust store via add_root_certificate()
- Use proper internal PKI for development
- Generate valid certificates for testing (Let's Encrypt, mkcert)

#### Handling Secrets

**Never hardcode credentials:**

```rust
// ❌ BAD
let proxy = Proxy::all("http://proxy.example.com:8080")?
    .basic_auth("admin", "password123");

// ✅ GOOD
let username = std::env::var("PROXY_USERNAME")?;
let password = std::env::var("PROXY_PASSWORD")?;
let proxy = Proxy::all("http://proxy.example.com:8080")?
    .basic_auth(&username, &password);
```

**Secret management best practices:**
- Use environment variables for configuration
- Integrate with secret stores (HashiCorp Vault, AWS Secrets Manager)
- Avoid logging secrets (sanitize error messages)
- Rotate credentials regularly
- Use short-lived tokens when possible

#### Certificate Expiration and Renewal

**Plan for certificate expiration:**
- Monitor certificate validity periods
- Automate renewal processes (Let's Encrypt ACME, cert-manager)
- Alert well before expiration (30+ days)
- Test renewal process regularly

**Handling expiration in code:**

```rust
use x509_parser::prelude::*;

fn check_cert_expiration(cert_der: &[u8]) -> anyhow::Result<()> {
    let (_, cert) = parse_x509_certificate(cert_der)?;
    let not_after = cert.validity().not_after;
    let now = std::time::SystemTime::now();
    
    // Warn if expiring within 30 days
    let thirty_days = std::time::Duration::from_secs(30 * 24 * 60 * 60);
    if not_after.timestamp() < (now + thirty_days).timestamp() {
        log::warn!("Certificate expires soon: {}", not_after);
    }
    
    Ok(())
}
```

#### Pinning Risks

**Operational risks of certificate pinning:**

1. **Outage during rotation:** If new certificate doesn't match pin, all clients fail
2. **Emergency re-keying:** Private key compromise requires emergency client updates
3. **Certificate authority changes:** Switching CAs requires pin updates
4. **Load balancer/CDN changes:** Infrastructure changes can break pins

**Mitigation strategies:**
- Pin multiple keys (current + backup)
- Implement gradual rollout for pin updates
- Maintain kill-switch to disable pinning remotely
- Monitor pin validation failures in production
- Document emergency procedures

### Error Handling

#### TLS Handshake Failures

Common TLS errors and their causes:

| Error | Likely Cause | Resolution |
|-------|--------------|------------|
| InvalidCertificate | Certificate validation failed | Check CA trust, hostname, expiration |
| UnknownIssuer | CA not in trust store | Add custom CA via add_root_certificate() |
| CertExpired | Certificate past validity period | Renew certificate on server |
| BadCertificate | Certificate format or signature invalid | Check certificate encoding, regenerate |
| HandshakeFailure | Protocol/cipher mismatch | Check TLS version, cipher suite support |

#### Certificate Validation Errors

```rust
match client.get("https://example.com").send().await {
    Ok(response) => { /* handle success */ },
    Err(e) if e.is_builder() => {
        eprintln!("Client configuration error: {}", e);
    },
    Err(e) if e.is_timeout() => {
        eprintln!("Request timeout: {}", e);
    },
    Err(e) if e.is_connect() => {
        eprintln!("Connection failed (possibly TLS): {}", e);
        // Check certificate validation, network connectivity
    },
    Err(e) => {
        eprintln!("Request failed: {}", e);
    }
}
```

#### Proxy Connection Issues

**Common proxy errors:**
- **407 Proxy Authentication Required:** Missing or invalid proxy credentials
- **Connection timeout:** Proxy unreachable or blocking traffic
- **SSL/TLS errors:** HTTPS proxy certificate validation failures

**Debugging proxy issues:**

```rust
// Test with verbose logging
env_logger::builder()
    .filter_level(log::LevelFilter::Debug)
    .init();

// reqwest will log connection attempts, proxy usage, TLS handshakes
```

#### Timeout vs Connection Errors

**Understanding timeout types:**

| Timeout | Meaning | Configuration |
|---------|---------|---------------|
| **Connect timeout** | TCP connection establishment failed | connect_timeout(Duration) |
| **Read timeout** | No data received within limit | Part of timeout(Duration) |
| **Overall timeout** | Entire request exceeded limit | timeout(Duration) |

**Best practice:** Set both connect and overall timeouts:

```rust
let client = ClientBuilder::new()
    .connect_timeout(Duration::from_secs(10))  // Fast-fail for dead hosts
    .timeout(Duration::from_secs(30))          // Reasonable for full request
    .build()?;
```

---

## Part VI: Reference Tables & Quick Lookup

### API Quick Reference

#### ClientBuilder Methods

| Method | Parameters | Purpose |
|--------|------------|---------|
| timeout(Duration) | Overall timeout | Total request time limit |
| connect_timeout(Duration) | Connection timeout | TCP handshake limit |
| proxy(Proxy) | Proxy config | Route traffic through proxy |
| add_root_certificate(Certificate) | CA certificate | Add custom trust anchor |
| identity(Identity) | Client cert + key | Enable mTLS |
| danger_accept_invalid_certs(bool) | Skip verification flag | **Disable cert validation (UNSAFE)** |
| redirect(Policy) | Redirect policy | Control redirect behavior |
| http2_adaptive_window(bool) | Enable adaptive flow | Optimize HTTP/2 performance |
| pool_max_idle_per_host(usize) | Pool size | Connection reuse limit |

#### Identity Methods

| Method | Parameters | Returns |
|--------|------------|---------|
| Identity::from_pem(&[u8]) | PEM bytes (cert + key) | Result<Identity> |
| Identity::from_pkcs12_der(&[u8], &str) | PKCS12 DER + password | Result<Identity> |

**Note:** from_pem() expects concatenated PEM (certificate followed by private key).

#### Certificate Methods

| Method | Parameters | Returns |
|--------|------------|---------|
| Certificate::from_pem(&[u8]) | PEM bytes | Result<Certificate> |
| Certificate::from_der(&[u8]) | DER bytes | Result<Certificate> |

### Common Error Types

| Error Type | Cause | Check |
|------------|-------|-------|
| reqwest::Error (builder) | Invalid client configuration | Review ClientBuilder calls |
| reqwest::Error (connect) | Network or TLS failure | Check connectivity, certificates |
| reqwest::Error (timeout) | Request exceeded timeout | Increase timeout or check server |
| reqwest::Error (redirect) | Too many redirects | Check redirect policy, server behavior |
| rustls::Error::InvalidCertificate | Cert validation failed | Verify CA trust, hostname, expiration |
| rustls::Error::General | Custom verifier rejection | Check custom verification logic |

### Certificate Format Cheatsheet

#### PEM Format

```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKJ...
...
-----END CERTIFICATE-----
```

**Characteristics:**
- Base64-encoded with headers/footers
- May contain multiple certificates (chain)
- Common extensions: .pem, .crt, .cer
- Human-readable (base64)

#### DER Format

- Binary encoding (ASN.1 DER)
- No headers/footers
- Single certificate per file
- Common extensions: .der, .cer
- Compact, not human-readable

#### Conversion

```bash
# PEM to DER
openssl x509 -in cert.pem -outform DER -out cert.der

# DER to PEM
openssl x509 -in cert.der -inform DER -outform PEM -out cert.pem
```

---

## Appendix: Certificate Operations

### Generating Test Certificates

#### Self-Signed CA

```bash
# Generate CA private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ca.key.pem

# Create self-signed CA certificate
openssl req -x509 -new -key ca.key.pem -days 3650 -out ca.crt.pem \
  -subj "/CN=Test CA/O=Example Org"
```

#### Server Certificate Signed by CA

```bash
# Generate server private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out server.key.pem

# Create CSR with SANs
openssl req -new -key server.key.pem -out server.csr \
  -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:*.example.com"

# Sign with CA
openssl x509 -req -in server.csr -CA ca.crt.pem -CAkey ca.key.pem \
  -CAcreateserial -days 365 -out server.crt.pem \
  -copy_extensions copy
```

#### Client Certificate for mTLS

```bash
# Generate client private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client.key.pem

# Create CSR
openssl req -new -key client.key.pem -out client.csr \
  -subj "/CN=client-1234"

# Sign with CA
openssl x509 -req -in client.csr -CA ca.crt.pem -CAkey ca.key.pem \
  -CAcreateserial -days 365 -out client.crt.pem
```

### Extracting Certificate Information

#### View Certificate Details

```bash
# From PEM file
openssl x509 -in cert.pem -noout -text

# From remote server
openssl s_client -connect example.com:443 -servername example.com < /dev/null \
  | openssl x509 -noout -text
```

#### Extract Specific Fields

```bash
# Subject
openssl x509 -in cert.pem -noout -subject

# Issuer
openssl x509 -in cert.pem -noout -issuer

# Validity dates
openssl x509 -in cert.pem -noout -dates

# Subject Alternative Names
openssl x509 -in cert.pem -noout -ext subjectAltName

# Public key
openssl x509 -in cert.pem -noout -pubkey
```

### Computing Hashes

#### SPKI SHA-256 (for Pinning)

```bash
# From certificate file
openssl x509 -in cert.pem -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | openssl sha256 -binary \
  | openssl base64 -A

# From remote server
openssl s_client -connect example.com:443 -servername example.com < /dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl sha256 -binary \
  | openssl base64 -A
```

#### Full Certificate SHA-256

```bash
# From certificate file
openssl x509 -in cert.pem -outform DER \
  | openssl sha256 -binary \
  | openssl base64 -A

# From remote server
openssl s_client -connect example.com:443 -servername example.com < /dev/null \
  | openssl x509 -outform DER \
  | openssl sha256 -binary \
  | openssl base64 -A
```

#### Hex Output (Alternative)

```bash
# SPKI SHA-256 (hex)
openssl x509 -in cert.pem -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | openssl sha256

# Certificate SHA-256 (hex)
openssl x509 -in cert.pem -outform DER | openssl sha256
```

---

## Summary

This guide covered the essential concepts and APIs for building production-ready HTTP clients in Rust with advanced TLS features:

- **Proxy configuration** routes traffic through intermediaries with authentication
- **Custom root certificates** extend trust to internal or private CAs
- **Mutual TLS** provides strong cryptographic client authentication
- **Certificate inspection** enables debugging and compliance logging
- **Certificate pinning** restricts trust to specific certificates or keys

**Key takeaways:**
1. Use rustls for memory-safe, modern TLS with fine-grained control
2. Never skip certificate verification in production
3. Prefer SPKI pinning over full-certificate pinning for operational flexibility
4. Handle secrets via environment variables or secret management systems
5. Plan for certificate expiration and rotation from day one

For a working implementation demonstrating these concepts, refer to the demo application in this repository.

---

**Additional Resources:**
- [Diátaxis Documentation Framework](https://diataxis.fr/)
- [rustls Documentation](https://docs.rs/rustls/)
- [reqwest Documentation](https://docs.rs/reqwest/)
- [OWASP Certificate Pinning Guide](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)
- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

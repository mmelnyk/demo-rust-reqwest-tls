use std::{fmt, fs, io::BufReader, path::Path, sync::Arc};

use anyhow::{anyhow, bail, Context};
use base64::Engine as _;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::DigitallySignedStruct;
use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::certs;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::cli::PinType;

/// Shared TLS state captured during verification for later reporting.
#[derive(Default, Clone)]
pub struct TlsReport {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub sans: Vec<String>,
    pub spki_sha256_b64: Option<String>,
    pub cert_sha256_b64: Option<String>,
}

impl fmt::Debug for TlsReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsReport")
            .field("subject", &self.subject)
            .field("issuer", &self.issuer)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("sans", &self.sans)
            .field("spki_sha256_b64", &self.spki_sha256_b64)
            .field("cert_sha256_b64", &self.cert_sha256_b64)
            .finish()
    }
}

/// Holder for data exchanged between the custom verifier and the app.
#[derive(Clone, Default, Debug)]
pub struct TlsState {
    pub report: Arc<std::sync::Mutex<TlsReport>>,
    pub pin_result: Arc<std::sync::Mutex<Option<bool>>>,
}

impl TlsState {
    pub fn set_report(&self, r: TlsReport) {
        *self.report.lock().unwrap() = r;
    }
    pub fn set_pin_result(&self, ok: bool) {
        *self.pin_result.lock().unwrap() = Some(ok);
    }
    pub fn take_report(&self) -> TlsReport {
        std::mem::take(&mut *self.report.lock().unwrap())
    }
    pub fn get_pin_result(&self) -> Option<bool> {
        *self.pin_result.lock().unwrap()
    }
}

/// Custom verifier that wraps the default web PKI verifier and optionally enforces pinning.
#[derive(Debug)]
struct PinningVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    pin: Option<Pin>,
    state: TlsState,
    insecure: bool,
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
        // Build a human-friendly report from the leaf cert.
        let report = build_report_from_leaf(end_entity.as_ref());
        self.state.set_report(report);

        // If not insecure, run the default verifier first.
        if !self.insecure {
            self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }

        // If a pin is configured, verify it against the leaf.
        if let Some(pin) = &self.pin {
            let ok = pin.matches(end_entity.as_ref());
            self.state.set_pin_result(ok);
            if !ok {
                return Err(rustls::Error::General("TLS pinning check failed".into()));
            }
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Supported pinning options: SPKI SHA-256 or full certificate SHA-256.
#[derive(Clone, Debug)]
pub enum Pin {
    Spki(Vec<u8>),
    Cert(Vec<u8>),
}

impl Pin {
    pub fn matches(&self, end_entity_der: &[u8]) -> bool {
        match self {
            Pin::Spki(expected) => {
                if let Ok(spki) = spki_sha256(end_entity_der) {
                    &spki == expected
                } else {
                    false
                }
            }
            Pin::Cert(expected) => {
                let mut hasher = Sha256::new();
                hasher.update(end_entity_der);
                let got = hasher.finalize().to_vec();
                &got == expected
            }
        }
    }
}

/// Perform a TLS probe to the origin to gather certificate info and optionally enforce pinning.
/// This runs a separate rustls handshake (not used for the actual reqwest request) to keep the
/// example simple and portable across reqwest versions.
pub async fn probe_tls(
    origin_host: &str,
    origin_port: u16,
    extra_ca_pem: Option<&Path>,
    pin: Option<(PinType, Vec<u8>)>,
    state: TlsState,
    insecure: bool,
) -> anyhow::Result<()> {
    // Root store: use native OS roots for practicality in demos.
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().context("loading native roots")? {
        let _ = roots.add(cert);
    }

    // Optionally add extra CA.
    if let Some(p) = extra_ca_pem {
        let ca_bytes =
            fs::read(p).with_context(|| format!("reading CA cert at {}", p.display()))?;
        let mut reader = BufReader::new(&ca_bytes[..]);
        let ders = certs(&mut reader)?
            .into_iter()
            .map(rustls::pki_types::CertificateDer::from)
            .collect::<Vec<_>>();
        let (added, _skipped) = roots.add_parsable_certificates(ders);
        if added == 0 {
            bail!("no CA certificates parsed from {}", p.display());
        }
    }

    // Build config with our root store.
    let mut config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
    );

    // Prepare pin, if any.
    let pin = if let Some((kind, raw)) = pin {
        match kind {
            PinType::Spki => Some(Pin::Spki(raw)),
            PinType::Cert => Some(Pin::Cert(raw)),
        }
    } else {
        None
    };

    // Install custom verifier (wrapping default WebPKI verifier).
    let default_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots.clone()))
        .build()
        .map_err(|e| anyhow!("failed to build default verifier: {e}"))?;
    let pv = PinningVerifier {
        inner: default_verifier,
        pin,
        state,
        insecure,
    };
    Arc::get_mut(&mut config)
        .expect("unique ClientConfig")
        .dangerous()
        .set_certificate_verifier(Arc::new(pv));

    // Connect and perform handshake to gather info and enforce pin if configured.
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    let addr = format!("{}:{}", origin_host, origin_port);
    let tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("connecting to {}", addr))?;
    let connector = TlsConnector::from(config);
    let host_owned = origin_host.to_owned();
    let sni: &'static str = Box::leak(host_owned.into_boxed_str());
    let server_name =
        ServerName::try_from(sni).map_err(|_| anyhow!("invalid DNS name for TLS SNI"))?;
    let _ = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")?;
    Ok(())
}

// Client authentication (mTLS) is applied via reqwest::Identity in the HTTP client builder.

/// Compute SPKI SHA-256 for the leaf certificate and also build a descriptive report.
fn build_report_from_leaf(leaf_der: &[u8]) -> TlsReport {
    let mut report = TlsReport::default();

    if let Ok((_, cert)) = parse_x509_certificate(leaf_der) {
        report.subject = Some(format_rdn(cert.tbs_certificate.subject()));
        report.issuer = Some(format_rdn(cert.tbs_certificate.issuer()));
        report.not_before = cert.tbs_certificate.validity().not_before.to_rfc2822().ok();
        report.not_after = cert.tbs_certificate.validity().not_after.to_rfc2822().ok();

        // SANs
        if let Ok(Some(san)) = cert.tbs_certificate.subject_alternative_name() {
            let names = san
                .value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::DNSName(d) => Some(d.to_string()),
                    GeneralName::IPAddress(ip) => Some(format_ip(ip)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            report.sans = names;
        }

        // Hashes
        if let Ok(spki) = spki_sha256(leaf_der) {
            report.spki_sha256_b64 = Some(base64::engine::general_purpose::STANDARD.encode(spki));
        }
        let mut hasher = Sha256::new();
        hasher.update(leaf_der);
        report.cert_sha256_b64 =
            Some(base64::engine::general_purpose::STANDARD.encode(hasher.finalize()));
    }

    report
}

fn format_rdn(name: &X509Name) -> String {
    name.iter_attributes()
        .map(|attr| format!("{}={}", attr.attr_type(), attr.as_str().unwrap_or("?")))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => {
            use std::fmt::Write;
            let mut s = String::new();
            for (i, chunk) in bytes.chunks(2).enumerate() {
                if i > 0 {
                    s.push(':');
                }
                let _ = write!(s, "{:02x}{:02x}", chunk[0], chunk[1]);
            }
            s
        }
        _ => format!("{:?}", bytes),
    }
}

fn spki_sha256(leaf_der: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (_, cert) = parse_x509_certificate(leaf_der)
        .map_err(|_| anyhow!("failed to parse leaf certificate"))?;
    let spki = cert.tbs_certificate.subject_pki.subject_public_key.data;
    let mut hasher = Sha256::new();
    hasher.update(spki);
    Ok(hasher.finalize().to_vec())
}

/// Parse a user-provided pin string, accepting base64 or hex.
pub fn parse_pin_bytes(pin_str: &str) -> anyhow::Result<Vec<u8>> {
    let s = pin_str.trim();
    // Try base64 first.
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s) {
        if !bytes.is_empty() {
            return Ok(bytes);
        }
    }
    // Fallback: hex
    let s = s.strip_prefix("0x").unwrap_or(s);
    let cleaned = s.replace(|c: char| c == ':' || c.is_whitespace(), "");
    if cleaned.len() % 2 != 0 {
        bail!("hex pin must have even length");
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
            .with_context(|| format!("invalid hex at position {}", i))?;
        out.push(byte);
    }
    Ok(out)
}

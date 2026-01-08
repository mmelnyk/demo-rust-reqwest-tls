use clap::{ArgGroup, Parser, ValueEnum};

/// Command-line arguments for the demo application.
///
/// This demo performs an HTTPS GET to the provided URL using reqwest + rustls.
/// You can optionally configure an HTTP/HTTPS proxy, provide a client
/// certificate/key pair in PEM for mutual TLS, trust an additional root CA,
/// and enable certificate pinning (SPKI or full-cert SHA-256).
#[derive(Debug, Parser, Clone)]
#[command(
    name = "reqwest-tls-proxy-demo",
    about = "Reqwest demo: proxy, mTLS (PEM), and optional TLS pinning",
    version
)]
#[command(group(
    ArgGroup::new("mtls")
        .args(["client_cert", "client_key"]) // enforced below
        .multiple(true)
))]
pub struct Args {
    /// The HTTPS URL to request.
    pub url: String,

    /// Explicit HTTP/HTTPS proxy URL (example: http://localhost:8080 or https://proxy:8443).
    #[arg(long)]
    pub proxy: Option<String>,

    /// Path to client certificate in PEM (for mutual TLS).
    #[arg(long)]
    pub client_cert: Option<String>,

    /// Path to client private key in PEM (unencrypted PKCS#8 or RSA) (for mutual TLS).
    #[arg(long)]
    pub client_key: Option<String>,

    /// Path to an additional root CA certificate (PEM) to trust.
    #[arg(long)]
    pub ca_cert: Option<String>,

    /// TLS pin hash string (base64 or hex). If set, enables pinning.
    /// The interpretation depends on `--pin-type`.
    #[arg(long)]
    pub tls_pin: Option<String>,

    /// Pin type: `spki` (SubjectPublicKeyInfo hash) or `cert` (full certificate DER hash).
    #[arg(long, value_enum, default_value_t = PinType::Spki)]
    pub pin_type: PinType,

    /// Insecure: skip default certificate verification (for demo/learning only!).
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// Request timeout in seconds (overall).
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,

    /// Increase verbosity (use multiple times: -v, -vv).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

/// Type of pinning to apply when `--tls-pin` is supplied.
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
pub enum PinType {
    /// Hash the SubjectPublicKeyInfo (SPKI) of the leaf certificate (recommended default).
    Spki,
    /// Hash the full DER-encoded leaf certificate.
    Cert,
}

impl Args {
    /// Validate argument combinations that clap's grouping doesn't fully enforce.
    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::{bail, Context};
        // If either client_cert or client_key is provided, both must be.
        match (&self.client_cert, &self.client_key) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => bail!("--client-cert and --client-key must be provided together for mTLS"),
        }

        // Basic URL sanity check (let reqwest handle full validation later).
        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            bail!("url must start with 'https://' or 'http://' (HTTPS recommended)");
        }

        // If pinning is supplied, ensure non-empty string.
        if let Some(pin) = &self.tls_pin {
            if pin.trim().is_empty() {
                bail!("--tls-pin cannot be empty when provided");
            }
        }

        // Proxy sanity check if present.
        if let Some(p) = &self.proxy {
            url::Url::parse(p).context("invalid proxy URL format")?;
        }

        Ok(())
    }
}

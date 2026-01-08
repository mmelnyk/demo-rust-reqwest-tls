use anyhow::Context;
use reqwest::{Client, ClientBuilder, Identity, Proxy};

use crate::cli::Args;
use crate::tls::TlsState;

/// Build a reqwest Client configured with rustls, optional proxy, optional mTLS, and optional pinning.
pub fn build_client(args: &Args, _state: TlsState) -> anyhow::Result<Client> {
    // Construct ClientBuilder with default rustls backend.
    let mut builder = ClientBuilder::new()
        .danger_accept_invalid_certs(args.insecure)
        .http2_adaptive_window(true)
        .http2_keep_alive_timeout(std::time::Duration::from_secs(30))
        .pool_max_idle_per_host(2)
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::from_secs(args.timeout));

    if let Some(proxy_url) = &args.proxy {
        builder = builder.proxy(Proxy::all(proxy_url).with_context(|| "invalid --proxy URL")?);
    }

    // Additional CA trust for reqwest side.
    if let Some(ca_path) = &args.ca_cert {
        let ca_bytes =
            std::fs::read(ca_path).with_context(|| format!("reading CA cert at {}", ca_path))?;
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&ca_bytes)?);
    }

    // Optional client identity (mTLS) using concatenated PEM of cert + key.
    if let (Some(cert_path), Some(key_path)) = (&args.client_cert, &args.client_key) {
        let cert_bytes = std::fs::read(cert_path)
            .with_context(|| format!("reading client cert at {}", cert_path))?;
        let key_bytes = std::fs::read(key_path)
            .with_context(|| format!("reading client key at {}", key_path))?;
        let mut pem = Vec::new();
        pem.extend_from_slice(&cert_bytes);
        if !pem.ends_with(b"\n") {
            pem.push(b'\n');
        }
        pem.extend_from_slice(&key_bytes);
        builder = builder.identity(Identity::from_pem(&pem)?);
    }

    Ok(builder.build()?)
}

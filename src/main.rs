mod cli;
mod http_client;
mod tls;

use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use clap::Parser;
use futures_util::StreamExt;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::cli::Args;
use crate::tls::{parse_pin_bytes, probe_tls, TlsState};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    // Parse CLI args and initialize logging before doing anything else.
    let args = Args::parse();
    args.validate()?;

    init_tracing(args.verbose);

    // Install a default crypto provider for rustls 0.23 (using ring backend).
    // This is required when using rustls directly.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring crypto provider");

    info!(target: "app", url = %args.url, "Starting request");

    let state = TlsState::default();

    // If proxy is set, we probe TLS directly to origin (not through proxy) for learning/demo purposes.
    // For production pinning, integrate with the actual TLS stack.
    let url = reqwest::Url::parse(&args.url).context("parsing URL")?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL missing host"))?
        .to_string();
    let port = url
        .port()
        .unwrap_or_else(|| if url.scheme() == "https" { 443 } else { 80 });

    // Prepare pin if supplied for the probe.
    let pin = if let Some(pin_str) = &args.tls_pin {
        let bytes = parse_pin_bytes(pin_str)?;
        Some((args.pin_type, bytes))
    } else {
        None
    };

    // Probe TLS to capture cert info and optionally enforce pinning.
    use std::path::Path;
    probe_tls(
        &host,
        port,
        args.ca_cert.as_deref().map(Path::new),
        pin,
        state.clone(),
        args.insecure,
    )
    .await?;

    // Build client
    let client = http_client::build_client(&args, state.clone()).context("building HTTP client")?;

    // Prepare request
    let req = client.get(&args.url);

    // Measure times
    let t_start = Instant::now();

    // Send and wait for headers (TTFB)
    let resp = req.send().await.context("sending request")?;
    let t_ttfb = Instant::now();

    let status = resp.status();
    let version = resp.version();
    let headers = resp.headers().clone();

    info!(target: "app", %status, ?version, "Headers received (TTFB)");

    // When pinning is off, print certificate information gathered by verifier.
    if args.tls_pin.is_none() {
        let report = state.take_report();
        print_cert_report(&report);
    } else if let Some(ok) = state.get_pin_result() {
        if ok {
            info!("TLS pin verified successfully");
        } else {
            error!("TLS pin verification failed");
        }
    }

    // Stream the body with progress.
    let mut stream = resp.bytes_stream();
    let mut total: u64 = 0;
    let mut last_print = Instant::now();

    let mut first_byte_time: Option<Instant> = None; // For clarity; equals t_ttfb usually.

    // Print basic response metadata.
    info!(target: "app", "Response headers:");
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            info!(target: "app", "{}: {}", name, v);
        }
    }

    while let Some(chunk) = stream.next().await {
        let chunk: Bytes = match chunk {
            Ok(c) => c,
            Err(e) => {
                error!("stream error: {e}");
                break;
            }
        };
        if first_byte_time.is_none() {
            first_byte_time = Some(Instant::now());
        }
        total += chunk.len() as u64;

        // Throttle progress output (every 200ms)
        if last_print.elapsed() >= Duration::from_millis(200) {
            let elapsed = t_start.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                (total as f64) / elapsed
            } else {
                0.0
            };
            info!(target: "progress", bytes = total, rate_bps = rate as u64, "downloading...");
            last_print = Instant::now();
        }
    }

    let t_end = Instant::now();

    // Final stats
    let ttfb_ms = (t_ttfb - t_start).as_millis();
    let total_ms = (t_end - t_start).as_millis();
    let throughput = if total_ms > 0 {
        (total * 1000) as u128 / total_ms
    } else {
        0
    };

    println!("\n===== Session Summary =====");
    println!("URL: {}", args.url);
    println!("Status: {}", status);
    println!("HTTP Version: {:?}", version);
    println!("TTFB: {} ms", ttfb_ms);
    println!("Total time: {} ms", total_ms);
    println!("Bytes downloaded: {} bytes", total);
    println!("Throughput: {} bytes/s (approx)", throughput);

    Ok(())
}

/// Initialize tracing/subscriber based on verbosity flags.
fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Pretty-print TLS certificate info gathered by the verifier.
fn print_cert_report(r: &tls::TlsReport) {
    println!("\n===== Server Certificate (leaf) =====");
    if let Some(s) = &r.subject {
        println!("Subject: {}", s);
    }
    if let Some(i) = &r.issuer {
        println!("Issuer: {}", i);
    }
    if let Some(nbf) = &r.not_before {
        println!("Not Before: {}", nbf);
    }
    if let Some(naf) = &r.not_after {
        println!("Not After: {}", naf);
    }
    if !r.sans.is_empty() {
        println!("SANs: {}", r.sans.join(", "));
    }
    if let Some(spki) = &r.spki_sha256_b64 {
        println!("SPKI SHA-256 (base64): {}", spki);
    }
    if let Some(ch) = &r.cert_sha256_b64 {
        println!("Cert SHA-256 (base64): {}", ch);
    }
}

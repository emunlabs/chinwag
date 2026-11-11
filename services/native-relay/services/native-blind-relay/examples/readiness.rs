//! A fresh, unauthorized identity must reach the actual iroh authentication denial.
//! This never loads a product key, sends a datagram, or changes an endpoint configuration.
use iroh_base::{RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::{ClientBuilder, ConnectError},
    protos::handshake,
    tls::CaTlsConfig,
};
use std::{error::Error, sync::Arc, time::Duration};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let origin = std::env::args()
        .nth(1)
        .ok_or("usage: readiness https://<relay-origin>")?;
    let url: RelayUrl = origin.parse()?;
    if !matches!(url.scheme(), "https" | "http") || url.path() != "/" || url.query().is_some() {
        return Err("supply a bare HTTP(S) relay origin".into());
    }
    let secret = SecretKey::generate();
    let tls =
        CaTlsConfig::default().client_config(Arc::new(rustls::crypto::ring::default_provider()))?;
    let builder = ClientBuilder::new(url, secret, DnsResolver::new()).tls_client_config(tls);
    match tokio::time::timeout(Duration::from_secs(15), builder.connect()).await {
        Ok(Err(ConnectError::Handshake {
            source: handshake::Error::ServerDeniedAuth { reason, .. },
            ..
        })) if reason == "unauthorized" => {
            println!("PASS iroh-relay=1.4.1 protocol=iroh-relay-v2 native_client=true expected_auth_denial=true");
            Ok(())
        }
        Ok(Ok(_)) => Err("FAIL fresh unknown identity was authorized".into()),
        Ok(Err(error)) => Err(format!("FAIL native relay negotiation: {error}").into()),
        Err(_) => Err("FAIL native relay negotiation timed out".into()),
    }
}

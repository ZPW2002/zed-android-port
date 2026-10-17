use std::sync::OnceLock;

use rustls::ClientConfig;
#[cfg(target_os = "android")]
use rustls::RootCertStore;
#[cfg(not(target_os = "android"))]
use rustls_platform_verifier::ConfigVerifierExt;

static TLS_CONFIG: OnceLock<rustls::ClientConfig> = OnceLock::new();

/// Build (once) a rustls ClientConfig.
///
/// On Android we trust the Mozilla CA bundle via webpki-roots. We previously
/// used rustls-platform-verifier, but its TrustManager bridge maps
/// UNDETERMINED_REVOCATION_STATUS to CertificateError::Revoked, which makes
/// downloads from CDN hosts like release-assets.githubusercontent.com
/// (Let's Encrypt cert, no OCSP responder) fail with a spurious "Revoked"
/// error. Static roots + no revocation matches reqwest's default
/// rustls-tls-webpki-roots behaviour and avoids that whole class.
///
/// Everywhere else we use the platform certificate verifier, falling back to
/// the bundled webpki roots when it cannot be loaded.
pub fn tls_config() -> ClientConfig {
    TLS_CONFIG
        .get_or_init(|| {
            // rustls uses the aws_lc_rs provider by default. install_default
            // errors if a provider is already installed; ignore that case.
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .ok();

            #[cfg(target_os = "android")]
            let config = {
                let mut roots = RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            };

            #[cfg(not(target_os = "android"))]
            let config = ClientConfig::with_platform_verifier().unwrap_or_else(|error| {
                log::error!(
                    "failed to load platform TLS certificate verifier, falling back to bundled webpki roots: {error}"
                );
                ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore {
                        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                    })
                    .with_no_client_auth()
            });

            config
        })
        .clone()
}

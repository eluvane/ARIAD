#![forbid(unsafe_code)]

pub(crate) const MAX_CERTIFICATE_DER_BYTES: usize = 16 * 1024;

#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
pub(crate) const H2_ALPN: &[u8] = b"h2";

#[cfg(feature = "h3")]
pub(crate) const H3_ALPN: &[u8] = b"h3";

#[cfg(feature = "tls-rustls")]
pub(crate) const RUSTLS_TLS_VERSION: &rustls::SupportedProtocolVersion = &rustls::version::TLS13;

#[cfg(feature = "tls-boring")]
pub(crate) const NATIVE_TLS_VERSION: boring::ssl::SslVersion = boring::ssl::SslVersion::TLS1_3;

#[cfg(feature = "tls-boring")]
// The native API needs length-prefixed offers; peer checks use the ALPN token.
pub(crate) const H2_ALPN_OFFER: [u8; H2_ALPN.len() + 1] = {
    let mut offer = [0; H2_ALPN.len() + 1];
    offer[0] = H2_ALPN.len() as u8;
    let mut index = 0;
    while index < H2_ALPN.len() {
        offer[index + 1] = H2_ALPN[index];
        index += 1;
    }
    offer
};

#[cfg(feature = "tls-boring")]
pub(crate) fn native_negotiation_matches(ssl: &boring::ssl::SslRef, alpn: &[u8]) -> bool {
    ssl.version2() == Some(NATIVE_TLS_VERSION) && ssl.selected_alpn_protocol() == Some(alpn)
}

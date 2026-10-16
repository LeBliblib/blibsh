use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};
use std::io::Cursor;

/// Load X.509 certificates from PEM-encoded data.
///
/// Cursor is used to read from include_bytes! embedded certificate data.
pub fn load_certs(cursor: &mut Cursor<&[u8]>) -> Vec<CertificateDer<'static>> {
    certs(cursor).collect::<Result<Vec<_>, _>>().unwrap()
}

/// Load a private key from PEM-encoded data.
///
/// Cursor is used to read from include_bytes! embedded key data.
pub fn load_key(cursor: &mut Cursor<&[u8]>) -> PrivateKeyDer<'static> {
    private_key(cursor).unwrap().unwrap()
}

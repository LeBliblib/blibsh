use common::message::{Request, Response};

use crate::{CLIENT_KEY, client::Client, response_handling::ResponseHandlingResult};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};

pub enum AuthStatus {
    NotAuthentified,
    WaitingForChallenge,
    Authentified,
}

pub fn handle_auth_success(client: &mut Client) -> ResponseHandlingResult {
    println!("Authentication successful.");
    client.auth_status = AuthStatus::Authentified;

    ResponseHandlingResult::None
}

/// Handle authentication challenge from the server (nonce-based signature verification).
///
/// Receive nonce, sign it with private key, send signature as proof of certificate possession.
pub fn handle_auth_challenge(response: &Response, client: &mut Client) -> ResponseHandlingResult {
    match &response {
        Response::AuthChallenge { nonce } => {
            let signature = sign_nonce(&nonce, CLIENT_KEY);
            client.auth_status = AuthStatus::WaitingForChallenge;
            return ResponseHandlingResult::Request(Request::AuthChallenge { sign: signature });
        }
        _ => {
            println!("Authentication: Unexpected response.");
            client.auth_status = AuthStatus::NotAuthentified;
            return ResponseHandlingResult::Request(Request::Disconnect {
                reason: String::from("Unexpected response."),
            });
        }
    }
}

/// Sign a nonce with the client's private key using SHA-256.
///
/// # Arguments
/// * `nonce` - The nonce to sign
/// * `pem` - The PEM-encoded private key
fn sign_nonce(nonce: &[u8], pem: &[u8]) -> Vec<u8> {
    let private_key = PKey::private_key_from_pem(pem).unwrap();

    let mut signer = Signer::new(MessageDigest::sha256(), &private_key).unwrap();

    signer.update(nonce).unwrap();

    signer.sign_to_vec().unwrap()
}

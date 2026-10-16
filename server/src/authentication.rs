use common::message::{AuthMode, Request, Response};
use tokio::process::Command;

use crate::{client::Client, password, request_handling::RequestHandlingResult, user::load_user};

#[derive(PartialEq)]
pub enum AuthStatus {
    NotAuthentified,
    WaitingForChallenge { nonce: Vec<u8> },
    Authentified,
}

/// Handle password-based authentication.
///
/// Verifies the user exists and the password matches the stored hash using Argon2.
pub async fn handle_password_auth(req: &Request, cli: &mut Client) -> RequestHandlingResult {
    if let Request::Auth {
        user,
        mode: AuthMode::Password { password },
    } = req
    {
        if cli.auth_status != AuthStatus::NotAuthentified {
            return RequestHandlingResult::None;
        }

        let res = load_user(user);

        if let Err(_) = res {
            return RequestHandlingResult::Response(Response::Disconnect {
                reason: String::from("User not found."),
            });
        }

        let (user, role) = res.unwrap();

        if !password::verify_password(password, &user.password_hash) {
            return RequestHandlingResult::Response(Response::Disconnect {
                reason: String::from("Incorrect password."),
            });
        }

        cli.set_user(user, role);
        if !on_auth_success(cli) {
            return RequestHandlingResult::Response(Response::Disconnect {
                reason: String::from("Failed to spawn shell process."),
            });
        }

        return RequestHandlingResult::Response(Response::AuthSuccess);
    }

    RequestHandlingResult::Response(Response::Disconnect {
        reason: String::from("Unknown server error."),
    })
}

/// Handle certificate-based authentication challenge.
///
/// Generates a random nonce and sends it to the client for signature verification.
pub async fn handle_certificate_auth(req: &Request, cli: &mut Client) -> RequestHandlingResult {
    if let Request::Auth {
        user,
        mode: AuthMode::Certificate,
    } = req
    {
        if cli.auth_status != AuthStatus::NotAuthentified {
            return RequestHandlingResult::None;
        }

        let res = load_user(user);

        if let Err(_) = res {
            return RequestHandlingResult::Response(Response::Disconnect {
                reason: String::from("User not found."),
            });
        }

        // Their might be a better way to generate a nonce.
        let mut n = [0u8; 32];
        rand::fill(&mut n);

        let (user, role) = res.unwrap();

        cli.set_user(user, role);
        cli.set_auth_status(AuthStatus::WaitingForChallenge { nonce: n.to_vec() });

        return RequestHandlingResult::Response(Response::AuthChallenge { nonce: n.to_vec() });
    }

    RequestHandlingResult::Response(Response::Disconnect {
        reason: String::from("Unknown server error."),
    })
}

use openssl::{hash::MessageDigest, sign::Verifier, x509::X509};

/// Handle the authentication challenge response.
///
/// Verifies the client's signature against the nonce using their public certificate.
pub async fn handle_auth_challenge(req: &Request, cli: &mut Client) -> RequestHandlingResult {
    if let Request::AuthChallenge { sign } = req {
        if let AuthStatus::WaitingForChallenge { nonce } = &cli.auth_status {
            let user = match &cli.user_data {
                Some(u) => u,
                None => {
                    return RequestHandlingResult::Response(Response::Disconnect {
                        reason: String::from("User not found."),
                    });
                }
            };

            let cert = match X509::from_pem(&user.public_cert) {
                Ok(c) => c,
                Err(_) => {
                    return RequestHandlingResult::Response(Response::Disconnect {
                        reason: String::from("Invalid certificate on server."),
                    });
                }
            };

            let public_key = match cert.public_key() {
                Ok(c) => c,
                Err(_) => {
                    return RequestHandlingResult::Response(Response::Disconnect {
                        reason: String::from("Invalid certificate on server."),
                    });
                }
            };

            let mut verifier = match Verifier::new(MessageDigest::sha256(), &public_key) {
                Ok(v) => v,
                Err(_) => {
                    return RequestHandlingResult::Response(Response::Disconnect {
                        reason: String::from("Invalid certificate on server."),
                    });
                }
            };

            if !verifier.update(nonce).is_ok() {
                return RequestHandlingResult::Response(Response::Disconnect {
                    reason: String::from("Certificates do not match."),
                });
            }

            if !verifier.verify(sign).unwrap_or(false) {
                return RequestHandlingResult::Response(Response::Disconnect {
                    reason: String::from("Certificates do not match."),
                });
            }

            if !on_auth_success(cli) {
                return RequestHandlingResult::Response(Response::Disconnect {
                    reason: String::from("Failed to spawn shell process."),
                });
            }

            return RequestHandlingResult::Response(Response::AuthSuccess);
        } else {
            return RequestHandlingResult::Response(Response::Disconnect {
                reason: String::from("Unexpected authentication challenge."),
            });
        }
    }

    RequestHandlingResult::Response(Response::Disconnect {
        reason: String::from("Unknown server error."),
    })
}

/// Perform post-authentication setup.
///
/// Spawns a shell process (bash) as the authenticated user using sudo.
fn on_auth_success(cli: &mut Client) -> bool {
    let role = match &cli.role_data {
        Some(r) => r,
        None => {
            return false;
        }
    };

    let child = Command::new("sudo")
        .args(&["-u", &role.os_user, "/bin/bash"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    if let Err(e) = child {
        println!("Failed to spawn shell process for {}: {}", cli.client_id, e);
        return false;
    }

    let mut child = child.unwrap();

    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    cli.set_shell_process(child, stdin, stdout, stderr);
    cli.set_auth_status(AuthStatus::Authentified);

    println!("Client {} authenticated successfully.", cli.client_id);
    true
}

#[cfg(test)]
mod tests {
    // Testing success is difficult because it relies on filesystem and a lot of other things.
    // Here we are only testing for errors.

    use std::net::SocketAddr;

    use common::admin::RoleType;
    use common::message::{AuthMode, Request, Response};

    use crate::user::{Role, User};

    use super::*;

    fn test_client(auth_status: AuthStatus) -> Client {
        let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut client = Client::new(addr);
        client.set_auth_status(auth_status);
        client
    }

    #[tokio::test]
    async fn password_auth_rejects_second_auth_attempt() {
        let req = Request::Auth {
            user: String::from("alice"),
            mode: AuthMode::Password {
                password: b"secret".to_vec(),
            },
        };
        let mut client = test_client(AuthStatus::Authentified);

        match handle_password_auth(&req, &mut client).await {
            RequestHandlingResult::None => {
                assert!(true);
            }
            other => panic!("expected none, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn password_auth_rejects_non_auth_request() {
        let req = Request::Disconnect {
            reason: String::from("bye"),
        };
        let mut client = test_client(AuthStatus::NotAuthentified);

        match handle_password_auth(&req, &mut client).await {
            RequestHandlingResult::Response(Response::Disconnect { reason }) => {
                assert_eq!(reason, "Unknown server error.");
            }
            other => panic!("expected disconnect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn certificate_auth_returns_none_when_already_authenticated() {
        let req = Request::Auth {
            user: String::from("alice"),
            mode: AuthMode::Certificate,
        };
        let mut client = test_client(AuthStatus::Authentified);

        match handle_certificate_auth(&req, &mut client).await {
            RequestHandlingResult::None => {}
            other => panic!("expected none, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn certificate_auth_rejects_non_auth_request() {
        let req = Request::Command {
            cmd_line: String::from("ls -la"),
        };
        let mut client = test_client(AuthStatus::NotAuthentified);

        match handle_certificate_auth(&req, &mut client).await {
            RequestHandlingResult::Response(Response::Disconnect { reason }) => {
                assert_eq!(reason, "Unknown server error.");
            }
            other => panic!("expected disconnect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn auth_challenge_rejects_unexpected_state() {
        let req = Request::AuthChallenge {
            sign: vec![1, 2, 3],
        };
        let mut client = test_client(AuthStatus::NotAuthentified);

        match handle_auth_challenge(&req, &mut client).await {
            RequestHandlingResult::Response(Response::Disconnect { reason }) => {
                assert_eq!(reason, "Unexpected authentication challenge.");
            }
            other => panic!("expected disconnect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn auth_challenge_rejects_missing_user_data() {
        let req = Request::AuthChallenge {
            sign: vec![1, 2, 3],
        };
        let mut client = test_client(AuthStatus::WaitingForChallenge {
            nonce: vec![4, 5, 6],
        });

        match handle_auth_challenge(&req, &mut client).await {
            RequestHandlingResult::Response(Response::Disconnect { reason }) => {
                assert_eq!(reason, "User not found.");
            }
            other => panic!("expected disconnect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn auth_challenge_rejects_invalid_certificate() {
        let req = Request::AuthChallenge {
            sign: vec![1, 2, 3],
        };
        let mut client = test_client(AuthStatus::WaitingForChallenge {
            nonce: vec![4, 5, 6],
        });
        client.user_data = Some(User {
            id: String::from("alice"),
            password_hash: String::from("hash"),
            public_cert: b"not a pem certificate".to_vec(),
        });
        client.role_data = Some(Role {
            os_user: String::from("alice"),
            role: RoleType::User,
        });

        match handle_auth_challenge(&req, &mut client).await {
            RequestHandlingResult::Response(Response::Disconnect { reason }) => {
                assert_eq!(reason, "Invalid certificate on server.");
            }
            other => panic!("expected disconnect, got {other:?}"),
        }
    }
}

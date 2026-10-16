mod admin;
mod authentication;
mod builtins;
mod client;
mod response_handling;
mod user;

use clap::Parser;
use common::{
    certs::{load_certs, load_key},
    message::{AuthMode, Request, Response},
    receiver::Receiver,
};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};

use std::{
    io::{Cursor, Write},
    process::exit,
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{self, AsyncBufReadExt},
    net::TcpStream,
    select,
    sync::{Mutex, mpsc},
};

use tokio_rustls::{TlsConnector, TlsStream};

use tokio::io::AsyncWriteExt;

use crate::builtins::BuiltinResult;
use crate::{authentication::AuthStatus, builtins::handle_builtin, client::Client};

use crate::response_handling::ResponseHandlingResult;

/// Shared input stream for interactive user prompts
pub type SharedInput = Arc<Mutex<io::Lines<io::BufReader<io::Stdin>>>>;

// Authentication mode constants
const AUTH_PASSWORD: &str = "password";
const AUTH_PASSWORD_SHORT: &str = "p";
const AUTH_CERT: &str = "certificate";
const AUTH_CERT_SHORT: &str = "c";

// Embedded certificate and key data
const CLIENT_CERT: &[u8] = include_bytes!("../../certs/client.crt");
const CLIENT_KEY: &[u8] = include_bytes!("../../certs/client.key");
const CA_CERT: &[u8] = include_bytes!("../../certs/ca.crt");

#[derive(Parser)]
#[command(name = "My App")]
#[command(about = "A simple CLI application", long_about = None)]
struct Args {
    /// Username to authenticate with
    user: String,
    /// Server address and port (e.g., 127.0.0.1:45000)
    address: String,

    /// Authentication method: 'password', 'p', 'certificate', 'c'
    #[arg(short, long, default_value = AUTH_PASSWORD_SHORT)]
    auth: String,
}

/// Exit status for client session loops.
#[derive(PartialEq, Eq)]
enum ExitStatus {
    /// Immediately kill the connection
    Kill,
    /// Wait for disconnect acknowledgment
    WaitingForAck,
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let args = Args::parse();

    // Load client certificate and key for mTLS
    let mut cursor = Cursor::new(CLIENT_CERT);
    let client_certs = load_certs(&mut cursor);

    let mut cursor = Cursor::new(CLIENT_KEY);
    let client_key = load_key(&mut cursor);

    // Load CA certificate for server verification
    let mut cursor = Cursor::new(CA_CERT);
    let ca = load_certs(&mut cursor);

    // Configure TLS with client certificate
    let mut roots = RootCertStore::empty();
    roots.add(ca[0].clone()).unwrap();

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certs, client_key)
        .unwrap();

    // Connect to server with TLS
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(args.address.clone()).await?;
    let domain = ServerName::try_from("localhost").unwrap();
    let stream = connector.connect(domain, stream).await?;

    let stream = TlsStream::Client(stream);

    let (stream_reader, mut stream_writer) = tokio::io::split(stream);
    let (resp_producer, mut resp_receiver) = mpsc::channel::<Response>(64);

    // Start async receiver task
    let mut receiver = Receiver::new(stream_reader, resp_producer);
    let receiver_handle = tokio::spawn(async move { receiver.run().await });

    // Create shared input for interactive prompts
    let lines: SharedInput = Arc::new(Mutex::new(io::BufReader::new(io::stdin()).lines()));

    let mut client = Client {
        auth_status: AuthStatus::NotAuthentified,
    };

    // Build and send authentication request
    let auth_req = build_auth_request(&args, &lines).await;

    let res = send_request(&auth_req, &mut stream_writer).await;

    if let Err(e) = res {
        eprintln!("Failed to send request: {}", e);
        receiver_handle.abort();
        return Ok(());
    }

    let mut prompt_visible = false;

    let status: ExitStatus;

    loop {
        if !prompt_visible {
            print!("> ");
            std::io::stdout().flush().unwrap();
            prompt_visible = true;
        }

        select! {
            Some(msg) = resp_receiver.recv() => {
                if prompt_visible {
                    clear_prompt();
                    prompt_visible = false;
                }

                let req = response_handling::handle_response(&msg, &mut client, &lines).await;

                match req {
                    ResponseHandlingResult::Request(req) => {
                        let res = send_request(&req, &mut stream_writer).await;

                        if let Err(e) = res {
                            eprintln!("Failed to send request: {}", e);
                            status = ExitStatus::Kill;
                            break;
                        }

                        if let Request::Disconnect { reason } = req {
                            println!("Disconnecting: {}...", reason);
                            status = ExitStatus::WaitingForAck;
                            break;
                        }

                        if let Request::DisconnectAck = req {
                            status = ExitStatus::Kill;
                            break;
                        }
                    }
                    ResponseHandlingResult::None => {}
                }

                println!();
            }

            res = next_input_line(&lines) => {
                let line = match res {
                    Ok(Some(line)) => line,
                    Ok(None) => {
                        eprintln!("Failed to read input.");
                        status = ExitStatus::Kill;
                        break;
                    }
                    Err(e) => {
                        eprintln!("Failed to read input: {}", e);
                        status = ExitStatus::Kill;
                        break;
                    }
                };

                prompt_visible = false;

                if !matches!(client.auth_status, AuthStatus::Authentified) {
                    continue;
                }

                let req = match handle_builtin(&line, &lines).await {
                    BuiltinResult::Request(req) => req,
                    BuiltinResult::None => continue,
                    BuiltinResult::NotBuiltin => Request::Command { cmd_line: line },
                };

                let res = send_request(&req, &mut stream_writer).await;

                if let Err(e) = res {
                    eprintln!("Failed to send request: {}", e);
                    status = ExitStatus::Kill;
                    break;
                }

                if let Request::Disconnect { reason } = req {
                    println!("Disconnecting: {}...", reason);
                    status = ExitStatus::WaitingForAck;
                    break;
                }

                if let Request::DisconnectAck = req {
                    status = ExitStatus::Kill;
                    break;
                }
            }
        }
    }

    match status {
        ExitStatus::Kill => {
            let _ = stream_writer.flush().await;
            let _ = stream_writer.shutdown().await;
        }
        ExitStatus::WaitingForAck => loop {
            match tokio::time::timeout(Duration::from_secs(3), resp_receiver.recv()).await {
                Ok(Some(msg)) => {
                    if let Response::DisconnectAck = msg {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    break;
                }
            }
        },
    }

    receiver_handle.abort();
    println!("Disconnected.");

    exit(0);
}

/// Clear the command prompt from the terminal display.
fn clear_prompt() {
    print!("\r\x1b[2K");
    std::io::stdout().flush().unwrap();
}

/// Build an authentication request based on command-line arguments.
/// Prompts for password if password auth is selected, otherwise creates certificate auth request.
async fn build_auth_request(args: &Args, lines: &SharedInput) -> Request {
    println!("Auth method: {}", args.auth);

    match args.auth.as_str() {
        AUTH_PASSWORD | AUTH_PASSWORD_SHORT => {
            println!("Password: ");

            let password = match next_input_line(lines).await {
                Ok(Some(l)) => l,
                _ => {
                    return Request::Disconnect {
                        reason: String::from("Failed to read password."),
                    };
                }
            };

            Request::Auth {
                user: args.user.clone(),
                mode: AuthMode::Password {
                    password: password.trim().as_bytes().to_vec(),
                },
            }
        }
        AUTH_CERT | AUTH_CERT_SHORT => Request::Auth {
            user: args.user.clone(),
            mode: AuthMode::Certificate,
        },
        _ => {
            println!("Unknown authentication method.");
            return Request::Disconnect {
                reason: String::from("Unknown authentication method."),
            };
        }
    }
}

/// Send a request message to the server over the TLS stream.
///
/// Serialize with message pack with usize sized header indicating message length.
/// [8-byte size in little-endian] [serialized message]
async fn send_request(
    req: &Request,
    stream_writer: &mut tokio::io::WriteHalf<TlsStream<tokio::net::TcpStream>>,
) -> Result<(), io::Error> {
    let res = rmp_serde::to_vec(&req);

    if let Err(e) = res {
        eprintln!("Unable to serialize request. {}", e);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Unable to serialize request.",
        ));
    }

    let buf = res.unwrap();

    let header = buf.len();
    stream_writer.write(&header.to_le_bytes()).await?;
    stream_writer.write(&buf).await?;

    Ok(())
}

/// Read the next line from the shared input.
pub async fn next_input_line(lines: &SharedInput) -> io::Result<Option<String>> {
    let mut lines = lines.lock().await;
    lines.next_line().await
}

mod admin;
mod authentication;
mod client;
mod commands;
mod password;
mod request_handling;
mod user;

use clap::Parser;
use is_root::is_root;

use std::{io::Cursor, process::exit, sync::Arc};

use common::{
    admin::RoleType,
    certs::{load_certs, load_key},
};
use rustls::{RootCertStore, server::WebPkiClientVerifier};
use tokio::{
    io::{self},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

use crate::client::client_handler;

// Embedded certificate and key data
const SRV_CERT: &[u8] = include_bytes!("../../certs/server.crt");
const SRV_KEY: &[u8] = include_bytes!("../../certs/server.key");
const CA_CERT: &[u8] = include_bytes!("../../certs/ca.crt");

/// Command-line arguments for the server.
#[derive(Parser)]
#[command(name = "Bsh Server")]
#[command(about = "Ssh like server", long_about = None)]
struct Args {
    /// Run initial server setup (creates admin user)
    #[arg(long)]
    setup: bool,

    /// Port to listen on (default: 45000)
    #[arg(short, long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // Verify root privileges
    if !is_root() {
        println!("Server should run as root.");
        exit(1);
    }

    let args = Args::parse();

    // Handle initial setup
    if args.setup {
        println!("Setting up server...");
        println!("");

        println!("Admin user setup:");
        if user::user_setup(RoleType::Admin, String::from("admin"))
            .await
            .is_err()
        {
            println!("Failed to setup admin user.");
            exit(1);
        }

        println!("Setup complete.");
        return Ok(());
    }

    println!("Starting server...");

    // Load server certificate and key
    let mut cursor = Cursor::new(SRV_CERT);
    let server_certs = load_certs(&mut cursor);

    let mut cursor = Cursor::new(SRV_KEY);
    let server_key = load_key(&mut cursor);

    // Load CA certificate for client verification
    let mut cursor = Cursor::new(CA_CERT);
    let ca = load_certs(&mut cursor);

    // Configure TLS with client certificate verification
    let mut roots = RootCertStore::empty();
    roots.add(ca[0].clone()).unwrap();

    let verifier = WebPkiClientVerifier::builder(roots.into()).build().unwrap();

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)
        .unwrap();

    let arc_config = Arc::new(config);
    let acceptor = TlsAcceptor::from(arc_config);
    let listener = TcpListener::bind(format!("127.0.0.1:{}", args.port.unwrap_or(45000))).await?;

    // Accept incoming client connections
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();

        // Spawn a new task for each client connection
        tokio::spawn(client_handler(stream, acceptor, peer_addr));
    }
}
